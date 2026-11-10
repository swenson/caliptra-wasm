// Licensed under the Apache-2.0 license

//! WASM wrapper for the Caliptra hardware emulator.
//!
//! Provides a JavaScript-friendly API to initialize and run the Caliptra
//! emulator with custom ROM, vendor/owner PK hashes, FW image, and UART
//! output capture.

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

use caliptra_api::SocManager;
use caliptra_api_types::{
    DeviceLifecycle, Fuses, SecurityState, DEFAULT_CPTRA_OBF_KEY, DEFAULT_CSR_HMAC_KEY,
};
use caliptra_emu_periph::MailboxRequester;
use caliptra_hw_model::{BootParams, ExitStatus, HwModel, InitParams, ModelEmulated, TrngMode};
use caliptra_hw_model_types::{EtrngResponse, RandomEtrngResponses, RandomNibbles};
use caliptra_image_types::ImageManifest;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha384};
use wasm_bindgen::prelude::*;
use zerocopy::{FromBytes, IntoBytes};

mod fuse_config;
use fuse_config::FuseConfig;

/// A shared buffer that captures log/UART output via the `Write` trait.
#[derive(Clone)]
struct SharedBuffer(Rc<RefCell<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Parse a hex string (e.g. "aabbccdd...") into a `[u32; 12]` array (big-endian words).
/// Expects exactly 96 hex characters (48 bytes = 12 × 4-byte words).
fn parse_pk_hash(hex: &str) -> Result<[u32; 12], String> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Ok([0u32; 12]);
    }

    // Strip optional "0x" prefix
    let hex = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);

    if hex.len() != 96 {
        return Err(format!(
            "PK hash must be 96 hex characters (48 bytes), got {} characters",
            hex.len()
        ));
    }

    let mut result = [0u32; 12];
    for (i, chunk) in hex.as_bytes().chunks(8).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|e| format!("Invalid UTF-8: {e}"))?;
        result[i] =
            u32::from_str_radix(s, 16).map_err(|e| format!("Invalid hex at word {i}: {e}"))?;
    }
    Ok(result)
}

/// Extract vendor public key hash from a Caliptra FW image manifest.
fn vendor_pk_hash_from_fw(fw: &[u8]) -> Option<[u8; 48]> {
    let (manifest, _) = ImageManifest::ref_from_prefix(fw).ok()?;
    let hash = Sha384::digest(manifest.preamble.vendor_pub_key_info.as_bytes());
    Some(hash.into())
}

/// Read all Caliptra fuse registers from a SocManager and return as JSON.
fn read_fuse_registers_json(mgr: &mut impl SocManager) -> String {
    use std::fmt::Write;
    let mut json = String::from("{");
    let mut first = true;

    macro_rules! fuse_array {
        ($mgr:expr, $name:expr, $accessor:ident, $count:expr) => {
            for i in 0..$count {
                if !first {
                    json.push(',');
                }
                first = false;
                let val: u32 = $mgr.soc_ifc().$accessor().at(i).read();
                let _ = write!(json, "\"{}[{}]\":\"0x{:08x}\"", $name, i, val);
            }
        };
    }
    macro_rules! fuse_scalar {
        ($mgr:expr, $name:expr, $accessor:ident) => {
            if !first {
                json.push(',');
            }
            #[allow(unused_assignments)]
            {
                first = false;
            }
            let val: u32 = $mgr.soc_ifc().$accessor().read().into();
            let _ = write!(json, "\"{}\":\"0x{:08x}\"", $name, val);
        };
    }

    fuse_array!(mgr, "fuse_vendor_pk_hash", fuse_vendor_pk_hash, 12);
    fuse_scalar!(mgr, "fuse_ecc_revocation", fuse_ecc_revocation);
    fuse_scalar!(mgr, "fuse_fmc_key_manifest_svn", fuse_fmc_key_manifest_svn);
    fuse_array!(mgr, "fuse_runtime_svn", fuse_runtime_svn, 4);
    fuse_scalar!(
        mgr,
        "fuse_anti_rollback_disable",
        fuse_anti_rollback_disable
    );
    fuse_array!(mgr, "fuse_idevid_cert_attr", fuse_idevid_cert_attr, 24);
    fuse_array!(mgr, "fuse_idevid_manuf_hsm_id", fuse_idevid_manuf_hsm_id, 4);
    fuse_scalar!(mgr, "fuse_lms_revocation", fuse_lms_revocation);
    fuse_scalar!(mgr, "fuse_mldsa_revocation", fuse_mldsa_revocation);
    fuse_scalar!(mgr, "fuse_soc_stepping_id", fuse_soc_stepping_id);
    fuse_array!(
        mgr,
        "fuse_manuf_dbg_unlock_token",
        fuse_manuf_dbg_unlock_token,
        16
    );
    fuse_scalar!(mgr, "fuse_pqc_key_type", fuse_pqc_key_type);
    fuse_array!(mgr, "fuse_soc_manifest_svn", fuse_soc_manifest_svn, 4);
    fuse_scalar!(mgr, "fuse_soc_manifest_max_svn", fuse_soc_manifest_max_svn);

    json.push('}');
    json
}

/// The Caliptra emulator, exposed to JavaScript via wasm-bindgen.
#[wasm_bindgen]
pub struct CaliptraEmulator {
    model: ModelEmulated,
    log_buffer: SharedBuffer,
    total_steps: u64,
    boot_error: Option<String>,
}

#[wasm_bindgen]
impl CaliptraEmulator {
    /// Create a new emulator instance.
    ///
    /// # Arguments
    /// * `rom` - The ROM binary image (96KB expected)
    /// * `vendor_pk_hash_hex` - Vendor PK hash as 96-char hex string (or empty for zeros)
    /// * `owner_pk_hash_hex` - Owner PK hash as 96-char hex string (or empty for zeros)
    /// * `fw_image` - Optional firmware image bundle (serialized ImageBundle)
    /// * `soc_manifest` - Optional SoC manifest (authorization manifest bytes)
    /// * `lifecycle` - Device lifecycle: "unprovisioned", "manufacturing", or "production"
    /// * `subsystem_mode` - Whether to boot the emulator in subsystem mode
    /// * `ocp_lock` - Whether to enable OCP lock
    /// * `mcu_fw` - Optional MCU firmware image for subsystem mode
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rom: &[u8],
        vendor_pk_hash_hex: &str,
        owner_pk_hash_hex: &str,
        fw_image: Option<Vec<u8>>,
        soc_manifest: Option<Vec<u8>>,
        lifecycle: &str,
        subsystem_mode: bool,
        ocp_lock: bool,
        mcu_fw: Option<Vec<u8>>,
        debug_intent: bool,
        fuses_json: &str,
    ) -> Result<CaliptraEmulator, JsValue> {
        console_error_panic_hook::set_once();

        // Parse PK hashes
        let vendor_pk_hash =
            parse_pk_hash(vendor_pk_hash_hex).map_err(|e| JsValue::from_str(&e))?;
        let owner_pk_hash = parse_pk_hash(owner_pk_hash_hex).map_err(|e| JsValue::from_str(&e))?;

        let fuse_config = FuseConfig::from_json(fuses_json).map_err(|e| JsValue::from_str(&e))?;

        let log_buffer = SharedBuffer(Rc::new(RefCell::new(Vec::new())));

        let device_lifecycle = match lifecycle.to_lowercase().as_str() {
            "unprovisioned" => DeviceLifecycle::Unprovisioned,
            "manufacturing" => DeviceLifecycle::Manufacturing,
            "production" => DeviceLifecycle::Production,
            _ => DeviceLifecycle::Manufacturing,
        };

        // Use a fixed seed for deterministic TRNG in the browser
        let trng_seed: u64 = 42;
        let itrng_nibbles: Box<dyn Iterator<Item = u8> + Send> =
            Box::new(RandomNibbles(StdRng::seed_from_u64(trng_seed)));
        let etrng_responses: Box<dyn Iterator<Item = EtrngResponse> + Send> =
            Box::new(RandomEtrngResponses(StdRng::seed_from_u64(trng_seed)));

        let mut fuses = Fuses {
            vendor_pk_hash,
            owner_pk_hash,
            life_cycle: device_lifecycle,
            debug_locked: debug_intent,
            ..Default::default()
        };
        fuse_config
            .apply_to_fuses(&mut fuses)
            .map_err(|e| JsValue::from_str(&e))?;

        let security_state = *SecurityState::default()
            .set_device_lifecycle(device_lifecycle)
            .set_debug_locked(debug_intent);

        let init_params = InitParams {
            rom,
            fuses,
            log_writer: Box::new(log_buffer.clone()),
            security_state,
            subsystem_mode,
            ocp_lock_en: ocp_lock,
            cptra_obf_key: DEFAULT_CPTRA_OBF_KEY,
            csr_hmac_key: DEFAULT_CSR_HMAC_KEY,
            itrng_nibbles,
            etrng_responses,
            trng_mode: Some(TrngMode::Internal),
            random_sram_puf: false,
            trace_path: None,
            soc_user: MailboxRequester::SocUser(1),
            debug_intent,
            ..Default::default()
        };

        let boot_params = BootParams {
            fw_image: fw_image.as_deref(),
            soc_manifest: soc_manifest.as_deref(),
            mcu_fw_image: mcu_fw.as_deref(),
            ..Default::default()
        };

        // Use new_unbooted + boot separately so we keep the model even if
        // boot fails (e.g., PK hash mismatch). This lets the user see UART
        // output and logs from the failed boot attempt.
        let mut model = caliptra_hw_model::ModelEmulated::new_unbooted(init_params)
            .map_err(|e| JsValue::from_str(&format!("Failed to create emulator: {e}")))?;

        let boot_error = model.boot(boot_params).err();

        let mut emu = CaliptraEmulator {
            model,
            log_buffer,
            total_steps: 0,
            boot_error: None,
        };

        if let Some(e) = boot_error {
            let msg = format!("[WASM] Boot error: {e}\n");
            emu.boot_error = Some(msg);
        }

        Ok(emu)
    }

    /// Step the emulator by `n` clock cycles. Returns true if the emulator
    /// is still running (has not exited).
    pub fn step(&mut self, n: u32) -> bool {
        for _ in 0..n {
            self.model.step();
            self.total_steps += 1;
        }
        !self.model.output().exit_requested()
    }

    /// Get accumulated UART output text since the last call to this method.
    pub fn get_uart_output(&mut self) -> String {
        self.model.output().take(usize::MAX)
    }

    /// Peek at accumulated UART output without consuming it.
    pub fn peek_uart_output(&mut self) -> String {
        self.model.output().peek().to_string()
    }

    /// Get the full log buffer contents (includes timestamped UART + system messages).
    pub fn get_log(&mut self) -> String {
        let bytes = self.log_buffer.0.borrow().clone();
        self.log_buffer.0.borrow_mut().clear();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Get the total number of steps executed so far.
    pub fn total_steps(&self) -> u64 {
        self.total_steps
    }

    /// Check if the emulator has signaled an exit (pass or fail).
    pub fn has_exited(&mut self) -> bool {
        self.model.output().exit_requested()
    }

    /// Check if the emulator exited with a PASS status.
    pub fn passed(&mut self) -> bool {
        self.model.output().exit_status() == Some(ExitStatus::Passed)
    }

    /// Get the boot error message, if boot failed.
    pub fn boot_error(&self) -> Option<String> {
        self.boot_error.clone()
    }

    /// Execute a mailbox command.
    ///
    /// Sends a raw mailbox command with the given opcode and request payload,
    /// steps the emulator until the command completes, and returns the raw
    /// response bytes. The request payload should include the MailboxReqHeader
    /// (4-byte checksum) if the firmware expects it.
    ///
    /// Returns the response bytes on success, or a JS error string on failure.
    pub fn mailbox_execute(
        &mut self,
        cmd: u32,
        request: &[u8],
    ) -> Result<Option<Vec<u8>>, JsValue> {
        self.model
            .mailbox_execute(cmd, request)
            .map_err(|e| JsValue::from_str(&format!("Mailbox error: {e:?}")))
    }

    /// Set the production debug unlock request bit in ss_dbg_service_reg_req.
    /// Must be called before sending PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.
    pub fn set_prod_dbg_unlock_req(&mut self, val: bool) {
        self.model
            .soc_ifc()
            .ss_dbg_service_reg_req()
            .write(|w| w.prod_dbg_unlock_req(val));
    }

    /// Set the manufacturing debug unlock request bit in ss_dbg_service_reg_req.
    /// Must be called before sending MANUF_DEBUG_UNLOCK_REQ_TOKEN.
    pub fn set_manuf_dbg_unlock_req(&mut self, val: bool) {
        self.model
            .soc_ifc()
            .ss_dbg_service_reg_req()
            .write(|w| w.manuf_dbg_unlock_req(val));
    }

    /// Get all Caliptra fuse register values as a JSON object.
    pub fn get_fuse_registers(&mut self) -> String {
        read_fuse_registers_json(&mut self.model)
    }

    /// Get current Caliptra firmware error register values as JSON.
    /// Returns an object with `cptra_fw_error_fatal`, `cptra_fw_error_non_fatal`,
    /// and `cptra_fw_extended_error_info` (array of 8 u32s).
    pub fn get_error_registers(&mut self) -> String {
        let soc_ifc = self.model.soc_ifc();
        let fatal: u32 = soc_ifc.cptra_fw_error_fatal().read();
        let non_fatal: u32 = soc_ifc.cptra_fw_error_non_fatal().read();
        let mut ext = [0u32; 8];
        for (i, slot) in ext.iter_mut().enumerate() {
            *slot = soc_ifc.cptra_fw_extended_error_info().at(i).read();
        }
        format!(
            "{{\"cptra_fw_error_fatal\":\"0x{:08x}\",\"cptra_fw_error_non_fatal\":\"0x{:08x}\",\"cptra_fw_extended_error_info\":[{}]}}",
            fatal,
            non_fatal,
            ext.iter()
                .map(|v| format!("\"0x{:08x}\"", v))
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    /// Get a snapshot of the Caliptra Key Vault as JSON.
    /// Returns an object with `keys` (24 hex strings, 64 bytes each),
    /// `key_control` (24 hex u32s), `pcrs` (32 hex strings, 48 bytes each),
    /// and `pcr_control` (32 hex u32s).
    pub fn get_keyvault(&mut self) -> String {
        format_keyvault_json(self.model.key_vault_snapshot())
    }
}

/// Format a `KeyVaultSnapshot` as a JSON string for the WASM/JS UI.
fn format_keyvault_json(snap: caliptra_emu_periph::KeyVaultSnapshot) -> String {
    use std::fmt::Write;
    let bytes_to_hex = |bytes: &[u8]| -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{:02x}", b);
        }
        s
    };

    let mut out = String::from("{\"keys\":[");
    for i in 0..24 {
        if i > 0 {
            out.push(',');
        }
        let start = i * 64;
        let _ = write!(out, "\"{}\"", bytes_to_hex(&snap.keys[start..start + 64]));
    }
    out.push_str("],\"key_control\":[");
    for (i, ctrl) in snap.key_control.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"0x{:08x}\"", ctrl);
    }
    out.push_str("],\"pcrs\":[");
    for (i, pcr) in snap.pcrs.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{}\"", bytes_to_hex(pcr));
    }
    out.push_str("],\"pcr_control\":[");
    for (i, ctrl) in snap.pcr_control.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"0x{:08x}\"", ctrl);
    }
    out.push_str("]}");
    out
}

// ---------------------------------------------------------------------------
// MCU Emulator (combined Caliptra + MCU subsystem)
// ---------------------------------------------------------------------------

/// The MCU emulator wrapping both Caliptra and MCU CPUs, exposed to JavaScript.
#[wasm_bindgen]
pub struct McuEmulator {
    model: mcu_hw_model::ModelEmulated,
    log_buffer: SharedBuffer,
    total_steps: u64,
    otp_log: Vec<String>,
    otp_logging_enabled: bool,
}

#[wasm_bindgen]
impl McuEmulator {
    /// Create a new MCU emulator instance.
    ///
    /// # Arguments
    /// * `caliptra_rom` - The Caliptra ROM binary
    /// * `caliptra_fw` - The Caliptra firmware bundle
    /// * `soc_manifest` - The SoC authorization manifest
    /// * `mcu_rom` - The MCU ROM binary
    /// * `mcu_firmware` - The MCU runtime firmware
    #[wasm_bindgen(constructor)]
    pub fn new(
        caliptra_rom: &[u8],
        caliptra_fw: &[u8],
        soc_manifest: &[u8],
        mcu_rom: &[u8],
        mcu_firmware: &[u8],
        debug_intent: bool,
        fuses_json: &str,
    ) -> Result<McuEmulator, JsValue> {
        console_error_panic_hook::set_once();

        let fuse_config = FuseConfig::from_json(fuses_json).map_err(|e| JsValue::from_str(&e))?;

        let log_buffer = SharedBuffer(Rc::new(RefCell::new(Vec::new())));

        let trng_seed: u64 = 42;
        let itrng_nibbles: Box<dyn Iterator<Item = u8> + Send> =
            Box::new(RandomNibbles(StdRng::seed_from_u64(trng_seed)));
        let etrng_responses: Box<dyn Iterator<Item = EtrngResponse> + Send> =
            Box::new(RandomEtrngResponses(StdRng::seed_from_u64(trng_seed)));

        // Build OTP memory ourselves so it is the single source of truth.
        // OTP partitions occupy bytes 0..LIFE_CYCLE end (0xe88).
        let otp_size = 0xe30 + 0x58;
        let mut otp = vec![0u8; otp_size];

        // Apply user-supplied fuse overrides. (Note: a few bytes — pqc_key_type
        // at OTP[0x420+48] and soc_manifest_max_svn at OTP[0x3b8+36] — are
        // overwritten by the model's Otp::new from vendor_pqc_type init param;
        // those are routed via init_params below to take effect.)
        fuse_config
            .apply_to_otp(&mut otp)
            .map_err(|e| JsValue::from_str(&e))?;

        // Determine vendor_pqc_type for init_params from FuseConfig (defaults to MLDSA).
        // Caliptra fuse convention: 0 = LMS, 1 = MLDSA.
        let vendor_pqc_type = match fuse_config.fuse_pqc_key_type {
            Some(0) => caliptra_image_types::FwVerificationPqcKeyType::LMS,
            _ => caliptra_image_types::FwVerificationPqcKeyType::MLDSA,
        };

        let init_params = mcu_hw_model::InitParams {
            caliptra_rom,
            caliptra_firmware: caliptra_fw,
            soc_manifest,
            mcu_rom,
            mcu_firmware,
            otp_memory: Some(&otp),
            // vendor_pk_hash: model writes vendor_pk_hash from FW manifest into
            // VENDOR_HASHES_MANUF partition. Pass FW-derived hash so it stays
            // consistent with the firmware.
            vendor_pk_hash: vendor_pk_hash_from_fw(caliptra_fw),
            vendor_pqc_type: Some(vendor_pqc_type),
            log_writer: Box::new(log_buffer.clone()),
            debug_intent,
            itrng_nibbles,
            etrng_responses,
            random_sram_puf: false,
            check_booted_to_runtime: false,
            ocp_lock_en: true,
            // Record the MCU's exit request (e.g. on a ROM fatal error) and
            // halt the MCU instead of terminating the host process.
            capture_mcu_exit: true,
            // Everything else (OTP controller register offsets, prod debug
            // unlock straps, flash/network boot, ...) follows the upstream
            // caliptra-mcu-sw emulator defaults.
            ..Default::default()
        };

        let mut model = {
            use mcu_hw_model::McuHwModel;
            mcu_hw_model::ModelEmulated::new_unbooted(init_params)
                .map_err(|e| JsValue::from_str(&format!("Failed to create MCU emulator: {e}")))?
        };

        // Enable CPU stepping (equivalent to boot() without waiting for completion)
        {
            use mcu_hw_model::McuHwModel;
            model
                .boot()
                .map_err(|e| JsValue::from_str(&format!("Failed to boot MCU emulator: {e}")))?;
        }

        let _ = {
            use mcu_hw_model::McuHwModel;
            model.read_otp_memory()
        };

        Ok(McuEmulator {
            model,
            log_buffer,
            total_steps: 0,
            otp_log: Vec::new(),
            otp_logging_enabled: true,
        })
    }

    /// Step both CPUs by `n` clock cycles. Returns the number of steps actually taken.
    /// May return fewer than `n` if the emulator hits an unrecoverable error.
    pub fn step(&mut self, n: u32) -> u32 {
        use mcu_hw_model::McuHwModel;
        let mut taken = 0u32;
        for _ in 0..n {
            self.model.step();
            self.total_steps += 1;
            taken += 1;
            // Drain DAI log per step so step numbers are accurate
            if self.otp_logging_enabled {
                let entries = self.model.take_otp_dai_log();
                for entry in entries {
                    self.otp_log
                        .push(format!("[step {}] {}", self.total_steps, entry));
                }
            }
        }
        // If logging is disabled, drain & discard so the buffer doesn't grow
        if !self.otp_logging_enabled {
            let _ = self.model.take_otp_dai_log();
        }
        taken
    }

    /// Get accumulated UART output text since the last call.
    pub fn get_uart_output(&mut self) -> String {
        use mcu_hw_model::McuHwModel;
        self.model.output().take(usize::MAX)
    }

    /// Get the full log buffer contents.
    pub fn get_log(&mut self) -> String {
        let bytes = self.log_buffer.0.borrow().clone();
        self.log_buffer.0.borrow_mut().clear();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Get total steps executed.
    pub fn total_steps(&self) -> u64 {
        self.total_steps
    }

    /// The status the MCU passed when it asked the emulator to exit (it does
    /// this on a fatal ROM/runtime error), or `undefined` while it is running.
    /// After an exit the MCU is halted; Caliptra keeps running.
    pub fn mcu_exit_status(&self) -> Option<i32> {
        use mcu_hw_model::McuHwModel;
        self.model.mcu_exit_status()
    }

    /// Execute a Caliptra mailbox command from the SoC side.
    pub fn mailbox_execute(
        &mut self,
        cmd: u32,
        request: &[u8],
    ) -> Result<Option<Vec<u8>>, JsValue> {
        use mcu_hw_model::McuHwModel;
        // Retry with stepping — the mailbox may be temporarily locked by Caliptra RT
        for attempt in 0..10 {
            match self.model.caliptra_mailbox_execute(cmd, request) {
                Ok(result) => return Ok(result),
                Err(caliptra_hw_model::ModelError::UnableToLockMailbox) if attempt < 9 => {
                    // Step the emulator to let Caliptra release the lock
                    for _ in 0..100_000 {
                        self.model.step();
                        self.total_steps += 1;
                        if self.otp_logging_enabled {
                            let entries = self.model.take_otp_dai_log();
                            for entry in entries {
                                self.otp_log
                                    .push(format!("[step {}] {}", self.total_steps, entry));
                            }
                        }
                    }
                }
                Err(e) => return Err(JsValue::from_str(&format!("Mailbox error: {e:?}"))),
            }
        }
        Err(JsValue::from_str(
            "Mailbox error: UnableToLockMailbox after retries",
        ))
    }

    /// Set the production debug unlock request bit in ss_dbg_service_reg_req.
    pub fn set_prod_dbg_unlock_req(&mut self, val: bool) {
        use mcu_hw_model::McuHwModel;
        self.model
            .caliptra_soc_manager()
            .soc_ifc()
            .ss_dbg_service_reg_req()
            .write(|w| w.prod_dbg_unlock_req(val));
    }

    /// Set the manufacturing debug unlock request bit in ss_dbg_service_reg_req.
    pub fn set_manuf_dbg_unlock_req(&mut self, val: bool) {
        use mcu_hw_model::McuHwModel;
        self.model
            .caliptra_soc_manager()
            .soc_ifc()
            .ss_dbg_service_reg_req()
            .write(|w| w.manuf_dbg_unlock_req(val));
    }

    /// Get all Caliptra fuse register values as a JSON object.
    pub fn get_fuse_registers(&mut self) -> String {
        use mcu_hw_model::McuHwModel;
        read_fuse_registers_json(&mut self.model.caliptra_soc_manager())
    }

    /// Get the raw OTP memory contents.
    pub fn get_otp_memory(&mut self) -> Vec<u8> {
        use mcu_hw_model::McuHwModel;
        self.model.read_otp_memory()
    }

    /// Enable or disable OTP DAI operation logging.
    pub fn set_otp_logging(&mut self, enabled: bool) {
        self.otp_logging_enabled = enabled;
        if !enabled {
            self.otp_log.clear();
        }
    }

    /// Get and clear the OTP change log entries.
    pub fn get_otp_log(&mut self) -> String {
        let log = self.otp_log.join("\n");
        self.otp_log.clear();
        log
    }

    /// Get current Caliptra and MCI firmware error register values as JSON.
    /// Returns `cptra_fw_error_fatal`, `cptra_fw_error_non_fatal`,
    /// `cptra_fw_extended_error_info` (8 u32s), `mci_fw_error_fatal`,
    /// `mci_fw_error_non_fatal`, and `mci_fw_extended_error_info` (8 u32s).
    pub fn get_error_registers(&mut self) -> String {
        use mcu_hw_model::McuHwModel;
        let (cptra_fatal, cptra_non_fatal, cptra_ext) = {
            let mut soc_mgr = self.model.caliptra_soc_manager();
            let soc_ifc = soc_mgr.soc_ifc();
            let f: u32 = soc_ifc.cptra_fw_error_fatal().read();
            let nf: u32 = soc_ifc.cptra_fw_error_non_fatal().read();
            let mut ext = [0u32; 8];
            for (i, slot) in ext.iter_mut().enumerate() {
                *slot = soc_ifc.cptra_fw_extended_error_info().at(i).read();
            }
            (f, nf, ext)
        };
        let (mci_fatal, mci_non_fatal, mci_ext) = {
            use mcu_hw_model::McuManager;
            let mut mcu_mgr = self.model.mcu_manager();
            let mci = mcu_mgr.mci();
            let f: u32 = mci.fw_error_fatal().read();
            let nf: u32 = mci.fw_error_non_fatal().read();
            let mut ext = [0u32; 8];
            for (i, slot) in ext.iter_mut().enumerate() {
                *slot = mci.fw_extended_error_info().at(i).read();
            }
            (f, nf, ext)
        };
        let fmt_arr = |arr: &[u32; 8]| {
            arr.iter()
                .map(|v| format!("\"0x{:08x}\"", v))
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "{{\"cptra_fw_error_fatal\":\"0x{:08x}\",\"cptra_fw_error_non_fatal\":\"0x{:08x}\",\"cptra_fw_extended_error_info\":[{}],\"mci_fw_error_fatal\":\"0x{:08x}\",\"mci_fw_error_non_fatal\":\"0x{:08x}\",\"mci_fw_extended_error_info\":[{}]}}",
            cptra_fatal, cptra_non_fatal, fmt_arr(&cptra_ext),
            mci_fatal, mci_non_fatal, fmt_arr(&mci_ext)
        )
    }

    /// Get a snapshot of the Caliptra Key Vault as JSON. Same shape as
    /// `CaliptraEmulator::get_keyvault`.
    pub fn get_keyvault(&mut self) -> String {
        use mcu_hw_model::McuHwModel;
        format_keyvault_json(self.model.key_vault_snapshot())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The emulators share process-wide state (e.g. caliptra-sw's SS MCI
    // offset, which the MCU model sets through an environment variable on
    // native targets), so the boot tests must not run concurrently.
    static EMULATOR_LOCK: Mutex<()> = Mutex::new(());

    /// Caliptra and the MCU share one UART stream, so lines they print at the
    /// same time interleave character by character. Treat `needle` as seen if
    /// it appears verbatim or as an in-order subsequence of a short window.
    fn uart_seen(uart: &str, needle: &str) -> bool {
        if uart.contains(needle) {
            return true;
        }
        let hay = uart.as_bytes();
        let pat = needle.as_bytes();
        let max_span = pat.len() * 4;
        (0..hay.len()).filter(|&i| hay[i] == pat[0]).any(|start| {
            let mut j = 0;
            for &b in &hay[start..hay.len().min(start + max_span)] {
                if b == pat[j] {
                    j += 1;
                    if j == pat.len() {
                        return true;
                    }
                }
            }
            false
        })
    }

    #[test]
    fn test_caliptra_emulator_boots() {
        let _guard = EMULATOR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let rom = std::fs::read("www/default-rom.bin").expect("default-rom.bin");
        let fw = std::fs::read("www/default-fw.bin").expect("default-fw.bin");
        let soc_manifest = std::fs::read("www/default-soc-manifest.bin").expect("soc-manifest");
        let mcu_fw = std::fs::read("www/default-mcu-fw.bin").expect("mcu-fw");

        let mut emu = CaliptraEmulator::new(
            &rom,
            "",
            "",
            Some(fw),
            Some(soc_manifest),
            "unprovisioned",
            true,
            true,
            Some(mcu_fw),
            false,
            "",
        )
        .expect("Failed to create Caliptra emulator");

        // Step a bit — should not panic
        for _ in 0..10 {
            emu.step(1000);
        }
        assert!(emu.total_steps() == 10_000);

        // Exercise get_keyvault — must not panic and should be valid JSON
        let kv = emu.get_keyvault();
        assert!(kv.starts_with("{"));
        assert!(kv.contains("\"keys\""));
        let parsed: serde_json::Value =
            serde_json::from_str(&kv).expect("get_keyvault() returned invalid JSON");
        assert_eq!(parsed["keys"].as_array().unwrap().len(), 24);
        assert_eq!(parsed["pcrs"].as_array().unwrap().len(), 32);
    }

    #[test]
    fn test_mcu_emulator_boots_and_steps() {
        let _guard = EMULATOR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let caliptra_rom = std::fs::read("www/default-rom.bin").expect("default-rom.bin");
        let caliptra_fw = std::fs::read("www/default-fw.bin").expect("default-fw.bin");
        let soc_manifest = std::fs::read("www/default-soc-manifest.bin").expect("soc-manifest.bin");
        let mcu_rom = std::fs::read("www/default-mcu-rom.bin").expect("default-mcu-rom.bin");
        // The default SoC manifest authorizes the real MCU runtime (see
        // build-wasm.sh), so boot with that rather than the placeholder.
        let mcu_fw = std::fs::read("www/default-mcu-runtime.bin").expect("default-mcu-runtime.bin");

        let mut emu = McuEmulator::new(
            &caliptra_rom,
            &caliptra_fw,
            &soc_manifest,
            &mcu_rom,
            &mcu_fw,
            false,
            "",
        )
        .expect("Failed to create MCU emulator");

        // Step through boot — 50k steps per batch like the browser does
        // Browser runs many frames, so test with lots of steps
        // Step in browser-sized batches until the MCU runtime reaches its
        // main loop (about 60M cycles), failing fast on any fatal error.
        const MILESTONES: [&str; 4] = [
            "[mcu-rom] Hello from ROM",
            "[rt] RT listening for mailbox commands",
            "[mcu-rom] Jumping to firmware",
            "[mcu-runtime] Entering main loop.",
        ];
        let mut uart = String::new();
        while emu.total_steps() < 150_000_000 {
            emu.step(1_000_000);
            uart.push_str(&emu.get_uart_output());
            let errs = emu.get_error_registers();
            let fatal = !errs.contains("\"mci_fw_error_fatal\":\"0x00000000\"")
                || !errs.contains("\"cptra_fw_error_fatal\":\"0x00000000\"")
                || emu.mcu_exit_status().is_some()
                || uart.contains("MCU fatal error");
            if fatal {
                panic!(
                    "fatal error after {} steps (MCU exit status {:?}): {errs}\nUART tail:\n{}",
                    emu.total_steps(),
                    emu.mcu_exit_status(),
                    &uart[uart.len().saturating_sub(4000)..]
                );
            }
            if MILESTONES.iter().all(|m| uart_seen(&uart, m)) {
                return;
            }
        }
        let missing: Vec<_> = MILESTONES.iter().filter(|m| !uart_seen(&uart, m)).collect();
        panic!(
            "boot milestones not reached after {} steps: {missing:?}\nUART tail:\n{}",
            emu.total_steps(),
            &uart[uart.len().saturating_sub(4000)..]
        );
    }
}

#[cfg(test)]
mod hash_test {
    use super::*;

    #[test]
    fn test_vendor_pk_hash_matches_defaults() {
        let fw = std::fs::read("www/default-fw.bin").expect("fw");
        let hash = vendor_pk_hash_from_fw(&fw).expect("hash");

        // Print as hex bytes
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        eprintln!("computed hash (bytes): {}", hex);

        // Read defaults.json
        let defaults: String = std::fs::read_to_string("www/defaults.json").unwrap();
        eprintln!("defaults.json: {}", defaults.trim());

        // The defaults.json vendor_pk_hash is big-endian u32 words
        // Our hash is raw SHA-384 bytes
        // Convert our bytes to big-endian u32 words for comparison
        let mut words = String::new();
        for chunk in hash.chunks(4) {
            words.push_str(&format!(
                "{:08x}",
                u32::from_be_bytes(chunk.try_into().unwrap())
            ));
        }
        eprintln!("computed hash (words): {}", words);

        assert!(defaults.contains(&words), "Hash mismatch!");
    }
}

#[cfg(test)]
mod otp_debug {
    use super::*;

    #[test]
    fn test_vendor_pk_hash_bytes() {
        let fw = std::fs::read("www/default-fw.bin").expect("fw");
        let hash = vendor_pk_hash_from_fw(&fw).expect("hash");
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        eprintln!("Raw SHA-384 bytes: {}", hex);

        // Show what swap_endianness would do
        let mut swapped = hash;
        for i in (0..48).step_by(4) {
            swapped[i..i + 4].reverse();
        }
        let swapped_hex: String = swapped.iter().map(|b| format!("{:02x}", b)).collect();
        eprintln!("After swap_endianness: {}", swapped_hex);

        // Show what ROM would read back as u32 LE
        for i in (0..48).step_by(4) {
            let word = u32::from_le_bytes(swapped[i..i + 4].try_into().unwrap());
            eprint!("{:08X}", word);
        }
        eprintln!();
    }
}
#[cfg(test)]
mod otp_offset_debug {
    use super::*;

    #[test]
    fn debug_otp_contents() {
        let fw = std::fs::read("www/default-fw.bin").expect("fw");
        let hash = vendor_pk_hash_from_fw(&fw).expect("hash");
        eprintln!("Expected hash (first 16 bytes): {:02x?}", &hash[..16]);

        // Manually create OTP the same way the MCU model does

        let offset = 0x3f8usize; // VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET

        // Create a buffer and do what OTP::new does
        let total_size = 4096; // big enough
        let mut partitions = vec![0u8; total_size];

        // swap endianness and store - this is what OTP::new does
        let mut swapped = hash;
        for i in (0..48).step_by(4) {
            swapped[i..i + 4].reverse();
        }
        partitions[offset..offset + 48].copy_from_slice(&swapped);

        // Now read back the way the ROM does: u32 LE at offset + i*4
        eprintln!("OTP contents at offset 0x{:x}:", offset);
        for i in 0..14 {
            let addr = offset + i * 4;
            if addr + 4 <= total_size {
                let word = u32::from_le_bytes(partitions[addr..addr + 4].try_into().unwrap());
                eprint!("{:08X}", word);
            }
        }
        eprintln!();

        // What if the ROM reads from offset 0 of the partition (relative)?
        // Maybe the ROM adds some extra offset we're not seeing
        eprintln!("Checking if there's an 8-byte shift...");
        for i in 0..14 {
            let addr = offset - 8 + i * 4; // Try 8 bytes earlier
            if addr + 4 <= total_size {
                let word = u32::from_le_bytes(partitions[addr..addr + 4].try_into().unwrap());
                eprint!("{:08X}", word);
            }
        }
        eprintln!();
    }
}
