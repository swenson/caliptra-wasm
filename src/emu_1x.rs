// Licensed under the Apache-2.0 license

//! Caliptra 1.x: the core-only emulator (1.x has no subsystem mode or MCU).
//!
//! Exposes the same JS API as the 2.x `CaliptraEmulator`. Arguments that only
//! mean something on 2.x (SoC manifest, subsystem mode, OCP LOCK, MCU
//! firmware) are accepted and ignored, and the 2.x debug unlock request
//! registers do not exist on 1.x.

use std::cell::RefCell;
use std::rc::Rc;

use caliptra_api::SocManager;
use caliptra_emu_periph::MailboxRequester;
use caliptra_hw_model::{
    BootParams, DeviceLifecycle, ExitStatus, Fuses, HwModel, InitParams, ModelEmulated,
    SecurityState, TrngMode,
};
use caliptra_hw_model_types::{EtrngResponse, RandomEtrngResponses, RandomNibbles};
use caliptra_image_types::ImageManifest;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha384};
use wasm_bindgen::prelude::*;
use zerocopy::{FromBytes, IntoBytes};

use crate::fuse_config::FuseConfig;
use crate::{format_keyvault_json, parse_pk_hash, SharedBuffer};

/// The vendor and owner PK hashes of a 1.x firmware bundle: SHA-384 of the
/// manifest preamble's `vendor_pub_keys` (4 ECC + 32 LMS keys) and
/// `owner_pub_keys`.
fn pk_hashes_from_fw(fw: &[u8]) -> Option<([u8; 48], [u8; 48])> {
    let (manifest, _) = ImageManifest::ref_from_prefix(fw).ok()?;
    let vendor = Sha384::digest(manifest.preamble.vendor_pub_keys.as_bytes());
    let owner = Sha384::digest(manifest.preamble.owner_pub_keys.as_bytes());
    Some((vendor.into(), owner.into()))
}

/// The vendor and owner PK hashes of a firmware bundle as JSON
/// (`{"vendor_pk_hash": hex, "owner_pk_hash": hex}`, the format of
/// defaults.json), or `undefined` if the bundle cannot be parsed.
#[wasm_bindgen]
pub fn fw_pk_hashes(fw: &[u8]) -> Option<String> {
    let hex = |h: &[u8]| h.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let (vendor, owner) = pk_hashes_from_fw(fw)?;
    Some(format!(
        "{{\"vendor_pk_hash\":\"{}\",\"owner_pk_hash\":\"{}\"}}",
        hex(&vendor),
        hex(&owner)
    ))
}

/// Read the 1.x Caliptra fuse registers and return them as JSON.
fn read_fuse_registers_json(mgr: &mut impl SocManager) -> String {
    use std::fmt::Write;
    let mut fields: Vec<String> = Vec::new();
    macro_rules! fuse_array {
        ($name:expr, $accessor:ident, $count:expr) => {
            for i in 0..$count {
                let val: u32 = mgr.soc_ifc().$accessor().at(i).read();
                fields.push(format!("\"{}[{}]\":\"0x{:08x}\"", $name, i, val));
            }
        };
    }
    macro_rules! fuse_scalar {
        ($name:expr, $accessor:ident) => {
            let val: u32 = mgr.soc_ifc().$accessor().read().into();
            fields.push(format!("\"{}\":\"0x{:08x}\"", $name, val));
        };
    }
    fuse_array!("fuse_key_manifest_pk_hash", fuse_key_manifest_pk_hash, 12);
    fuse_scalar!(
        "fuse_key_manifest_pk_hash_mask",
        fuse_key_manifest_pk_hash_mask
    );
    fuse_array!("fuse_owner_pk_hash", fuse_owner_pk_hash, 12);
    fuse_scalar!("fuse_fmc_key_manifest_svn", fuse_fmc_key_manifest_svn);
    fuse_array!("fuse_runtime_svn", fuse_runtime_svn, 4);
    fuse_scalar!("fuse_anti_rollback_disable", fuse_anti_rollback_disable);
    fuse_array!("fuse_idevid_cert_attr", fuse_idevid_cert_attr, 24);
    fuse_array!("fuse_idevid_manuf_hsm_id", fuse_idevid_manuf_hsm_id, 4);
    fuse_scalar!("fuse_life_cycle", fuse_life_cycle);
    fuse_scalar!("fuse_lms_verify", fuse_lms_verify);
    fuse_scalar!("fuse_lms_revocation", fuse_lms_revocation);
    fuse_scalar!("fuse_soc_stepping_id", fuse_soc_stepping_id);
    let mut json = String::from("{");
    let _ = write!(json, "{}", fields.join(","));
    json.push('}');
    json
}

/// The Caliptra 1.x emulator, exposed to JavaScript via wasm-bindgen.
#[wasm_bindgen]
pub struct CaliptraEmulator {
    model: ModelEmulated,
    log_buffer: SharedBuffer,
    total_steps: u64,
    boot_error: Option<String>,
}

#[wasm_bindgen]
impl CaliptraEmulator {
    /// Create a new emulator instance. Same arguments as the 2.x emulator;
    /// `soc_manifest`, `subsystem_mode`, `ocp_lock` and `mcu_fw` are ignored
    /// because Caliptra 1.x has no subsystem.
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
        let _ = (soc_manifest, subsystem_mode, ocp_lock, mcu_fw);

        let key_manifest_pk_hash =
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
            key_manifest_pk_hash,
            owner_pk_hash,
            life_cycle: device_lifecycle,
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
            log_writer: Box::new(log_buffer.clone()),
            security_state,
            itrng_nibbles,
            etrng_responses,
            trng_mode: Some(TrngMode::Internal),
            random_sram_puf: false,
            trace_path: None,
            soc_user: MailboxRequester::SocUser(1),
            ..Default::default()
        };

        let boot_params = BootParams {
            fuses,
            fw_image: fw_image.as_deref(),
            ..Default::default()
        };

        // Use new_unbooted + boot separately so we keep the model even if
        // boot fails (e.g., PK hash mismatch). This lets the user see UART
        // output and logs from the failed boot attempt.
        let mut model = ModelEmulated::new_unbooted(init_params)
            .map_err(|e| JsValue::from_str(&format!("Failed to create emulator: {e}")))?;
        let boot_error = model
            .boot(boot_params)
            .err()
            .map(|e| format!("[WASM] Boot error: {e}\n"));

        Ok(CaliptraEmulator {
            model,
            log_buffer,
            total_steps: 0,
            boot_error,
        })
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

    /// Execute a mailbox command; see the 2.x emulator.
    pub fn mailbox_execute(
        &mut self,
        cmd: u32,
        request: &[u8],
    ) -> Result<Option<Vec<u8>>, JsValue> {
        self.model
            .mailbox_execute(cmd, request)
            .map_err(|e| JsValue::from_str(&format!("Mailbox error: {e:?}")))
    }

    /// Start a mailbox command without waiting for it to finish. Call
    /// `step` until `mailbox_busy()` is false, then `mailbox_finish` for the
    /// response. Lets the page keep updating during long commands (the
    /// software ML-DSA commands on 1.x take tens of millions of cycles).
    pub fn mailbox_start(&mut self, cmd: u32, request: &[u8]) -> Result<(), JsValue> {
        self.model
            .start_mailbox_execute(cmd, request)
            .map_err(|e| JsValue::from_str(&format!("Mailbox error: {e:?}")))
    }

    /// Whether the command started by `mailbox_start` is still executing.
    pub fn mailbox_busy(&mut self) -> bool {
        self.model.soc_mbox().status().read().status().cmd_busy()
    }

    /// Finish the command started by `mailbox_start` and return its response.
    pub fn mailbox_finish(&mut self) -> Result<Option<Vec<u8>>, JsValue> {
        self.model
            .finish_mailbox_execute()
            .map_err(|e| JsValue::from_str(&format!("Mailbox error: {e:?}")))
    }

    /// No-op: Caliptra 1.x has no subsystem debug unlock request register.
    pub fn set_prod_dbg_unlock_req(&mut self, _val: bool) {}

    /// No-op: Caliptra 1.x has no subsystem debug unlock request register.
    pub fn set_manuf_dbg_unlock_req(&mut self, _val: bool) {}

    /// Get all Caliptra fuse register values as a JSON object.
    pub fn get_fuse_registers(&mut self) -> String {
        read_fuse_registers_json(&mut self.model)
    }

    /// Get current Caliptra firmware error register values as JSON
    /// (`cptra_fw_error_fatal`, `cptra_fw_error_non_fatal`,
    /// `cptra_fw_extended_error_info`).
    pub fn get_error_registers(&mut self) -> String {
        let soc_ifc = self.model.soc_ifc();
        let fatal: u32 = soc_ifc.cptra_fw_error_fatal().read();
        let non_fatal: u32 = soc_ifc.cptra_fw_error_non_fatal().read();
        let ext: Vec<String> = (0..8)
            .map(|i| {
                format!(
                    "\"0x{:08x}\"",
                    soc_ifc.cptra_fw_extended_error_info().at(i).read()
                )
            })
            .collect();
        format!(
            "{{\"cptra_fw_error_fatal\":\"0x{fatal:08x}\",\"cptra_fw_error_non_fatal\":\"0x{non_fatal:08x}\",\"cptra_fw_extended_error_info\":[{}]}}",
            ext.join(",")
        )
    }

    /// Get a snapshot of the Caliptra Key Vault as JSON. 1.x has 32 keys of
    /// 48 bytes; otherwise the same shape as the 2.x emulator's.
    pub fn get_keyvault(&mut self) -> String {
        format_keyvault_json(self.model.key_vault_snapshot())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_asset;

    /// Boots `rom` + `fw` and returns the emulator once the runtime has been
    /// ready for 40M more cycles, or an error describing how it failed.
    fn boot_to_runtime(rom: &[u8], fw: Vec<u8>) -> Result<CaliptraEmulator, String> {
        let hashes = fw_pk_hashes(&fw).ok_or("cannot parse the firmware manifest")?;
        let vendor = hashes.split('"').nth(3).unwrap().to_string();
        let owner = hashes.split('"').nth(7).unwrap().to_string();
        let mut emu = CaliptraEmulator::new(
            rom,
            &vendor,
            &owner,
            Some(fw),
            None,
            "production",
            false,
            false,
            None,
            false,
            "",
        )
        .map_err(|e| format!("{e:?}"))?;
        if let Some(e) = emu.boot_error() {
            return Err(e);
        }
        let mut ready_at = None;
        while emu.total_steps() < 200_000_000 {
            if !emu.step(1_000_000) {
                return Err("emulator exited".into());
            }
            let errs = emu.get_error_registers();
            if !errs.contains("\"cptra_fw_error_fatal\":\"0x00000000\"") {
                return Err(format!(
                    "fatal error after {} steps: {errs}",
                    emu.total_steps()
                ));
            }
            // FLOW_STATUS ready_for_runtime: the runtime has started and
            // accepts mailbox commands.
            if ready_at.is_none()
                && emu
                    .model
                    .soc_ifc()
                    .cptra_flow_status()
                    .read()
                    .ready_for_runtime()
            {
                ready_at = Some(emu.total_steps());
            }
            if ready_at.is_some_and(|at| emu.total_steps() >= at + 40_000_000) {
                return Ok(emu);
            }
        }
        Err(format!(
            "runtime not ready after {} steps",
            emu.total_steps()
        ))
    }

    /// Boots every ROM release with every firmware release from
    /// firmware.json and reports which pairs reach the runtime. Ignored by
    /// default; run with `cargo test --release -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn test_caliptra_1x_release_matrix() {
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(test_asset("firmware.json")).unwrap()).unwrap();
        for rom in index["roms"].as_array().unwrap() {
            let rom_bytes = std::fs::read(test_asset(rom["file"].as_str().unwrap())).unwrap();
            for fw in index["firmware"].as_array().unwrap() {
                let fw_bytes = std::fs::read(test_asset(fw["file"].as_str().unwrap())).unwrap();
                let result = boot_to_runtime(&rom_bytes, fw_bytes);
                eprintln!(
                    "ROM {} + FW {}: {}",
                    rom["version"].as_str().unwrap(),
                    fw["version"].as_str().unwrap(),
                    match &result {
                        Ok(_) => "boots to runtime".to_string(),
                        Err(e) => format!("FAILS: {e}"),
                    }
                );
            }
        }
    }

    /// Boots the default 1.x ROM and firmware (downloaded releases) to the
    /// runtime and keeps running for a while, failing on any fatal error.
    #[test]
    fn test_caliptra_1x_boots_to_runtime() {
        let rom = std::fs::read(test_asset("default-rom.bin")).expect("default-rom.bin");
        let fw = std::fs::read(test_asset("default-fw.bin")).expect("default-fw.bin");
        boot_to_runtime(&rom, fw).unwrap();
    }

    /// Sends a mailbox command through the non-blocking API the page uses
    /// (start, step until not busy, finish) and returns the response.
    fn mailbox(emu: &mut CaliptraEmulator, cmd: u32, payload: &[u8]) -> Vec<u8> {
        let mut req = caliptra_api::calc_checksum(cmd, payload)
            .to_le_bytes()
            .to_vec();
        req.extend_from_slice(payload);
        emu.mailbox_start(cmd, &req).unwrap();
        let start = emu.total_steps();
        while emu.mailbox_busy() {
            assert!(
                emu.total_steps() - start < 200_000_000,
                "command 0x{cmd:08x} timed out"
            );
            emu.step(100_000);
        }
        emu.mailbox_finish().unwrap().expect("response")
    }

    /// Runtime 1.3's PQ.DevID identity: provision the ML-DSA-87 seed, then
    /// read the public key and the CSR (a DER SEQUENCE).
    #[test]
    fn test_pq_devid_flow() {
        use caliptra_api::mailbox::CommandId;
        let rom = std::fs::read(test_asset("rom-1.2.0.bin")).expect("rom-1.2.0.bin");
        let fw = std::fs::read(test_asset("fw-1.3.1.bin")).expect("fw-1.3.1.bin");
        let mut emu = boot_to_runtime(&rom, fw).unwrap();

        let resp = mailbox(&mut emu, CommandId::SET_PQ_SEED.into(), &[0x5a; 32]);
        assert_eq!(resp.len(), 8, "SET_PQ_SEED response");

        let resp = mailbox(&mut emu, CommandId::GET_PQ_INFO.into(), &[]);
        assert_eq!(
            resp.len(),
            8 + 2592,
            "GET_PQ_INFO returns the ML-DSA-87 public key"
        );

        let resp = mailbox(&mut emu, CommandId::GET_PQ_CSR.into(), &[]);
        let size = u32::from_le_bytes(resp[8..12].try_into().unwrap()) as usize;
        assert!(size > 2592 && 12 + size <= resp.len(), "CSR size {size}");
        assert_eq!(&resp[12..14], &[0x30, 0x82], "CSR is a DER SEQUENCE");
    }
}
