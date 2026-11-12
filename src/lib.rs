// Licensed under the Apache-2.0 license

//! WASM wrapper for the Caliptra hardware emulator.
//!
//! Provides a JavaScript-friendly API to initialize and run the Caliptra
//! emulator with custom ROM, vendor/owner PK hashes, FW image, and UART
//! output capture.
//!
//! The JS API is the same for every release. `emu_2x` implements it for
//! Caliptra 2.x (core and, with the MCU, subsystem mode); `emu_1x` for the
//! core-only 1.x emulator.

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

use wasm_bindgen::prelude::*;

mod fuse_config;
#[cfg(test)]
mod provisioning_tests;

#[cfg(not(feature = "caliptra-1x"))]
mod emu_2x;
#[cfg(not(feature = "caliptra-1x"))]
pub use emu_2x::{CaliptraEmulator, McuEmulator};

#[cfg(feature = "caliptra-1x")]
mod emu_1x;
#[cfg(feature = "caliptra-1x")]
pub use emu_1x::CaliptraEmulator;

#[cfg(not(any(
    feature = "caliptra-1-0",
    feature = "caliptra-1-1",
    feature = "caliptra-2-0",
    feature = "caliptra-2-1"
)))]
compile_error!(
    "enable one of the caliptra-1-0, caliptra-1-1, caliptra-2-0 or caliptra-2-1 features"
);

/// The Caliptra release this module emulates (selected by the
/// `caliptra-*` feature of the versions/<release> build). For 1.x this is
/// the hardware release; the ROM and firmware releases are chosen at runtime.
/// (Cargo features are additive, so only one release feature may be enabled.)
#[cfg(feature = "caliptra-1-0")]
pub const CALIPTRA_RELEASE: &str = "1.0";
#[cfg(feature = "caliptra-1-1")]
pub const CALIPTRA_RELEASE: &str = "1.1";
#[cfg(feature = "caliptra-2-0")]
pub const CALIPTRA_RELEASE: &str = "2.0";
#[cfg(feature = "caliptra-2-1")]
pub const CALIPTRA_RELEASE: &str = "2.1";

/// The Caliptra release this module emulates, e.g. "2.1".
#[wasm_bindgen]
pub fn caliptra_release() -> String {
    CALIPTRA_RELEASE.to_string()
}

/// Path to one of this release's default assets in www/v<release>/, for tests.
#[cfg(test)]
pub(crate) fn test_asset(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../www")
        .join(format!("v{CALIPTRA_RELEASE}"))
        .join(name)
}

/// A shared buffer that captures log/UART output via the `Write` trait.
#[derive(Clone)]
pub(crate) struct SharedBuffer(pub(crate) Rc<RefCell<Vec<u8>>>);

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
pub(crate) fn parse_pk_hash(hex: &str) -> Result<[u32; 12], String> {
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

/// The CPTRA_DBG_MANUF_SERVICE_REG flag that asks the ROM for the IDevID
/// certificate signing request. On hardware a manufacturing tester sets it
/// (over JTAG, or from the SoC) before releasing Caliptra from reset.
pub(crate) const MFG_FLAG_GENERATE_IDEVID_CSR: u32 = 0x01;

/// Plays the manufacturing tester's part of the IDevID CSR flow. With
/// GENERATE_IDEVID_CSR set, the ROM builds the CSR (1.x: the ECC CSR; 2.x: an
/// envelope with the ECC and ML-DSA CSRs and their HMAC), puts it in the
/// mailbox, raises `idevid_csr_ready` and waits for the flag to clear. This
/// steps `model` until the CSR is ready, reads it from the mailbox, clears
/// the flag, and returns what the ROM sent.
pub(crate) fn download_idevid_csr<M: caliptra_hw_model::HwModel>(
    model: &mut M,
) -> Result<Vec<u8>, String> {
    const MAX_WAIT_CYCLES: u32 = 40_000_000;
    let mut cycles = 0u32;
    let mut wait = |model: &mut M, what: &str, done: &dyn Fn(&mut M) -> bool| {
        while !done(model) {
            let fatal = model.soc_ifc().cptra_fw_error_fatal().read();
            if fatal != 0 {
                return Err(format!(
                    "fatal error 0x{fatal:08x} while waiting for {what}"
                ));
            }
            cycles += 1;
            if cycles > MAX_WAIT_CYCLES {
                return Err(format!("timed out waiting for {what}"));
            }
            model.step();
        }
        Ok(())
    };
    wait(model, "the ROM to produce the IDevID CSR", &|m| {
        m.soc_ifc().cptra_flow_status().read().idevid_csr_ready()
    })?;
    wait(model, "the IDevID CSR in the mailbox", &|m| {
        m.soc_mbox()
            .status()
            .read()
            .mbox_fsm_ps()
            .mbox_execute_soc()
    })?;
    let mut txn = model
        .try_mailbox_receive()
        .map_err(|e| format!("reading the IDevID CSR from the mailbox: {e}"))?
        .ok_or("the IDevID CSR was not in the mailbox")?;
    let csr = std::mem::take(&mut txn.req.data);
    txn.respond_success();
    model.soc_ifc().cptra_dbg_manuf_service_reg().write(|_| 0);
    Ok(csr)
}

/// Steps `model` until the ROM is ready for the firmware image.
pub(crate) fn wait_ready_for_fw<M: caliptra_hw_model::HwModel>(
    model: &mut M,
) -> Result<(), String> {
    // Same bound as HwModel::boot.
    const MAX_WAIT_CYCLES: u32 = 20_000_000;
    for _ in 0..MAX_WAIT_CYCLES {
        if model.ready_for_fw() {
            return Ok(());
        }
        model.step();
    }
    Err("timed out waiting for the ROM to be ready for firmware".into())
}

/// Format a `KeyVaultSnapshot` as a JSON string for the WASM/JS UI.
pub(crate) fn format_keyvault_json(snap: caliptra_emu_periph::KeyVaultSnapshot) -> String {
    use std::fmt::Write;
    let bytes_to_hex = |bytes: &[u8]| -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{:02x}", b);
        }
        s
    };

    // 2.x has 24 keys of 64 bytes; 1.x has 32 keys of 48 bytes.
    let key_count = snap.key_control.len();
    let key_size = snap.keys.len() / key_count.max(1);
    let mut out = String::from("{\"keys\":[");
    for i in 0..key_count {
        if i > 0 {
            out.push(',');
        }
        let start = i * key_size;
        let _ = write!(
            out,
            "\"{}\"",
            bytes_to_hex(&snap.keys[start..start + key_size])
        );
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
