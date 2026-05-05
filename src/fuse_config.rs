// Licensed under the Apache-2.0 license

//! Fuse configuration that maps to either the Caliptra Fuses struct
//! (core mode) or to OTP partition bytes (MCU subsystem mode).
//!
//! Designed to be deserialized from JSON sent by the JavaScript UI.
//! All fields are optional; missing fields keep their default values.
//!
//! Fields already exposed elsewhere in the UI are intentionally not
//! duplicated here:
//!   * `vendor_pk_hash`, `owner_pk_hash` (top-level inputs)
//!   * `manuf_dbg_unlock_token` (debug-unlock page)
//!   * `life_cycle` (lifecycle dropdown)
//!   * `debug_locked` (debug-intent checkbox)

use caliptra_api_types::{Fuses, U4};
use serde::Deserialize;

/// Hex string parsing. Accepts optional "0x" prefix and ignores whitespace.
fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let cleaned: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(format!("Hex string has odd length: {}", cleaned.len()));
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
            .map_err(|e| format!("invalid hex: {e}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// User-facing configuration of a single fuse value. Fields are stored as
/// strings (hex/decimal) in JSON to make the UI simple.
#[derive(Default, Debug, Deserialize)]
#[serde(default)]
pub struct FuseConfig {
    /// PQC key type: 0 = LMS, 1 = MLDSA. (Caliptra fuse_pqc_key_type)
    pub fuse_pqc_key_type: Option<u32>,
    /// 4-bit ECC key revocation mask.
    pub fuse_ecc_revocation: Option<u32>,
    /// 32-bit LMS key revocation mask.
    pub fuse_lms_revocation: Option<u32>,
    /// 32-bit MLDSA key revocation mask.
    pub fuse_mldsa_revocation: Option<u32>,
    /// Anti-rollback disable bit.
    pub anti_rollback_disable: Option<bool>,
    /// SoC stepping ID (16-bit).
    pub soc_stepping_id: Option<u16>,
    /// SoC manifest max SVN.
    pub soc_manifest_max_svn: Option<u8>,
    /// SoC manifest SVN: 4 u32 words (one-hot encoding for `n` set bits).
    pub soc_manifest_svn: Option<[u32; 4]>,
    /// Firmware (runtime) SVN: 4 u32 words (one-hot encoding).
    pub fw_svn: Option<[u32; 4]>,
    /// IDevID certificate attributes: 96 bytes (24 u32s) hex-encoded.
    pub idevid_cert_attr: Option<String>,
    /// IDevID manufacturer HSM ID: 16 bytes (4 u32s) hex-encoded.
    pub idevid_manuf_hsm_id: Option<String>,
    /// Production debug unlock public key hashes for unlock levels 1-8.
    /// Each entry is a 48-byte (96 hex char) SHA-384 hash.
    pub prod_debug_unlock_pks: Option<Vec<String>>,
}

impl FuseConfig {
    /// Parse from a JSON string. Empty string returns the default.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let trimmed = json.trim();
        if trimmed.is_empty() || trimmed == "{}" {
            return Ok(Self::default());
        }
        serde_json::from_str(trimmed).map_err(|e| format!("FuseConfig JSON parse error: {e}"))
    }

    /// Apply this configuration to a Caliptra `Fuses` struct (core mode).
    pub fn apply_to_fuses(&self, fuses: &mut Fuses) -> Result<(), String> {
        if let Some(v) = self.fuse_pqc_key_type {
            fuses.fuse_pqc_key_type = v;
        }
        if let Some(v) = self.fuse_ecc_revocation {
            fuses.fuse_ecc_revocation = U4::try_from(v).unwrap_or_default();
        }
        if let Some(v) = self.fuse_lms_revocation {
            fuses.fuse_lms_revocation = v;
        }
        if let Some(v) = self.fuse_mldsa_revocation {
            fuses.fuse_mldsa_revocation = v;
        }
        if let Some(v) = self.anti_rollback_disable {
            fuses.anti_rollback_disable = v;
        }
        if let Some(v) = self.soc_stepping_id {
            fuses.soc_stepping_id = v;
        }
        if let Some(v) = self.soc_manifest_max_svn {
            fuses.soc_manifest_max_svn = v;
        }
        if let Some(v) = self.soc_manifest_svn {
            fuses.soc_manifest_svn = v;
        }
        if let Some(v) = self.fw_svn {
            fuses.fw_svn = v;
        }
        if let Some(s) = &self.idevid_cert_attr {
            let bytes = parse_hex(s)?;
            if bytes.len() != 96 {
                return Err(format!(
                    "idevid_cert_attr must be 96 bytes, got {}",
                    bytes.len()
                ));
            }
            for (i, chunk) in bytes.chunks(4).enumerate() {
                fuses.idevid_cert_attr[i] = u32::from_be_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3],
                ]);
            }
        }
        if let Some(s) = &self.idevid_manuf_hsm_id {
            let bytes = parse_hex(s)?;
            if bytes.len() != 16 {
                return Err(format!(
                    "idevid_manuf_hsm_id must be 16 bytes, got {}",
                    bytes.len()
                ));
            }
            for (i, chunk) in bytes.chunks(4).enumerate() {
                fuses.idevid_manuf_hsm_id[i] = u32::from_be_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3],
                ]);
            }
        }
        Ok(())
    }

    /// Apply this configuration to OTP bytes (MCU subsystem mode).
    /// Writes to known partition offsets per the fuse register map.
    ///
    /// Note: `fuse_pqc_key_type` uses the Caliptra convention (0=LMS, 1=MLDSA),
    /// but the MCU OTP byte uses the inverse encoding (0=MLDSA, 1=LMS). This
    /// helper translates automatically.
    pub fn apply_to_otp(&self, otp: &mut [u8]) -> Result<(), String> {
        // SW_MANUF partition starts at 0xf8.
        // Layout (offsets within partition):
        //   0:    anti_rollback_disable     (4 bytes)
        //   4:    idevid_cert_attr          (96 bytes)
        //   100:  idevid_cert (soc_specific) (4 bytes)  -- skipped
        //   104:  idevid_manuf_hsm_id       (16 bytes)
        //   120:  soc_stepping_id           (4 bytes)
        //   124:  prod_debug_unlock_pks_0   (48 bytes)
        //   ...   prod_debug_unlock_pks_1..7 (8 total, 384 bytes)
        const SW_MANUF_OFF: usize = 0xf8;
        if let Some(v) = self.anti_rollback_disable {
            let val = if v { 1u32 } else { 0 };
            otp[SW_MANUF_OFF..SW_MANUF_OFF + 4].copy_from_slice(&val.to_le_bytes());
        }
        if let Some(s) = &self.idevid_cert_attr {
            let bytes = parse_hex(s)?;
            if bytes.len() != 96 {
                return Err(format!(
                    "idevid_cert_attr must be 96 bytes, got {}",
                    bytes.len()
                ));
            }
            otp[SW_MANUF_OFF + 4..SW_MANUF_OFF + 100].copy_from_slice(&bytes);
        }
        if let Some(s) = &self.idevid_manuf_hsm_id {
            let bytes = parse_hex(s)?;
            if bytes.len() != 16 {
                return Err(format!(
                    "idevid_manuf_hsm_id must be 16 bytes, got {}",
                    bytes.len()
                ));
            }
            otp[SW_MANUF_OFF + 104..SW_MANUF_OFF + 120].copy_from_slice(&bytes);
        }
        if let Some(v) = self.soc_stepping_id {
            otp[SW_MANUF_OFF + 120..SW_MANUF_OFF + 124]
                .copy_from_slice(&(v as u32).to_le_bytes());
        }
        if let Some(pks) = &self.prod_debug_unlock_pks {
            for (i, pk_hex) in pks.iter().take(8).enumerate() {
                let bytes = parse_hex(pk_hex)?;
                if bytes.len() != 48 {
                    return Err(format!(
                        "prod_debug_unlock_pks[{i}] must be 48 bytes, got {}",
                        bytes.len()
                    ));
                }
                let off = SW_MANUF_OFF + 124 + i * 48;
                otp[off..off + 48].copy_from_slice(&bytes);
            }
        }

        // SVN partition (0x3b8): fmc_key_manifest_svn (4) + runtime_svn (16) +
        // soc_manifest_svn (16) + soc_manifest_max_svn (4)
        //
        // NOTE: byte 36 (soc_manifest_max_svn) and bytes 20..36 (soc_manifest_svn)
        // are overwritten by the MCU model's Otp::new from `soc_manifest_max_svn`
        // / `soc_manifest_svn` OtpArgs (currently always None from mcu-hw-model
        // InitParams). Writes here will be clobbered. The fields are kept so
        // they take effect in core mode (Caliptra Fuses struct).
        const SVN_OFF: usize = 0x3b8;
        if let Some(v) = self.fw_svn {
            // OTP runtime_svn at offset +4
            for (i, w) in v.iter().enumerate() {
                let off = SVN_OFF + 4 + i * 4;
                otp[off..off + 4].copy_from_slice(&w.to_le_bytes());
            }
        }
        if let Some(v) = self.soc_manifest_svn {
            for (i, w) in v.iter().enumerate() {
                let off = SVN_OFF + 20 + i * 4;
                otp[off..off + 4].copy_from_slice(&w.to_le_bytes());
            }
        }
        if let Some(v) = self.soc_manifest_max_svn {
            otp[SVN_OFF + 36..SVN_OFF + 40].copy_from_slice(&(v as u32).to_le_bytes());
        }

        // VENDOR_HASHES_MANUF (0x420): vendor_pk_hash (48) + pqc_key_type (4)
        //
        // NOTE: byte 48 (pqc_key_type) is overwritten by the MCU model based on
        // its `vendor_pqc_type` init param. The lib.rs constructor derives that
        // init param from `fuse_pqc_key_type` here. We still write the byte for
        // completeness in case the model ever stops overriding it.
        const VENDOR_HASHES_MANUF_OFF: usize = 0x420;
        if let Some(v) = self.fuse_pqc_key_type {
            // Caliptra: 0=LMS, 1=MLDSA. OTP: 0=MLDSA, 1=LMS.
            let otp_val: u32 = if v == 1 { 0 } else { 1 };
            otp[VENDOR_HASHES_MANUF_OFF + 48..VENDOR_HASHES_MANUF_OFF + 52]
                .copy_from_slice(&otp_val.to_le_bytes());
        }

        // VENDOR_REVOCATIONS_PROD (0x7c0): owner_ecc/lms/mldsa_revocation (4 ea),
        // then cptra_core_ecc/lms/mldsa_revocation_0..3 (4 bytes each, 36 bytes total).
        const VENDOR_REV_OFF: usize = 0x7c0;
        // We populate the cptra_core_*_revocation_0 slot for the core fuse fields.
        if let Some(v) = self.fuse_ecc_revocation {
            otp[VENDOR_REV_OFF + 12..VENDOR_REV_OFF + 16].copy_from_slice(&v.to_le_bytes());
        }
        if let Some(v) = self.fuse_lms_revocation {
            otp[VENDOR_REV_OFF + 16..VENDOR_REV_OFF + 20].copy_from_slice(&v.to_le_bytes());
        }
        if let Some(v) = self.fuse_mldsa_revocation {
            otp[VENDOR_REV_OFF + 20..VENDOR_REV_OFF + 24].copy_from_slice(&v.to_le_bytes());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_json() {
        let cfg = FuseConfig::from_json("").unwrap();
        assert!(cfg.fuse_pqc_key_type.is_none());
    }

    #[test]
    fn test_parse_json_basic() {
        let cfg = FuseConfig::from_json(
            r#"{"fuse_pqc_key_type":1,"anti_rollback_disable":true,"soc_stepping_id":42}"#,
        )
        .unwrap();
        assert_eq!(cfg.fuse_pqc_key_type, Some(1));
        assert_eq!(cfg.anti_rollback_disable, Some(true));
        assert_eq!(cfg.soc_stepping_id, Some(42));
    }

    #[test]
    fn test_apply_to_fuses() {
        let cfg = FuseConfig::from_json(
            r#"{"fuse_pqc_key_type":1,"fuse_lms_revocation":7,"soc_manifest_max_svn":64}"#,
        )
        .unwrap();
        let mut fuses = Fuses::default();
        cfg.apply_to_fuses(&mut fuses).unwrap();
        assert_eq!(fuses.fuse_pqc_key_type, 1);
        assert_eq!(fuses.fuse_lms_revocation, 7);
        assert_eq!(fuses.soc_manifest_max_svn, 64);
    }

    #[test]
    fn test_apply_to_otp_svn() {
        let cfg = FuseConfig::from_json(
            r#"{"soc_manifest_max_svn":64,"fw_svn":[1,0,0,0]}"#,
        )
        .unwrap();
        let mut otp = vec![0u8; 4096];
        cfg.apply_to_otp(&mut otp).unwrap();
        // soc_manifest_max_svn at SVN_OFF + 36
        assert_eq!(otp[0x3b8 + 36], 64);
        // fw_svn[0] = 1 at SVN_OFF + 4
        assert_eq!(otp[0x3b8 + 4], 1);
    }

    #[test]
    fn test_apply_to_otp_vendor_revocations() {
        let cfg = FuseConfig::from_json(
            r#"{"fuse_lms_revocation":15,"fuse_mldsa_revocation":255}"#,
        )
        .unwrap();
        let mut otp = vec![0u8; 4096];
        cfg.apply_to_otp(&mut otp).unwrap();
        assert_eq!(otp[0x7c0 + 16], 15);
        assert_eq!(otp[0x7c0 + 20], 255);
    }

    #[test]
    fn test_idevid_cert_attr_size_check() {
        let cfg = FuseConfig {
            idevid_cert_attr: Some("aabb".into()),
            ..Default::default()
        };
        let mut fuses = Fuses::default();
        let err = cfg.apply_to_fuses(&mut fuses).unwrap_err();
        assert!(err.contains("96 bytes"));
    }
}
