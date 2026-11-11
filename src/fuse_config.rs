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
#[cfg(not(feature = "caliptra-1x"))]
use mcu_registers_generated::fuses as otp_map;
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
        let byte =
            u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|e| format!("invalid hex: {e}"))?;
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
    #[cfg(feature = "caliptra-1x")]
    pub fn apply_to_fuses(&self, fuses: &mut Fuses) -> Result<(), String> {
        // Caliptra 1.x has no ML-DSA or SoC manifest fuses.
        let unsupported = [
            ("fuse_pqc_key_type", self.fuse_pqc_key_type.is_some()),
            (
                "fuse_mldsa_revocation",
                self.fuse_mldsa_revocation.is_some(),
            ),
            ("soc_manifest_svn", self.soc_manifest_svn.is_some()),
            ("soc_manifest_max_svn", self.soc_manifest_max_svn.is_some()),
        ];
        if let Some((name, _)) = unsupported.iter().find(|(_, set)| *set) {
            return Err(format!("{name} is not a Caliptra 1.x fuse"));
        }
        if let Some(v) = self.fuse_ecc_revocation {
            // 1.x calls the vendor ECC key revocation mask key_manifest_pk_hash_mask.
            fuses.key_manifest_pk_hash_mask = U4::try_from(v).unwrap_or_default();
        }
        if let Some(v) = self.fuse_lms_revocation {
            fuses.fuse_lms_revocation = v;
        }
        if let Some(v) = self.anti_rollback_disable {
            fuses.anti_rollback_disable = v;
        }
        if let Some(v) = self.soc_stepping_id {
            fuses.soc_stepping_id = v;
        }
        if let Some(v) = self.fw_svn {
            fuses.runtime_svn = v;
        }
        self.apply_idevid_fuses(&mut fuses.idevid_cert_attr, &mut fuses.idevid_manuf_hsm_id)
    }

    #[cfg(not(feature = "caliptra-1x"))]
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
        self.apply_idevid_fuses(&mut fuses.idevid_cert_attr, &mut fuses.idevid_manuf_hsm_id)
    }

    fn apply_idevid_fuses(
        &self,
        idevid_cert_attr: &mut [u32; 24],
        idevid_manuf_hsm_id: &mut [u32; 4],
    ) -> Result<(), String> {
        if let Some(s) = &self.idevid_cert_attr {
            let bytes = parse_hex(s)?;
            if bytes.len() != 96 {
                return Err(format!(
                    "idevid_cert_attr must be 96 bytes, got {}",
                    bytes.len()
                ));
            }
            for (i, chunk) in bytes.chunks(4).enumerate() {
                idevid_cert_attr[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
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
                idevid_manuf_hsm_id[i] =
                    u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
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
    #[cfg(not(feature = "caliptra-1x"))]
    pub fn apply_to_otp(&self, otp: &mut [u8]) -> Result<(), String> {
        // Byte offsets come from the release's generated OTP map; the
        // partitions moved between releases (2.0's start 0x28 bytes earlier
        // than 2.1's).
        //
        // SW_MANUF partition: anti_rollback_disable (4), idevid_cert_attr
        // (96), idevid_cert (4, skipped), idevid_manuf_hsm_id (16),
        // soc_stepping_id (4), prod_debug_unlock_pks_0..7 (48 each).
        let anti_rollback = otp_map::OTP_CPTRA_CORE_ANTI_ROLLBACK_DISABLE.byte_offset;
        let cert_attr = otp_map::OTP_CPTRA_CORE_IDEVID_CERT_IDEVID_ATTR.byte_offset;
        let hsm_id = otp_map::OTP_CPTRA_CORE_IDEVID_MANUF_HSM_IDENTIFIER.byte_offset;
        let stepping_id = otp_map::OTP_CPTRA_CORE_SOC_STEPPING_ID.byte_offset;
        let prod_dbg_pks = [
            otp_map::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_0.byte_offset,
            otp_map::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_1.byte_offset,
            otp_map::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_2.byte_offset,
            otp_map::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_3.byte_offset,
            otp_map::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_4.byte_offset,
            otp_map::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_5.byte_offset,
            otp_map::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_6.byte_offset,
            otp_map::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_7.byte_offset,
        ];
        if let Some(v) = self.anti_rollback_disable {
            let val = if v { 1u32 } else { 0 };
            otp[anti_rollback..anti_rollback + 4].copy_from_slice(&val.to_le_bytes());
        }
        if let Some(s) = &self.idevid_cert_attr {
            let bytes = parse_hex(s)?;
            if bytes.len() != 96 {
                return Err(format!(
                    "idevid_cert_attr must be 96 bytes, got {}",
                    bytes.len()
                ));
            }
            otp[cert_attr..cert_attr + 96].copy_from_slice(&bytes);
        }
        if let Some(s) = &self.idevid_manuf_hsm_id {
            let bytes = parse_hex(s)?;
            if bytes.len() != 16 {
                return Err(format!(
                    "idevid_manuf_hsm_id must be 16 bytes, got {}",
                    bytes.len()
                ));
            }
            otp[hsm_id..hsm_id + 16].copy_from_slice(&bytes);
        }
        if let Some(v) = self.soc_stepping_id {
            otp[stepping_id..stepping_id + 4].copy_from_slice(&(v as u32).to_le_bytes());
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
                let off = prod_dbg_pks[i];
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
        let runtime_svn = otp_map::OTP_CPTRA_CORE_RUNTIME_SVN.byte_offset;
        let manifest_svn = otp_map::OTP_CPTRA_CORE_SOC_MANIFEST_SVN.byte_offset;
        let manifest_max_svn = otp_map::OTP_CPTRA_CORE_SOC_MANIFEST_MAX_SVN.byte_offset;
        if let Some(v) = self.fw_svn {
            for (i, w) in v.iter().enumerate() {
                let off = runtime_svn + i * 4;
                otp[off..off + 4].copy_from_slice(&w.to_le_bytes());
            }
        }
        if let Some(v) = self.soc_manifest_svn {
            for (i, w) in v.iter().enumerate() {
                let off = manifest_svn + i * 4;
                otp[off..off + 4].copy_from_slice(&w.to_le_bytes());
            }
        }
        if let Some(v) = self.soc_manifest_max_svn {
            otp[manifest_max_svn..manifest_max_svn + 4].copy_from_slice(&(v as u32).to_le_bytes());
        }

        // VENDOR_HASHES_MANUF (0x420): vendor_pk_hash (48) + pqc_key_type (4)
        //
        // NOTE: byte 48 (pqc_key_type) is overwritten by the MCU model based on
        // its `vendor_pqc_type` init param. The lib.rs constructor derives that
        // init param from `fuse_pqc_key_type` here. We still write the byte for
        // completeness in case the model ever stops overriding it.
        let pqc_key_type = otp_map::OTP_CPTRA_CORE_PQC_KEY_TYPE_0.byte_offset;
        if let Some(v) = self.fuse_pqc_key_type {
            // Caliptra: 0=LMS, 1=MLDSA. OTP: 0=MLDSA, 1=LMS.
            let otp_val: u32 = if v == 1 { 0 } else { 1 };
            otp[pqc_key_type..pqc_key_type + 4].copy_from_slice(&otp_val.to_le_bytes());
        }

        // VENDOR_REVOCATIONS_PROD (0x7c0): owner_ecc/lms/mldsa_revocation (4 ea),
        // then cptra_core_ecc/lms/mldsa_revocation_0..3 (4 bytes each, 36 bytes total).
        let ecc_rev = otp_map::OTP_CPTRA_CORE_ECC_REVOCATION_0.byte_offset;
        let lms_rev = otp_map::OTP_CPTRA_CORE_LMS_REVOCATION_0.byte_offset;
        let mldsa_rev = otp_map::OTP_CPTRA_CORE_MLDSA_REVOCATION_0.byte_offset;
        // We populate the cptra_core_*_revocation_0 slot for the core fuse fields.
        if let Some(v) = self.fuse_ecc_revocation {
            otp[ecc_rev..ecc_rev + 4].copy_from_slice(&v.to_le_bytes());
        }
        if let Some(v) = self.fuse_lms_revocation {
            otp[lms_rev..lms_rev + 4].copy_from_slice(&v.to_le_bytes());
        }
        if let Some(v) = self.fuse_mldsa_revocation {
            otp[mldsa_rev..mldsa_rev + 4].copy_from_slice(&v.to_le_bytes());
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
    #[cfg(not(feature = "caliptra-1x"))]
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
    #[cfg(feature = "caliptra-1x")]
    fn test_apply_to_fuses_1x() {
        let cfg = FuseConfig::from_json(
            r#"{"fuse_ecc_revocation":5,"fuse_lms_revocation":7,"fw_svn":[3,0,0,0]}"#,
        )
        .unwrap();
        let mut fuses = Fuses::default();
        cfg.apply_to_fuses(&mut fuses).unwrap();
        assert_eq!(u32::from(fuses.key_manifest_pk_hash_mask), 5);
        assert_eq!(fuses.fuse_lms_revocation, 7);
        assert_eq!(fuses.runtime_svn, [3, 0, 0, 0]);

        let err = FuseConfig::from_json(r#"{"fuse_mldsa_revocation":1}"#)
            .unwrap()
            .apply_to_fuses(&mut fuses)
            .unwrap_err();
        assert!(err.contains("not a Caliptra 1.x fuse"), "{err}");
    }

    // Partition start offsets, written out per release so these tests also
    // check the generated OTP map that apply_to_otp uses.
    #[cfg(feature = "caliptra-2-0")]
    const SVN_PARTITION: usize = 0x390;
    // (1.x has no OTP; these are only used by the 2.x tests.)
    #[cfg(feature = "caliptra-2-1")]
    const SVN_PARTITION: usize = 0x3b8;
    #[cfg(feature = "caliptra-2-0")]
    const VENDOR_REVOCATIONS_PARTITION: usize = 0x798;
    #[cfg(feature = "caliptra-2-1")]
    const VENDOR_REVOCATIONS_PARTITION: usize = 0x7c0;

    #[test]
    #[cfg(not(feature = "caliptra-1x"))]
    fn test_apply_to_otp_svn() {
        let cfg =
            FuseConfig::from_json(r#"{"soc_manifest_max_svn":64,"fw_svn":[1,0,0,0]}"#).unwrap();
        let mut otp = vec![0u8; 4096];
        cfg.apply_to_otp(&mut otp).unwrap();
        assert_eq!(otp[SVN_PARTITION + 36], 64); // soc_manifest_max_svn
        assert_eq!(otp[SVN_PARTITION + 4], 1); // fw_svn[0]
    }

    #[test]
    #[cfg(not(feature = "caliptra-1x"))]
    fn test_apply_to_otp_vendor_revocations() {
        let cfg =
            FuseConfig::from_json(r#"{"fuse_lms_revocation":15,"fuse_mldsa_revocation":255}"#)
                .unwrap();
        let mut otp = vec![0u8; 4096];
        cfg.apply_to_otp(&mut otp).unwrap();
        assert_eq!(otp[VENDOR_REVOCATIONS_PARTITION + 16], 15);
        assert_eq!(otp[VENDOR_REVOCATIONS_PARTITION + 20], 255);
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
