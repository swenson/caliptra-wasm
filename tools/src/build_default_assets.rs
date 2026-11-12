// Licensed under the Apache-2.0 license

use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use caliptra_auth_man_gen::{
    AuthManifestGenerator, AuthManifestGeneratorConfig, AuthManifestGeneratorKeyConfig,
};
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestImageMetadata, AuthManifestPrivKeysConfig,
    AuthManifestPubKeysConfig, ImageMetadataFlags,
};
use caliptra_builder::firmware;
use caliptra_builder::version;
use caliptra_builder::ImageOptions;
use caliptra_image_crypto::RustCrypto;
use caliptra_image_fake_keys::*;
use caliptra_image_gen::{from_hw_format, ImageGeneratorCrypto};
use caliptra_image_types::FwVerificationPqcKeyType;
use zerocopy::IntoBytes;

/// Placeholder MCU firmware: `jal zero, 0` (an infinite loop) padded to 256
/// bytes. Matches caliptra-sw 2.1's `default_test_manifest::DEFAULT_MCU_FW`,
/// which 2.0 does not have.
static DEFAULT_MCU_FW: [u8; 256] = {
    let mut fw = [0u8; 256];
    fw[0] = 0x6f;
    fw
};

/// The runtime firmware to build: 2.1 adds OCP LOCK, which 2.0 lacks.
#[cfg(feature = "caliptra-2-0")]
const APP_FW: &caliptra_builder::FwId = &firmware::APP_WITH_UART;
#[cfg(feature = "caliptra-2-1")]
const APP_FW: &caliptra_builder::FwId = &firmware::APP_WITH_UART_OCP_LOCK;

fn main() -> Result<()> {
    let output_dir = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("www"));

    // Optional: path to the real MCU runtime binary for SoC manifest generation
    let mcu_runtime_path = env::args_os().nth(2).map(PathBuf::from);

    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;

    let original_dir = env::current_dir().context("Failed to read current directory")?;
    env::set_current_dir(caliptra_builder::THIS_WORKSPACE_DIR)
        .context("Failed to switch to caliptra-builder workspace")?;

    let result = build_assets(&output_dir, mcu_runtime_path.as_deref());

    env::set_current_dir(original_dir).context("Failed to restore current directory")?;
    result
}

fn build_assets(output_dir: &Path, mcu_runtime_path: Option<&Path>) -> Result<()> {
    let rom = caliptra_builder::build_firmware_rom(&firmware::ROM_WITH_UART)
        .context("Failed to build default ROM image")?;
    let rom_path = output_dir.join("default-rom.bin");
    std::fs::write(&rom_path, rom)
        .with_context(|| format!("Failed to write {}", rom_path.display()))?;
    println!("Wrote {}", rom_path.display());

    let fw_image = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        APP_FW,
        ImageOptions {
            fmc_version: version::get_fmc_version(),
            app_version: version::get_runtime_version(),
            fw_svn: 0,
            pqc_key_type: FwVerificationPqcKeyType::MLDSA,
            ..Default::default()
        },
    )
    .context("Failed to build default firmware bundle")?
    .to_bytes()
    .context("Failed to serialize default firmware bundle")?;

    let fw_path = output_dir.join("default-fw.bin");
    std::fs::write(&fw_path, &fw_image)
        .with_context(|| format!("Failed to write {}", fw_path.display()))?;
    println!("Wrote {} ({} bytes)", fw_path.display(), fw_image.len());

    let (vendor_pk_hash, owner_pk_hash) = caliptra_wasm_hash_tool::extract_pk_hashes(&fw_image)
        .context("Failed to extract PK hashes")?;

    let defaults_path = output_dir.join("defaults.json");
    std::fs::write(
        &defaults_path,
        format!(
            concat!(
                "{{\n",
                "  \"vendor_pk_hash\": \"{}\",\n",
                "  \"owner_pk_hash\": \"{}\"\n",
                "}}\n"
            ),
            vendor_pk_hash, owner_pk_hash
        ),
    )
    .with_context(|| format!("Failed to write {}", defaults_path.display()))?;
    println!("Wrote {}", defaults_path.display());

    // Generate default SoC manifest for subsystem mode (signed with test keys).
    // Uses the same key configuration as the MCU builder (CaliptraBuilder) to
    // ensure MLDSA signatures match what Caliptra expects.
    let mcu_fw_for_manifest: Vec<u8> = if let Some(rt_path) = mcu_runtime_path {
        std::fs::read(rt_path)
            .with_context(|| format!("Failed to read MCU runtime at {}", rt_path.display()))?
    } else {
        DEFAULT_MCU_FW.to_vec()
    };

    let crypto = RustCrypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&mcu_fw_for_manifest).unwrap());

    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);

    let image_metadata_list = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];

    // Match the MCU builder's key configuration exactly:
    // vendor_fw uses KEY_0, vendor_man uses KEY_1 for ECC/LMS but KEY_0 for MLDSA
    let gen_config = AuthManifestGeneratorConfig {
        vendor_fw_key_info: Some(AuthManifestGeneratorKeyConfig {
            pub_keys: AuthManifestPubKeysConfig {
                ecc_pub_key: VENDOR_ECC_KEY_0_PUBLIC,
                lms_pub_key: VENDOR_LMS_KEY_0_PUBLIC,
                mldsa_pub_key: VENDOR_MLDSA_KEY_0_PUBLIC,
            },
            priv_keys: Some(AuthManifestPrivKeysConfig {
                ecc_priv_key: VENDOR_ECC_KEY_0_PRIVATE,
                lms_priv_key: VENDOR_LMS_KEY_0_PRIVATE,
                mldsa_priv_key: VENDOR_MLDSA_KEY_0_PRIVATE,
            }),
        }),
        vendor_man_key_info: Some(AuthManifestGeneratorKeyConfig {
            pub_keys: AuthManifestPubKeysConfig {
                ecc_pub_key: VENDOR_ECC_KEY_1_PUBLIC,
                lms_pub_key: VENDOR_LMS_KEY_1_PUBLIC,
                mldsa_pub_key: VENDOR_MLDSA_KEY_0_PUBLIC,
            },
            priv_keys: Some(AuthManifestPrivKeysConfig {
                ecc_priv_key: VENDOR_ECC_KEY_1_PRIVATE,
                lms_priv_key: VENDOR_LMS_KEY_1_PRIVATE,
                mldsa_priv_key: VENDOR_MLDSA_KEY_0_PRIVATE,
            }),
        }),
        owner_fw_key_info: Some(AuthManifestGeneratorKeyConfig {
            pub_keys: AuthManifestPubKeysConfig {
                ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
                lms_pub_key: OWNER_LMS_KEY_PUBLIC,
                mldsa_pub_key: OWNER_MLDSA_KEY_PUBLIC,
            },
            priv_keys: Some(AuthManifestPrivKeysConfig {
                ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
                lms_priv_key: OWNER_LMS_KEY_PRIVATE,
                mldsa_priv_key: OWNER_MLDSA_KEY_PRIVATE,
            }),
        }),
        owner_man_key_info: Some(AuthManifestGeneratorKeyConfig {
            pub_keys: AuthManifestPubKeysConfig {
                ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
                lms_pub_key: OWNER_LMS_KEY_PUBLIC,
                mldsa_pub_key: OWNER_MLDSA_KEY_PUBLIC,
            },
            priv_keys: Some(AuthManifestPrivKeysConfig {
                ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
                lms_priv_key: OWNER_LMS_KEY_PRIVATE,
                mldsa_priv_key: OWNER_MLDSA_KEY_PRIVATE,
            }),
        }),
        image_metadata_list,
        version: 1,
        flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type: FwVerificationPqcKeyType::MLDSA,
        svn: 0,
    };

    let gen = AuthManifestGenerator::new(crypto);
    let soc_manifest = gen
        .generate(&gen_config)
        .context("Failed to generate SoC manifest")?;
    let soc_manifest_path = output_dir.join("default-soc-manifest.bin");
    std::fs::write(&soc_manifest_path, soc_manifest.as_bytes())
        .with_context(|| format!("Failed to write {}", soc_manifest_path.display()))?;
    println!(
        "Wrote {} ({} bytes)",
        soc_manifest_path.display(),
        soc_manifest.as_bytes().len()
    );

    // Write default MCU firmware (infinite loop) for subsystem mode
    let mcu_fw_path = output_dir.join("default-mcu-fw.bin");
    std::fs::write(&mcu_fw_path, DEFAULT_MCU_FW)
        .with_context(|| format!("Failed to write {}", mcu_fw_path.display()))?;
    println!(
        "Wrote {} ({} bytes)",
        mcu_fw_path.display(),
        DEFAULT_MCU_FW.len()
    );

    write_build_info(output_dir)?;

    Ok(())
}

/// Whether this release's firmware supports OCP LOCK (added in 2.1).
const OCP_LOCK: bool = cfg!(feature = "caliptra-2-1");

/// Write `build-info.json` describing which Caliptra release the default
/// images come from, so the UI can display it. build-wasm.sh passes the
/// upstream revisions in `CALIPTRA_SW_REV` / `CALIPTRA_MCU_SW_REV` and the
/// repositories they come from in `CALIPTRA_SW_REPO` / `CALIPTRA_MCU_SW_REPO`.
fn write_build_info(output_dir: &Path) -> Result<()> {
    let rev = |var: &str| env::var(var).unwrap_or_default();
    let info = format!(
        concat!(
            "{{\n",
            "  \"caliptra_release\": \"{}.{}\",\n",
            "  \"rom_version\": \"{}.{}.{}\",\n",
            "  \"fmc_version\": \"{}.{}.{}\",\n",
            "  \"runtime_version\": \"{}.{}.{}\",\n",
            "  \"caliptra_sw_rev\": \"{}\",\n",
            "  \"caliptra_mcu_sw_rev\": \"{}\",\n",
            "  \"caliptra_sw_repo\": \"{}\",\n",
            "  \"caliptra_mcu_sw_repo\": \"{}\",\n",
            "  \"features\": {{ \"ocp_lock\": {} }}\n",
            "}}\n"
        ),
        version::ROM_VERSION_MAJOR,
        version::ROM_VERSION_MINOR,
        version::ROM_VERSION_MAJOR,
        version::ROM_VERSION_MINOR,
        version::ROM_VERSION_PATCH,
        version::FMC_VERSION_MAJOR,
        version::FMC_VERSION_MINOR,
        version::FMC_VERSION_PATCH,
        version::RUNTIME_VERSION_MAJOR,
        version::RUNTIME_VERSION_MINOR,
        version::RUNTIME_VERSION_PATCH,
        rev("CALIPTRA_SW_REV"),
        rev("CALIPTRA_MCU_SW_REV"),
        rev("CALIPTRA_SW_REPO"),
        rev("CALIPTRA_MCU_SW_REPO"),
        OCP_LOCK,
    );
    let path = output_dir.join("build-info.json");
    std::fs::write(&path, info).with_context(|| format!("Failed to write {}", path.display()))?;
    println!("Wrote {}", path.display());
    Ok(())
}
