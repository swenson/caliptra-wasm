// Licensed under the Apache-2.0 license

use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use caliptra_auth_man_gen::default_test_manifest::{default_test_soc_manifest, DEFAULT_MCU_FW};
use caliptra_builder::firmware;
use caliptra_builder::version;
use caliptra_builder::ImageOptions;
use caliptra_image_crypto::RustCrypto;
use caliptra_image_types::FwVerificationPqcKeyType;
use zerocopy::IntoBytes;

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
        &firmware::APP_WITH_UART_OCP_LOCK,
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
    // Must use the same PQC key type as the FW image above.
    // Use the real MCU runtime binary if provided, otherwise fall back to stub.
    let mcu_fw_for_manifest: Vec<u8> = if let Some(rt_path) = mcu_runtime_path {
        std::fs::read(rt_path)
            .with_context(|| format!("Failed to read MCU runtime at {}", rt_path.display()))?
    } else {
        DEFAULT_MCU_FW.to_vec()
    };
    let soc_manifest = default_test_soc_manifest(
        &mcu_fw_for_manifest,
        FwVerificationPqcKeyType::MLDSA,
        0,
        RustCrypto::default(),
    );
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

    Ok(())
}
