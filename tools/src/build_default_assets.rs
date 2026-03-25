// Licensed under the Apache-2.0 license

use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use caliptra_builder::firmware;
use caliptra_builder::version;
use caliptra_builder::ImageOptions;
use caliptra_image_types::FwVerificationPqcKeyType;

fn main() -> Result<()> {
    let output_dir = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("www"));

    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;

    let original_dir = env::current_dir().context("Failed to read current directory")?;
    env::set_current_dir(caliptra_builder::THIS_WORKSPACE_DIR)
        .context("Failed to switch to caliptra-builder workspace")?;

    let result = build_assets(&output_dir);

    env::set_current_dir(original_dir).context("Failed to restore current directory")?;
    result
}

fn build_assets(output_dir: &Path) -> Result<()> {
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

    Ok(())
}
