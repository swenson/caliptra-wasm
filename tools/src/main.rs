// Licensed under the Apache-2.0 license
//! Extracts vendor and owner PK hashes from a Caliptra FW image bundle.
//! Usage: extract-pk-hashes <fw-image.bin>

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("Usage: extract-pk-hashes <fw-image.bin>");
    let data = std::fs::read(&path).expect("Failed to read file");
    let (vendor_hash, owner_hash) =
        caliptra_wasm_hash_tool::extract_pk_hashes(&data).expect("Failed to extract PK hashes");

    println!("VENDOR_PK_HASH={vendor_hash}");
    println!("OWNER_PK_HASH={owner_hash}");
}
