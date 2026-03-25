// Licensed under the Apache-2.0 license

use caliptra_image_types::ImageManifest;
use sha2::{Digest, Sha384};
use zerocopy::{FromBytes, IntoBytes};

pub fn extract_pk_hashes(data: &[u8]) -> anyhow::Result<(String, String)> {
    let (manifest, _) = ImageManifest::ref_from_prefix(data)
        .map_err(|_| anyhow::anyhow!("Failed to parse manifest from image"))?;

    let vendor_hash = Sha384::digest(manifest.preamble.vendor_pub_key_info.as_bytes());
    let owner_hash = Sha384::digest(manifest.preamble.owner_pub_keys.as_bytes());

    Ok((hash_to_hex(&vendor_hash), hash_to_hex(&owner_hash)))
}

fn hash_to_hex(hash: &[u8]) -> String {
    let mut s = String::with_capacity(96);
    for chunk in hash.chunks(4) {
        s.push_str(&format!(
            "{:08x}",
            u32::from_be_bytes(chunk.try_into().unwrap())
        ));
    }
    s
}
