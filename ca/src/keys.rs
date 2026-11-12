// Licensed under the Apache-2.0 license

//! The test CA's keys and the two signature algorithms it handles:
//! ML-DSA-87 (FIPS 204, pure mode with an empty context, as RFC 9881 uses in
//! X.509) and ECDSA P-384 with SHA-384.
//!
//! The CA keys come from fixed seeds that are published on the CA page, so
//! everything the CA issues is reproducible. They protect nothing.

use std::sync::OnceLock;

use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use p384::ecdsa::signature::hazmat::PrehashVerifier;
use p384::ecdsa::signature::Signer as _;
use p384::ecdsa::{Signature as EccSignature, SigningKey, VerifyingKey};

use crate::der;

/// ML-DSA-87 key generation seed (FIPS 204 ξ) of the ML-DSA test CA.
pub const MLDSA87_CA_SEED: &[u8; 32] = b"caliptra-wasm test CA ML-DSA-87!";
/// Private scalar of the ECC P-384 test CA (big-endian).
pub const ECC384_CA_PRIVATE_KEY: &[u8; 48] = b"caliptra-wasm test CA ECC P-384 private key v001";

pub const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const OID_SECP384R1: &str = "1.3.132.0.34";
pub const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
pub const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
pub const OID_ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
pub const OID_MLDSA87: &str = "2.16.840.1.101.3.4.3.19";

pub const MLDSA87_PUBLIC_KEY_LEN: usize = 2592;
pub const MLDSA87_SIGNATURE_LEN: usize = 4627;
pub const ECC384_COORD_LEN: usize = 48;

/// A signature algorithm (and the key type that goes with it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Mldsa87,
    Ecc384,
}

impl Alg {
    pub const ALL: [Alg; 2] = [Alg::Mldsa87, Alg::Ecc384];

    pub fn id(self) -> &'static str {
        match self {
            Alg::Mldsa87 => "mldsa87",
            Alg::Ecc384 => "ecc384",
        }
    }

    pub fn from_id(id: &str) -> Result<Alg, String> {
        match id {
            "mldsa87" => Ok(Alg::Mldsa87),
            "ecc384" => Ok(Alg::Ecc384),
            _ => Err(format!(
                "unknown algorithm \"{id}\" (expected mldsa87 or ecc384)"
            )),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Alg::Mldsa87 => "ML-DSA-87",
            Alg::Ecc384 => "ECDSA P-384 with SHA-384",
        }
    }

    pub fn signature_oid(self) -> &'static str {
        match self {
            Alg::Mldsa87 => OID_MLDSA87,
            Alg::Ecc384 => OID_ECDSA_SHA384,
        }
    }

    /// The signature AlgorithmIdentifier. Neither algorithm takes parameters.
    pub fn signature_algorithm_der(self) -> Vec<u8> {
        der::sequence(&[&der::oid(self.signature_oid())])
    }

    pub fn from_signature_oid(oid: &str) -> Option<Alg> {
        Alg::ALL.into_iter().find(|a| a.signature_oid() == oid)
    }
}

/// A subject public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// Uncompressed SEC1 point: 0x04, X, Y (97 bytes).
    Ecc384(Vec<u8>),
    /// The 2592-byte ML-DSA-87 public key.
    Mldsa87(Vec<u8>),
    /// A key type the CA cannot verify signatures with.
    Other {
        algorithm_oid: String,
        bits: Vec<u8>,
    },
}

impl PublicKey {
    /// From raw key material: an ML-DSA-87 public key, or P-384 X and Y
    /// back to back (96 bytes) or as an uncompressed point (97 bytes).
    pub fn from_raw(alg: Alg, raw: &[u8]) -> Result<PublicKey, String> {
        match alg {
            Alg::Mldsa87 if raw.len() == MLDSA87_PUBLIC_KEY_LEN => {
                Ok(PublicKey::Mldsa87(raw.to_vec()))
            }
            Alg::Mldsa87 => Err(format!(
                "an ML-DSA-87 public key is {MLDSA87_PUBLIC_KEY_LEN} bytes; got {}",
                raw.len()
            )),
            Alg::Ecc384 => {
                let point = match raw.len() {
                    96 => [&[4u8][..], raw].concat(),
                    97 if raw[0] == 4 => raw.to_vec(),
                    n => {
                        return Err(format!(
                            "a P-384 public key is X and Y (96 bytes) or an uncompressed point (97 bytes); got {n}"
                        ))
                    }
                };
                VerifyingKey::from_sec1_bytes(&point)
                    .map_err(|_| "the P-384 public key is not a point on the curve")?;
                Ok(PublicKey::Ecc384(point))
            }
        }
    }

    /// From a SubjectPublicKeyInfo element.
    pub fn from_spki(spki: &[u8]) -> Result<PublicKey, String> {
        let spki = der::single(spki, der::SEQUENCE, "SubjectPublicKeyInfo")?;
        let mut r = der::Reader::new(spki.value);
        let alg = r.expect(der::SEQUENCE, "public key algorithm")?;
        let key = r.expect(der::BIT_STRING, "public key")?;
        r.finish("SubjectPublicKeyInfo")?;
        let bits = der::bit_string_bytes(&key, "public key")?;

        let mut a = der::Reader::new(alg.value);
        let oid = der::oid_to_string(a.expect(der::OID, "public key algorithm")?.value);
        match oid.as_str() {
            OID_EC_PUBLIC_KEY => {
                let curve = a.expect(der::OID, "EC curve")?;
                if der::oid_to_string(curve.value) != OID_SECP384R1 {
                    return Ok(PublicKey::Other {
                        algorithm_oid: format!("{oid} (curve {})", der::oid_to_string(curve.value)),
                        bits: bits.to_vec(),
                    });
                }
                PublicKey::from_raw(Alg::Ecc384, bits)
            }
            OID_MLDSA87 => {
                a.finish("ML-DSA-87 AlgorithmIdentifier (parameters must be absent)")?;
                PublicKey::from_raw(Alg::Mldsa87, bits)
            }
            _ => Ok(PublicKey::Other {
                algorithm_oid: oid,
                bits: bits.to_vec(),
            }),
        }
    }

    /// The SubjectPublicKeyInfo element for this key.
    pub fn to_spki(&self) -> Result<Vec<u8>, String> {
        let alg = match self {
            PublicKey::Ecc384(_) => {
                der::sequence(&[&der::oid(OID_EC_PUBLIC_KEY), &der::oid(OID_SECP384R1)])
            }
            PublicKey::Mldsa87(_) => der::sequence(&[&der::oid(OID_MLDSA87)]),
            PublicKey::Other { algorithm_oid, .. } => {
                return Err(format!("unsupported public key algorithm {algorithm_oid}"))
            }
        };
        Ok(der::sequence(&[&alg, &der::bit_string(self.bits())]))
    }

    /// The contents of the subjectPublicKey BIT STRING.
    pub fn bits(&self) -> &[u8] {
        match self {
            PublicKey::Ecc384(b) | PublicKey::Mldsa87(b) => b,
            PublicKey::Other { bits, .. } => bits,
        }
    }

    pub fn alg(&self) -> Option<Alg> {
        match self {
            PublicKey::Ecc384(_) => Some(Alg::Ecc384),
            PublicKey::Mldsa87(_) => Some(Alg::Mldsa87),
            PublicKey::Other { .. } => None,
        }
    }

    pub fn description(&self) -> String {
        match self {
            PublicKey::Ecc384(_) => "ECC P-384".into(),
            PublicKey::Mldsa87(_) => "ML-DSA-87".into(),
            PublicKey::Other { algorithm_oid, .. } => format!("unsupported ({algorithm_oid})"),
        }
    }

    /// Verifies `signature` (the contents of a certificate's or request's
    /// signature BIT STRING) over `message`. `Err` means the check could not
    /// be made (unsupported algorithm, malformed signature).
    pub fn verify(
        &self,
        signature_oid: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        match (self, signature_oid) {
            (PublicKey::Ecc384(point), OID_ECDSA_SHA256 | OID_ECDSA_SHA384 | OID_ECDSA_SHA512) => {
                // The CA signs with SHA-384, as Caliptra does, but accepts
                // requests signed with the other SHA-2 hashes too (OpenSSL
                // signs requests with SHA-256 unless told otherwise).
                use sha2::Digest;
                let digest = match signature_oid {
                    OID_ECDSA_SHA256 => sha2::Sha256::digest(message).to_vec(),
                    OID_ECDSA_SHA384 => sha2::Sha384::digest(message).to_vec(),
                    _ => sha2::Sha512::digest(message).to_vec(),
                };
                let key = VerifyingKey::from_sec1_bytes(point)
                    .map_err(|_| "the P-384 public key is not a point on the curve")?;
                let sig = EccSignature::from_slice(&ecdsa_der_to_raw(signature)?)
                    .map_err(|_| "the ECDSA signature is out of range")?;
                Ok(key.verify_prehash(&digest, &sig).is_ok())
            }
            (PublicKey::Mldsa87(pk), OID_MLDSA87) => {
                let pk: [u8; MLDSA87_PUBLIC_KEY_LEN] = pk
                    .as_slice()
                    .try_into()
                    .map_err(|_| "bad ML-DSA-87 key length")?;
                let Ok(pk) = ml_dsa_87::PublicKey::try_from_bytes(pk) else {
                    return Ok(false);
                };
                let Ok(sig) = <[u8; MLDSA87_SIGNATURE_LEN]>::try_from(signature) else {
                    return Err(format!(
                        "an ML-DSA-87 signature is {MLDSA87_SIGNATURE_LEN} bytes; got {}",
                        signature.len()
                    ));
                };
                Ok(pk.verify(message, &sig, &[]))
            }
            _ => Err(format!(
                "cannot verify a signature with algorithm {signature_oid} using a {} key",
                self.description()
            )),
        }
    }
}

/// A signature in both of the forms the flows need.
pub struct SignatureBytes {
    /// What goes in the certificate's signature BIT STRING: the DER
    /// Ecdsa-Sig-Value for ECDSA, the signature itself for ML-DSA.
    pub encoded: Vec<u8>,
    /// The fixed-size form the Caliptra mailbox takes: R then S (96 bytes)
    /// for ECDSA, the 4627-byte signature for ML-DSA.
    pub raw: Vec<u8>,
}

struct CaKeys {
    mldsa_public: Vec<u8>,
    mldsa_private: ml_dsa_87::PrivateKey,
    ecc_public: Vec<u8>,
    ecc_private: SigningKey,
}

fn ca_keys() -> &'static CaKeys {
    static KEYS: OnceLock<CaKeys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let (mldsa_public, mldsa_private) = ml_dsa_87::KG::keygen_from_seed(MLDSA87_CA_SEED);
        let ecc_private = SigningKey::from_slice(ECC384_CA_PRIVATE_KEY)
            .expect("the ECC CA private key is a valid scalar");
        let ecc_public = ecc_private
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        CaKeys {
            mldsa_public: mldsa_public.into_bytes().to_vec(),
            mldsa_private,
            ecc_public,
            ecc_private,
        }
    })
}

/// The public key of the test CA for `alg`.
pub fn ca_public_key(alg: Alg) -> PublicKey {
    match alg {
        Alg::Mldsa87 => PublicKey::Mldsa87(ca_keys().mldsa_public.clone()),
        Alg::Ecc384 => PublicKey::Ecc384(ca_keys().ecc_public.clone()),
    }
}

/// Signs `message` with the test CA key for `alg`. Both algorithms sign
/// deterministically (ML-DSA with all-zero randomness, ECDSA per RFC 6979),
/// so the same input always gives the same certificate.
pub fn ca_sign(alg: Alg, message: &[u8]) -> Result<SignatureBytes, String> {
    match alg {
        Alg::Mldsa87 => {
            let sig = ca_keys()
                .mldsa_private
                .try_sign_with_seed(&[0u8; 32], message, &[])
                .map_err(|e| format!("ML-DSA-87 signing failed: {e}"))?;
            Ok(SignatureBytes {
                encoded: sig.to_vec(),
                raw: sig.to_vec(),
            })
        }
        Alg::Ecc384 => {
            let sig: EccSignature = ca_keys().ecc_private.sign(message);
            let raw = sig.to_bytes().to_vec();
            Ok(SignatureBytes {
                encoded: ecdsa_raw_to_der(&raw)?,
                raw,
            })
        }
    }
}

/// Converts R and S back to back (96 bytes) to a DER Ecdsa-Sig-Value.
pub fn ecdsa_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.len() != 2 * ECC384_COORD_LEN {
        return Err(format!(
            "a P-384 signature is R and S, 96 bytes; got {}",
            raw.len()
        ));
    }
    let (r, s) = raw.split_at(ECC384_COORD_LEN);
    Ok(der::sequence(&[&der::integer(r), &der::integer(s)]))
}

/// Converts a DER Ecdsa-Sig-Value to R and S back to back (96 bytes).
pub fn ecdsa_der_to_raw(encoded: &[u8]) -> Result<Vec<u8>, String> {
    let seq = der::single(encoded, der::SEQUENCE, "ECDSA signature")?;
    let mut r = der::Reader::new(seq.value);
    let mut raw = Vec::with_capacity(2 * ECC384_COORD_LEN);
    for name in ["ECDSA signature R", "ECDSA signature S"] {
        let int = r.expect(der::INTEGER, name)?;
        let magnitude = der::unsigned_integer(&int, name)?;
        if magnitude.len() > ECC384_COORD_LEN {
            return Err(format!("{name} is too large for P-384"));
        }
        raw.resize(raw.len() + ECC384_COORD_LEN - magnitude.len(), 0);
        raw.extend_from_slice(magnitude);
    }
    r.finish("ECDSA signature")?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_both_algorithms() {
        for alg in Alg::ALL {
            let key = ca_public_key(alg);
            let sig = ca_sign(alg, b"message").unwrap();
            assert!(key
                .verify(alg.signature_oid(), b"message", &sig.encoded)
                .unwrap());
            assert!(!key
                .verify(alg.signature_oid(), b"other", &sig.encoded)
                .unwrap());
            // Deterministic.
            assert_eq!(ca_sign(alg, b"message").unwrap().raw, sig.raw);
            // SPKI round trip.
            let spki = key.to_spki().unwrap();
            assert_eq!(PublicKey::from_spki(&spki).unwrap(), key);
        }
        assert_eq!(
            ca_sign(Alg::Mldsa87, b"m").unwrap().raw.len(),
            MLDSA87_SIGNATURE_LEN
        );
        assert_eq!(ca_sign(Alg::Ecc384, b"m").unwrap().raw.len(), 96);
    }

    #[test]
    fn mismatched_algorithm_is_an_error() {
        let key = ca_public_key(Alg::Ecc384);
        assert!(key.verify(OID_MLDSA87, b"m", &[0; 4627]).is_err());
    }

    #[test]
    fn ecdsa_signature_encodings() {
        let mut raw = vec![0u8; 96];
        raw[47] = 0x7f; // R = 0x7f
        raw[48] = 0x80; // S has its top bit set, so DER adds a leading zero
        let encoded = ecdsa_raw_to_der(&raw).unwrap();
        assert_eq!(&encoded[..5], &[0x30, 0x36, 0x02, 0x01, 0x7f]);
        assert_eq!(ecdsa_der_to_raw(&encoded).unwrap(), raw);
    }
}
