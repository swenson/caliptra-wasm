// Licensed under the Apache-2.0 license

//! A test certificate authority for the browser: an ML-DSA-87 root and an
//! ECC P-384 root with fixed, public keys. It checks PKCS#10 requests,
//! issues certificates from requests or from bare public keys, signs
//! TBSCertificates, verifies chains and produces CRLs.
//!
//! The CA is stateless and deterministic: the page keeps the serial counter
//! and the list of issued certificates, and passes the validity dates in.
//! `api` holds the functions (structured data in and out as JSON, binary
//! fields as hex); the `#[wasm_bindgen]` wrappers at the bottom expose them
//! to JavaScript.
//!
//! The module also hashes and does P-384 key operations for the site's other
//! pages, which cannot count on the browser's WebCrypto: it exists only on
//! `localhost` and HTTPS origins.

use wasm_bindgen::prelude::*;

pub mod der;
pub mod keys;
pub mod x509;

pub mod api {
    use serde_json::{json, Value};

    use crate::der::{self, Time};
    use crate::keys::{self, Alg, PublicKey};
    use crate::x509::{self, Cert, Csr, Extension, IssueRequest, Profile, Revoked, Tbs};

    fn str_field<'a>(v: &'a Value, name: &str) -> Result<Option<&'a str>, String> {
        match v.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(format!("\"{name}\" must be a string")),
        }
    }

    fn required<'a>(v: &'a Value, name: &str) -> Result<&'a str, String> {
        str_field(v, name)?.ok_or_else(|| format!("missing \"{name}\""))
    }

    fn hex_field(v: &Value, name: &str) -> Result<Option<Vec<u8>>, String> {
        str_field(v, name)?
            .map(|s| der::unhex(s).map_err(|e| format!("\"{name}\": {e}")))
            .transpose()
    }

    /// The test CAs: name, algorithm, the fixed key material and the
    /// self-signed certificate of each.
    pub fn ca_list() -> String {
        let list: Vec<Value> = Alg::ALL
            .into_iter()
            .map(|alg| {
                let ca = x509::authority(alg);
                let (seed, seed_label) = match alg {
                    Alg::Mldsa87 => (
                        &keys::MLDSA87_CA_SEED[..],
                        "Key generation seed (FIPS 204 \u{3be})",
                    ),
                    Alg::Ecc384 => (
                        &keys::ECC384_CA_PRIVATE_KEY[..],
                        "Private scalar (big-endian)",
                    ),
                };
                json!({
                    "id": alg.id(),
                    "algorithm": alg.label(),
                    "subject": x509::name_to_string(&ca.name),
                    "seed": der::hex(seed),
                    "seed_text": String::from_utf8_lossy(seed),
                    "seed_label": seed_label,
                    "public_key": der::hex(ca.key.bits()),
                    "key_id": der::hex(&ca.key_id),
                    "cert": der::hex(&ca.cert),
                    "signature_size": match alg {
                        Alg::Mldsa87 => keys::MLDSA87_SIGNATURE_LEN,
                        Alg::Ecc384 => 2 * keys::ECC384_COORD_LEN,
                    },
                })
            })
            .collect();
        Value::Array(list).to_string()
    }

    /// Describes a PKCS#10 request and checks its signature.
    pub fn csr_info(csr: &[u8]) -> Result<String, String> {
        Ok(Csr::parse(csr)?.to_json().to_string())
    }

    /// Describes a certificate.
    pub fn cert_info(cert: &[u8]) -> Result<String, String> {
        Ok(Cert::parse(cert)?.to_json().to_string())
    }

    /// Describes a TBSCertificate.
    pub fn tbs_info(tbs: &[u8]) -> Result<String, String> {
        Ok(Tbs::parse(tbs)?.to_json().to_string())
    }

    fn issued_json(issued: &x509::Issued) -> Result<String, String> {
        Ok(json!({
            "cert": der::hex(&issued.cert),
            "tbs": der::hex(&issued.tbs),
            // The form the Caliptra mailbox takes: R then S for ECDSA, the
            // signature itself for ML-DSA.
            "signature": der::hex(&issued.signature.raw),
            "info": Cert::parse(&issued.cert)?.to_json(),
        })
        .to_string())
    }

    /// Issues a certificate. The request is a JSON object:
    ///
    /// * `ca`: `"mldsa87"` or `"ecc384"`, the CA that signs.
    /// * `serial`: serial number, hex.
    /// * `not_before`, `not_after`: UTC times, `YYYY-MM-DD HH:MM:SS`.
    /// * Either `csr` (a PKCS#10 request, hex; its signature must verify
    ///   unless `allow_invalid_csr` is true), or `public_key` (raw key, hex)
    ///   with `key_algorithm` and a subject: `subject` (a DER Name, hex) or
    ///   `subject_cn`.
    /// * `profile`: `"requested"` (the request's extensions), `"ca"`,
    ///   `"leaf"` or `"none"`. Defaults to `"requested"` for a request that
    ///   asks for extensions and `"ca"` otherwise. `path_len` applies to
    ///   `"ca"`.
    /// * `extra_extensions`: DER Extensions (hex) to add.
    /// * `subject_key_id`: hex, instead of SHA-1 of the key.
    ///
    /// Returns `{cert, tbs, signature, info}`.
    pub fn issue(request: &str) -> Result<String, String> {
        let v: Value = serde_json::from_str(request).map_err(|e| format!("bad request: {e}"))?;
        let ca = Alg::from_id(required(&v, "ca")?)?;

        let (subject, spki, requested) = if let Some(csr) = hex_field(&v, "csr")? {
            let csr = Csr::parse(&csr)?;
            if v.get("allow_invalid_csr") != Some(&Value::Bool(true)) {
                match csr.verify() {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(
                            "the request's signature does not verify (no proof of possession)"
                                .into(),
                        )
                    }
                    Err(e) => return Err(format!("cannot check the request's signature: {e}")),
                }
            }
            (csr.subject, csr.spki, csr.extensions)
        } else {
            let key_alg = Alg::from_id(required(&v, "key_algorithm")?)?;
            let raw = hex_field(&v, "public_key")?.ok_or("missing \"csr\" or \"public_key\"")?;
            let spki = PublicKey::from_raw(key_alg, &raw)?.to_spki()?;
            let subject = match hex_field(&v, "subject")? {
                Some(name) => name,
                None => x509::common_name(required(&v, "subject_cn")?),
            };
            (subject, spki, Vec::new())
        };

        let path_len = match v.get("path_len") {
            None | Some(Value::Null) => None,
            Some(n) => Some(
                n.as_u64()
                    .filter(|n| *n <= 255)
                    .ok_or("\"path_len\" must be a number from 0 to 255")? as u8,
            ),
        };
        let profile = match str_field(&v, "profile")? {
            Some("requested") => Profile::Requested,
            Some("ca") => Profile::Ca { path_len },
            Some("leaf") => Profile::Leaf,
            Some("none") => Profile::None,
            None if !requested.is_empty() => Profile::Requested,
            None => Profile::Ca { path_len },
            Some(other) => return Err(format!("unknown profile \"{other}\"")),
        };

        let mut extra = Vec::new();
        if let Some(list) = v.get("extra_extensions").and_then(Value::as_array) {
            for item in list {
                let raw = der::unhex(
                    item.as_str()
                        .ok_or("\"extra_extensions\" holds hex strings")?,
                )?;
                let cert_like = der::sequence(&[&raw]);
                let parsed = der::single(&cert_like, der::SEQUENCE, "extension")?;
                let ext = der::single(parsed.value, der::SEQUENCE, "extension")?;
                let mut r = der::Reader::new(ext.value);
                let oid = der::oid_to_string(r.expect(der::OID, "extension OID")?.value);
                let critical = matches!(r.optional(der::BOOLEAN)?, Some(b) if b.value != [0]);
                let value = r
                    .expect(der::OCTET_STRING, "extension value")?
                    .value
                    .to_vec();
                extra.push(Extension::new(&oid, critical, value));
            }
        }

        let issued = x509::issue(&IssueRequest {
            ca,
            serial: hex_field(&v, "serial")?.ok_or("missing \"serial\"")?,
            not_before: Time::parse(required(&v, "not_before")?)?,
            not_after: Time::parse(required(&v, "not_after")?)?,
            subject,
            spki,
            profile,
            requested,
            extra,
            subject_key_id: hex_field(&v, "subject_key_id")?,
        })?;
        issued_json(&issued)
    }

    /// Signs a TBSCertificate with the CA `ca` and returns `{cert, tbs,
    /// signature, info}`. The TBS must name that CA as issuer and declare
    /// its signature algorithm.
    pub fn sign_tbs(ca: &str, tbs: &[u8]) -> Result<String, String> {
        issued_json(&x509::sign_tbs(Alg::from_id(ca)?, tbs)?)
    }

    /// Verifies a chain given as a JSON array of hex certificates, root
    /// first. See `x509::verify_chain`.
    pub fn verify_chain(certs: &str) -> Result<String, String> {
        let v: Value = serde_json::from_str(certs).map_err(|e| format!("bad request: {e}"))?;
        let list = v.as_array().ok_or("expected an array of certificates")?;
        let certs = list
            .iter()
            .map(|c| der::unhex(c.as_str().ok_or("certificates must be hex strings")?))
            .collect::<Result<Vec<_>, String>>()?;
        Ok(x509::verify_chain(&certs).to_string())
    }

    /// Builds a CRL from `{ca, revoked: [{serial, date}], this_update,
    /// next_update, crl_number}` and returns its DER.
    pub fn crl(request: &str) -> Result<Vec<u8>, String> {
        let v: Value = serde_json::from_str(request).map_err(|e| format!("bad request: {e}"))?;
        let mut revoked = Vec::new();
        for item in v
            .get("revoked")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            revoked.push(Revoked {
                serial: hex_field(item, "serial")?.ok_or("revoked entry without a serial")?,
                date: Time::parse(required(item, "date")?)?,
            });
        }
        x509::crl(
            Alg::from_id(required(&v, "ca")?)?,
            &revoked,
            &Time::parse(required(&v, "this_update")?)?,
            &Time::parse(required(&v, "next_update")?)?,
            v.get("crl_number").and_then(Value::as_u64).unwrap_or(1),
        )
    }

    /// Splits what Caliptra's ROM sends when the IDevID CSR is requested at
    /// boot into its CSRs. Returns `{format, csrs: [hex]}`, and for an
    /// envelope also `mac` (hex), `mac_algorithm` and `mac_covers` (how many
    /// leading bytes the tag covers).
    pub fn idevid_csr_blob(blob: &[u8]) -> Result<String, String> {
        Ok(x509::parse_idevid_csr_blob(blob)?.to_string())
    }

    /// Converts an ECDSA P-384 signature between R-then-S (96 bytes) and DER.
    pub fn ecdsa_signature_to_der(raw: &[u8]) -> Result<Vec<u8>, String> {
        keys::ecdsa_raw_to_der(raw)
    }

    /// SHA-256, for certificate fingerprints. The pages hash here rather than
    /// with the browser's WebCrypto, which only exists on `localhost` and
    /// HTTPS origins.
    pub fn sha256(data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha256::digest(data).to_vec()
    }

    /// HMAC-SHA-512, the tag on the ROM's IDevID CSR envelope.
    pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::Mac;
        let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(key)
            .expect("HMAC takes a key of any length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// SHA-384, for the PK hash calculator and the Debug unlock page.
    pub fn sha384(data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha384::digest(data).to_vec()
    }

    /// SHA-512, for the Debug unlock page.
    pub fn sha512(data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha512::digest(data).to_vec()
    }

    fn p384_signing_key(private: &[u8]) -> Result<p384::ecdsa::SigningKey, String> {
        if private.len() != 48 {
            return Err(format!(
                "a P-384 private key is 48 bytes, not {}",
                private.len()
            ));
        }
        p384::ecdsa::SigningKey::from_slice(private).map_err(|_| {
            "not a valid P-384 private key: it is zero or not below the curve order".into()
        })
    }

    /// The public key of a P-384 private key (48 bytes, big-endian), as the
    /// 96 bytes X || Y. The Debug unlock page makes a key pair from 48 random
    /// bytes with this, and asks again in the rare case that they are not a
    /// valid private key.
    pub fn p384_public_key(private: &[u8]) -> Result<Vec<u8>, String> {
        let point = p384_signing_key(private)?
            .verifying_key()
            .to_encoded_point(false);
        // Uncompressed SEC1: 0x04 || X || Y.
        Ok(point.as_bytes()[1..].to_vec())
    }

    /// An ECDSA P-384 signature over the SHA-384 of `message`, as the 96
    /// bytes R || S. The nonce is deterministic (RFC 6979).
    pub fn p384_sign(private: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
        use p384::ecdsa::signature::Signer;
        let signature: p384::ecdsa::Signature = p384_signing_key(private)?.sign(message);
        Ok(signature.to_bytes().to_vec())
    }
}

fn js<T>(result: Result<T, String>) -> Result<T, JsError> {
    result.map_err(|e| JsError::new(&e))
}

/// See [`api::ca_list`].
#[wasm_bindgen]
pub fn ca_list() -> String {
    console_error_panic_hook::set_once();
    api::ca_list()
}

/// See [`api::csr_info`].
#[wasm_bindgen]
pub fn csr_info(csr: &[u8]) -> Result<String, JsError> {
    js(api::csr_info(csr))
}

/// See [`api::cert_info`].
#[wasm_bindgen]
pub fn cert_info(cert: &[u8]) -> Result<String, JsError> {
    js(api::cert_info(cert))
}

/// See [`api::tbs_info`].
#[wasm_bindgen]
pub fn tbs_info(tbs: &[u8]) -> Result<String, JsError> {
    js(api::tbs_info(tbs))
}

/// See [`api::issue`].
#[wasm_bindgen]
pub fn issue(request: &str) -> Result<String, JsError> {
    js(api::issue(request))
}

/// See [`api::sign_tbs`].
#[wasm_bindgen]
pub fn sign_tbs(ca: &str, tbs: &[u8]) -> Result<String, JsError> {
    js(api::sign_tbs(ca, tbs))
}

/// See [`api::verify_chain`].
#[wasm_bindgen]
pub fn verify_chain(certs: &str) -> Result<String, JsError> {
    js(api::verify_chain(certs))
}

/// See [`api::crl`].
#[wasm_bindgen]
pub fn crl(request: &str) -> Result<Vec<u8>, JsError> {
    js(api::crl(request))
}

/// See [`api::idevid_csr_blob`].
#[wasm_bindgen]
pub fn idevid_csr_blob(blob: &[u8]) -> Result<String, JsError> {
    js(api::idevid_csr_blob(blob))
}

/// See [`api::ecdsa_signature_to_der`].
#[wasm_bindgen]
pub fn ecdsa_signature_to_der(raw: &[u8]) -> Result<Vec<u8>, JsError> {
    js(api::ecdsa_signature_to_der(raw))
}

/// See [`api::sha256`].
#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    api::sha256(data)
}

/// See [`api::hmac_sha512`].
#[wasm_bindgen]
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
    api::hmac_sha512(key, data)
}

/// See [`api::sha384`].
#[wasm_bindgen]
pub fn sha384(data: &[u8]) -> Vec<u8> {
    api::sha384(data)
}

/// See [`api::sha512`].
#[wasm_bindgen]
pub fn sha512(data: &[u8]) -> Vec<u8> {
    api::sha512(data)
}

/// See [`api::p384_public_key`].
#[wasm_bindgen]
pub fn p384_public_key(private: &[u8]) -> Result<Vec<u8>, JsError> {
    js(api::p384_public_key(private))
}

/// See [`api::p384_sign`].
#[wasm_bindgen]
pub fn p384_sign(private: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
    js(api::p384_sign(private, message))
}

#[cfg(test)]
mod tests {
    use super::{api, der};

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sha384_known_answer() {
        assert_eq!(
            der::hex(&api::sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn sha512_known_answer() {
        assert_eq!(
            der::hex(&api::sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    /// RFC 6979 appendix A.2.6: the P-384 key, and its SHA-384 signature
    /// over "sample".
    const RFC6979_P384_PRIVATE: &str = "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba\
                                        9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5";

    #[test]
    fn p384_public_key_known_answer() {
        assert_eq!(
            der::hex(&api::p384_public_key(&unhex(RFC6979_P384_PRIVATE)).unwrap()),
            "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64\
             def8f0ea9055866064a254515480bc13\
             8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1\
             288b231c3ae0d4fe7344fd2533264720"
        );
    }

    #[test]
    fn p384_sign_known_answer() {
        assert_eq!(
            der::hex(&api::p384_sign(&unhex(RFC6979_P384_PRIVATE), b"sample").unwrap()),
            "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c\
             81a648152e44acf96e36dd1e80fabe46\
             99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94f\
             a329c145786e679e7b82c71a38628ac8"
        );
    }

    #[test]
    fn p384_rejects_bad_private_keys() {
        assert!(api::p384_public_key(&[0u8; 48]).is_err());
        assert!(api::p384_public_key(&[0xffu8; 48]).is_err());
        assert!(api::p384_public_key(&[1u8; 47]).is_err());
        assert!(api::p384_sign(&[0u8; 48], b"sample").is_err());
    }

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            der::hex(&api::sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// RFC 4231 test case 2.
    #[test]
    fn hmac_sha512_known_answer() {
        assert_eq!(
            der::hex(&api::hmac_sha512(b"Jefe", b"what do ya want for nothing?")),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
    }
}
