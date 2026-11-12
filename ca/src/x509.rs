// Licensed under the Apache-2.0 license

//! PKCS#10 requests, X.509 certificates and CRLs: parsing, describing,
//! issuing and verifying.

use serde_json::{json, Value};
use sha1::{Digest, Sha1};

use crate::der::{self, Reader, Time, Tlv};
use crate::keys::{self, Alg, PublicKey};

pub const OID_SUBJECT_KEY_ID: &str = "2.5.29.14";
pub const OID_KEY_USAGE: &str = "2.5.29.15";
pub const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
pub const OID_CRL_NUMBER: &str = "2.5.29.20";
pub const OID_AUTHORITY_KEY_ID: &str = "2.5.29.35";
pub const OID_EXTENSION_REQUEST: &str = "1.2.840.113549.1.9.14";
pub const OID_COMMON_NAME: &str = "2.5.4.3";

/// Names for the OIDs that turn up in Caliptra's requests and certificates.
fn oid_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        OID_SUBJECT_KEY_ID => "subjectKeyIdentifier",
        OID_KEY_USAGE => "keyUsage",
        "2.5.29.17" => "subjectAltName",
        OID_BASIC_CONSTRAINTS => "basicConstraints",
        OID_CRL_NUMBER => "cRLNumber",
        "2.5.29.32" => "certificatePolicies",
        OID_AUTHORITY_KEY_ID => "authorityKeyIdentifier",
        "2.5.29.37" => "extKeyUsage",
        "2.23.133.5.4.1" => "tcg-dice-TcbInfo",
        "2.23.133.5.4.4" => "tcg-dice-Ueid",
        "2.23.133.5.4.5" => "tcg-dice-MultiTcbInfo",
        "2.23.133.5.4.100.6" => "tcg-dice-kp-identityInit",
        "2.23.133.5.4.100.7" => "tcg-dice-kp-identityLoc",
        "2.23.133.5.4.100.8" => "tcg-dice-kp-attestInit",
        "2.23.133.5.4.100.9" => "tcg-dice-kp-attestLoc",
        "2.23.133.5.4.100.12" => "tcg-dice-kp-eca",
        keys::OID_ECDSA_SHA256 => "ecdsa-with-SHA256",
        keys::OID_ECDSA_SHA384 => "ecdsa-with-SHA384",
        keys::OID_ECDSA_SHA512 => "ecdsa-with-SHA512",
        keys::OID_MLDSA87 => "id-ml-dsa-87",
        keys::OID_EC_PUBLIC_KEY => "id-ecPublicKey",
        keys::OID_SECP384R1 => "secp384r1",
        OID_EXTENSION_REQUEST => "extensionRequest",
        _ => return None,
    })
}

fn oid_label(oid: &str) -> String {
    match oid_name(oid) {
        Some(name) => name.to_string(),
        None => oid.to_string(),
    }
}

/// An X.509 extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub oid: String,
    pub critical: bool,
    /// The contents of extnValue.
    pub value: Vec<u8>,
}

impl Extension {
    pub fn new(oid: &str, critical: bool, value: Vec<u8>) -> Extension {
        Extension {
            oid: oid.to_string(),
            critical,
            value,
        }
    }

    fn parse(tlv: &Tlv<'_>) -> Result<Extension, String> {
        let mut r = Reader::new(tlv.value);
        let oid = der::oid_to_string(r.expect(der::OID, "extension OID")?.value);
        let critical = match r.optional(der::BOOLEAN)? {
            Some(b) => b.value != [0],
            None => false,
        };
        let value = r
            .expect(der::OCTET_STRING, "extension value")?
            .value
            .to_vec();
        r.finish("extension")?;
        Ok(Extension {
            oid,
            critical,
            value,
        })
    }

    pub fn to_der(&self) -> Vec<u8> {
        let oid = der::oid(&self.oid);
        let value = der::octet_string(&self.value);
        if self.critical {
            der::sequence(&[&oid, &der::boolean(true), &value])
        } else {
            der::sequence(&[&oid, &value])
        }
    }

    /// A one-line description of the value.
    pub fn summary(&self) -> String {
        let fallback = || der::hex(&self.value);
        match self.oid.as_str() {
            OID_BASIC_CONSTRAINTS => (|| -> Result<String, String> {
                let seq = der::single(&self.value, der::SEQUENCE, "basicConstraints")?;
                let mut r = Reader::new(seq.value);
                let ca = matches!(r.optional(der::BOOLEAN)?, Some(b) if b.value != [0]);
                let path = match r.optional(der::INTEGER)? {
                    Some(n) => format!(", pathLen {}", be_to_u64(n.value)),
                    None => String::new(),
                };
                Ok(format!("CA:{}{path}", if ca { "TRUE" } else { "FALSE" }))
            })()
            .unwrap_or_else(|_| fallback()),
            OID_KEY_USAGE => (|| -> Result<String, String> {
                let bits = der::single(&self.value, der::BIT_STRING, "keyUsage")?;
                const NAMES: [&str; 9] = [
                    "digitalSignature",
                    "nonRepudiation",
                    "keyEncipherment",
                    "dataEncipherment",
                    "keyAgreement",
                    "keyCertSign",
                    "cRLSign",
                    "encipherOnly",
                    "decipherOnly",
                ];
                let bytes = bits.value.get(1..).unwrap_or(&[]);
                let set: Vec<&str> = NAMES
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| bytes.get(i / 8).is_some_and(|b| b & (0x80 >> (i % 8)) != 0))
                    .map(|(_, n)| *n)
                    .collect();
                Ok(set.join(", "))
            })()
            .unwrap_or_else(|_| fallback()),
            OID_SUBJECT_KEY_ID => der::single(&self.value, der::OCTET_STRING, "SKI")
                .map(|t| der::hex(t.value))
                .unwrap_or_else(|_| fallback()),
            OID_AUTHORITY_KEY_ID => authority_key_id(&self.value)
                .map(|id| format!("keyid {}", der::hex(&id)))
                .unwrap_or_else(fallback),
            "2.23.133.5.4.4" => (|| -> Result<String, String> {
                let seq = der::single(&self.value, der::SEQUENCE, "UEID")?;
                let ueid = der::single(seq.value, der::OCTET_STRING, "UEID")?;
                Ok(format!("UEID {}", der::hex(ueid.value)))
            })()
            .unwrap_or_else(|_| fallback()),
            "2.5.29.37" => (|| -> Result<String, String> {
                let seq = der::single(&self.value, der::SEQUENCE, "extKeyUsage")?;
                Ok(der::elements(seq.value)?
                    .iter()
                    .map(|t| oid_label(&der::oid_to_string(t.value)))
                    .collect::<Vec<_>>()
                    .join(", "))
            })()
            .unwrap_or_else(|_| fallback()),
            _ => fallback(),
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "oid": self.oid,
            "name": oid_label(&self.oid),
            "critical": self.critical,
            "summary": self.summary(),
            "der": der::hex(&self.to_der()),
        })
    }
}

fn be_to_u64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

/// The keyIdentifier in an AuthorityKeyIdentifier value, if it has one.
fn authority_key_id(value: &[u8]) -> Option<Vec<u8>> {
    let seq = der::single(value, der::SEQUENCE, "AKI").ok()?;
    let mut r = Reader::new(seq.value);
    r.optional(der::context_primitive(0))
        .ok()?
        .map(|t| t.value.to_vec())
}

/// The key identifier in a SubjectKeyIdentifier value.
fn subject_key_id(value: &[u8]) -> Option<Vec<u8>> {
    der::single(value, der::OCTET_STRING, "SKI")
        .ok()
        .map(|t| t.value.to_vec())
}

fn find<'a>(extensions: &'a [Extension], oid: &str) -> Option<&'a Extension> {
    extensions.iter().find(|e| e.oid == oid)
}

fn parse_extensions(seq_of: &[u8]) -> Result<Vec<Extension>, String> {
    let seq = der::single(seq_of, der::SEQUENCE, "extensions")?;
    let mut out = Vec::new();
    for tlv in der::elements(seq.value)? {
        if tlv.tag != der::SEQUENCE {
            return Err("extensions: expected a SEQUENCE".into());
        }
        let ext = Extension::parse(&tlv)?;
        if out.iter().any(|e: &Extension| e.oid == ext.oid) {
            return Err(format!("extension {} appears twice", oid_label(&ext.oid)));
        }
        out.push(ext);
    }
    Ok(out)
}

/// Text form of a distinguished name, e.g. `CN=Caliptra 2.1 Ecc384 IDevID,
/// serialNumber=0123...`.
pub fn name_to_string(name: &[u8]) -> String {
    let parse = || -> Result<String, String> {
        let seq = der::single(name, der::SEQUENCE, "name")?;
        let mut parts = Vec::new();
        for rdn in der::elements(seq.value)? {
            for attr in der::elements(rdn.value)? {
                let mut r = Reader::new(attr.value);
                let oid = der::oid_to_string(r.expect(der::OID, "attribute type")?.value);
                let value = r.any()?;
                let text = match value.tag {
                    der::UTF8_STRING
                    | der::PRINTABLE_STRING
                    | der::IA5_STRING
                    | der::T61_STRING => String::from_utf8_lossy(value.value).into_owned(),
                    _ => format!("#{}", der::hex(value.raw)),
                };
                parts.push(format!("{}={text}", oid_label(&oid)));
            }
        }
        Ok(parts.join(", "))
    };
    parse().unwrap_or_else(|_| format!("(unparseable name {})", der::hex(name)))
}

/// A distinguished name with a single common name.
pub fn common_name(cn: &str) -> Vec<u8> {
    der::sequence(&[&der::constructed(
        der::SET,
        &[&der::sequence(&[
            &der::oid(OID_COMMON_NAME),
            &der::tlv(der::UTF8_STRING, cn.as_bytes()),
        ])],
    )])
}

/// A signature AlgorithmIdentifier's OID.
fn algorithm_oid(tlv: &Tlv<'_>) -> Result<String, String> {
    let mut r = Reader::new(tlv.value);
    Ok(der::oid_to_string(
        r.expect(der::OID, "signature algorithm")?.value,
    ))
}

/// A PKCS#10 certification request.
#[derive(Debug)]
pub struct Csr {
    /// CertificationRequestInfo: what the signature covers.
    pub info: Vec<u8>,
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
    pub key: PublicKey,
    /// The extensions in the extensionRequest attribute.
    pub extensions: Vec<Extension>,
    pub signature_oid: String,
    pub signature: Vec<u8>,
}

impl Csr {
    pub fn parse(input: &[u8]) -> Result<Csr, String> {
        let outer = der::single(input, der::SEQUENCE, "certification request")?;
        let mut r = Reader::new(outer.value);
        let info = r.expect(der::SEQUENCE, "CertificationRequestInfo")?;
        let sig_alg = r.expect(der::SEQUENCE, "signature algorithm")?;
        let sig = r.expect(der::BIT_STRING, "signature")?;
        r.finish("certification request")?;

        let mut i = Reader::new(info.value);
        let version = i.expect(der::INTEGER, "version")?;
        if version.value != [0] {
            return Err("unsupported certification request version".into());
        }
        let subject = i.expect(der::SEQUENCE, "subject")?;
        let spki = i.expect(der::SEQUENCE, "SubjectPublicKeyInfo")?;
        let mut extensions = Vec::new();
        if let Some(attrs) = i.optional(der::context(0))? {
            for attr in der::elements(attrs.value)? {
                let mut a = Reader::new(attr.value);
                let oid = der::oid_to_string(a.expect(der::OID, "attribute type")?.value);
                let values = a.expect(der::SET, "attribute values")?;
                if oid == OID_EXTENSION_REQUEST {
                    extensions = parse_extensions(values.value)?;
                }
            }
        }
        i.finish("CertificationRequestInfo")?;

        Ok(Csr {
            info: info.raw.to_vec(),
            subject: subject.raw.to_vec(),
            spki: spki.raw.to_vec(),
            key: PublicKey::from_spki(spki.raw)?,
            extensions,
            signature_oid: algorithm_oid(&sig_alg)?,
            signature: der::bit_string_bytes(&sig, "signature")?.to_vec(),
        })
    }

    /// Checks proof of possession: the request's signature under its own
    /// public key.
    pub fn verify(&self) -> Result<bool, String> {
        self.key
            .verify(&self.signature_oid, &self.info, &self.signature)
    }

    pub fn to_json(&self) -> Value {
        let (valid, error) = match self.verify() {
            Ok(v) => (Some(v), None),
            Err(e) => (None, Some(e)),
        };
        json!({
            "subject": name_to_string(&self.subject),
            "subject_der": der::hex(&self.subject),
            "key_algorithm": self.key.alg().map(Alg::id),
            "key_description": self.key.description(),
            "public_key": der::hex(self.key.bits()),
            "signature_algorithm": oid_label(&self.signature_oid),
            "signature_valid": valid,
            "signature_error": error,
            "extensions": self.extensions.iter().map(Extension::to_json).collect::<Vec<_>>(),
        })
    }
}

/// A parsed TBSCertificate.
#[derive(Debug)]
pub struct Tbs {
    pub raw: Vec<u8>,
    pub version: u64,
    pub serial: Vec<u8>,
    pub signature_oid: String,
    pub issuer: Vec<u8>,
    pub not_before: Time,
    pub not_after: Time,
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
    pub key: PublicKey,
    pub extensions: Vec<Extension>,
}

impl Tbs {
    pub fn parse(input: &[u8]) -> Result<Tbs, String> {
        let tbs = der::single(input, der::SEQUENCE, "TBSCertificate")?;
        let mut r = Reader::new(tbs.value);
        let version = match r.optional(der::context(0))? {
            Some(v) => be_to_u64(der::single(v.value, der::INTEGER, "version")?.value) + 1,
            None => 1,
        };
        let serial = r.expect(der::INTEGER, "serial number")?;
        let sig_alg = r.expect(der::SEQUENCE, "signature algorithm")?;
        let issuer = r.expect(der::SEQUENCE, "issuer")?;
        let validity = r.expect(der::SEQUENCE, "validity")?;
        let subject = r.expect(der::SEQUENCE, "subject")?;
        let spki = r.expect(der::SEQUENCE, "SubjectPublicKeyInfo")?;
        let _issuer_uid = r.optional(der::context_primitive(1))?;
        let _subject_uid = r.optional(der::context_primitive(2))?;
        let extensions = match r.optional(der::context(3))? {
            Some(e) => parse_extensions(e.value)?,
            None => Vec::new(),
        };
        r.finish("TBSCertificate")?;

        let mut v = Reader::new(validity.value);
        let not_before = Time::from_der(&v.any()?)?;
        let not_after = Time::from_der(&v.any()?)?;
        v.finish("validity")?;

        Ok(Tbs {
            raw: tbs.raw.to_vec(),
            version,
            serial: der::unsigned_integer(&serial, "serial number")?.to_vec(),
            signature_oid: algorithm_oid(&sig_alg)?,
            issuer: issuer.raw.to_vec(),
            not_before,
            not_after,
            subject: subject.raw.to_vec(),
            spki: spki.raw.to_vec(),
            key: PublicKey::from_spki(spki.raw)?,
            extensions,
        })
    }

    pub fn is_ca(&self) -> bool {
        find(&self.extensions, OID_BASIC_CONSTRAINTS)
            .is_some_and(|e| e.summary().starts_with("CA:TRUE"))
    }

    pub fn subject_key_id(&self) -> Option<Vec<u8>> {
        find(&self.extensions, OID_SUBJECT_KEY_ID).and_then(|e| subject_key_id(&e.value))
    }

    pub fn authority_key_id(&self) -> Option<Vec<u8>> {
        find(&self.extensions, OID_AUTHORITY_KEY_ID).and_then(|e| authority_key_id(&e.value))
    }

    pub fn to_json(&self) -> Value {
        json!({
            "version": self.version,
            "serial": der::hex(&self.serial),
            "issuer": name_to_string(&self.issuer),
            "issuer_der": der::hex(&self.issuer),
            "subject": name_to_string(&self.subject),
            "subject_der": der::hex(&self.subject),
            "not_before": self.not_before.display(),
            "not_after": self.not_after.display(),
            "key_algorithm": self.key.alg().map(Alg::id),
            "key_description": self.key.description(),
            "public_key": der::hex(self.key.bits()),
            "tbs_signature_algorithm": oid_label(&self.signature_oid),
            "is_ca": self.is_ca(),
            "subject_key_id": self.subject_key_id().map(|k| der::hex(&k)),
            "authority_key_id": self.authority_key_id().map(|k| der::hex(&k)),
            "extensions": self.extensions.iter().map(Extension::to_json).collect::<Vec<_>>(),
            "tbs_size": self.raw.len(),
        })
    }
}

/// A parsed certificate.
#[derive(Debug)]
pub struct Cert {
    pub tbs: Tbs,
    pub signature_oid: String,
    pub signature: Vec<u8>,
    pub raw: Vec<u8>,
}

impl Cert {
    pub fn parse(input: &[u8]) -> Result<Cert, String> {
        let outer = der::single(input, der::SEQUENCE, "certificate")?;
        let mut r = Reader::new(outer.value);
        let tbs = r.expect(der::SEQUENCE, "TBSCertificate")?;
        let sig_alg = r.expect(der::SEQUENCE, "signature algorithm")?;
        let sig = r.expect(der::BIT_STRING, "signature")?;
        r.finish("certificate")?;
        Ok(Cert {
            tbs: Tbs::parse(tbs.raw)?,
            signature_oid: algorithm_oid(&sig_alg)?,
            signature: der::bit_string_bytes(&sig, "signature")?.to_vec(),
            raw: outer.raw.to_vec(),
        })
    }

    /// Verifies this certificate's signature with `issuer_key`.
    pub fn verify(&self, issuer_key: &PublicKey) -> Result<bool, String> {
        issuer_key.verify(&self.signature_oid, &self.tbs.raw, &self.signature)
    }

    pub fn to_json(&self) -> Value {
        let mut v = self.tbs.to_json();
        v["signature_algorithm"] = json!(oid_label(&self.signature_oid));
        v["size"] = json!(self.raw.len());
        v["self_issued"] = json!(self.tbs.issuer == self.tbs.subject);
        v
    }
}

/// SHA-1 of the public key bits: RFC 5280's first key identifier method,
/// and what Caliptra's ROM uses for the IDevID key identifier unless its
/// fuses select something else.
pub fn key_id_sha1(key: &PublicKey) -> Vec<u8> {
    Sha1::digest(key.bits()).to_vec()
}

/// Which extensions an issued certificate gets (besides the key identifiers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Profile {
    /// The extensions the request asks for, unchanged.
    Requested,
    /// A CA certificate (as device identities are in DICE): basicConstraints
    /// CA:TRUE with an optional path length, keyUsage keyCertSign.
    Ca { path_len: Option<u8> },
    /// An end-entity certificate: CA:FALSE, keyUsage digitalSignature.
    Leaf,
    /// No extensions at all (a version 1 certificate).
    None,
}

/// What to put in a certificate.
#[derive(Clone, Debug)]
pub struct IssueRequest {
    pub ca: Alg,
    /// Serial number as an unsigned big-endian magnitude.
    pub serial: Vec<u8>,
    pub not_before: Time,
    pub not_after: Time,
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
    pub profile: Profile,
    /// Extensions asked for (from a request), used by `Profile::Requested`.
    pub requested: Vec<Extension>,
    /// Extensions to add whatever the profile, e.g. the device's UEID.
    pub extra: Vec<Extension>,
    /// Subject key identifier to use instead of SHA-1 of the key.
    pub subject_key_id: Option<Vec<u8>>,
}

/// A certificate with its parts.
pub struct Issued {
    pub tbs: Vec<u8>,
    pub signature: keys::SignatureBytes,
    pub cert: Vec<u8>,
}

/// A CA name, key and self-signed certificate.
pub struct Authority {
    pub alg: Alg,
    pub name: Vec<u8>,
    pub key: PublicKey,
    pub key_id: Vec<u8>,
    pub cert: Vec<u8>,
}

/// The test CA for `alg`: a self-signed root with a fixed key, serial number
/// and validity, so its certificate is the same everywhere.
pub fn authority(alg: Alg) -> &'static Authority {
    use std::sync::OnceLock;
    static MLDSA: OnceLock<Authority> = OnceLock::new();
    static ECC: OnceLock<Authority> = OnceLock::new();
    let (cell, cn) = match alg {
        Alg::Mldsa87 => (&MLDSA, "Caliptra WASM Test CA ML-DSA-87"),
        Alg::Ecc384 => (&ECC, "Caliptra WASM Test CA ECC P-384"),
    };
    cell.get_or_init(|| {
        let name = common_name(cn);
        let key = keys::ca_public_key(alg);
        let key_id = key_id_sha1(&key);
        let tbs = build_tbs(
            alg,
            &[1],
            &name,
            &Time::parse("20230101000000").unwrap(),
            &Time::parse("99991231235959").unwrap(),
            &name,
            &key.to_spki().expect("CA key"),
            &[
                basic_constraints(true, None),
                key_usage(&[5, 6]),
                Extension::new(OID_SUBJECT_KEY_ID, false, der::octet_string(&key_id)),
            ],
        );
        let signature = keys::ca_sign(alg, &tbs).expect("self-sign the CA certificate");
        Authority {
            alg,
            cert: assemble(&tbs, alg, &signature.encoded),
            name,
            key,
            key_id,
        }
    })
}

fn basic_constraints(ca: bool, path_len: Option<u8>) -> Extension {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    if ca {
        parts.push(der::boolean(true));
        if let Some(n) = path_len {
            parts.push(der::integer_u64(n as u64));
        }
    }
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    Extension::new(OID_BASIC_CONSTRAINTS, true, der::sequence(&refs))
}

fn key_usage(bits: &[u8]) -> Extension {
    Extension::new(OID_KEY_USAGE, true, der::named_bits(bits))
}

#[allow(clippy::too_many_arguments)]
fn build_tbs(
    ca: Alg,
    serial: &[u8],
    issuer: &[u8],
    not_before: &Time,
    not_after: &Time,
    subject: &[u8],
    spki: &[u8],
    extensions: &[Extension],
) -> Vec<u8> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    if !extensions.is_empty() {
        // Version 3; a certificate without extensions is version 1 (the default).
        parts.push(der::constructed(der::context(0), &[&der::integer_u64(2)]));
    }
    parts.push(der::integer(serial));
    parts.push(ca.signature_algorithm_der());
    parts.push(issuer.to_vec());
    parts.push(der::sequence(&[&not_before.to_der(), &not_after.to_der()]));
    parts.push(subject.to_vec());
    parts.push(spki.to_vec());
    if !extensions.is_empty() {
        let encoded: Vec<Vec<u8>> = extensions.iter().map(Extension::to_der).collect();
        let refs: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
        parts.push(der::constructed(der::context(3), &[&der::sequence(&refs)]));
    }
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    der::sequence(&refs)
}

/// Wraps a TBS, the signature algorithm and the signature into a certificate
/// (or CRL): the same thing Caliptra's GET_IDEV_*_CERT commands do.
pub fn assemble(tbs: &[u8], alg: Alg, encoded_signature: &[u8]) -> Vec<u8> {
    der::sequence(&[
        tbs,
        &alg.signature_algorithm_der(),
        &der::bit_string(encoded_signature),
    ])
}

/// Builds and signs a certificate.
pub fn issue(req: &IssueRequest) -> Result<Issued, String> {
    let ca = authority(req.ca);
    der::single(&req.subject, der::SEQUENCE, "subject name")?;
    let key = PublicKey::from_spki(&req.spki)?;
    if key.alg().is_none() {
        return Err(format!(
            "cannot certify a {} key: the CA handles ECC P-384 and ML-DSA-87 keys",
            key.description()
        ));
    }
    if req.serial.iter().all(|&b| b == 0) || req.serial.len() > 20 {
        return Err("the serial number must be positive and at most 20 bytes".into());
    }
    if req.not_after < req.not_before {
        return Err("the certificate would expire before it becomes valid".into());
    }

    let mut extensions: Vec<Extension> = match &req.profile {
        Profile::None => Vec::new(),
        Profile::Requested => req.requested.clone(),
        Profile::Ca { path_len } => vec![basic_constraints(true, *path_len), key_usage(&[5])],
        Profile::Leaf => vec![basic_constraints(false, None), key_usage(&[0])],
    };
    if req.profile != Profile::None {
        for extra in &req.extra {
            if find(&extensions, &extra.oid).is_none() {
                extensions.push(extra.clone());
            }
        }
        // The CA sets the key identifiers itself.
        let requested_ski =
            find(&extensions, OID_SUBJECT_KEY_ID).and_then(|e| subject_key_id(&e.value));
        extensions.retain(|e| e.oid != OID_SUBJECT_KEY_ID && e.oid != OID_AUTHORITY_KEY_ID);
        let ski = req
            .subject_key_id
            .clone()
            .or(requested_ski)
            .unwrap_or_else(|| key_id_sha1(&key));
        if ski.is_empty() || ski.len() > 64 {
            return Err("the subject key identifier must be 1 to 64 bytes".into());
        }
        extensions.push(Extension::new(
            OID_SUBJECT_KEY_ID,
            false,
            der::octet_string(&ski),
        ));
        extensions.push(Extension::new(
            OID_AUTHORITY_KEY_ID,
            false,
            der::sequence(&[&der::tlv(der::context_primitive(0), &ca.key_id)]),
        ));
    }

    let tbs = build_tbs(
        req.ca,
        &req.serial,
        &ca.name,
        &req.not_before,
        &req.not_after,
        &req.subject,
        &req.spki,
        &extensions,
    );
    let signature = keys::ca_sign(req.ca, &tbs)?;
    let cert = assemble(&tbs, req.ca, &signature.encoded);
    Ok(Issued {
        tbs,
        signature,
        cert,
    })
}

/// Signs a TBSCertificate someone else built, after checking that it names
/// this CA as issuer and declares the CA's signature algorithm.
pub fn sign_tbs(alg: Alg, tbs: &[u8]) -> Result<Issued, String> {
    let ca = authority(alg);
    let parsed = Tbs::parse(tbs)?;
    if parsed.signature_oid != alg.signature_oid() {
        return Err(format!(
            "the TBS declares signature algorithm {}, but the {} CA signs with {}",
            oid_label(&parsed.signature_oid),
            alg.label(),
            oid_label(alg.signature_oid())
        ));
    }
    if parsed.issuer != ca.name {
        return Err(format!(
            "the TBS names \"{}\" as issuer, not this CA (\"{}\")",
            name_to_string(&parsed.issuer),
            name_to_string(&ca.name)
        ));
    }
    let signature = keys::ca_sign(alg, tbs)?;
    let cert = assemble(tbs, alg, &signature.encoded);
    Ok(Issued {
        tbs: tbs.to_vec(),
        signature,
        cert,
    })
}

/// A revoked certificate for a CRL.
pub struct Revoked {
    pub serial: Vec<u8>,
    pub date: Time,
}

/// Builds and signs a version 2 CRL.
pub fn crl(
    alg: Alg,
    revoked: &[Revoked],
    this_update: &Time,
    next_update: &Time,
    crl_number: u64,
) -> Result<Vec<u8>, String> {
    let ca = authority(alg);
    let mut parts: Vec<Vec<u8>> = vec![
        der::integer_u64(1),
        alg.signature_algorithm_der(),
        ca.name.clone(),
        this_update.to_der(),
        next_update.to_der(),
    ];
    if !revoked.is_empty() {
        let entries: Vec<Vec<u8>> = revoked
            .iter()
            .map(|r| der::sequence(&[&der::integer(&r.serial), &r.date.to_der()]))
            .collect();
        let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
        parts.push(der::sequence(&refs));
    }
    let extensions = [
        Extension::new(
            OID_AUTHORITY_KEY_ID,
            false,
            der::sequence(&[&der::tlv(der::context_primitive(0), &ca.key_id)]),
        ),
        Extension::new(OID_CRL_NUMBER, false, der::integer_u64(crl_number)),
    ];
    let encoded: Vec<Vec<u8>> = extensions.iter().map(Extension::to_der).collect();
    let refs: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
    parts.push(der::constructed(der::context(0), &[&der::sequence(&refs)]));

    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let tbs = der::sequence(&refs);
    let signature = keys::ca_sign(alg, &tbs)?;
    Ok(assemble(&tbs, alg, &signature.encoded))
}

/// Verifies a certificate chain given root-first: each certificate must be
/// signed by the one before it, and the first by one of the test CAs (or by
/// itself). Validity dates are reported but not compared with the clock:
/// Caliptra's own certificates carry fixed dates.
pub fn verify_chain(certs: &[Vec<u8>]) -> Value {
    let mut links = Vec::new();
    let mut all_ok = !certs.is_empty();
    let mut previous: Option<Cert> = None;
    for (index, raw) in certs.iter().enumerate() {
        let cert = match Cert::parse(raw) {
            Ok(c) => c,
            Err(e) => {
                links.push(
                    json!({"index": index, "ok": false, "error": format!("cannot parse: {e}")}),
                );
                all_ok = false;
                previous = None;
                continue;
            }
        };

        // Who should have signed it.
        struct Issuer {
            label: String,
            name: Vec<u8>,
            key: PublicKey,
            key_id: Option<Vec<u8>>,
            is_ca: bool,
        }
        let issuer = if let Some(prev) = &previous {
            Some(Issuer {
                label: format!("certificate {index}: {}", name_to_string(&prev.tbs.subject)),
                name: prev.tbs.subject.clone(),
                key: prev.tbs.key.clone(),
                key_id: prev.tbs.subject_key_id(),
                is_ca: prev.tbs.is_ca(),
            })
        } else if let Some(ca) = Alg::ALL
            .into_iter()
            .map(authority)
            .find(|ca| ca.name == cert.tbs.issuer)
        {
            Some(Issuer {
                label: format!("test CA: {}", name_to_string(&ca.name)),
                name: ca.name.clone(),
                key: ca.key.clone(),
                key_id: Some(ca.key_id.clone()),
                is_ca: true,
            })
        } else if index == 0 && cert.tbs.issuer == cert.tbs.subject {
            Some(Issuer {
                label: "itself (self-signed)".into(),
                name: cert.tbs.subject.clone(),
                key: cert.tbs.key.clone(),
                key_id: cert.tbs.subject_key_id(),
                is_ca: cert.tbs.is_ca(),
            })
        } else {
            None
        };

        let mut link = json!({
            "index": index,
            "subject": name_to_string(&cert.tbs.subject),
            "issuer": name_to_string(&cert.tbs.issuer),
            "key_description": cert.tbs.key.description(),
            "signature_algorithm": oid_label(&cert.signature_oid),
            "not_before": cert.tbs.not_before.display(),
            "not_after": cert.tbs.not_after.display(),
            "size": cert.raw.len(),
        });
        let mut problems: Vec<String> = Vec::new();
        match &issuer {
            None => problems.push(format!(
                "no issuer: \"{}\" is not a test CA and no certificate precedes it",
                name_to_string(&cert.tbs.issuer)
            )),
            Some(issuer) => {
                link["verified_with"] = json!(issuer.label);
                match cert.verify(&issuer.key) {
                    Ok(true) => link["signature_ok"] = json!(true),
                    Ok(false) => {
                        link["signature_ok"] = json!(false);
                        problems.push("the signature does not verify".into());
                    }
                    Err(e) => {
                        link["signature_ok"] = json!(false);
                        problems.push(e);
                    }
                }
                if issuer.name != cert.tbs.issuer {
                    problems.push(format!(
                        "issuer name \"{}\" does not match the issuing certificate's subject \"{}\"",
                        name_to_string(&cert.tbs.issuer),
                        name_to_string(&issuer.name)
                    ));
                }
                if let (Some(aki), Some(ski)) = (cert.tbs.authority_key_id(), &issuer.key_id) {
                    link["key_id_ok"] = json!(&aki == ski);
                    if &aki != ski {
                        problems.push(format!(
                            "authority key identifier {} does not match the issuer's subject key identifier {}",
                            der::hex(&aki),
                            der::hex(ski)
                        ));
                    }
                }
                if !issuer.is_ca {
                    problems.push(
                        "the issuing certificate is not a CA (no basicConstraints CA:TRUE)".into(),
                    );
                }
            }
        }
        link["ok"] = json!(problems.is_empty());
        link["problems"] = json!(problems);
        all_ok &= problems.is_empty();
        links.push(link);
        previous = Some(cert);
    }
    json!({"ok": all_ok, "links": links})
}

/// Splits the blob Caliptra's ROM hands to the SoC when the IDevID CSR is
/// requested at boot. Caliptra 1.x sends the ECC CSR on its own; 2.x sends an
/// envelope holding the ECC and ML-DSA CSRs and an HMAC over both.
pub fn parse_idevid_csr_blob(blob: &[u8]) -> Result<Value, String> {
    const MARKER: u32 = 0x0043_5352; // "CSR"
    const HEADER_LEN: usize = 8; // marker, size
    const ECC_SLOT: usize = 4 + 512;
    const MAC_LEN: usize = 64;
    let word = |at: usize| -> Option<usize> {
        blob.get(at..at + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
    };

    if blob.first() == Some(&der::SEQUENCE) {
        let len = der::first_element_len(blob)?;
        return Ok(json!({
            "format": "CSR",
            "csrs": [der::hex(&blob[..len])],
        }));
    }
    if word(0) != Some(MARKER as usize) {
        return Err("not an IDevID CSR: expected a DER CSR or a CSR envelope".into());
    }
    // The envelope is the header, the ECC CSR slot, the ML-DSA CSR slot and
    // the MAC. A slot is a length and a fixed-size buffer; the ML-DSA buffer
    // is 7680 bytes in 2.0 and 8192 in 2.1, so take its size from what is
    // left between the ECC slot and the MAC.
    let size = word(4).unwrap_or(0).min(blob.len());
    if size < HEADER_LEN + ECC_SLOT + MAC_LEN {
        return Err("CSR envelope: too short to hold a CSR".into());
    }
    let mac_at = size - MAC_LEN;
    let mut csrs = Vec::new();
    let mut slot = HEADER_LEN;
    for slot_len in [ECC_SLOT, mac_at - HEADER_LEN - ECC_SLOT] {
        if slot_len < 4 {
            break;
        }
        let len = word(slot).unwrap();
        if len > slot_len - 4 {
            return Err(format!("CSR envelope: CSR length {len} is out of range"));
        }
        csrs.push(der::hex(&blob[slot + 4..slot + 4 + len]));
        slot += slot_len;
    }
    Ok(json!({
        "format": "CSR envelope",
        "csrs": csrs,
        "mac": der::hex(&blob[mac_at..size]),
        "mac_algorithm": "HMAC-SHA-512",
        // The tag covers everything before it.
        "mac_covers": mac_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forever() -> (Time, Time) {
        (
            Time::parse("20230101000000").unwrap(),
            Time::parse("99991231235959").unwrap(),
        )
    }

    fn device_request(ca: Alg, key_alg: Alg) -> IssueRequest {
        // Use the other CA's key as a stand-in device key.
        let (not_before, not_after) = forever();
        IssueRequest {
            ca,
            serial: vec![0x12, 0x34],
            not_before,
            not_after,
            subject: common_name("Test Device"),
            spki: keys::ca_public_key(key_alg).to_spki().unwrap(),
            profile: Profile::Ca { path_len: Some(5) },
            requested: Vec::new(),
            extra: Vec::new(),
            subject_key_id: None,
        }
    }

    #[test]
    fn roots_are_self_signed_cas() {
        for alg in Alg::ALL {
            let ca = authority(alg);
            let cert = Cert::parse(&ca.cert).unwrap();
            assert_eq!(cert.tbs.issuer, cert.tbs.subject);
            assert!(cert.tbs.is_ca());
            assert_eq!(cert.tbs.version, 3);
            assert_eq!(cert.tbs.subject_key_id().unwrap(), ca.key_id);
            assert!(cert.verify(&ca.key).unwrap());
            let chain = verify_chain(std::slice::from_ref(&ca.cert));
            assert_eq!(chain["ok"], true, "{chain}");
        }
    }

    #[test]
    fn issue_every_ca_and_key_combination() {
        for ca in Alg::ALL {
            for key_alg in Alg::ALL {
                let issued = issue(&device_request(ca, key_alg)).unwrap();
                let cert = Cert::parse(&issued.cert).unwrap();
                assert_eq!(cert.tbs.raw, issued.tbs);
                assert_eq!(cert.tbs.serial, [0x12, 0x34]);
                assert_eq!(cert.tbs.issuer, authority(ca).name);
                assert_eq!(cert.tbs.authority_key_id().unwrap(), authority(ca).key_id);
                assert_eq!(
                    cert.tbs.subject_key_id().unwrap(),
                    key_id_sha1(&keys::ca_public_key(key_alg))
                );
                assert!(cert.tbs.is_ca());
                assert!(cert.verify(&authority(ca).key).unwrap());
                let chain = verify_chain(std::slice::from_ref(&issued.cert));
                assert_eq!(chain["ok"], true, "{chain}");
                // Signing the same TBS again gives the same certificate.
                assert_eq!(sign_tbs(ca, &issued.tbs).unwrap().cert, issued.cert);
            }
        }
    }

    #[test]
    fn profiles() {
        let mut req = device_request(Alg::Ecc384, Alg::Ecc384);
        req.profile = Profile::Leaf;
        let cert = Cert::parse(&issue(&req).unwrap().cert).unwrap();
        assert!(!cert.tbs.is_ca());
        assert_eq!(
            find(&cert.tbs.extensions, OID_KEY_USAGE).unwrap().summary(),
            "digitalSignature"
        );

        req.profile = Profile::None;
        let cert = Cert::parse(&issue(&req).unwrap().cert).unwrap();
        assert_eq!(cert.tbs.version, 1);
        assert!(cert.tbs.extensions.is_empty());

        req.profile = Profile::Requested;
        req.requested = vec![
            basic_constraints(true, Some(5)),
            Extension::new(
                "2.23.133.5.4.4",
                false,
                der::sequence(&[&der::octet_string(&[7; 17])]),
            ),
        ];
        req.subject_key_id = Some(vec![0xaa; 20]);
        let cert = Cert::parse(&issue(&req).unwrap().cert).unwrap();
        assert_eq!(
            find(&cert.tbs.extensions, OID_BASIC_CONSTRAINTS)
                .unwrap()
                .summary(),
            "CA:TRUE, pathLen 5"
        );
        assert!(find(&cert.tbs.extensions, "2.23.133.5.4.4")
            .unwrap()
            .summary()
            .starts_with("UEID 07"));
        assert_eq!(cert.tbs.subject_key_id().unwrap(), vec![0xaa; 20]);
    }

    #[test]
    fn rejects_bad_requests() {
        let mut req = device_request(Alg::Ecc384, Alg::Ecc384);
        req.serial = vec![0];
        assert!(issue(&req).is_err());
        let mut req = device_request(Alg::Ecc384, Alg::Ecc384);
        std::mem::swap(&mut req.not_before, &mut req.not_after);
        assert!(issue(&req).is_err());
        // A TBS for the other CA.
        let issued = issue(&device_request(Alg::Ecc384, Alg::Ecc384)).unwrap();
        assert!(sign_tbs(Alg::Mldsa87, &issued.tbs).is_err());
    }

    #[test]
    fn chain_reports_broken_links() {
        let good = issue(&device_request(Alg::Mldsa87, Alg::Ecc384))
            .unwrap()
            .cert;
        let mut bad = good.clone();
        let n = bad.len();
        bad[n - 1] ^= 1; // corrupt the signature
        let chain = verify_chain(&[bad]);
        assert_eq!(chain["ok"], false);
        assert_eq!(chain["links"][0]["signature_ok"], false);

        // A certificate that does not chain to the one before it.
        let other = issue(&device_request(Alg::Ecc384, Alg::Mldsa87))
            .unwrap()
            .cert;
        let chain = verify_chain(&[good, other]);
        assert_eq!(chain["links"][0]["ok"], true);
        assert_eq!(chain["links"][1]["ok"], false, "{chain}");
        assert_eq!(verify_chain(&[])["ok"], false);
    }

    #[test]
    fn crl_parses_and_verifies() {
        let (this_update, next_update) = forever();
        for alg in Alg::ALL {
            let list = crl(
                alg,
                &[Revoked {
                    serial: vec![0x12, 0x34],
                    date: this_update.clone(),
                }],
                &this_update,
                &next_update,
                7,
            )
            .unwrap();
            let outer = der::single(&list, der::SEQUENCE, "crl").unwrap();
            let mut r = Reader::new(outer.value);
            let tbs = r.expect(der::SEQUENCE, "tbs").unwrap();
            let _alg = r.expect(der::SEQUENCE, "alg").unwrap();
            let sig = r.expect(der::BIT_STRING, "sig").unwrap();
            assert!(authority(alg)
                .key
                .verify(alg.signature_oid(), tbs.raw, &sig.value[1..])
                .unwrap());
        }
    }

    #[test]
    fn csr_blob_formats() {
        let csr = der::sequence(&[&der::integer_u64(0)]);
        let mut padded = csr.clone();
        padded.extend_from_slice(&[0; 9]);
        let parsed = parse_idevid_csr_blob(&padded).unwrap();
        assert_eq!(parsed["csrs"][0], der::hex(&csr));

        // The ML-DSA slot is 7680 bytes in 2.0 and 8192 in 2.1.
        for mldsa_slot in [7680usize, 8192] {
            let total = 8 + 4 + 512 + 4 + mldsa_slot + 64;
            let mut envelope = Vec::new();
            envelope.extend_from_slice(&0x0043_5352u32.to_le_bytes());
            envelope.extend_from_slice(&(total as u32).to_le_bytes());
            for (slot, fill) in [(512usize, 0x11u8), (mldsa_slot, 0x22)] {
                envelope.extend_from_slice(&3u32.to_le_bytes());
                let mut buf = vec![0u8; slot];
                buf[..3].fill(fill);
                envelope.extend_from_slice(&buf);
            }
            envelope.extend_from_slice(&[0x33; 64]);
            assert_eq!(envelope.len(), total);
            let parsed = parse_idevid_csr_blob(&envelope).unwrap();
            assert_eq!(parsed["csrs"][0], "111111");
            assert_eq!(parsed["csrs"][1], "222222");
            assert_eq!(parsed["mac"], "33".repeat(64));
            assert_eq!(parsed["mac_covers"], total - 64);
        }
        assert!(parse_idevid_csr_blob(&[1, 2, 3, 4]).is_err());
    }
}
