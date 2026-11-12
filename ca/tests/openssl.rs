// Licensed under the Apache-2.0 license

//! Interoperability with OpenSSL: requests OpenSSL writes are accepted, and
//! what the CA issues verifies under OpenSSL. Skipped when the `openssl`
//! command is missing or too old for ML-DSA (before 3.5).

use std::path::Path;
use std::process::Command;

use caliptra_test_ca::{api, der};

fn openssl(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out.status.success().then_some(text)
}

fn must(dir: &Path, args: &[&str]) -> String {
    openssl(dir, args).unwrap_or_else(|| panic!("openssl {args:?} failed"))
}

fn field(json: &str, name: &str) -> Vec<u8> {
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    der::unhex(v[name].as_str().unwrap()).unwrap()
}

#[test]
fn openssl_accepts_what_the_ca_issues() {
    let dir = std::env::temp_dir().join(format!("caliptra-test-ca-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    if openssl(
        &dir,
        &["genpkey", "-algorithm", "ML-DSA-87", "-out", "mldsa87.key"],
    )
    .is_none()
    {
        eprintln!("skipping: openssl with ML-DSA support not found");
        return;
    }
    must(
        &dir,
        &[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-384",
            "-out",
            "ecc384.key",
        ],
    );

    let cas: serde_json::Value = serde_json::from_str(&api::ca_list()).unwrap();
    for ca in cas.as_array().unwrap() {
        let id = ca["id"].as_str().unwrap();
        std::fs::write(
            dir.join(format!("{id}-ca.der")),
            der::unhex(ca["cert"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        must(
            &dir,
            &[
                "x509",
                "-inform",
                "DER",
                "-in",
                &format!("{id}-ca.der"),
                "-out",
                &format!("{id}-ca.pem"),
            ],
        );
        // The root verifies as its own trust anchor.
        must(
            &dir,
            &[
                "verify",
                "-CAfile",
                &format!("{id}-ca.pem"),
                &format!("{id}-ca.pem"),
            ],
        );

        for key in ["ecc384", "mldsa87"] {
            // A request from OpenSSL, asking for CA extensions.
            must(
                &dir,
                &[
                    "req",
                    "-new",
                    "-key",
                    &format!("{key}.key"),
                    "-subj",
                    "/CN=OpenSSL Device/serialNumber=1234",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE,pathlen:3",
                    "-addext",
                    "keyUsage=critical,keyCertSign",
                    "-outform",
                    "DER",
                    "-out",
                    "req.der",
                ],
            );
            let csr = std::fs::read(dir.join("req.der")).unwrap();
            let info: serde_json::Value =
                serde_json::from_str(&api::csr_info(&csr).unwrap()).unwrap();
            assert_eq!(info["signature_valid"], true, "{info}");
            assert_eq!(info["key_algorithm"], key);
            assert_eq!(info["subject"], "CN=OpenSSL Device, serialNumber=1234");

            let request = serde_json::json!({
                "ca": id, "serial": "0a0b", "csr": der::hex(&csr),
                "not_before": "2023-01-01 00:00:00", "not_after": "9999-12-31 23:59:59",
            });
            let issued = api::issue(&request.to_string()).unwrap();
            std::fs::write(dir.join("cert.der"), field(&issued, "cert")).unwrap();
            must(
                &dir,
                &[
                    "x509", "-inform", "DER", "-in", "cert.der", "-out", "cert.pem",
                ],
            );
            let text = must(&dir, &["x509", "-in", "cert.pem", "-noout", "-text"]);
            assert!(text.contains("CA:TRUE, pathlen:3"), "{text}");
            assert!(text.contains("Certificate Sign"), "{text}");
            must(
                &dir,
                &[
                    "verify",
                    "-x509_strict",
                    "-CAfile",
                    &format!("{id}-ca.pem"),
                    "cert.pem",
                ],
            );

            // A corrupted request is refused.
            let mut bad = csr.clone();
            let n = bad.len();
            bad[n - 1] ^= 1;
            let request = serde_json::json!({
                "ca": id, "serial": "0a0b", "csr": der::hex(&bad),
                "not_before": "2023-01-01 00:00:00", "not_after": "9999-12-31 23:59:59",
            });
            assert!(api::issue(&request.to_string()).is_err());
        }

        // A CRL revoking that serial number.
        let request = serde_json::json!({
            "ca": id, "this_update": "2026-01-01 00:00:00", "next_update": "2027-01-01 00:00:00",
            "crl_number": 3, "revoked": [{"serial": "0a0b", "date": "2026-01-01 00:00:00"}],
        });
        std::fs::write(dir.join("ca.crl"), api::crl(&request.to_string()).unwrap()).unwrap();
        let text = must(
            &dir,
            &[
                "crl",
                "-inform",
                "DER",
                "-in",
                "ca.crl",
                "-CAfile",
                &format!("{id}-ca.pem"),
                "-noout",
                "-text",
            ],
        );
        assert!(text.contains("Serial Number: 0A0B"), "{text}");
        assert!(text.contains("verify OK"), "{text}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
