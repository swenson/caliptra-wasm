// Licensed under the Apache-2.0 license

//! End-to-end provisioning flows against the test CA (the `ca/` crate): the
//! ROM's IDevID CSR is taken at boot, checked and certified by the CA, the
//! certificate is handed back through the mailbox, and the device's
//! certificate chain is verified down to the runtime alias.

use caliptra_test_ca::{api, der};
use serde_json::{json, Value};

use crate::CaliptraEmulator;

// Mailbox command IDs. The ECC ones are the same on every release (2.x
// renamed them, e.g. GET_IDEV_CERT became GET_IDEV_ECC384_CERT).
const GET_IDEV_ECC384_CERT: u32 = 0x4944_4543;
const GET_IDEV_ECC384_INFO: u32 = 0x4944_4549;
const POPULATE_IDEV_ECC384_CERT: u32 = 0x4944_4550;
const GET_LDEV_ECC384_CERT: u32 = 0x4C44_4556;
const GET_FMC_ALIAS_ECC384_CERT: u32 = 0x4345_5246;
const GET_RT_ALIAS_ECC384_CERT: u32 = 0x4345_5252;
const GET_IDEV_ECC384_CSR: u32 = 0x4944_4352;

/// The commands of one identity's provisioning flow.
pub(crate) struct Flow {
    /// The CA that certifies it, and the algorithm of the identity's key.
    pub alg: &'static str,
    /// Index of this identity's CSR in what the ROM sends at boot.
    pub csr_index: usize,
    pub get_csr: Option<u32>,
    pub get_info: u32,
    pub get_cert: u32,
    /// Size of the signature field of the `get_cert` request.
    pub cert_req_signature_len: usize,
    /// Largest TBS the `get_cert` request takes.
    pub cert_req_max_tbs: usize,
    pub populate: u32,
    pub ldev: u32,
    pub fmc_alias: u32,
    pub rt_alias: u32,
}

pub(crate) const ECC384: Flow = Flow {
    alg: "ecc384",
    csr_index: 0,
    get_csr: Some(GET_IDEV_ECC384_CSR),
    get_info: GET_IDEV_ECC384_INFO,
    get_cert: GET_IDEV_ECC384_CERT,
    cert_req_signature_len: 96,
    cert_req_max_tbs: 916,
    populate: POPULATE_IDEV_ECC384_CERT,
    ldev: GET_LDEV_ECC384_CERT,
    fmc_alias: GET_FMC_ALIAS_ECC384_CERT,
    rt_alias: GET_RT_ALIAS_ECC384_CERT,
};

#[cfg(not(feature = "caliptra-1x"))]
pub(crate) const MLDSA87: Flow = Flow {
    alg: "mldsa87",
    csr_index: 1,
    get_csr: Some(0x4944_4D52),
    get_info: 0x4944_4D49,
    get_cert: 0x4944_4D43,
    cert_req_signature_len: 4628,
    cert_req_max_tbs: 2820,
    populate: 0x4944_4D50,
    ldev: 0x4C44_4D43,
    fmc_alias: 0x434D_4346,
    rt_alias: 0x434D_4352,
};

const NOT_BEFORE: &str = "2023-01-01 00:00:00";
const NOT_AFTER: &str = "9999-12-31 23:59:59";

fn parse(json: Result<String, String>) -> Value {
    serde_json::from_str(&json.expect("CA call failed")).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    der::unhex(v.as_str().expect("hex string")).unwrap()
}

/// Sends a mailbox command through the non-blocking API the page uses
/// (start, step until not busy, finish) and returns the response.
pub(crate) fn mailbox(
    emu: &mut CaliptraEmulator,
    cmd: u32,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut req = caliptra_api::calc_checksum(cmd, payload)
        .to_le_bytes()
        .to_vec();
    req.extend_from_slice(payload);
    emu.mailbox_start(cmd, &req)
        .map_err(|_| format!("command 0x{cmd:08x} did not start"))?;
    let start = emu.total_steps();
    while emu.mailbox_busy() {
        if emu.total_steps() - start > 400_000_000 {
            return Err(format!("command 0x{cmd:08x} timed out"));
        }
        emu.step(100_000);
    }
    emu.mailbox_finish()
        .map(|resp| resp.unwrap_or_default())
        .map_err(|_| format!("command 0x{cmd:08x} failed: {}", emu.get_error_registers()))
}

/// The variable-size data of a response: header (8 bytes), size, data.
pub(crate) fn sized(resp: &[u8]) -> Vec<u8> {
    let size = u32::from_le_bytes(resp[8..12].try_into().unwrap()) as usize;
    resp[12..12 + size].to_vec()
}

/// A request carrying a size and that many bytes (POPULATE_*_CERT).
pub(crate) fn sized_request(data: &[u8]) -> Vec<u8> {
    let mut req = (data.len() as u32).to_le_bytes().to_vec();
    req.extend_from_slice(data);
    req
}

/// Runs one identity's flow on an emulator that was created with
/// `gen_idevid_csr` and has reached the runtime. `runtime_has_csr_command`
/// is whether the runtime can return the CSR too (GET_IDEV_*_CSR).
pub(crate) fn run_idevid_flow(
    emu: &mut CaliptraEmulator,
    flow: &Flow,
    runtime_has_csr_command: bool,
) {
    // 1. The CSR the ROM handed over at boot, with proof of possession.
    let envelope = emu
        .idevid_csr_envelope()
        .expect("the ROM sent no IDevID CSR");
    let blob = parse(api::idevid_csr_blob(&envelope));
    let csr = unhex(&blob["csrs"][flow.csr_index]);
    let info = parse(api::csr_info(&csr));
    assert_eq!(info["key_algorithm"], flow.alg, "{info}");
    assert_eq!(info["signature_valid"], true, "{info}");
    eprintln!(
        "{} IDevID CSR: {} bytes ({}), subject \"{}\", extensions {:?}",
        flow.alg,
        csr.len(),
        blob["format"],
        info["subject"].as_str().unwrap(),
        info["extensions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| format!(
                "{}: {}",
                e["name"].as_str().unwrap(),
                e["summary"].as_str().unwrap()
            ))
            .collect::<Vec<_>>()
    );

    // The runtime returns the same CSR.
    if let (Some(cmd), true) = (flow.get_csr, runtime_has_csr_command) {
        assert_eq!(sized(&mailbox(emu, cmd, &[]).unwrap()), csr);
    }

    // 2. The LDevID certificate names the IDevID as its issuer: take the
    // key identifier it expects from there.
    let ldev = sized(&mailbox(emu, flow.ldev, &[]).unwrap());
    let ldev_info = parse(api::cert_info(&ldev));
    assert_eq!(ldev_info["issuer"], info["subject"]);
    let idev_key_id = ldev_info["authority_key_id"].clone();

    // 3. The CA certifies the request.
    let issued = parse(api::issue(
        &json!({
            "ca": flow.alg, "serial": "01", "csr": der::hex(&csr),
            "not_before": NOT_BEFORE, "not_after": NOT_AFTER,
            "subject_key_id": idev_key_id,
        })
        .to_string(),
    ));
    let idev = unhex(&issued["cert"]);
    assert_eq!(issued["info"]["subject"], info["subject"]);
    assert_eq!(issued["info"]["is_ca"], true);
    eprintln!(
        "{} IDevID certificate: {} bytes (TBS {} bytes)",
        flow.alg,
        idev.len(),
        issued["info"]["tbs_size"]
    );

    // 4. Hand it to Caliptra.
    let resp = mailbox(emu, flow.populate, &sized_request(&idev)).unwrap();
    assert_eq!(resp.len(), 8, "POPULATE_IDEV_CERT returns a header only");

    // 5. The whole chain: test CA, IDevID, LDevID, FMC alias, runtime alias.
    let fmc = sized(&mailbox(emu, flow.fmc_alias, &[]).unwrap());
    let rt = sized(&mailbox(emu, flow.rt_alias, &[]).unwrap());
    let chain: Vec<String> = [&idev, &ldev, &fmc, &rt]
        .iter()
        .map(|c| der::hex(c))
        .collect();
    let result = parse(api::verify_chain(&json!(chain).to_string()));
    assert_eq!(result["ok"], true, "{result:#}");
    assert_eq!(result["links"].as_array().unwrap().len(), 4);

    // 6. The other way to a certificate: the CA builds and signs a TBS for
    // the public key Caliptra reports, and Caliptra assembles the
    // certificate from the TBS and the signature.
    let key_info = mailbox(emu, flow.get_info, &[]).unwrap();
    let public_key = &key_info[8..];
    assert_eq!(
        der::hex(public_key).trim_start_matches("04"),
        info["public_key"]
            .as_str()
            .unwrap()
            .trim_start_matches("04")
    );
    let issued = parse(api::issue(
        &json!({
            "ca": flow.alg, "serial": "02",
            "public_key": der::hex(public_key), "key_algorithm": flow.alg,
            "subject": ldev_info["issuer_der"],
            "profile": "ca", "path_len": 5,
            "not_before": NOT_BEFORE, "not_after": NOT_AFTER,
            "subject_key_id": idev_key_id,
        })
        .to_string(),
    ));
    let tbs = unhex(&issued["tbs"]);
    let signature = unhex(&issued["signature"]);
    eprintln!(
        "{} IDevID TBS from the public key: {} bytes (GET_IDEV_CERT takes up to {})",
        flow.alg,
        tbs.len(),
        flow.cert_req_max_tbs
    );
    if tbs.len() <= flow.cert_req_max_tbs {
        let mut req = (tbs.len() as u32).to_le_bytes().to_vec();
        req.extend_from_slice(&signature);
        req.resize(4 + flow.cert_req_signature_len, 0);
        req.extend_from_slice(&tbs);
        let assembled = sized(&mailbox(emu, flow.get_cert, &req).unwrap());
        assert_eq!(der::hex(&assembled), issued["cert"].as_str().unwrap());
    }
    let chain: Vec<String> = [&unhex(&issued["cert"]), &ldev, &fmc, &rt]
        .iter()
        .map(|c| der::hex(c))
        .collect();
    let result = parse(api::verify_chain(&json!(chain).to_string()));
    assert_eq!(result["ok"], true, "{result:#}");
}
