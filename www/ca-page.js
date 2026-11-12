// Licensed under the Apache-2.0 license
//
// The CA page: shows the two test roots, issues certificates from requests,
// public keys or TBS certificates, lists what was issued (here and by the
// emulator page), and verifies chains. The CA itself is in ca-core.js.

import {
  loadCa, cas, caById, toHex, fromHex, toPem, decodeBlobs, decodeOne, sha256Hex,
  csrInfo, certInfo, tbsInfo, issue, signTbs, crl, verifyChain, orderChain, formatChain,
  store, caInbox, emulatorInbox, showDownloads, describe, fromBase64,
  DEFAULT_NOT_BEFORE, DEFAULT_NOT_AFTER,
} from "./ca-core.js";

const $ = (id) => document.getElementById(id);
const caStatus = $("ca-status");
const issueStatus = $("issue-status");
const issueParsed = $("issue-parsed");
const issueOutput = $("issue-output");
const issueDownloads = $("issue-downloads");
const issueCa = $("issue-ca");
const issueCaHint = $("issue-ca-hint");
const issueProfile = $("issue-profile");
const issuePathLen = $("issue-pathlen");
const issueSerial = $("issue-serial");
const issueNotBefore = $("issue-not-before");
const issueNotAfter = $("issue-not-after");
const btnIssue = $("btn-issue");
const btnSendEmulator = $("btn-send-emulator");
const inputs = { csr: $("csr-input"), key: $("key-input"), tbs: $("tbs-input") };

function setStatus(el, text, kind) {
  el.textContent = text;
  el.className = "status" + (kind ? ` status-${kind}` : "");
}

function mode() {
  return document.querySelector('input[name="issue-mode"]:checked').value;
}

// --- The roots ---

async function renderRoots() {
  const container = $("roots");
  container.replaceChildren();
  for (const ca of cas()) {
    const block = document.createElement("div");
    block.className = "key-block";
    const title = document.createElement("span");
    title.className = "label";
    title.textContent = `${ca.subject.replace(/^CN=/, "")} (signs with ${ca.algorithm})`;
    const rows = document.createElement("dl");
    rows.className = "facts";
    const fact = (name, value) => {
      const dt = document.createElement("dt");
      dt.textContent = name;
      const dd = document.createElement("dd");
      dd.textContent = value;
      rows.append(dt, dd);
    };
    fact("Subject", ca.subject);
    fact(ca.seed_label, `${ca.seed}\n(the ASCII text "${ca.seed_text}")`);
    fact("Public key", `${toHex(ca.publicKey.subarray(0, 24))}… (${ca.publicKey.length} bytes)`);
    fact("Key identifier", ca.key_id);
    fact("Certificate SHA-256", sha256Hex(ca.cert));
    const downloads = document.createElement("div");
    downloads.className = "downloads";
    showDownloads(downloads, [
      { name: `caliptra-test-ca-${ca.id}.pem`, bytes: new TextEncoder().encode(toPem("CERTIFICATE", ca.cert)) },
      { name: `caliptra-test-ca-${ca.id}.der`, bytes: ca.cert },
      { name: `caliptra-test-ca-${ca.id}-public-key.bin`, bytes: ca.publicKey },
    ]);
    const details = document.createElement("details");
    details.className = "sub";
    const summary = document.createElement("summary");
    summary.textContent = "Certificate";
    const pem = document.createElement("div");
    pem.className = "console response";
    pem.textContent = describe(certInfo(ca.cert)) + "\n" + toPem("CERTIFICATE", ca.cert);
    details.append(summary, pem);
    block.append(title, rows, downloads, details);
    container.appendChild(block);
  }
}

// --- Issuing ---

let caChosenByHand = false;
let profileChosenByHand = false;
let lastIssued = null; // {cert, label}

function refreshSerialPlaceholder() {
  issueSerial.placeholder = `Next: ${store.nextSerial(issueCa.value)}`;
}

function updateCaHint(keyAlgorithm) {
  const ca = caById(issueCa.value);
  let hint = `Signs with ${ca.algorithm}.`;
  if (keyAlgorithm === "ecc384" && ca.id === "mldsa87") {
    hint += " An ML-DSA signature makes the certificate about 5 KB, more than Caliptra's ECC commands take (POPULATE_IDEV_ECC384_CERT: 1024 bytes).";
  }
  issueCaHint.textContent = hint;
}

// Parse whatever is in the current mode's input and describe it. Returns
// what the Issue button needs, or null if the input is not usable yet.
function readInput() {
  const text = inputs[mode()].value;
  if (!text.trim()) return null;
  if (mode() === "csr") {
    const csr = decodeOne(text, "certificate request");
    const info = csrInfo(csr);
    return { csr, info, keyAlgorithm: info.key_algorithm };
  }
  if (mode() === "key") {
    const publicKey = decodeOne(text, "public key");
    return { publicKey, keyAlgorithm: $("key-alg").value };
  }
  const tbs = decodeOne(text, "TBS certificate");
  return { tbs, info: tbsInfo(tbs) };
}

function refreshInput() {
  btnIssue.textContent = mode() === "tbs" ? "Sign TBS" : "Issue certificate";
  for (const el of document.querySelectorAll("[data-not-tbs]")) el.hidden = mode() === "tbs";
  for (const m of Object.keys(inputs)) $(`mode-${m}`).hidden = m !== mode();
  let input = null;
  try {
    input = readInput();
  } catch (e) {
    issueParsed.textContent = `Cannot read the input: ${e.message}\n`;
    btnIssue.disabled = true;
    return;
  }
  btnIssue.disabled = !input;
  // Only a request can ask for extensions.
  const requested = issueProfile.querySelector('option[value="requested"]');
  requested.disabled = mode() !== "csr";
  if (requested.disabled && issueProfile.value === "requested") issueProfile.value = "ca";
  if (!input) {
    issueParsed.textContent = "";
    updateCaHint(null);
    return;
  }
  let text = "";
  if (input.csr) {
    const info = input.info;
    text = describe(info);
    if (info.signature_valid === true) {
      text += `\n✓ The request's ${info.signature_algorithm} signature verifies: the requester holds the private key.\n`;
    } else if (info.signature_valid === false) {
      text += "\n✗ The request's signature does NOT verify. The CA will not certify it.\n";
      btnIssue.disabled = true;
    } else {
      text += `\n✗ Cannot check the request's signature: ${info.signature_error}\n`;
      btnIssue.disabled = true;
    }
    requested.disabled = info.extensions.length === 0;
    if (requested.disabled && issueProfile.value === "requested") issueProfile.value = "ca";
    if (!requested.disabled && !profileChosenByHand) issueProfile.value = "requested";
  } else if (input.tbs) {
    const info = input.info;
    text = describe(info) + `\nTBS size: ${input.tbs.length} bytes, to be signed with ${info.tbs_signature_algorithm}\n`;
    // The TBS says which CA it is for.
    const wanted = cas().find((ca) => ca.subject === info.issuer);
    if (wanted) issueCa.value = wanted.id;
  } else {
    text = `${input.publicKey.length}-byte public key\n`;
  }
  if (input.keyAlgorithm && !caChosenByHand) issueCa.value = input.keyAlgorithm;
  issueParsed.textContent = text;
  updateCaHint(input.keyAlgorithm || input.info?.key_algorithm);
  refreshSerialPlaceholder();
}

function showIssued(result, label) {
  const ca = caById(issueCa.value);
  let text = `Issued by ${ca.subject}\n\n` + describe(result.info);
  text += `\nCertificate: ${result.cert.length} bytes (TBS ${result.tbs.length} bytes)\n\n`;
  if (ca.id === "ecc384") {
    text += `Signature R: ${toHex(result.signature.subarray(0, 48))}\nSignature S: ${toHex(result.signature.subarray(48))}\n\n`;
  } else {
    text += `Signature (${result.signature.length} bytes): ${toHex(result.signature.subarray(0, 32))}…\n\n`;
  }
  text += toPem("CERTIFICATE", result.cert);
  issueOutput.textContent = text;
  const base = `${label}-${result.info.serial}`;
  showDownloads(issueDownloads, [
    { name: `${base}.pem`, bytes: new TextEncoder().encode(toPem("CERTIFICATE", result.cert)) },
    { name: `${base}.der`, bytes: result.cert },
    { name: `${base}.tbs.der`, bytes: result.tbs },
    { name: `${base}.signature.bin`, bytes: result.signature },
  ]);
  lastIssued = { cert: result.cert, label: result.info.subject };
  btnSendEmulator.disabled = false;
}

btnIssue.addEventListener("click", () => {
  try {
    const input = readInput();
    if (!input) return;
    let result;
    if (input.tbs) {
      result = signTbs(issueCa.value, input.tbs, "CA page (TBS)");
    } else {
      const pathLen = issuePathLen.value.trim();
      if (pathLen && !/^\d+$/.test(pathLen)) throw new Error("the path length must be a number");
      result = issue({
        ca: issueCa.value,
        csr: input.csr,
        publicKey: input.publicKey,
        keyAlgorithm: input.publicKey ? input.keyAlgorithm : undefined,
        subjectCn: input.publicKey ? $("key-subject").value.trim() || "Test Device" : undefined,
        profile: issueProfile.value,
        pathLen: pathLen ? Number(pathLen) : null,
        serial: issueSerial.value.trim() || undefined,
        notBefore: issueNotBefore.value,
        notAfter: issueNotAfter.value,
      }, input.csr ? "CA page (CSR)" : "CA page (public key)");
    }
    showIssued(result, `caliptra-test-ca-${issueCa.value}`);
    issueSerial.value = "";
    setStatus(issueStatus, `Issued serial ${result.info.serial}`, "ok");
  } catch (e) {
    issueOutput.textContent = `The CA refused: ${e.message}\n`;
    showDownloads(issueDownloads, []);
    setStatus(issueStatus, "Not issued", "err");
  }
  refreshSerialPlaceholder();
});

btnSendEmulator.addEventListener("click", () => {
  if (!lastIssued) return;
  const ok = emulatorInbox.put({ label: lastIssued.label, bytes: lastIssued.cert });
  setStatus(issueStatus, ok ? "Sent to the emulator tab" : "Could not send (browser storage is unavailable)", ok ? "ok" : "err");
});

for (const radio of document.querySelectorAll('input[name="issue-mode"]')) {
  radio.addEventListener("change", refreshInput);
}
for (const el of [...Object.values(inputs), $("key-alg")]) el.addEventListener("input", refreshInput);
issueCa.addEventListener("change", () => {
  caChosenByHand = true;
  refreshInput();
});
issueProfile.addEventListener("change", () => {
  profileChosenByHand = true;
});

function readFileInto(fileInput, textarea, pemLabel, after) {
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files[0];
    if (!file) return;
    const bytes = new Uint8Array(await file.arrayBuffer());
    // Text (PEM, hex) stays as it is; binary DER is shown as PEM.
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    textarea.value = bytes[0] === 0x30 ? toPem(pemLabel, bytes) : text;
    after();
  });
}
readFileInto($("csr-file"), inputs.csr, "CERTIFICATE REQUEST", refreshInput);

// A request sent from the emulator page.
function takeInbox(item) {
  if (!item || item.kind !== "csr") return;
  document.querySelector('input[name="issue-mode"][value="csr"]').checked = true;
  inputs.csr.value = toPem("CERTIFICATE REQUEST", item.bytes);
  caChosenByHand = false;
  refreshInput();
  setStatus(issueStatus, `Request received: ${item.label}`, "ok");
  caInbox.clear();
}

// --- The log ---

const logDetail = $("log-detail");
const logDownloads = $("log-downloads");

function renderLog() {
  const body = $("issued-table").querySelector("tbody");
  const issued = store.issued().slice().reverse();
  $("issued-empty").hidden = issued.length > 0;
  $("issued-table").hidden = issued.length === 0;
  body.replaceChildren(...issued.map((entry) => {
    const tr = document.createElement("tr");
    const cell = (text, cls) => {
      const td = document.createElement("td");
      td.textContent = text;
      if (cls) td.className = cls;
      tr.appendChild(td);
      return td;
    };
    cell(entry.serial, "mono");
    cell(entry.ca === "mldsa87" ? "ML-DSA-87" : "ECC P-384");
    cell(entry.subject, "wrap");
    cell(entry.source);
    cell(entry.issuedAt.slice(0, 19).replace("T", " "));
    const status = cell("");
    const badge = document.createElement("span");
    badge.className = `status ${entry.revokedAt ? "status-err" : "status-ok"}`;
    badge.textContent = entry.revokedAt ? "Revoked" : "Valid";
    status.appendChild(badge);
    const actions = cell("");
    const group = document.createElement("div");
    group.className = "toolbar";
    const view = document.createElement("button");
    view.className = "small";
    view.textContent = "View";
    view.addEventListener("click", () => {
      const cert = fromBase64(entry.cert);
      logDetail.hidden = false;
      logDetail.textContent = describe(certInfo(cert)) + "\n" + toPem("CERTIFICATE", cert);
      showDownloads(logDownloads, [
        { name: `caliptra-test-ca-${entry.ca}-${entry.serial}.pem`, bytes: new TextEncoder().encode(toPem("CERTIFICATE", cert)) },
        { name: `caliptra-test-ca-${entry.ca}-${entry.serial}.der`, bytes: cert },
      ]);
    });
    const revoke = document.createElement("button");
    revoke.className = "small";
    revoke.textContent = entry.revokedAt ? "Reinstate" : "Revoke";
    revoke.addEventListener("click", () => store.setRevoked(entry.ca, entry.serial, !entry.revokedAt));
    group.append(view, revoke);
    actions.appendChild(group);
    return tr;
  }));
  refreshSerialPlaceholder();
}

for (const ca of ["mldsa87", "ecc384"]) {
  $(`btn-crl-${ca}`).addEventListener("click", () => {
    const der = crl(ca);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([der], { type: "application/pkix-crl" }));
    a.download = `caliptra-test-ca-${ca}.crl`;
    a.click();
  });
}

$("btn-reset-ca").addEventListener("click", () => {
  if (!confirm("Forget every issued certificate and restart the serial numbers?")) return;
  store.reset();
  logDetail.hidden = true;
  showDownloads(logDownloads, []);
});

// --- Verifying ---

const verifyInput = $("verify-input");
const verifyOutput = $("verify-output");
const verifyStatus = $("verify-status");
const btnVerify = $("btn-verify");

readFileInto($("verify-file"), verifyInput, "CERTIFICATE", () => btnVerify.click());

btnVerify.addEventListener("click", () => {
  try {
    const certs = decodeBlobs(verifyInput.value).map((b) => b.bytes);
    if (certs.length === 0) throw new Error("paste one or more certificates");
    const result = verifyChain(orderChain(certs));
    verifyOutput.textContent = formatChain(result);
    setStatus(verifyStatus, result.ok ? "Chain verifies" : "Chain does not verify", result.ok ? "ok" : "err");
  } catch (e) {
    verifyOutput.textContent = `Cannot verify: ${e.message}\n`;
    setStatus(verifyStatus, "Not verified", "err");
  }
});

// --- Start ---

try {
  await loadCa();
  for (const ca of cas()) {
    const o = document.createElement("option");
    o.value = ca.id;
    o.textContent = ca.subject.replace(/^CN=/, "");
    issueCa.appendChild(o);
  }
  issueNotBefore.value = DEFAULT_NOT_BEFORE;
  issueNotAfter.value = DEFAULT_NOT_AFTER;
  await renderRoots();
  renderLog();
  store.onChange(renderLog);
  refreshInput();
  btnVerify.disabled = false;
  takeInbox(caInbox.peek());
  caInbox.watch(takeInbox);
  caStatus.textContent = "Runs entirely in this page: nothing is sent anywhere.";
} catch (e) {
  caStatus.textContent = `Failed to load the CA: ${e.message || e}`;
  console.error(e);
}

// For tests and the console.
window.caliptraTestCa = { cas, issue, signTbs, verifyChain, csrInfo, certInfo, store, fromHex, toHex };
