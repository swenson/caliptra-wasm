// Licensed under the Apache-2.0 license
//
// The test CA, shared by the CA page (ca.html) and the emulator page's
// Provisioning section. The PK hash calculator and the Debug unlock page load
// it too, for the hashes and P-384 operations at the end of this section.
// The CA itself is a WebAssembly module (the ca/ crate,
// built into ca/): an ML-DSA-87 root and an ECC P-384 root with fixed, public
// keys. This module loads it, converts between bytes and the JSON it speaks,
// and keeps the CA's state, which is the serial counters and the list of
// issued certificates, in localStorage so that both pages (and both tabs)
// see the same CA.

let wasm = null;
let caList = null;

/// Loads the CA module. Call once before anything else here.
export async function loadCa() {
  if (!wasm) {
    const mod = await import("./ca/caliptra_test_ca.js");
    await mod.default();
    wasm = mod;
    caList = JSON.parse(wasm.ca_list()).map((ca) => ({
      ...ca,
      cert: fromHex(ca.cert),
      publicKey: fromHex(ca.public_key),
    }));
  }
  return caList;
}

/// The test CAs: [{id, algorithm, subject, seed, seed_text, seed_label,
/// key_id, cert, publicKey, signature_size}].
export function cas() {
  return caList;
}

export function caById(id) {
  return caList.find((ca) => ca.id === id);
}

// --- Bytes and text ---

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(text) {
  const cleaned = text.replace(/^0x/i, "").replace(/[\s:,]/g, "");
  if (cleaned.length % 2 !== 0 || /[^0-9a-f]/i.test(cleaned)) {
    throw new Error("not valid hex");
  }
  const out = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function toBase64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export function fromBase64(text) {
  const s = atob(text.replace(/\s/g, ""));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function toPem(label, der) {
  return `-----BEGIN ${label}-----\n${toBase64(der).match(/.{1,64}/g).join("\n")}\n-----END ${label}-----\n`;
}

/// Decodes pasted text into DER blobs: any number of PEM blocks, or one
/// blob as hex or base64. Returns [{label, bytes}] (label is null without
/// PEM armor).
export function decodeBlobs(text) {
  const trimmed = text.trim();
  if (!trimmed) return [];
  const blocks = [...trimmed.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g)];
  if (blocks.length) {
    return blocks.map((m) => ({ label: m[1], bytes: fromBase64(m[2]) }));
  }
  if (trimmed.includes("-----BEGIN")) throw new Error("unterminated PEM block");
  try {
    return [{ label: null, bytes: fromHex(trimmed) }];
  } catch (e) {
    try {
      return [{ label: null, bytes: fromBase64(trimmed) }];
    } catch (e2) {
      throw new Error("expected PEM, hex or base64");
    }
  }
}

/// Decodes pasted text that must hold exactly one blob.
export function decodeOne(text, what) {
  const blobs = decodeBlobs(text);
  if (blobs.length !== 1) throw new Error(`expected one ${what}, found ${blobs.length}`);
  return blobs[0].bytes;
}


// --- The CA ---

export const DEFAULT_NOT_BEFORE = "2023-01-01 00:00:00";
// RFC 5280's "no well-defined expiration date", which IEEE 802.1AR asks for
// in IDevID certificates and Caliptra uses in the ones it issues itself.
export const DEFAULT_NOT_AFTER = "9999-12-31 23:59:59";

function call(fn, ...args) {
  try {
    return fn(...args);
  } catch (e) {
    throw new Error(e && e.message ? e.message : String(e));
  }
}

export function csrInfo(csr) {
  return JSON.parse(call(wasm.csr_info, csr));
}

export function certInfo(cert) {
  return JSON.parse(call(wasm.cert_info, cert));
}

export function tbsInfo(tbs) {
  return JSON.parse(call(wasm.tbs_info, tbs));
}

function issuedFromJson(json) {
  const r = JSON.parse(json);
  return { cert: fromHex(r.cert), tbs: fromHex(r.tbs), signature: fromHex(r.signature), info: r.info };
}

/// Verifies a chain of DER certificates given root first: each must be
/// signed by the one before it, the first by a test CA (or by itself).
/// Returns {ok, links: [{subject, issuer, verified_with, signature_ok,
/// problems, ...}]}.
export function verifyChain(certs) {
  return JSON.parse(call(wasm.verify_chain, JSON.stringify(certs.map(toHex))));
}

// The hashes and P-384 operations below run in the CA module rather than the
// browser's WebCrypto, which is missing unless the page is on localhost or
// HTTPS.

/// SHA-256 of some bytes, as hex (a certificate fingerprint).
export function sha256Hex(bytes) {
  return toHex(call(wasm.sha256, bytes));
}

/// Whether `tag` is the HMAC-SHA-512 of `data` under `key`.
export function hmacSha512Matches(key, data, tag) {
  return toHex(call(wasm.hmac_sha512, key, data)) === toHex(tag);
}

export function sha384(bytes) {
  return call(wasm.sha384, bytes);
}

export function sha512(bytes) {
  return call(wasm.sha512, bytes);
}

/// The public key (96 bytes, X || Y) of a 48-byte P-384 private key. Throws
/// if the bytes are not a valid private key.
export function p384PublicKey(privateKey) {
  return call(wasm.p384_public_key, privateKey);
}

/// A new P-384 key pair: {privateKey (48 bytes), publicKey (96 bytes, X || Y)}.
export function p384GenerateKey() {
  // Not every 48-byte string is a private key (it has to be nonzero and below
  // the curve order), so draw again in the rare case that it is not.
  for (let attempt = 0; ; attempt++) {
    const privateKey = crypto.getRandomValues(new Uint8Array(48));
    try {
      return { privateKey, publicKey: p384PublicKey(privateKey) };
    } catch (e) {
      if (attempt >= 8) throw e;
    }
  }
}

/// An ECDSA P-384 signature over the SHA-384 of `message`: 96 bytes, R || S.
export function p384Sign(privateKey, message) {
  return call(wasm.p384_sign, privateKey, message);
}

/// Copies text to the clipboard and returns whether that worked. Like
/// WebCrypto, navigator.clipboard is missing unless the page is on localhost
/// or HTTPS, so without it this copies through a temporary text field.
export async function copyText(text) {
  if (navigator.clipboard) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {}
  }
  const field = document.createElement("textarea");
  field.value = text;
  field.readOnly = true;
  field.style.position = "fixed";
  field.style.opacity = "0";
  document.body.append(field);
  field.focus();
  field.select();
  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch {}
  field.remove();
  return copied;
}

/// Splits what the ROM sends when the IDevID CSR is requested at boot into
/// its CSRs: {format, csrs: [bytes]}, and for a 2.x envelope also mac
/// (bytes), mac_algorithm and mac_covers (how many leading bytes of the blob
/// the tag covers).
export function idevidCsrBlob(blob) {
  const r = JSON.parse(call(wasm.idevid_csr_blob, blob));
  return { ...r, csrs: r.csrs.map(fromHex), mac: r.mac ? fromHex(r.mac) : null };
}

// --- CA state (localStorage) ---

const STORE_KEY = "caliptra-wasm.ca.v1";
const MAX_LOG = 100;
const listeners = new Set();

function emptyState() {
  // The roots hold serial number 1.
  return { lastSerial: { mldsa87: 1, ecc384: 1 }, crlNumber: { mldsa87: 0, ecc384: 0 }, issued: [] };
}

let memoryState = null; // used when localStorage is unavailable

function readState() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (raw) return { ...emptyState(), ...JSON.parse(raw) };
  } catch (e) {
    return memoryState || emptyState();
  }
  return memoryState || emptyState();
}

function writeState(state) {
  memoryState = state;
  // If the log outgrows localStorage, drop the oldest certificates.
  for (;;) {
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(state));
      break;
    } catch (e) {
      if (state.issued.length === 0) break;
      state.issued.shift();
    }
  }
  for (const cb of listeners) cb();
}

if (typeof window !== "undefined") {
  window.addEventListener("storage", (e) => {
    if (e.key === STORE_KEY || e.key === null) for (const cb of listeners) cb();
  });
}

function serialToHex(n) {
  const hex = n.toString(16);
  return hex.length % 2 ? "0" + hex : hex;
}

// A serial number as the CA reports it: lowercase hex, whole bytes, no
// leading zero bytes.
function canonicalSerial(text) {
  const digits = text.trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(digits)) throw new Error("the serial number must be hex");
  const stripped = digits.replace(/^0+/, "") || "0";
  return stripped.length % 2 ? "0" + stripped : stripped;
}

export const store = {
  /// Calls `cb` whenever the CA's state changes, in this tab or another.
  onChange(cb) {
    listeners.add(cb);
  },

  /// The issued certificates, oldest first: [{ca, serial, subject, key,
  /// source, issuedAt, notBefore, notAfter, cert (base64), revokedAt}].
  issued() {
    return readState().issued;
  },

  /// The serial number (hex) the next certificate from `ca` gets.
  nextSerial(ca) {
    return serialToHex(readState().lastSerial[ca] + 1);
  },

  setRevoked(ca, serial, revoked) {
    const state = readState();
    for (const entry of state.issued) {
      if (entry.ca === ca && entry.serial === serial) {
        entry.revokedAt = revoked ? new Date().toISOString() : null;
      }
    }
    writeState(state);
  },

  /// Forgets every issued certificate and restarts the serial numbers.
  reset() {
    writeState(emptyState());
  },
};

function record(state, ca, result, source) {
  const info = result.info;
  const serialNumber = parseInt(info.serial, 16);
  if (Number.isSafeInteger(serialNumber) && serialNumber > state.lastSerial[ca]) {
    state.lastSerial[ca] = serialNumber;
  }
  state.issued.push({
    ca,
    serial: info.serial,
    subject: info.subject,
    key: info.key_description,
    source,
    issuedAt: new Date().toISOString(),
    notBefore: info.not_before,
    notAfter: info.not_after,
    cert: toBase64(result.cert),
    revokedAt: null,
  });
  if (state.issued.length > MAX_LOG) state.issued.splice(0, state.issued.length - MAX_LOG);
  writeState(state);
}

/// Issues a certificate and adds it to the log. `request` is the CA
/// module's issue request (see ca/src/lib.rs) with bytes where it takes hex:
/// {ca, csr | (publicKey, keyAlgorithm, subject | subjectCn), profile,
/// pathLen, extraExtensions, subjectKeyId, serial, notBefore, notAfter}.
/// The serial number defaults to the CA's next one. `source` says where the
/// request came from, for the log. Returns {cert, tbs, signature, info}.
export function issue(request, source) {
  const state = readState();
  const serial = canonicalSerial(request.serial || serialToHex(state.lastSerial[request.ca] + 1));
  if (state.issued.some((e) => e.ca === request.ca && canonicalSerial(e.serial) === serial)) {
    throw new Error(`serial number ${serial} was already issued by this CA`);
  }
  const hex = (b) => (b ? toHex(b) : undefined);
  const result = issuedFromJson(call(wasm.issue, JSON.stringify({
    ca: request.ca,
    serial,
    not_before: request.notBefore || DEFAULT_NOT_BEFORE,
    not_after: request.notAfter || DEFAULT_NOT_AFTER,
    csr: hex(request.csr),
    public_key: hex(request.publicKey),
    key_algorithm: request.keyAlgorithm,
    subject: hex(request.subject),
    subject_cn: request.subjectCn,
    profile: request.profile,
    path_len: request.pathLen ?? null,
    extra_extensions: (request.extraExtensions || []).map(toHex),
    subject_key_id: hex(request.subjectKeyId),
  })));
  record(state, request.ca, result, source);
  return result;
}

/// Signs a TBSCertificate built elsewhere and adds the certificate to the
/// log. Returns {cert, tbs, signature, info}.
export function signTbs(ca, tbs, source) {
  const result = issuedFromJson(call(wasm.sign_tbs, ca, tbs));
  record(readState(), ca, result, source);
  return result;
}

/// Builds a CRL listing `ca`'s revoked certificates, valid for 30 days.
export function crl(ca) {
  const state = readState();
  state.crlNumber[ca] += 1;
  const stamp = (d) => d.toISOString().slice(0, 19).replace("T", " ");
  const now = new Date();
  const der = call(wasm.crl, JSON.stringify({
    ca,
    this_update: stamp(now),
    next_update: stamp(new Date(now.getTime() + 30 * 86400 * 1000)),
    crl_number: state.crlNumber[ca],
    revoked: state.issued
      .filter((e) => e.ca === ca && e.revokedAt)
      .map((e) => ({ serial: e.serial, date: stamp(new Date(e.revokedAt)) })),
  }));
  writeState(state);
  return der;
}

// --- Handing things between the emulator tab and the CA tab ---

const INBOX_KEY = "caliptra-wasm.ca.inbox";
const OUTBOX_KEY = "caliptra-wasm.ca.outbox";

function put(key, item) {
  try {
    localStorage.setItem(key, JSON.stringify({ ...item, bytes: toBase64(item.bytes), time: Date.now() }));
    return true;
  } catch (e) {
    return false;
  }
}

function peek(key) {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const item = JSON.parse(raw);
    return { ...item, bytes: fromBase64(item.bytes) };
  } catch (e) {
    return null;
  }
}

function watch(key, cb) {
  window.addEventListener("storage", (e) => {
    if (e.key === key && e.newValue) cb(peek(key));
  });
}

/// Emulator page to CA page: a request to look at, {kind: "csr", label, bytes}.
export const caInbox = {
  put: (item) => put(INBOX_KEY, item),
  peek: () => peek(INBOX_KEY),
  clear: () => { try { localStorage.removeItem(INBOX_KEY); } catch (e) {} },
  watch: (cb) => watch(INBOX_KEY, cb),
};

/// CA page to emulator page: a certificate to hand to Caliptra,
/// {label, bytes}.
export const emulatorInbox = {
  put: (item) => put(OUTBOX_KEY, item),
  peek: () => peek(OUTBOX_KEY),
  clear: () => { try { localStorage.removeItem(OUTBOX_KEY); } catch (e) {} },
  watch: (cb) => watch(OUTBOX_KEY, cb),
};

/// Fills `container` with download links for [{name, bytes}].
export function showDownloads(container, downloads) {
  container.replaceChildren();
  for (const d of downloads || []) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([d.bytes], { type: "application/octet-stream" }));
    a.download = d.name;
    a.textContent = `Download ${d.name}`;
    a.className = "download";
    container.appendChild(a);
  }
}

/// A few lines describing a certificate or request, from the CA's info JSON.
export function describe(info) {
  const lines = [];
  if (info.serial) lines.push(`Serial number: ${info.serial}`);
  if (info.issuer) lines.push(`Issuer:        ${info.issuer}`);
  lines.push(`Subject:       ${info.subject}`);
  if (info.not_before) lines.push(`Valid:         ${info.not_before} to ${info.not_after}`);
  lines.push(`Public key:    ${info.key_description} (${info.public_key.length / 2} bytes)`);
  if (info.signature_algorithm) lines.push(`Signed with:   ${info.signature_algorithm}`);
  if (info.extensions.length) {
    lines.push("Extensions:");
    for (const e of info.extensions) {
      lines.push(`  ${e.name}${e.critical ? " (critical)" : ""}: ${e.summary}`);
    }
  }
  return lines.join("\n") + "\n";
}

/// Orders DER certificates root first by following issuer and subject
/// names. Certificates that do not link up are left at the end.
export function orderChain(certs) {
  const items = certs.map((bytes) => {
    const info = certInfo(bytes);
    return { bytes, subject: info.subject_der, issuer: info.issuer_der };
  });
  const ordered = [];
  const rest = items.slice();
  // Start from the certificate whose issuer is not another one in the set.
  let at = rest.findIndex((c) => !rest.some((o) => o !== c && o.subject === c.issuer));
  while (at >= 0) {
    const [cert] = rest.splice(at, 1);
    ordered.push(cert);
    at = rest.findIndex((c) => c.issuer === cert.subject);
  }
  return [...ordered, ...rest].map((c) => c.bytes);
}

/// Text report of a verifyChain result.
export function formatChain(result) {
  let s = "";
  for (const link of result.links) {
    s += `${link.ok ? "✓" : "✗"} ${link.index + 1}. ${link.subject || "(unreadable certificate)"}\n`;
    if (link.error) s += `     ${link.error}\n`;
    if (link.key_description) {
      s += `     ${link.key_description} key, ${link.size} bytes, valid ${link.not_before} to ${link.not_after}\n`;
    }
    if (link.verified_with) {
      s += `     ${link.signature_algorithm} signature ${link.signature_ok ? "verifies" : "does NOT verify"} under ${link.verified_with}\n`;
    }
    for (const p of link.problems || []) s += `     Problem: ${p}\n`;
  }
  s += result.ok
    ? `\nThe chain verifies: ${result.links.length} certificate${result.links.length === 1 ? "" : "s"}, each signed by the one before it.\n`
    : "\nThe chain does NOT verify.\n";
  return s;
}
