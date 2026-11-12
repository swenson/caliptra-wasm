// Licensed under the Apache-2.0 license
//
// The emulator page's Provisioning section: give a Caliptra device identity its
// certificate with the test CA (ca-core.js), in four steps:
//
//   1. Get the request: the certificate request (CSR) Caliptra made for the
//      identity's key, or, with the TBS method, just the public key.
//   2. Issue: the CA checks the request and issues the certificate (or
//      builds and signs a TBS for the public key).
//   3. Give it to Caliptra: with the TBS method, Caliptra assembles the
//      certificate from the TBS and the signature (GET_IDEV_*_CERT,
//      GET_PQ_CERT); then the certificate is stored with POPULATE_*_CERT.
//   4. Verify the chain from the CA to the runtime alias certificate.
//
// The identities are the IDevID (ECC P-384 everywhere, ML-DSA-87 too on
// 2.x) and, on Caliptra 1.x with a 1.3 runtime, PQ.DevID.

import {
  loadCa, cas, caById, toHex, fromHex, toPem, csrInfo, certInfo, issue, verifyChain,
  formatChain, idevidCsrBlob, hmacSha512Matches, caInbox, emulatorInbox, showDownloads, describe,
} from "./ca-core.js";

const UEID_OID = "2.23.133.5.4.4";

// Mailbox commands by the names the page's command list uses (the 2.x
// names; 1.x has the ECC ones under shorter names with the same IDs).
// `certReq` is the layout of the "assemble a certificate" request: the size
// of its signature field and the largest TBS it takes. `maxCert` is the
// largest certificate POPULATE takes. POPULATE_IDEV_*_CERT puts the
// certificate at the front of the runtime's DPE certificate chain, ahead of
// any it was given before, so an IDevID certificate is stored once per boot
// (`storedOncePerBoot`); POPULATE_PQ_CERT replaces the last one.
const IDENTITIES = [
  {
    id: "idev-ecc",
    label: "IDevID (ECC P-384)",
    alg: "ecc384",
    csrIndex: 0,
    needs: "GET_IDEV_ECC384_INFO",
    cmd: {
      csr: "GET_IDEV_ECC384_CSR", info: "GET_IDEV_ECC384_INFO", cert: "GET_IDEV_ECC384_CERT",
      populate: "POPULATE_IDEV_ECC384_CERT", ldev: "GET_LDEV_ECC384_CERT",
      fmc: "GET_FMC_ALIAS_ECC384_CERT", rt: "GET_RT_ALIAS_ECC384_CERT",
    },
    certReq: { signature: 96, maxTbs: 916 },
    maxCert: 1024,
    storedOncePerBoot: true,
    about: "Caliptra's manufacturer identity, derived from the UDS. Its ECC key certifies the LDevID.",
  },
  {
    id: "idev-mldsa",
    label: "IDevID (ML-DSA-87)",
    alg: "mldsa87",
    csrIndex: 1,
    needs: "GET_IDEV_MLDSA87_INFO",
    cmd: {
      csr: "GET_IDEV_MLDSA87_CSR", info: "GET_IDEV_MLDSA87_INFO", cert: "GET_IDEV_MLDSA87_CERT",
      populate: "POPULATE_IDEV_MLDSA87_CERT", ldev: "GET_LDEV_MLDSA87_CERT",
      fmc: "GET_FMC_ALIAS_MLDSA87_CERT", rt: "GET_RT_ALIAS_MLDSA87_CERT",
    },
    certReq: { signature: 4628, maxTbs: 2820 },
    maxCert: 8192,
    storedOncePerBoot: true,
    about: "The post-quantum half of the manufacturer identity (Caliptra 2.x): an ML-DSA-87 key derived from the UDS.",
  },
  {
    id: "pq-devid",
    label: "PQ.DevID (ML-DSA-87)",
    alg: "mldsa87",
    needs: "SET_PQ_SEED",
    cmd: { csr: "GET_PQ_CSR", info: "GET_PQ_INFO", cert: "GET_PQ_CERT", populate: "POPULATE_PQ_CERT" },
    certReq: { signature: 4627, maxTbs: 3543 },
    maxCert: 8192,
    about: "Runtime 1.3's post-quantum identity on Caliptra 1.x, derived from the seed provisioned under PQ.DevID identity, below. Provision the seed first.",
  },
];

const STEP_LABELS = {
  csr: ["1. Get the request", "2. Issue the certificate", "3. Give it to Caliptra", "4. Verify the chain"],
  tbs: ["1. Get the public key", "2. Sign a TBS", "3. Assemble and store it", "4. Verify the chain"],
};

function sized(buf) {
  if (!buf || buf.length < 12) throw new Error("the response is too short");
  const size = (buf[8] | (buf[9] << 8) | (buf[10] << 16) | (buf[11] << 24)) >>> 0;
  return buf.slice(12, 12 + Math.min(size, buf.length - 12));
}

function u32le(n) {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function same(a, b) {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/// Sets up the section. `ctx` is the emulator page's side of the bargain:
///   emulator()                        the running emulator, or null
///   busy()                            a mailbox command is in flight
///   sendMailbox(id, request, onProgress)  -> response bytes
///   withRunLoopPaused(fn), drainOutput()
///   commandId(name), commandAvailable(name)
///   makeChecksummedRequest(id, payload), lookupError(hex)
///   csrHmacKey()                      key of the CSR envelope's tag, or null
///   isMcu(), release
export async function initProvisioning(ctx) {
  const $ = (id) => document.getElementById(id);
  const section = $("provisioning");
  const statusEl = $("prov-status");
  const identitySelect = $("prov-identity");
  const methodSelect = $("prov-method");
  const caSelect = $("prov-ca");
  const output = $("prov-output");
  const downloads = $("prov-downloads");
  const stepItems = [...$("prov-steps").querySelectorAll("li")];
  const stepButtons = stepItems.map((li) => li.querySelector("button"));
  const stepHints = stepItems.map((li) => li.querySelector(".hint"));
  const runAll = $("prov-run-all");
  const openInCa = $("prov-open-ca");
  const useSent = $("prov-use-sent");

  function setStatus(text, kind) {
    statusEl.textContent = text;
    statusEl.className = "status" + (kind ? ` ${kind}` : "");
  }

  try {
    await loadCa();
  } catch (e) {
    setStatus("The test CA failed to load", "status-err");
    output.textContent = `The test CA module could not be loaded: ${e.message || e}\n`;
    console.error(e);
    return { refresh() {}, emulatorCreated() {}, emulatorReset() {} };
  }

  for (const ca of cas()) {
    const o = document.createElement("option");
    o.value = ca.id;
    o.textContent = ca.subject.replace(/^CN=/, "");
    caSelect.appendChild(o);
  }

  // What the flow has collected so far.
  let st = {};
  let busy = false;
  let caChosenByHand = false;
  let sent = null; // a certificate sent from the Test CA tab
  let stored = {}; // identity id -> the certificate this boot's Caliptra was given
  let mcuSettled = false; // this boot's MCU is done booting (see waitForMcu)

  const identity = () => IDENTITIES.find((i) => i.id === identitySelect.value) || IDENTITIES[0];
  const method = () => methodSelect.value;

  function log(text) {
    output.textContent += text + "\n";
    output.scrollTop = output.scrollHeight;
  }

  function markStep(i, state, hint) {
    stepItems[i].className = state || "";
    if (hint !== undefined) stepHints[i].textContent = hint;
  }

  function resetFlow() {
    st = {};
    output.textContent = "";
    showDownloads(downloads, []);
    for (let i = 0; i < 4; i++) markStep(i, "", "");
    openInCa.disabled = true;
    setStatus("", "");
  }

  function updateHints() {
    const id = identity();
    $("prov-identity-hint").textContent = id.about;
    const ca = caById(caSelect.value);
    let caHint = `Signs with ${ca.algorithm}.`;
    if (id.alg === "ecc384" && ca.id === "mldsa87") {
      caHint += ` The certificate will be about 5 KB; ${id.cmd.populate} takes ${id.maxCert} bytes, so step 3 will be refused.`;
    }
    $("prov-ca-hint").textContent = caHint;
    const isIdev = id.id !== "pq-devid";
    $("prov-method-hint").textContent = method() === "csr"
      ? (isIdev
        ? "The CSR the ROM makes when the IDevID CSR is requested at boot (Boot options, Caliptra-only mode). The runtime can return it again later."
        : "The CSR the runtime makes for PQ.DevID (GET_PQ_CSR).")
      : `No CSR: the CA builds a TBS certificate for the public key and signs it, and Caliptra assembles the certificate from the TBS and signature (${id.cmd.cert}).`;
    STEP_LABELS[method()].forEach((label, i) => { stepButtons[i].textContent = label; });
  }

  // Offer the identities this release (and runtime) has.
  function refresh() {
    const before = identitySelect.value;
    const available = IDENTITIES.filter((i) => ctx.commandAvailable(i.needs));
    identitySelect.replaceChildren(...available.map((i) => {
      const o = document.createElement("option");
      o.value = i.id;
      o.textContent = i.label;
      return o;
    }));
    if (available.some((i) => i.id === before)) identitySelect.value = before;
    if (identitySelect.value !== before) onIdentityChange();
    updateHints();
    updateButtons();
  }

  function updateButtons() {
    const idle = !!ctx.emulator() && !busy && !ctx.busy();
    for (const b of stepButtons) b.disabled = !idle;
    runAll.disabled = !idle;
    identitySelect.disabled = methodSelect.disabled = caSelect.disabled = busy;
    openInCa.disabled = busy || !st.csr;
    useSent.disabled = busy;
  }

  function onIdentityChange() {
    if (!caChosenByHand) caSelect.value = identity().alg;
    resetFlow();
    updateHints();
  }
  identitySelect.addEventListener("change", onIdentityChange);
  methodSelect.addEventListener("change", () => {
    resetFlow();
    updateHints();
  });
  caSelect.addEventListener("change", () => {
    caChosenByHand = true;
    // A certificate from the other CA is no longer what was asked for.
    st.issued = null;
    st.given = false;
    st.chain = null;
    for (let i = 1; i < 4; i++) markStep(i, "", "");
    updateHints();
  });

  // --- Talking to Caliptra ---

  function explain(err) {
    const text = String(err && err.message ? err.message : err);
    const code = text.match(/MailboxCmdFailed\((\d+)\)/);
    const info = code && ctx.lookupError("0x" + (Number(code[1]) >>> 0).toString(16).padStart(8, "0"));
    return info ? `${text} (${info.name}: ${info.desc})` : text;
  }

  async function command(name, payload = new Uint8Array(0)) {
    if (!ctx.commandAvailable(name)) {
      throw new Error(`${name} is not available on Caliptra ${ctx.release} with this runtime`);
    }
    const id = ctx.commandId(name);
    const request = ctx.makeChecksummedRequest(id, payload);
    // In Caliptra + MCU mode the MCU uses the same mailbox, most of all
    // while it boots: if it holds the lock, let it run and try again.
    for (let attempt = 0; ; attempt++) {
      try {
        return await ctx.sendMailbox(id, request, (cycles) => {
          setStatus(`${name}: ${(cycles / 1e6).toFixed(1)}M cycles`, "running");
        });
      } catch (e) {
        if (!/UnableToLockMailbox/.test(String(e)) || attempt >= 100) {
          throw new Error(`${name} failed: ${explain(e)}`);
        }
        setStatus(`${name}: waiting for the mailbox`, "running");
        await stepEmulator(2_000_000);
      }
    }
  }

  // Step the emulator from animation frames, so the page stays responsive.
  async function stepEmulator(cycles) {
    const STEPS = 200_000;
    for (let done = 0; done < cycles; done += STEPS) {
      await new Promise((resolve) => requestAnimationFrame(resolve));
      ctx.emulator().step(STEPS);
      ctx.drainOutput();
    }
  }

  // Step the emulator until the runtime takes mailbox commands.
  async function waitForRuntime() {
    const emu = ctx.emulator();
    if (!emu.ready_for_runtime) return;
    const LIMIT = 400_000_000;
    const STEPS = 200_000;
    let cycles = 0;
    while (!emu.ready_for_runtime()) {
      const fatal = JSON.parse(emu.get_error_registers()).cptra_fw_error_fatal;
      if (fatal !== "0x00000000") {
        const info = ctx.lookupError(fatal);
        throw new Error(`Caliptra stopped with fatal error ${fatal}${info ? ` (${info.name})` : ""} before the runtime started`);
      }
      if (cycles >= LIMIT) throw new Error("the runtime did not start");
      setStatus(`Booting to the runtime: ${(cycles / 1e6).toFixed(1)}M cycles`, "running");
      await stepEmulator(STEPS);
      cycles += STEPS;
    }
  }

  // In Caliptra + MCU mode the MCU uses Caliptra's mailbox too. Its ROM
  // stops with a fatal error if it finds the mailbox taken, and its runtime
  // keeps using it for a while after it starts. So before the first command,
  // let the MCU ROM finish and then wait for the mailbox to go quiet.
  async function waitForMcu() {
    const emu = ctx.emulator();
    if (mcuSettled || !ctx.isMcu() || !emu.step_watching_mailbox) return;
    const STEPS = 200_000;
    const QUIET = 5_000_000;
    const LIMIT = 300_000_000;
    let cycles = 0;
    const halted = () => emu.mcu_exit_status() !== undefined;
    while (!emu.mcu_rom_boot_complete() && !halted()) {
      if (cycles >= LIMIT) throw new Error("the MCU ROM did not finish booting");
      setStatus(`Waiting for the MCU to boot: ${(cycles / 1e6).toFixed(1)}M cycles`, "running");
      await stepEmulator(STEPS);
      cycles += STEPS;
    }
    // If the mailbox never goes quiet, go ahead anyway: commands wait for
    // the lock.
    for (cycles = 0; cycles < LIMIT && !halted(); cycles += STEPS) {
      setStatus(`Waiting for the MCU to finish with the mailbox: ${(cycles / 1e6).toFixed(1)}M cycles`, "running");
      await new Promise((resolve) => requestAnimationFrame(resolve));
      const quiet = emu.step_watching_mailbox(STEPS);
      ctx.drainOutput();
      if (quiet >= QUIET) break;
    }
    mcuSettled = true;
  }

  // The LDevID certificate names the IDevID as its issuer, so it says what
  // subject name and key identifier the IDevID certificate must carry for
  // the chain to link up, whatever the key identifier fuses select.
  async function ldevid() {
    if (!st.ldev) {
      st.ldev = sized(await command(identity().cmd.ldev));
      st.ldevInfo = certInfo(st.ldev);
    }
    return st.ldevInfo;
  }

  // --- The steps ---

  async function stepGet() {
    const id = identity();
    if (method() === "tbs") {
      const resp = await command(id.cmd.info);
      st.publicKey = resp.slice(8);
      log(`${id.cmd.info}: ${id.label} public key, ${st.publicKey.length} bytes:\n  ${toHex(st.publicKey.subarray(0, 48))}${st.publicKey.length > 48 ? "…" : ""}`);
      if (id.id === "pq-devid") {
        // PQ.DevID has no certificate below it to say what its name is, so
        // take the subject and extensions from its CSR.
        st.csrInfo = csrInfo(sized(await command(id.cmd.csr)));
        log(`${id.cmd.csr}: subject and extensions taken from the CSR:\n  ${st.csrInfo.subject}`);
      }
      return `${st.publicKey.length}-byte public key from ${id.cmd.info}`;
    }

    let source;
    const envelope = id.csrIndex !== undefined && ctx.emulator().idevid_csr_envelope
      ? ctx.emulator().idevid_csr_envelope()
      : null;
    if (envelope) {
      const blob = idevidCsrBlob(new Uint8Array(envelope));
      if (!blob.csrs[id.csrIndex]) throw new Error(`the ROM's ${blob.format} holds no ${id.label} request`);
      st.csr = blob.csrs[id.csrIndex];
      source = "the ROM at boot";
      log(`The ROM handed over a ${blob.format} at boot (${envelope.length} bytes: ` +
        blob.csrs.map((c) => `a ${c.length}-byte CSR`).join(", ") +
        (blob.mac ? `, and a ${blob.mac_algorithm} tag over them` : "") + ").");
      // The tag shows the CSRs came out of this silicon: its key is built
      // into the chip and known to the manufacturer's signing service.
      const key = blob.mac && ctx.csrHmacKey();
      if (key) {
        const covered = new Uint8Array(envelope).subarray(0, blob.mac_covers);
        if (!hmacSha512Matches(new Uint8Array(key), covered, blob.mac)) {
          throw new Error("the CSR envelope's HMAC tag does not verify under the CSR HMAC key");
        }
        log("  \u2713 The envelope's tag verifies under the CSR HMAC key (the emulator uses caliptra-sw's default key).");
      }
    } else if (ctx.commandAvailable(id.cmd.csr)) {
      try {
        st.csr = sized(await command(id.cmd.csr));
      } catch (e) {
        if (/UNPROVISIONED|UNSUPPORTED_ROM/.test(e.message) && id.csrIndex !== undefined) {
          throw new Error(`${e.message}\nThe ROM only makes the IDevID CSR when it is requested at boot. ` +
            (ctx.isMcu()
              ? "That is not available in Caliptra + MCU mode: use the public key and TBS method, or Caliptra-only mode."
              : "Tick “Provisioning: request the IDevID CSR” under Boot options, press Reset, then Run."));
        }
        if (/PQ_SEED|SEED/.test(e.message)) {
          throw new Error(`${e.message}\nProvision the PQ.DevID seed first (step 1 under PQ.DevID identity, below).`);
        }
        throw e;
      }
      source = id.cmd.csr;
    } else {
      throw new Error(`This runtime cannot return the ${id.label} CSR (${id.cmd.csr} is not available), and the ROM was not asked for it at boot. ` +
        "Tick “Provisioning: request the IDevID CSR” under Boot options, press Reset, then Run.");
    }
    st.csrInfo = csrInfo(st.csr);
    st.csrSource = source;
    log(`${id.label} certificate request from ${source} (${st.csr.length} bytes):\n` +
      describe(st.csrInfo).replace(/^/gm, "  "));
    if (st.csrInfo.signature_valid !== true) {
      throw new Error(`the request's signature does not verify${st.csrInfo.signature_error ? `: ${st.csrInfo.signature_error}` : ""}`);
    }
    log(`  ✓ The ${st.csrInfo.signature_algorithm} signature verifies: Caliptra holds the private key.\n`);
    showDownloads(downloads, [{ name: `caliptra-${id.id}.csr.der`, bytes: st.csr }]);
    openInCa.disabled = false;
    return `${st.csr.length}-byte CSR from ${source}; its signature verifies`;
  }

  async function stepIssue() {
    const id = identity();
    const ca = caById(caSelect.value);
    const source = `Emulator: ${id.label}, Caliptra ${ctx.release}`;
    let request;
    if (id.id === "pq-devid") {
      request = method() === "csr"
        ? { csr: st.csr }
        : {
          publicKey: st.publicKey, keyAlgorithm: id.alg, subject: fromHex(st.csrInfo.subject_der),
          profile: "requested", extraExtensions: st.csrInfo.extensions.map((e) => fromHex(e.der)),
        };
    } else {
      const ldev = await ldevid();
      const subjectKeyId = ldev.authority_key_id ? fromHex(ldev.authority_key_id) : undefined;
      if (method() === "csr") {
        request = { csr: st.csr, subjectKeyId };
      } else {
        // Mirror what the IDevID request asks for: a CA one level above the
        // LDevID, with the device's UEID.
        const pathLen = ldev.extensions.find((e) => e.name === "basicConstraints")?.summary.match(/pathLen (\d+)/);
        const ueid = ldev.extensions.find((e) => e.oid === UEID_OID);
        request = {
          publicKey: st.publicKey, keyAlgorithm: id.alg, subject: fromHex(ldev.issuer_der),
          profile: "ca", pathLen: pathLen ? Number(pathLen[1]) + 1 : null,
          extraExtensions: ueid ? [fromHex(ueid.der)] : [], subjectKeyId,
        };
        log(`The LDevID certificate (${id.cmd.ldev}) names its issuer, so the TBS takes the IDevID's subject name, key identifier, UEID and path length from it.`);
      }
    }
    st.issued = issue({ ca: ca.id, ...request }, source);
    st.assembledBy = "the CA";
    st.given = false;
    st.chain = null;
    const { cert, tbs, signature, info } = st.issued;
    log(`${ca.subject} issued serial ${info.serial} (${cert.length} bytes; TBS ${tbs.length} bytes, ${ca.algorithm} signature ${signature.length} bytes):\n` +
      describe(info).replace(/^/gm, "  "));
    if (method() === "tbs") {
      log(`  TBS:       ${toHex(tbs.subarray(0, 32))}… (${tbs.length} bytes)\n  Signature: ${toHex(signature.subarray(0, 32))}… (${signature.length} bytes)\n`);
    } else {
      log(toPem("CERTIFICATE", cert));
    }
    return method() === "tbs"
      ? `${tbs.length}-byte TBS signed by ${ca.subject.replace(/^CN=/, "")}, serial ${info.serial}`
      : `Serial ${info.serial} from ${ca.subject.replace(/^CN=/, "")} (${cert.length} bytes)`;
  }

  async function stepGive() {
    const id = identity();
    const { cert, tbs, signature } = st.issued;
    const notes = [];
    if (method() === "tbs" && st.assembledBy !== "the Test CA tab") {
      if (tbs.length > id.certReq.maxTbs) {
        log(`${id.cmd.cert} takes a TBS of at most ${id.certReq.maxTbs} bytes and this one is ${tbs.length} ` +
          "(an ML-DSA-87 public key alone is 2592 bytes, and the IDevID subject name and extensions take the rest over the limit), " +
          "so the CA's own assembly of the certificate is used instead. It is the same wrapping: TBS, signature algorithm, signature.");
        notes.push(`TBS too large for ${id.cmd.cert}; assembled by the CA`);
      } else {
        const sig = new Uint8Array(id.certReq.signature);
        sig.set(signature);
        const assembled = sized(await command(id.cmd.cert, concat(u32le(tbs.length), sig, tbs)));
        if (!same(assembled, cert)) {
          throw new Error(`${id.cmd.cert} returned a different certificate than the CA assembled from the same TBS and signature`);
        }
        st.assembledBy = "Caliptra";
        log(`${id.cmd.cert}: Caliptra assembled the ${assembled.length}-byte certificate from the TBS and signature. ` +
          "It is identical to the one the CA assembled.\n" + toPem("CERTIFICATE", assembled));
        notes.push(`${id.cmd.cert} assembled the certificate`);
      }
    }
    if (cert.length > id.maxCert) {
      throw new Error(`the certificate is ${cert.length} bytes and ${id.cmd.populate} takes at most ${id.maxCert}. ` +
        (id.alg === "ecc384" ? "Issue it from the ECC P-384 CA instead: an ML-DSA signature alone is 4627 bytes." : ""));
    }
    const held = stored[id.id];
    if (id.storedOncePerBoot && held) {
      if (same(held.cert, cert)) {
        log(`${id.cmd.populate}: Caliptra already holds this certificate.\n`);
        notes.push("Caliptra already holds it");
        return notes.join("; ");
      }
      log(`${id.cmd.populate} is not sent again: Caliptra was given serial ${held.serial} earlier in this boot. ` +
        "The command puts a certificate at the front of the DPE certificate chain, ahead of any it was given before, " +
        "so a device gets its IDevID certificate once per boot. Reset the emulator to store this one instead.\n");
      notes.push(`not stored: this boot already holds serial ${held.serial} (Reset to store another)`);
      return { skipped: notes.join("; ") };
    }
    try {
      await command(id.cmd.populate, concat(u32le(cert.length), cert));
    } catch (e) {
      if (!/INCORRECT_PAUSER_PRIVILEGE_LEVEL/.test(e.message)) throw e;
      // Storing a certificate is reserved for the privileged mailbox user
      // (PL0). In Caliptra 2.0's Caliptra + MCU mode the page talks to
      // Caliptra as a second SoC user, which is not.
      log(`${e.message}\nCaliptra only lets its privileged mailbox user (PL0) store a certificate, and on this release ` +
        "the page's mailbox user in Caliptra + MCU mode is not that user. The certificate is not stored; " +
        "use Caliptra-only mode to store it.\n");
      notes.push("not stored: the page's mailbox user is not privileged (PL0) in this mode");
      return { skipped: notes.join("; ") };
    }
    stored[id.id] = { cert, serial: st.issued.info.serial };
    log(`${id.cmd.populate}: Caliptra accepted the ${cert.length}-byte certificate. ` +
      (id.id === "pq-devid"
        ? "It replaces the PQ.DevID certificate chain the runtime's DPE returns."
        : "It now heads the certificate chain the runtime's DPE returns.") + "\n");
    notes.push(`${id.cmd.populate} accepted it`);
    return notes.join("; ");
  }

  async function stepVerify() {
    const id = identity();
    const names = [id.label];
    const certs = [st.issued.cert];
    if (id.cmd.ldev) {
      await ldevid();
      certs.push(st.ldev, sized(await command(id.cmd.fmc)), sized(await command(id.cmd.rt)));
      names.push("LDevID", "FMC alias", "Runtime alias");
    }
    const result = verifyChain(certs);
    st.chain = result;
    log(`Certificate chain from the test CA (${names.join(", ")}):\n` + formatChain(result));
    const ca = cas().find((c) => c.subject === st.issued.info.issuer);
    const pem = (ca ? [ca.cert] : []).concat(certs).map((c) => toPem("CERTIFICATE", c)).join("");
    showDownloads(downloads, [
      { name: `caliptra-${id.id}-chain.pem`, bytes: new TextEncoder().encode(pem) },
      { name: `caliptra-${id.id}.crt.der`, bytes: st.issued.cert },
      ...(st.csr ? [{ name: `caliptra-${id.id}.csr.der`, bytes: st.csr }] : []),
    ]);
    if (!result.ok) throw new Error("the chain does not verify");
    return `Verifies: test CA → ${names.join(" → ")}`;
  }

  const STEPS = [
    { run: stepGet, done: () => (method() === "csr" ? !!st.csr : !!st.publicKey) },
    { run: stepIssue, done: () => !!st.issued },
    { run: stepGive, done: () => !!st.given },
    { run: stepVerify, done: () => !!st.chain },
  ];

  // Runs step `last`, and first any earlier step that has not been done.
  async function runThrough(last, fresh) {
    if (busy) return;
    if (!ctx.emulator()) {
      setStatus("Run the emulator first", "status-warn");
      return;
    }
    if (fresh) resetFlow();
    busy = true;
    updateButtons();
    let current = 0;
    try {
      await ctx.withRunLoopPaused(async () => {
        await waitForRuntime();
        await waitForMcu();
        for (current = 0; current <= last; current++) {
          if (current < last && STEPS[current].done()) continue;
          markStep(current, "", "Working…");
          // A step returns a summary, or {skipped} when it could not do its
          // job but the flow can go on.
          const outcome = await STEPS[current].run();
          if (typeof outcome === "string") markStep(current, "done", outcome);
          else markStep(current, "skipped", outcome.skipped);
          if (current === 2) st.given = true;
          ctx.drainOutput();
        }
      });
      if (last < 3) setStatus(`Step ${last + 1} done`, "status-ok");
      else if (stepItems[2].className === "skipped") setStatus("Verified; certificate not stored", "status-warn");
      else setStatus("Provisioned and verified", "status-ok");
    } catch (e) {
      const message = String(e && e.message ? e.message : e);
      markStep(current, "failed", message.split("\n")[0]);
      log(`✗ ${message}\n`);
      setStatus(`Step ${current + 1} failed`, "status-err");
    } finally {
      busy = false;
      updateButtons();
    }
  }

  stepButtons.forEach((b, i) => b.addEventListener("click", () => runThrough(i, false)));
  runAll.addEventListener("click", () => runThrough(3, true));

  // --- The Test CA tab ---

  openInCa.addEventListener("click", () => {
    if (!st.csr) return;
    caInbox.put({ kind: "csr", label: `${identity().label}, Caliptra ${ctx.release}`, bytes: st.csr });
    window.open("ca.html", "caliptra-ca");
  });

  function offerSent(item) {
    if (!item) return;
    try {
      sent = { bytes: item.bytes, info: certInfo(item.bytes) };
    } catch (e) {
      return;
    }
    useSent.hidden = false;
    useSent.textContent = `Use the certificate from the Test CA tab (serial ${sent.info.serial})`;
    useSent.title = sent.info.subject;
  }
  useSent.addEventListener("click", () => {
    if (!sent) return;
    // A certificate issued by hand in the Test CA tab replaces step 2.
    st.issued = { cert: sent.bytes, tbs: new Uint8Array(0), signature: new Uint8Array(0), info: sent.info };
    st.assembledBy = "the Test CA tab";
    st.given = false;
    st.chain = null;
    markStep(1, "done", `Serial ${sent.info.serial}, issued in the Test CA tab`);
    markStep(2, "", "");
    markStep(3, "", "");
    log(`Using the certificate issued in the Test CA tab:\n` + describe(sent.info).replace(/^/gm, "  "));
    emulatorInbox.clear();
    useSent.hidden = true;
    sent = null;
  });
  offerSent(emulatorInbox.peek());
  emulatorInbox.watch(offerSent);

  refresh();
  section.dataset.ready = "true";

  return {
    /// The release's or runtime's command list changed.
    refresh,
    /// A new emulator was created.
    emulatorCreated() {
      stored = {};
      mcuSettled = false;
      resetFlow();
      const envelope = ctx.emulator().idevid_csr_envelope ? ctx.emulator().idevid_csr_envelope() : null;
      if (envelope) {
        log(`The ROM handed over the IDevID CSR at boot (${envelope.length} bytes). Step 1 takes it from there.\n`);
        setStatus("IDevID CSR received at boot", "status-ok");
      }
      updateButtons();
    },
    /// The emulator was reset.
    emulatorReset() {
      stored = {};
      mcuSettled = false;
      resetFlow();
      updateButtons();
    },
    /// The mailbox became busy or free.
    updateButtons,
  };
}
