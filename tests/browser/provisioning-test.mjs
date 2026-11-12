#!/usr/bin/env node
// Licensed under the Apache-2.0 license
//
// End-to-end test of the Test CA page and the emulator page's Provisioning
// section, run in a real (headless) browser.
//
// First the CA page: both roots are shown, a certificate is issued for a
// public key, it appears in the log, its chain verifies, and a corrupted
// copy does not.
//
// Then, for every release, the emulator page:
//   * Caliptra only, with "Provisioning: request the IDevID CSR" ticked:
//     every identity the release offers (IDevID ECC, IDevID ML-DSA on 2.x,
//     PQ.DevID on 1.x) is provisioned by both methods (certificate request,
//     and public key with TBS signing) with "Run all four steps". Each run
//     must end with the certificate stored in Caliptra and the chain from
//     the test CA to the runtime alias certificate verified. The request is
//     also sent to the CA page, issued there by hand and sent back.
//   * Caliptra + MCU (2.x): the public key and TBS method for both IDevIDs,
//     and the certificate request method failing with a pointer to it.
//
// Usage:
//   node tests/browser/provisioning-test.mjs [--release 2.1]... [--out DIR]
//
// See harness.mjs for the environment variables that pick the browser.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { WWW, sleep, tail, withBrowser } from "./harness.mjs";

function parseArgs(argv) {
  const out = { releases: [], outDir: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--release") out.releases.push(argv[++i]);
    else if (argv[i] === "--out") out.outDir = argv[++i];
    else if (argv[i] === "-h" || argv[i] === "--help") {
      console.log("usage: provisioning-test.mjs [--release R]... [--out DIR]");
      process.exit(0);
    } else throw new Error(`unknown argument: ${argv[i]}`);
  }
  return out;
}

async function screenshot(bidi, context, outDir, name) {
  if (!outDir) return;
  mkdirSync(outDir, { recursive: true });
  try {
    const shot = await bidi.send("browsingContext.captureScreenshot", { context, origin: "document" });
    writeFileSync(join(outDir, `${name}.png`), Buffer.from(shot.data, "base64"));
  } catch (e) {
    console.warn(`screenshot failed: ${e.message}`);
  }
}

// Poll `expression` (evaluated in the page) until `done(value)`.
async function waitFor(bidi, context, expression, done, what, timeoutSecs = 60) {
  const t0 = Date.now();
  for (;;) {
    const value = await bidi.eval(context, expression);
    if (done(value)) return value;
    if (Date.now() - t0 > timeoutSecs * 1000) {
      throw new Error(`timed out after ${timeoutSecs}s waiting for ${what}; last: ${JSON.stringify(value).slice(0, 600)}`);
    }
    await sleep(500);
  }
}

const setValue = (id, value) => `(() => {
  const el = document.getElementById(${JSON.stringify(id)});
  el.value = ${JSON.stringify(value)};
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  return true;
})()`;
const click = (id) => `(document.getElementById(${JSON.stringify(id)}).click(), true)`;
const text = (id) => `document.getElementById(${JSON.stringify(id)}).textContent`;

// ------------------------------------------------------------------ CA page

async function testCaPage(bidi, context, baseUrl, outDir, pageErrors) {
  console.log("\n=== Test CA page ===");
  pageErrors.length = 0;
  await bidi.send("browsingContext.navigate", { context, url: `${baseUrl}ca.html`, wait: "complete" });
  await waitFor(bidi, context, text("ca-status"), (s) => /Runs entirely/.test(s) || /Failed/.test(s), "the CA to load");
  if (await bidi.eval(context, `crypto.subtle !== undefined`)) {
    throw new Error("CA page: the test did not take WebCrypto away");
  }
  const roots = await bidi.eval(context, `({
    status: ${text("ca-status")},
    roots: [...document.querySelectorAll("#roots .key-block > .label")].map((e) => e.textContent),
    seeds: [...document.querySelectorAll("#roots dd")].map((e) => e.textContent).filter((t) => t.includes("ASCII")),
    cas: [...document.querySelectorAll("#issue-ca option")].map((o) => o.value),
  })`);
  if (roots.roots.length !== 2 || roots.cas.join() !== "mldsa87,ecc384" || roots.seeds.length !== 2) {
    throw new Error(`CA page: expected two roots, got ${JSON.stringify(roots)}`);
  }
  console.log(`roots: ${roots.roots.join("; ")}`);
  // Start from an empty CA so serial numbers are predictable.
  await bidi.eval(context, `(window.caliptraTestCa.store.reset(), true)`);

  // Certify a public key (the ECC root's own, as a stand-in device key)
  // with each CA.
  const key = await bidi.eval(context, `window.caliptraTestCa.toHex(window.caliptraTestCa.cas()[1].publicKey)`);
  await bidi.eval(context, `(document.querySelector('input[name="issue-mode"][value="key"]').click(), true)`);
  await bidi.eval(context, setValue("key-alg", "ecc384"));
  await bidi.eval(context, setValue("key-input", key));
  const pems = [];
  for (const [ca, serial] of [["mldsa87", "02"], ["ecc384", "02"]]) {
    await bidi.eval(context, setValue("issue-ca", ca));
    await bidi.eval(context, click("btn-issue"));
    const out = await waitFor(bidi, context, `({ status: ${text("issue-status")}, output: ${text("issue-output")} })`,
      (v) => v.status !== "", `the ${ca} CA to issue`);
    if (out.status !== `Issued serial ${serial}` || !out.output.includes("BEGIN CERTIFICATE")) {
      throw new Error(`CA page: ${ca} issue failed: ${out.status}\n${out.output.slice(0, 600)}`);
    }
    pems.push(out.output.slice(out.output.indexOf("-----BEGIN")));
    console.log(`  ${ca}: ${out.status}`);
    await bidi.eval(context, `(document.getElementById("issue-status").textContent = "", true)`);
  }
  const rows = await bidi.eval(context, `document.querySelectorAll("#issued-table tbody tr").length`);
  if (rows !== 2) throw new Error(`CA page: the log shows ${rows} certificates, expected 2`);

  // The issued certificate verifies; a corrupted copy does not.
  // (Flip a character in the middle of the base64 body, which lands in the
  // public key or the signature.)
  const body = pems[0].indexOf("\n", pems[0].length / 2) + 10;
  const corrupted = pems[0].slice(0, body) + (pems[0][body] === "A" ? "B" : "A") + pems[0].slice(body + 1);
  for (const [input, want] of [[pems[0], "Chain verifies"], [corrupted, "Chain does not verify"]]) {
    await bidi.eval(context, `(document.getElementById("verify-status").textContent = "", true)`);
    await bidi.eval(context, setValue("verify-input", input));
    await bidi.eval(context, click("btn-verify"));
    const got = await waitFor(bidi, context, text("verify-status"), (s) => s !== "", "chain verification");
    if (got !== want) {
      throw new Error(`CA page: verification gave "${got}", expected ${want}`);
    }
    console.log(`  verify: ${got}`);
  }

  // Revoking shows up in the log.
  await bidi.eval(context, `([...document.querySelectorAll("#issued-table button")].find((b) => b.textContent === "Revoke").click(), true)`);
  const revoked = await bidi.eval(context, `[...document.querySelectorAll("#issued-table .status")].map((s) => s.textContent)`);
  if (!revoked.includes("Revoked")) throw new Error(`CA page: revoking did not show in the log (${revoked})`);
  await screenshot(bidi, context, outDir, "ca-page");
  if (pageErrors.length) throw new Error(`CA page: JavaScript errors:\n${pageErrors.join("\n")}`);
  console.log("PASS Test CA page");
}

// ------------------------------------------------------------ emulator page

// A visit without ?version= opens the newest release, whatever was picked
// on an earlier visit (which older builds of the page remembered in
// localStorage).
async function testDefaultRelease(bidi, context, baseUrl) {
  console.log("\n=== Default release ===");
  const { releases } = JSON.parse(readFileSync(join(WWW, "versions.json"), "utf8"));
  const newest = [...releases].sort((a, b) => {
    const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
    return pb[0] - pa[0] || pb[1] - pa[1];
  })[0];
  const oldest = releases.find((r) => r !== newest);
  await bidi.send("browsingContext.navigate", { context, url: `${baseUrl}ca.html`, wait: "complete" });
  await bidi.eval(context, `(localStorage.setItem("caliptra-wasm.release", ${JSON.stringify(oldest ?? newest)}), sessionStorage.clear(), true)`);
  await bidi.send("browsingContext.navigate", { context, url: baseUrl, wait: "complete" });
  const shown = await waitFor(bidi, context, `({
    status: ${text("status")},
    release: document.getElementById("caliptra-version").value,
  })`, (st) => st.status === "Ready", "the page to be ready");
  if (shown.release !== newest) throw new Error(`default release: the page opened ${shown.release}, expected ${newest}`);
  console.log(`PASS the page opens Caliptra ${shown.release} by default`);
}

async function openEmulator(bidi, context, baseUrl, release, mode, provisioning) {
  await bidi.send("browsingContext.navigate", {
    context,
    url: `${baseUrl}?version=${encodeURIComponent(release)}`,
    wait: "complete",
  });
  await waitFor(bidi, context, `({
    status: ${text("status")},
    runDisabled: document.getElementById("btn-run").disabled,
    provisioning: document.getElementById("provisioning").dataset.ready,
    identities: document.querySelectorAll("#prov-identity option").length,
  })`, (st) => st.status === "Ready" && !st.runDisabled && st.provisioning === "true" && st.identities > 0, "the page to be ready");
  await bidi.eval(context, `(() => {
    const sel = document.getElementById("emu-mode");
    sel.value = ${JSON.stringify(mode)};
    sel.dispatchEvent(new Event("change", { bubbles: true }));
    const prov = document.getElementById("provisioning-mode");
    if (prov.checked !== ${provisioning}) prov.click();
    document.getElementById("start-paused").checked = false;
    document.getElementById("btn-run").click();
    return true;
  })()`);
  const st = await bidi.eval(context, `({
    status: ${text("status")},
    lifecycle: document.getElementById("lifecycle").value,
    prov: ${text("prov-status")},
  })`);
  if (!/^Running/.test(st.status)) throw new Error(`the emulator did not start: ${st.status}`);
  return st;
}

const provState = `(() => {
  const dec = document.getElementById("error-decoder");
  return {
    status: ${text("prov-status")},
    steps: [...document.querySelectorAll("#prov-steps li")].map((li) => ({ state: li.className, hint: li.querySelector(".hint").textContent })),
    output: ${text("prov-output")},
    downloads: [...document.querySelectorAll("#prov-downloads a")].map((a) => a.download),
    decoder: dec && !dec.hidden ? dec.textContent : "",
  };
})()`;

// Select an identity and method, press "Run all four steps" and wait for
// the outcome.
async function runFlow(bidi, context, identity, method, timeoutSecs = 600) {
  await bidi.eval(context, setValue("prov-identity", identity));
  await bidi.eval(context, setValue("prov-method", method));
  await bidi.eval(context, click("prov-run-all"));
  return waitFor(bidi, context, provState,
    (st) => /^Provisioned and verified$|^Verified; |failed$/.test(st.status) || /fw_error_fatal/.test(st.decoder),
    `${identity} (${method})`, timeoutSecs);
}

// The flow must have run to a verified chain. `stored` is whether step 3
// should have stored the certificate in Caliptra, or been skipped.
function expectProvisioned(st, name, stored = true) {
  const want = stored ? ["done", "done", "done", "done"] : ["done", "done", "skipped", "done"];
  const wantStatus = stored ? "Provisioned and verified" : "Verified; certificate not stored";
  if (st.status !== wantStatus || st.steps.map((s) => s.state).join() !== want.join()) {
    throw new Error(`${name}: ${st.status} (expected ${wantStatus})\nsteps: ${JSON.stringify(st.steps, null, 1)}\n${tail(st.output, 2500)}`);
  }
  if (!/The chain verifies/.test(st.output)) throw new Error(`${name}: no chain verification in the output`);
  if (!st.downloads.some((d) => d.endsWith("-chain.pem"))) throw new Error(`${name}: no chain download`);
}

async function testRelease(bidi, context, baseUrl, release, outDir, pageErrors) {
  const info = JSON.parse(readFileSync(join(WWW, `v${release}`, "build-info.json"), "utf8"));
  const oneX = release.startsWith("1.");

  console.log(`\n=== Caliptra ${release}: Caliptra only, IDevID CSR requested at boot ===`);
  pageErrors.length = 0;
  const started = await openEmulator(bidi, context, baseUrl, release, "caliptra", true);
  if (started.lifecycle !== "manufacturing") throw new Error(`${release}: lifecycle is ${started.lifecycle}, expected manufacturing`);
  if (started.prov !== "IDevID CSR received at boot") throw new Error(`${release}: no IDevID CSR at boot (${started.prov})`);
  // The ROM ran while the emulator was created; what it printed is shown.
  const bootUart = await bidi.eval(context, text("uart-output"));
  if (!/\[idev\][^\n]*CSR = [0-9A-F]{64}/.test(bootUart)) {
    throw new Error(`${release}: the UART panel does not show the ROM making the IDevID CSR:\n${tail(bootUart, 1500)}`);
  }
  const identities = await bidi.eval(context, `[...document.querySelectorAll("#prov-identity option")].map((o) => o.value)`);
  const want = oneX ? ["idev-ecc", "pq-devid"] : ["idev-ecc", "idev-mldsa"];
  if (identities.join() !== want.join()) throw new Error(`${release}: identities offered: ${identities}, expected ${want}`);

  for (const identity of identities) {
    if (identity === "pq-devid") {
      // PQ.DevID needs its seed first (under PQ.DevID identity).
      await bidi.eval(context, click("pq-provision"));
      await waitFor(bidi, context, text("pq-status"), (s) => /done|failed/.test(s), "the PQ.DevID seed", 300);
    }
    for (const method of ["csr", "tbs"]) {
      const name = `${release} ${identity} ${method}`;
      const st = await runFlow(bidi, context, identity, method);
      // An IDevID certificate is stored once per boot, so the second
      // method's is not; PQ.DevID's is replaced.
      expectProvisioned(st, name, method === "csr" || identity === "pq-devid");
      if (method === "csr" && identity !== "pq-devid" && !/from the ROM at boot/.test(st.steps[0].hint)) {
        throw new Error(`${name}: the CSR did not come from the ROM (${st.steps[0].hint})`);
      }
      // 2.x wraps its CSRs in an envelope with an HMAC tag, which the page
      // checks.
      if (method === "csr" && identity !== "pq-devid" && !oneX && !/envelope's tag verifies/.test(st.output)) {
        throw new Error(`${name}: the CSR envelope's tag was not verified\n${tail(st.output, 1500)}`);
      }
      if (pageErrors.length) throw new Error(`${name}: JavaScript errors:\n${pageErrors.join("\n")}`);
      console.log(`PASS ${name}: ${st.steps.map((s) => s.hint).join(" | ")}`);
      await screenshot(bidi, context, outDir, `${release}-${identity}-${method}`);
    }
  }

  // An ECC identity certified by the ML-DSA CA is too big for Caliptra.
  await bidi.eval(context, setValue("prov-identity", "idev-ecc"));
  await bidi.eval(context, setValue("prov-method", "csr"));
  await bidi.eval(context, setValue("prov-ca", "mldsa87"));
  await bidi.eval(context, click("prov-run-all"));
  const big = await waitFor(bidi, context, provState, (st) => /verified$|not stored$|failed$/.test(st.status), "the oversized certificate");
  if (big.status !== "Step 3 failed" || !/takes at most 1024/.test(big.output)) {
    throw new Error(`${release}: ML-DSA-signed ECC IDevID: ${big.status}\n${tail(big.output, 1200)}`);
  }
  console.log(`PASS ${release} oversized certificate refused: ${big.steps[2].hint}`);
  await bidi.eval(context, setValue("prov-ca", "ecc384"));

  // By hand through the CA page: send the request there, issue, send the
  // certificate back, and finish here.
  await bidi.eval(context, `(document.querySelector('#prov-steps button[data-step="0"]').click(), true)`);
  await waitFor(bidi, context, provState, (st) => /^Step 1 done$|failed$/.test(st.status), "step 1");
  // The CA page opens in another tab; drive it in an iframe here instead,
  // which shares the same storage.
  await bidi.eval(context, `(() => {
    window.open = () => null;
    document.getElementById("prov-open-ca").click();
    const frame = document.createElement("iframe");
    frame.id = "ca-frame";
    frame.src = "ca.html";
    document.body.appendChild(frame);
    return true;
  })()`);
  const frameDoc = `document.getElementById("ca-frame").contentDocument`;
  await waitFor(bidi, context, `({
    status: ${frameDoc}.getElementById("issue-status")?.textContent || "",
    disabled: ${frameDoc}.getElementById("btn-issue")?.disabled,
  })`, (v) => /^Request received/.test(v.status) && v.disabled === false, "the request on the CA page");
  await bidi.eval(context, `(${frameDoc}.getElementById("btn-issue").click(), true)`);
  await waitFor(bidi, context, `${frameDoc}.getElementById("issue-status").textContent`, (s) => /^Issued serial/.test(s), "the CA page to issue");
  await bidi.eval(context, `(${frameDoc}.getElementById("btn-send-emulator").click(), true)`);
  await waitFor(bidi, context, `!document.getElementById("prov-use-sent").hidden`, (v) => v === true, "the certificate from the CA page");
  await bidi.eval(context, click("prov-use-sent"));
  await bidi.eval(context, `(document.querySelector('#prov-steps button[data-step="3"]').click(), true)`);
  const byHand = await waitFor(bidi, context, provState, (st) => /verified$|not stored$|failed$/.test(st.status), "the by-hand flow", 300);
  expectProvisioned(byHand, `${release} by hand through the CA page`, false);
  if (!/issued in the Test CA tab/.test(byHand.steps[1].hint)) throw new Error(`${release}: by hand: ${byHand.steps[1].hint}`);
  if (pageErrors.length) throw new Error(`${release}: JavaScript errors:\n${pageErrors.join("\n")}`);
  console.log(`PASS ${release} by hand through the CA page: ${byHand.steps.map((s) => s.hint).join(" | ")}`);
  await bidi.eval(context, click("btn-stop"));

  if (info.features?.subsystem === false) return;

  console.log(`\n=== Caliptra ${release}: Caliptra + MCU ===`);
  pageErrors.length = 0;
  await openEmulator(bidi, context, baseUrl, release, "mcu", false);
  const refused = await runFlow(bidi, context, "idev-ecc", "csr", 900);
  if (refused.status !== "Step 1 failed" || !/public key and TBS method/.test(refused.output)) {
    throw new Error(`${release} mcu: CSR method: ${refused.status}\n${tail(refused.output, 1200)}`);
  }
  console.log(`PASS ${release} mcu: the CSR method points to the TBS method`);
  for (const identity of ["idev-ecc", "idev-mldsa"]) {
    const name = `${release} mcu ${identity} tbs`;
    const st = await runFlow(bidi, context, identity, "tbs", 900);
    // On 2.0 the page's mailbox user in this mode is not the privileged
    // one, so Caliptra refuses to store the certificate.
    expectProvisioned(st, name, release !== "2.0");
    if (pageErrors.length) throw new Error(`${name}: JavaScript errors:\n${pageErrors.join("\n")}`);
    console.log(`PASS ${name}: ${st.steps.map((s) => s.hint).join(" | ")}`);
  }
  // The MCU shares the mailbox with the page: it must still be running.
  await sleep(3000);
  const mcu = await bidi.eval(context, `(() => {
    const dec = document.getElementById("error-decoder");
    return {
      status: ${text("status")},
      decoder: dec && !dec.hidden ? dec.textContent : "",
      uart: ${text("uart-output")},
    };
  })()`);
  await screenshot(bidi, context, outDir, `${release}-mcu`);
  if (!/^Running/.test(mcu.status) || /fw_error_fatal/.test(mcu.decoder) || /MCU fatal error/i.test(mcu.uart)) {
    throw new Error(`${release} mcu: the MCU did not survive the flows: ${mcu.status}\n${mcu.decoder}\nUART (tail):\n${tail(mcu.uart, 1500)}`);
  }
  console.log(`PASS ${release} mcu: the MCU is still running (${mcu.status})`);
  await bidi.eval(context, click("btn-stop"));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!existsSync(join(WWW, "ca", "caliptra_test_ca_bg.wasm"))) {
    throw new Error("www/ca/ is missing; run ./build-wasm.sh first");
  }
  const failed = await withBrowser(async (bidi, context, baseUrl, pageErrors) => {
    // Browsers give WebCrypto (crypto.subtle) only to pages on localhost or
    // HTTPS. Take it away, so that the pages are tested the way they run
    // when the site is served from another host name over plain HTTP.
    await bidi.send("script.addPreloadScript", {
      functionDeclaration: `() => { Object.defineProperty(Crypto.prototype, "subtle", { get: () => undefined }); }`,
    });
    const releases = args.releases.length
      ? args.releases
      : JSON.parse(readFileSync(join(WWW, "versions.json"), "utf8")).releases;
    let failed = false;
    const attempt = async (fn) => {
      try {
        await fn();
      } catch (e) {
        failed = true;
        console.error(`FAIL ${e.message}`);
        await screenshot(bidi, context, args.outDir, `failure-${Date.now()}`);
      }
    };
    await attempt(() => testCaPage(bidi, context, baseUrl, args.outDir, pageErrors));
    await attempt(() => testDefaultRelease(bidi, context, baseUrl));
    for (const release of releases) {
      await attempt(() => testRelease(bidi, context, baseUrl, release, args.outDir, pageErrors));
    }
    return failed;
  });
  if (failed) process.exit(1);
  console.log("\nAll provisioning tests passed.");
}

main().catch((e) => {
  console.error(e.stack || String(e));
  process.exit(1);
});
