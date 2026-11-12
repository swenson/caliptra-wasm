#!/usr/bin/env node
// Licensed under the Apache-2.0 license
//
// Test of the PK hash calculator and the Debug unlock page, run in a real
// (headless) browser with WebCrypto (crypto.subtle) and navigator.clipboard
// taken away. Browsers give those only to pages on localhost or HTTPS, so
// this is how the pages run when the site is served from another host name
// over plain HTTP. Every value the pages compute is checked against Node's
// own crypto.
//
// PK hash calculator: the hashes of the test keys match the newest 2.x
// release's default firmware, an edited key changes its hash to the right
// value, and the Copy buttons copy.
//
// Debug unlock: the manufacturing token hash and command, generating and
// importing a P-384 key, the public key hash, and a P-384 signature. If the
// ML-DSA library (loaded from esm.sh) is reachable, the whole production
// token is built and the ECC signature inside it verified.
//
// Usage:
//   node tests/browser/calculators-test.mjs [--out DIR]
//
// See harness.mjs for the environment variables that pick the browser.

import { createECDH, createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { WWW, sleep, withBrowser } from "./harness.mjs";

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const unhex = (text) => Buffer.from(text, "hex");
const sha = (alg, bytes) => createHash(alg).update(bytes).digest();

function parseArgs(argv) {
  const out = { outDir: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--out") out.outDir = argv[++i];
    else if (argv[i] === "-h" || argv[i] === "--help") {
      console.log("usage: calculators-test.mjs [--out DIR]");
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
    await sleep(250);
  }
}

const byId = (id) => `document.getElementById(${JSON.stringify(id)})`;
const text = (id) => `${byId(id)}.textContent`;
const value = (id) => `${byId(id)}.value`;
const setValue = (id, v) => `(() => {
  const el = ${byId(id)};
  el.value = ${JSON.stringify(v)};
  el.dispatchEvent(new Event("input", { bubbles: true }));
  return true;
})()`;

// Clicks the element that `element` (a page expression) gives, the way a
// person does, with a pointer: the browser only lets a page copy in response
// to a real click.
async function pointerClick(bidi, context, element) {
  const r = await bidi.send("script.evaluate", {
    expression: `(() => { const el = ${element}; el.scrollIntoView({ block: "center" }); return el; })()`,
    target: { context },
    awaitPromise: false,
  });
  if (r.type === "exception" || !r.result.sharedId) throw new Error(`nothing to click: ${element}`);
  const origin = { type: "element", element: { sharedId: r.result.sharedId } };
  await bidi.send("input.performActions", {
    context,
    actions: [
      {
        type: "pointer",
        id: "mouse",
        actions: [
          { type: "pointerMove", x: 0, y: 0, origin },
          { type: "pointerDown", button: 0 },
          { type: "pointerUp", button: 0 },
        ],
      },
    ],
  });
  await bidi.send("input.releaseActions", { context });
}

// Clicks a Copy button and returns what the page copied. The preload script
// records it (see main).
async function copied(bidi, context, button) {
  await bidi.eval(context, `(window.__copied = null, true)`);
  await pointerClick(bidi, context, button);
  return waitFor(bidi, context, `window.__copied`, (v) => v !== null, `the click on ${button} to copy`, 10);
}

async function open(bidi, context, url) {
  await bidi.send("browsingContext.navigate", { context, url, wait: "complete" });
  const missing = await bidi.eval(context, `[typeof crypto.subtle, typeof navigator.clipboard]`);
  if (missing.join() !== "undefined,undefined") {
    throw new Error(`WebCrypto and the clipboard API should be missing in this test; got ${missing}`);
  }
}

function expectNoErrors(pageErrors, from, what, except = null) {
  const errors = pageErrors.slice(from).filter((e) => !except || !except.test(e));
  if (errors.length) throw new Error(`${what} logged errors: ${errors.join(" | ").slice(0, 600)}`);
}

// ---------------------------------------------------------- PK hash calculator

async function testPkHash(bidi, context, baseUrl, outDir, pageErrors) {
  console.log("=== PK hash calculator ===");
  const errorsBefore = pageErrors.length;
  const versions = JSON.parse(readFileSync(join(WWW, "versions.json"), "utf8"));
  const release = versions.releases.find((r) => Number(r.split(".")[0]) >= 2);
  if (!release) {
    console.log("SKIP no 2.x release is built, and the calculator computes 2.x hashes");
    return;
  }
  const defaults = JSON.parse(readFileSync(join(WWW, `v${release}`, "defaults.json"), "utf8"));

  await open(bidi, context, `${baseUrl}pk-hash.html?version=${release}`);
  const isHash = (v) => /^[0-9a-f]{96}$/.test(v);
  const state = `({ vendor: ${text("v-hash")}, owner: ${text("o-hash")}, vendorMatch: ${text("v-match")},
    ownerMatch: ${text("o-match")}, error: ${text("load-error")} })`;
  const first = await waitFor(
    bidi, context, state,
    (s) => s.error || (isHash(s.vendor) && isHash(s.owner) && s.vendorMatch && s.ownerMatch),
    "the hashes of the test keys",
  );
  await screenshot(bidi, context, outDir, "pk-hash");
  if (first.error) throw new Error(`PK hash calculator: ${first.error}`);
  if (first.vendor !== defaults.vendor_pk_hash || first.owner !== defaults.owner_pk_hash) {
    throw new Error(`PK hash calculator: the test keys hash to ${first.vendor} / ${first.owner}, ` +
      `and v${release}/defaults.json has ${defaults.vendor_pk_hash} / ${defaults.owner_pk_hash}`);
  }
  if (!/^Matches/.test(first.vendorMatch) || !/^Matches/.test(first.ownerMatch)) {
    throw new Error(`PK hash calculator: expected both hashes to match; got "${first.vendorMatch}" and "${first.ownerMatch}"`);
  }
  console.log(`PASS the test keys' hashes match the Caliptra ${release} default firmware`);

  // Change the owner ECC key and compute the expected hash here.
  const x = randomBytes(48);
  await bidi.eval(context, setValue("oex", hex(x)));
  const owner = Buffer.concat([
    x,
    unhex(await bidi.eval(context, value("oey"))),
    unhex(await bidi.eval(context, value("om"))),
  ]);
  if (owner.length !== 2688) throw new Error(`PK hash calculator: the owner keys are ${owner.length} bytes, not 2688`);
  const expected = hex(sha("sha384", owner));
  const second = await waitFor(bidi, context, state, (s) => s.owner !== first.owner, "the owner hash to change");
  if (second.owner !== expected) {
    throw new Error(`PK hash calculator: owner hash ${second.owner} after an edit; expected ${expected}`);
  }
  if (!/^Differs/.test(second.ownerMatch) || second.vendor !== first.vendor) {
    throw new Error(`PK hash calculator: after editing the owner key: ${JSON.stringify(second)}`);
  }
  console.log("PASS an edited owner key hashes to the value Node computes");

  const hash = await copied(bidi, context, byId("btn-copy-o"));
  const words = await copied(bidi, context, byId("btn-copy-ow"));
  if (hash !== expected || words.replace(/ /g, "") !== expected || words.split(" ").length !== 12) {
    throw new Error(`PK hash calculator: copied "${hash}" and "${words}"; expected ${expected}`);
  }
  console.log("PASS the Copy buttons copy without navigator.clipboard");
  expectNoErrors(pageErrors, errorsBefore, "PK hash calculator");
}

// ---------------------------------------------------------------- Debug unlock

const ecdhPublic = (privateKey) => {
  const ecdh = createECDH("secp384r1");
  ecdh.setPrivateKey(privateKey);
  return ecdh.getPublicKey().subarray(1); // drop the 0x04 of the uncompressed point
};

const p384Verifies = (publicKey, message, signature) =>
  verify(
    "sha384",
    message,
    {
      key: createPublicKey({
        key: {
          kty: "EC",
          crv: "P-384",
          x: publicKey.subarray(0, 48).toString("base64url"),
          y: publicKey.subarray(48).toString("base64url"),
        },
        format: "jwk",
      }),
      dsaEncoding: "ieee-p1363",
    },
    signature,
  );

// Caliptra's hardware format for ECC values: each 4-byte group reversed.
const swapWords = (bytes) => {
  const out = Buffer.from(bytes);
  for (let i = 0; i < out.length; i += 4) out.subarray(i, i + 4).reverse();
  return out;
};

// The mailbox checksum: 0 minus the sum of the command id's bytes and the
// payload's bytes.
const checksum = (cmd, payload) => {
  let sum = 0;
  for (const b of [cmd & 0xff, (cmd >>> 8) & 0xff, (cmd >>> 16) & 0xff, cmd >>> 24, ...payload]) sum += b;
  const out = Buffer.alloc(4);
  out.writeUInt32LE((0x100000000 - (sum % 0x100000000)) % 0x100000000);
  return out;
};

async function testDebugUnlock(bidi, context, baseUrl, outDir, pageErrors) {
  console.log("=== Debug unlock ===");
  const errorsBefore = pageErrors.length;
  await open(bidi, context, `${baseUrl}debug-unlock.html`);

  // Manufacturing: both default tokens are hashed when the page loads.
  for (const [input, hashId, cmdId] of [
    ["manuf-token", "manuf-hash", "manuf-cmd"],
    ["manuf-token-otp", "manuf-hash-otp", "manuf-cmd-otp"],
  ]) {
    const state = `({ token: ${value(input)}, hash: ${text(hashId)}, cmd: ${text(cmdId)}, error: ${text("load-error")} })`;
    const s = await waitFor(bidi, context, state, (v) => v.error || (v.hash && v.cmd), `the ${input} hash`);
    if (s.error) throw new Error(`Debug unlock: ${s.error}`);
    const token = unhex(s.token);
    const cmd = hex(Buffer.concat([checksum(0x4d445554, token), token]));
    if (s.hash !== hex(sha("sha512", token)) || s.cmd !== cmd) {
      throw new Error(`Debug unlock: ${input} gave hash ${s.hash} and command ${s.cmd}`);
    }
  }
  console.log("PASS manufacturing: both default tokens hash to SHA-512 and build the command");
  const payload = await copied(bidi, context, `document.querySelector("[onclick=\\"copyPayload('manuf-cmd')\\"]")`);
  if (payload !== (await bidi.eval(context, value("manuf-token")))) {
    throw new Error(`Debug unlock: Copy payload copied "${payload}"`);
  }
  console.log("PASS Copy payload copies without navigator.clipboard");

  // ECC keys: a generated pair, then an imported one.
  const eccState = `({ status: ${text("ecc-status")}, d: ${value("ecc-priv-d")}, x: ${value("ecc-pub-x")}, y: ${value("ecc-pub-y")} })`;
  await bidi.eval(context, `(generateEccKeys(), true)`);
  const generated = await bidi.eval(context, eccState);
  if (generated.status !== "Generated" || generated.x + generated.y !== hex(ecdhPublic(unhex(generated.d)))) {
    throw new Error(`Debug unlock: generated ECC key: ${JSON.stringify(generated)}`);
  }
  const d = createECDH("secp384r1");
  d.generateKeys();
  const privateKey = Buffer.concat([Buffer.alloc(48), d.getPrivateKey()]).subarray(-48);
  const publicKey = ecdhPublic(privateKey);
  await bidi.eval(context, setValue("ecc-priv-d", hex(privateKey)));
  await bidi.eval(context, `(importEccPrivateKey(), true)`);
  const imported = await bidi.eval(context, eccState);
  if (imported.status !== "Imported" || imported.x + imported.y !== hex(publicKey)) {
    throw new Error(`Debug unlock: imported ECC key: ${JSON.stringify(imported)}; expected ${hex(publicKey)}`);
  }
  await bidi.eval(context, setValue("ecc-priv-d", "00".repeat(48)));
  await bidi.eval(context, `(importEccPrivateKey(), true)`);
  const refused = await bidi.eval(context, eccState);
  if (!/^Import failed: not a valid P-384 private key/.test(refused.status) || refused.x + refused.y !== hex(publicKey)) {
    throw new Error(`Debug unlock: importing a zero private key: ${JSON.stringify(refused)}`);
  }
  await bidi.eval(context, setValue("ecc-priv-d", hex(privateKey)));
  console.log("PASS ECC: generated and imported keys have the public key Node derives; a zero key is refused");

  // A P-384 signature straight from the module the page signs with.
  const message = randomBytes(84);
  const direct = await bidi.eval(
    context,
    `import("./ca-core.js").then((m) => m.toHex(m.p384Sign(m.fromHex(${JSON.stringify(hex(privateKey))}), m.fromHex(${JSON.stringify(hex(message))}))))`,
  );
  if (!p384Verifies(publicKey, message, unhex(direct))) {
    throw new Error(`Debug unlock: Node does not verify the P-384 signature ${direct}`);
  }
  console.log("PASS ECC: Node verifies a signature from the page's signing module");

  // The ML-DSA library comes from esm.sh. Without it the page can still
  // import keys, which is enough for the public key hash.
  const lib = await waitFor(
    bidi, context, text("mldsa-lib-status"), (v) => /^Library (loaded|unavailable)/.test(v),
    "the ML-DSA library to load or fail",
  );
  const haveMldsa = /^Library loaded/.test(lib);
  if (haveMldsa) {
    await bidi.eval(context, `(generateMldsaKeys(), true)`);
  } else {
    await bidi.eval(context, setValue("mldsa-pub", hex(randomBytes(2592))));
    await bidi.eval(context, setValue("mldsa-sec", hex(randomBytes(4896))));
    await bidi.eval(context, `(importMldsaKeys(), true)`);
  }
  const mldsaStatus = await waitFor(
    bidi, context, text("mldsa-status"), (v) => /^(Generated \(|Imported|Error)/.test(v), "the ML-DSA keys", 120,
  );
  if (/^Error/.test(mldsaStatus)) throw new Error(`Debug unlock: ML-DSA keys: ${mldsaStatus}`);
  const mldsaPublic = unhex(await bidi.eval(context, value("mldsa-pub")));
  const pkHash = await bidi.eval(context, text("pk-hash-output"));
  const expectedPkHash = hex(sha("sha384", Buffer.concat([swapWords(publicKey), mldsaPublic])));
  if (pkHash !== expectedPkHash) {
    throw new Error(`Debug unlock: public key hash ${pkHash}; expected ${expectedPkHash}`);
  }
  console.log("PASS the public key hash is the SHA-384 Node computes");

  if (!haveMldsa) {
    console.log(`SKIP the production token: the ML-DSA library did not load (${lib})`);
    // The browser logs the failed load itself.
    expectNoErrors(pageErrors, errorsBefore, "Debug unlock", /esm\.sh/);
    return;
  }

  // The production token for a made-up challenge.
  const level = 3;
  const uid = randomBytes(32);
  const challenge = randomBytes(48);
  const response = Buffer.concat([Buffer.alloc(4), Buffer.from([20, 0, 0, 0]), uid, challenge]);
  await bidi.eval(context, setValue("unlock-level", String(level)));
  await bidi.eval(context, setValue("challenge-hex", hex(response)));
  await bidi.eval(context, `(parseChallenge(), true)`);
  await bidi.eval(context, `(signAndBuildToken(), true)`);
  const signStatus = await waitFor(
    bidi, context, text("sign-status"), (v) => /^(Token built|Error)/.test(v), "the token to be signed", 120,
  );
  await screenshot(bidi, context, outDir, "debug-unlock");
  if (!/^Token built \(7504 bytes\)/.test(signStatus)) throw new Error(`Debug unlock: signing: ${signStatus}`);
  const token = unhex(await bidi.eval(context, text("prod-token-cmd")));
  const body = token.subarray(4);
  const signed = Buffer.concat([uid, Buffer.from([level, 0, 0, 0]), challenge]);
  const fields = {
    checksum: [token.subarray(0, 4), checksum(0x50445554, body)],
    length: [body.subarray(0, 4), Buffer.from([0x53, 0x07, 0, 0])], // 7500 bytes in 4-byte words
    "uid, level and challenge": [body.subarray(4, 88), signed],
    "ECC public key": [body.subarray(88, 184), swapWords(publicKey)],
    "ML-DSA public key": [body.subarray(184, 2776), mldsaPublic],
  };
  for (const [name, [got, want]] of Object.entries(fields)) {
    if (!got.equals(want)) throw new Error(`Debug unlock: token ${name} is ${hex(got).slice(0, 200)}; expected ${hex(want).slice(0, 200)}`);
  }
  if (!p384Verifies(publicKey, signed, swapWords(body.subarray(2776, 2872)))) {
    throw new Error("Debug unlock: Node does not verify the token's ECC signature");
  }
  console.log("PASS the production token carries the keys and an ECC signature that Node verifies");
  expectNoErrors(pageErrors, errorsBefore, "Debug unlock");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!existsSync(join(WWW, "ca", "caliptra_test_ca_bg.wasm"))) {
    throw new Error("www/ca/ is missing; run ./build-wasm.sh first");
  }
  const failed = await withBrowser(async (bidi, context, baseUrl, pageErrors) => {
    // Take away what browsers keep for localhost and HTTPS pages, and record
    // what the pages copy: the fallback copies the text of a focused field.
    await bidi.send("script.addPreloadScript", {
      functionDeclaration: `() => {
        Object.defineProperty(Crypto.prototype, "subtle", { get: () => undefined });
        Object.defineProperty(Navigator.prototype, "clipboard", { get: () => undefined });
        window.__copied = null;
        document.addEventListener("copy", () => {
          const field = document.activeElement;
          window.__copied = field && "value" in field ? field.value : String(document.getSelection());
        });
      }`,
    });
    let failed = false;
    for (const test of [testPkHash, testDebugUnlock]) {
      try {
        await test(bidi, context, baseUrl, args.outDir, pageErrors);
      } catch (e) {
        failed = true;
        console.error(`FAIL ${e.message}`);
        await screenshot(bidi, context, args.outDir, `failure-${Date.now()}`);
      }
    }
    return failed;
  });
  if (failed) process.exit(1);
  console.log("\nAll calculator tests passed.");
}

main().catch((e) => {
  console.error(e.stack || String(e));
  process.exit(1);
});
