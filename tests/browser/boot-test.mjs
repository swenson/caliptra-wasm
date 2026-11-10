#!/usr/bin/env node
// Licensed under the Apache-2.0 license
//
// End-to-end boot test for the emulator page, run in a real (headless)
// browser.
//
// Serves www/ on a local port, launches headless Firefox, drives it over
// WebDriver BiDi (built into Firefox, so no npm packages or driver binaries
// are needed), and for each emulator mode clicks Run on the page exactly as a
// user would. Each mode must reach its boot milestones in the UART output
// without a fatal error in the page's error decoder.
//
// Usage:
//   node tests/browser/boot-test.mjs [--release 2.1]... [--mode caliptra|mcu]...
//       [--timeout SECS] [--settle SECS] [--out DIR]
//
// By default every release listed in www/versions.json is tested in both
// modes. After the boot milestones appear, each run keeps going for
// --settle seconds (default 20) and fails if anything halts in that time. With --out, each run's full UART output, final page state and a
// full-page screenshot are written to DIR/<release>-<mode>-uart.txt,
// DIR/<release>-<mode>-state.json and DIR/<release>-<mode>.png.
//
// Environment:
//   FIREFOX                 Firefox binary (default: "firefox")
//   BROWSER_TEST_PROFILE_DIR  Parent dir for the temporary Firefox profile.
//                           Defaults to the OS temp dir, or
//                           ~/snap/firefox/common/tmp for snap Firefox
//                           (which cannot see the host /tmp).
//
// Requires Node 22+ (global WebSocket).

import { spawn } from "node:child_process";
import { createReadStream, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { homedir, tmpdir } from "node:os";
import { dirname, extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const WWW = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "www");

// Boot milestones per mode. All `expect` strings must appear in the UART
// output; any `fatal` pattern fails the run immediately.
const MODES = {
  caliptra: {
    label: "Caliptra only",
    expect: ["[rt] RT listening for mailbox commands"],
  },
  mcu: {
    label: "MCU + Caliptra (subsystem)",
    expect: [
      "[mcu-rom] Hello from ROM",
      "[rt] RT listening for mailbox commands",
      "[mcu-rom] Jumping to firmware",
      "[mcu-runtime] Entering main loop.",
    ],
  },
};
// Caliptra and the MCU share one UART panel, and lines they print at the same
// moment interleave character by character (how they interleave varies from
// run to run). So a milestone counts as seen if it appears verbatim, or if its
// characters appear in order within a window a few times its length.
function seen(uart, needle) {
  if (uart.includes(needle)) return true;
  const maxSpan = needle.length * 4;
  for (let start = uart.indexOf(needle[0]); start !== -1; start = uart.indexOf(needle[0], start + 1)) {
    let j = 1;
    let i = start + 1;
    const end = Math.min(uart.length, start + maxSpan);
    for (; i < end && j < needle.length; i++) if (uart[i] === needle[j]) j++;
    if (j === needle.length) return true;
  }
  return false;
}

const FATAL_UART = [/MCU fatal error/i, /panicked at/i, /RuntimeError: unreachable/];

function parseArgs(argv) {
  const out = { releases: [], modes: [], timeout: 600, settle: 20, outDir: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--mode") out.modes.push(argv[++i]);
    else if (argv[i] === "--release") out.releases.push(argv[++i]);
    else if (argv[i] === "--timeout") out.timeout = Number(argv[++i]);
    else if (argv[i] === "--out") out.outDir = argv[++i];
    else if (argv[i] === "--settle") out.settle = Number(argv[++i]);
    else if (argv[i] === "-h" || argv[i] === "--help") {
      console.log("usage: boot-test.mjs [--release R]... [--mode caliptra|mcu]... [--timeout SECS] [--settle SECS] [--out DIR]");
      process.exit(0);
    } else throw new Error(`unknown argument: ${argv[i]}`);
  }
  if (out.modes.length === 0) out.modes = Object.keys(MODES);
  for (const m of out.modes) if (!MODES[m]) throw new Error(`unknown mode: ${m}`);
  return out;
}

// ---------------------------------------------------------------- web server

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".wasm": "application/wasm",
  ".bin": "application/octet-stream",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

function serveWww() {
  const server = createServer((req, res) => {
    let path = decodeURIComponent(new URL(req.url, "http://x").pathname);
    if (path.endsWith("/")) path += "index.html";
    const file = normalize(join(WWW, path));
    if (!file.startsWith(WWW + sep) || !existsSync(file) || !statSync(file).isFile()) {
      res.writeHead(404).end("not found");
      return;
    }
    res.writeHead(200, {
      "Content-Type": MIME[extname(file)] || "application/octet-stream",
      "Cache-Control": "no-store",
    });
    createReadStream(file).pipe(res);
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => ok(server)));
}

// ------------------------------------------------------------------- browser

function freePort() {
  return new Promise((ok, fail) => {
    const s = createServer();
    s.on("error", fail);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => ok(port));
    });
  });
}

function profileParent() {
  if (process.env.BROWSER_TEST_PROFILE_DIR) return process.env.BROWSER_TEST_PROFILE_DIR;
  // Snap-packaged Firefox has a private /tmp, so a profile created under the
  // host's /tmp is invisible to it. Use the snap's own writable area instead.
  if (!process.env.FIREFOX && existsSync("/snap/bin/firefox")) {
    return join(homedir(), "snap", "firefox", "common", "tmp");
  }
  return tmpdir();
}

async function launchFirefox() {
  const bin = process.env.FIREFOX || "firefox";
  const parent = profileParent();
  mkdirSync(parent, { recursive: true });
  const profile = mkdtempSync(join(parent, "caliptra-wasm-boot-test-"));
  const port = await freePort();
  const proc = spawn(
    bin,
    ["--headless", "--no-remote", "--profile", profile, "--remote-debugging-port", String(port), "about:blank"],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let stderr = "";
  const wsUrl = await new Promise((ok, fail) => {
    const timer = setTimeout(() => fail(new Error(`Firefox did not start BiDi within 60s:\n${stderr}`)), 60_000);
    const onData = (d) => {
      stderr += d;
      const m = stderr.match(/WebDriver BiDi listening on (ws:\/\/\S+)/);
      if (m) {
        clearTimeout(timer);
        ok(m[1]);
      }
    };
    proc.stderr.on("data", onData);
    proc.stdout.on("data", onData);
    proc.on("exit", (code) => {
      clearTimeout(timer);
      fail(new Error(`Firefox exited (${code}) before BiDi was ready:\n${stderr}`));
    });
    proc.on("error", (e) => {
      clearTimeout(timer);
      fail(new Error(`could not launch ${bin}: ${e.message}`));
    });
  });
  const cleanup = () => {
    proc.kill("SIGTERM");
    try {
      rmSync(profile, { recursive: true, force: true });
    } catch {}
  };
  return { wsUrl, cleanup, proc };
}

class Bidi {
  constructor(ws) {
    this.ws = ws;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = [];
    ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id !== undefined && this.pending.has(msg.id)) {
        const { ok, fail } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.type === "error") fail(new Error(`${msg.error}: ${msg.message}`));
        else ok(msg.result);
      } else if (msg.type === "event") {
        for (const l of this.listeners) l(msg);
      }
    });
  }

  static async connect(url) {
    const ws = new WebSocket(url.replace(/\/?$/, "/session"));
    await new Promise((ok, fail) => {
      ws.addEventListener("open", ok, { once: true });
      ws.addEventListener("error", () => fail(new Error(`cannot connect to ${url}`)), { once: true });
    });
    const bidi = new Bidi(ws);
    await bidi.send("session.new", { capabilities: { alwaysMatch: {} } });
    return bidi;
  }

  send(method, params = {}) {
    const id = this.nextId++;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((ok, fail) => this.pending.set(id, { ok, fail }));
  }

  on(fn) {
    this.listeners.push(fn);
  }

  // Evaluate `expression` in the page; it must produce a JSON-serializable
  // value (or a promise of one).
  async eval(context, expression) {
    const r = await this.send("script.evaluate", {
      expression: `(async () => JSON.stringify(await (${expression})))()`,
      target: { context },
      awaitPromise: true,
      resultOwnership: "none",
    });
    if (r.type === "exception") {
      throw new Error(`page script threw: ${r.exceptionDetails?.text}`);
    }
    return r.result.value === undefined ? undefined : JSON.parse(r.result.value);
  }
}

// ---------------------------------------------------------------------- test

const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));
const tail = (s, n = 3000) => (s.length > n ? "…" + s.slice(-n) : s);

// Release-specific UI: the version menu shows the loaded release, OCP LOCK
// is offered only where the release supports it, and mailbox commands the
// release lacks are disabled and tagged with the releases that have them.
async function checkReleaseUi(bidi, context, release) {
  const all = JSON.parse(readFileSync(join(WWW, "versions.json"), "utf8")).releases;
  const info = JSON.parse(readFileSync(join(WWW, `v${release}`, "build-info.json"), "utf8"));
  const newest = [...all].sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))[0];
  let ui;
  for (let i = 0; i < 40; i++) {
    ui = await bidi.eval(context, `(() => {
      const opts = [...document.querySelectorAll("#mbox-cmd option")];
      return {
        selected: document.getElementById("caliptra-version").value,
        ocpHidden: document.getElementById("ocp-lock").closest(".check").hidden,
        tagged: opts.filter((o) => /\\(\\d+\\.\\d+(\\+| only)\\)$/.test(o.textContent)).length,
        disabled: opts.filter((o) => o.disabled).map((o) => o.textContent),
      };
    })()`);
    if (all.length < 2 || ui.tagged > 0) break;
    await sleep(250);
  }
  const problems = [];
  if (ui.selected !== release) problems.push(`version menu shows ${ui.selected}`);
  const ocp = info.features?.ocp_lock !== false;
  if (ui.ocpHidden === ocp) problems.push(`OCP LOCK option ${ui.ocpHidden ? "hidden" : "shown"} but ocp_lock=${ocp}`);
  if (all.length > 1 && ui.tagged === 0) problems.push("no mailbox commands are tagged with a release");
  const untagged = ui.disabled.filter((t) => !/\((\d+\.\d+\+|[\d., ]+ only)\)$/.test(t));
  if (untagged.length) problems.push(`disabled without a release tag: ${untagged.join(", ")}`);
  if (release === newest && ui.disabled.length) problems.push(`newest release disables: ${ui.disabled.join(", ")}`);
  if (problems.length) throw new Error(`${release} UI: ${problems.join("; ")}`);
  console.log(
    `UI ok: ${ui.tagged} mailbox commands tagged, ${ui.disabled.length} disabled, ` +
      `OCP LOCK ${ui.ocpHidden ? "hidden" : "shown"}`,
  );
}

async function runMode(bidi, context, baseUrl, release, mode, timeoutSecs, settleSecs, outDir, pageErrors) {
  const spec = MODES[mode];
  const name = `${release}-${mode}`;
  console.log(`\n=== Caliptra ${release}: ${spec.label} (${mode}) ===`);
  pageErrors.length = 0;
  await bidi.send("browsingContext.navigate", {
    context,
    url: `${baseUrl}?version=${encodeURIComponent(release)}`,
    wait: "complete",
  });

  // Wait for WASM init + default assets.
  const readyBy = Date.now() + 60_000;
  for (;;) {
    const st = await bidi.eval(context, `({
      status: document.getElementById("status").textContent,
      runDisabled: document.getElementById("btn-run").disabled,
      badge: document.getElementById("caliptra-release-badge")?.textContent,
      buildInfo: document.getElementById("build-info")?.textContent,
    })`);
    if (st.status === "Ready" && !st.runDisabled && st.badge === `Caliptra ${release}`) {
      console.log(`page ready: ${st.badge} — ${st.buildInfo}`);
      break;
    }
    if (/failed|error/i.test(st.status)) throw new Error(`page failed to initialize: ${st.status}`);
    if (Date.now() > readyBy) {
      throw new Error(`page not ready after 60s (status: ${st.status}, badge: ${st.badge})`);
    }
    await sleep(250);
  }

  if (mode === "caliptra") await checkReleaseUi(bidi, context, release);

  // Select the mode and press Run, as a user would.
  await bidi.eval(context, `(() => {
    const sel = document.getElementById("emu-mode");
    sel.value = ${JSON.stringify(mode)};
    sel.dispatchEvent(new Event("change", { bubbles: true }));
    document.getElementById("start-paused").checked = false;
    document.getElementById("btn-run").click();
    return true;
  })()`);

  const t0 = Date.now();
  let lastReport = 0;
  let bootedAt = null; // elapsed seconds when every milestone had appeared
  for (;;) {
    await sleep(1000);
    const st = await bidi.eval(context, `(() => {
      const dec = document.getElementById("error-decoder");
      return {
        status: document.getElementById("status").textContent,
        stats: document.getElementById("stats").textContent,
        uart: document.getElementById("uart-output").textContent,
        decoder: dec && !dec.hidden ? dec.textContent : "",
      };
    })()`);
    const elapsed = (Date.now() - t0) / 1000;
    const missing = spec.expect.filter((m) => !seen(st.uart, m));
    const fatalUart = FATAL_UART.find((re) => re.test(st.uart));
    const fatalDecoder = /fw_error_fatal/.test(st.decoder);
    const save = async () => {
      if (!outDir) return;
      mkdirSync(outDir, { recursive: true });
      writeFileSync(join(outDir, `${name}-uart.txt`), st.uart);
      const { uart, ...rest } = st;
      writeFileSync(join(outDir, `${name}-state.json`), JSON.stringify({ ...rest, missing, pageErrors }, null, 2));
      try {
        const shot = await bidi.send("browsingContext.captureScreenshot", { context, origin: "document" });
        writeFileSync(join(outDir, `${name}.png`), Buffer.from(shot.data, "base64"));
      } catch (e) {
        console.warn(`screenshot failed: ${e.message}`);
      }
    };

    const fail = async (why) => {
      await save();
      throw new Error(
        `${name}: ${why}\nstatus: ${st.status}\nstats: ${st.stats}\n` +
          (st.decoder ? `error decoder:\n${st.decoder}\n` : "") +
          (pageErrors.length ? `page errors:\n${pageErrors.join("\n")}\n` : "") +
          `UART (tail):\n${tail(st.uart)}`,
      );
    };

    if (fatalUart) await fail(`fatal output in UART (${fatalUart})`);
    if (fatalDecoder) await fail("error decoder reports a fatal error");
    if (pageErrors.length) await fail("JavaScript errors on the page");
    if (/^Error|^Failed|Exited: failed|MCU halted/.test(st.status)) await fail(`emulator stopped: ${st.status}`);
    if (missing.length === 0 && bootedAt === null) {
      bootedAt = elapsed;
      console.log(`  booted in ${elapsed.toFixed(0)}s; running ${settleSecs}s more to check it stays up`);
    }
    // Keep running after boot: the MCU runtime and Caliptra keep exchanging
    // mailbox commands after the main loop starts, and a failure there halts
    // the MCU (caught above via the status and UART checks).
    if (bootedAt !== null && elapsed - bootedAt >= settleSecs) {
      await save();
      console.log(`PASS ${name}: booted in ${bootedAt.toFixed(0)}s, stayed up ${settleSecs}s — ${st.stats}`);
      if (st.decoder) console.log(`(non-fatal) error decoder:\n${st.decoder}`);
      // Stop the run loop before moving on.
      await bidi.eval(context, `(document.getElementById("btn-stop").click(), true)`);
      return;
    }
    if (bootedAt === null && elapsed > timeoutSecs) {
      await fail(`timed out after ${timeoutSecs}s; missing: ${JSON.stringify(missing)}`);
    }
    if (elapsed - lastReport >= 15) {
      lastReport = elapsed;
      console.log(`  ${elapsed.toFixed(0)}s: ${st.stats || st.status}; waiting for ${JSON.stringify(missing)}`);
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (typeof WebSocket === "undefined") throw new Error("Node 22+ is required (global WebSocket)");
  if (!existsSync(join(WWW, "versions.json"))) {
    throw new Error("www/versions.json is missing; run ./build-wasm.sh first");
  }

  const server = await serveWww();
  const baseUrl = `http://127.0.0.1:${server.address().port}/`;
  console.log(`serving ${WWW} at ${baseUrl}`);
  const ff = await launchFirefox();
  let failed = false;
  try {
    const bidi = await Bidi.connect(ff.wsUrl);
    const pageErrors = [];
    await bidi.send("session.subscribe", { events: ["log.entryAdded"] });
    bidi.on((ev) => {
      if (ev.method === "log.entryAdded" && ev.params.level === "error") {
        pageErrors.push(ev.params.text);
      }
    });
    const tree = await bidi.send("browsingContext.getTree", {});
    const context = tree.contexts[0].context;
    const releases = args.releases.length
      ? args.releases
      : JSON.parse(readFileSync(join(WWW, "versions.json"), "utf8")).releases;
    for (const release of releases) for (const mode of args.modes) {
      try {
        await runMode(bidi, context, baseUrl, release, mode, args.timeout, args.settle, args.outDir, pageErrors);
      } catch (e) {
        failed = true;
        console.error(`FAIL ${e.message}`);
      }
    }
    await bidi.send("session.end").catch(() => {});
  } finally {
    ff.cleanup();
    server.close();
  }
  if (failed) process.exit(1);
  console.log("\nAll browser boot tests passed.");
}

main().catch((e) => {
  console.error(e.stack || String(e));
  process.exit(1);
});
