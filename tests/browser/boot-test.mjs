#!/usr/bin/env node
// Licensed under the Apache-2.0 license
//
// End-to-end boot test for the emulator page, run in a real (headless)
// browser.
//
// Serves www/ on a local port, launches headless Firefox, drives it over
// WebDriver BiDi (see harness.mjs), and for each emulator mode clicks Run on
// the page exactly as a user would. Each mode must reach its boot milestones
// in the UART output without a fatal error in the page's error decoder.
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
// See harness.mjs for the environment variables that pick the browser.
//
// Requires Node 22+ (global WebSocket).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { WWW, sleep, tail, withBrowser } from "./harness.mjs";

// Boot milestones per mode. Every `expect` entry must appear in the UART
// output (an array entry means any one of its strings); any `fatal` pattern
// fails the run immediately. Caliptra runtimes before 1.2 say "Runtime
// listening" where later ones say "RT listening".
const RT_READY = ["[rt] RT listening for mailbox commands", "[rt] Runtime listening for mailbox commands"];

const MODES = {
  caliptra: {
    label: "Caliptra only",
    expect: [RT_READY],
  },
  mcu: {
    label: "MCU + Caliptra (subsystem)",
    expect: [
      "[mcu-rom] Hello from ROM",
      RT_READY,
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

// ---------------------------------------------------------------------- test

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
        tagged: opts.filter((o) => /\\([^()]*(\\+|only)\\)$/.test(o.textContent)).length,
        disabled: opts.filter((o) => o.disabled).map((o) => o.textContent),
        mcuDisabled: document.querySelector('#emu-mode option[value="mcu"]').disabled,
        subsystemShown: [...document.querySelectorAll("[data-subsystem-only], #soc-manifest-row, #mcu-fw-row")]
          .some((el) => !el.hidden) || !document.getElementById("subsystem-mode").closest(".check").hidden,
        romChoices: document.getElementById("rom-release-row").hidden ? 0 : document.querySelectorAll("#rom-release option").length,
        fwChoices: document.getElementById("fw-release-row").hidden ? 0 : document.querySelectorAll("#fw-release option").length,
        vendorPk: document.getElementById("vendor-pk").value,
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
  // Tags look like "(2.1+)", "(1.1 only)" or "(1.1 only, runtime 1.3+)".
  const untagged = ui.disabled.filter((t) => !/\([^()]*(\+|only)\)$/.test(t));
  if (untagged.length) problems.push(`disabled without a release tag: ${untagged.join(", ")}`);
  // The newest release can only lack commands that older releases dropped or
  // never shared (e.g. 1.x's PQ.DevID commands), tagged "... only".
  const newestDisables = ui.disabled.filter((t) => !/ only[,)]/.test(t));
  if (release === newest && newestDisables.length) problems.push(`newest release disables: ${newestDisables.join(", ")}`);
  if (info.features?.subsystem === false) {
    if (!ui.mcuDisabled) problems.push("MCU mode is offered without a subsystem");
    if (ui.subsystemShown) problems.push("subsystem-only options are shown");
  }
  if (existsSync(join(WWW, `v${release}`, "firmware.json"))) {
    const fw = JSON.parse(readFileSync(join(WWW, `v${release}`, "firmware.json"), "utf8"));
    if (ui.romChoices !== fw.roms.length || ui.fwChoices !== fw.firmware.length) {
      problems.push(`release pickers offer ${ui.romChoices} ROMs / ${ui.fwChoices} firmware, expected ${fw.roms.length} / ${fw.firmware.length}`);
    }
    if (!/^[0-9a-f]{96}$/.test(ui.vendorPk)) problems.push(`vendor PK hash not filled from the firmware (${ui.vendorPk})`);
  }
  if (problems.length) throw new Error(`${release} UI: ${problems.join("; ")}`);
  console.log(
    `UI ok: ${ui.tagged} mailbox commands tagged, ${ui.disabled.length} disabled, ` +
      `OCP LOCK ${ui.ocpHidden ? "hidden" : "shown"}` +
      (ui.romChoices ? `, ${ui.romChoices} ROM / ${ui.fwChoices} firmware releases` : ""),
  );
}

// Choose a ROM and firmware release in the pickers and wait until both are
// loaded and the vendor PK hash has been refilled from the new bundle.
async function pickReleases(bidi, context, picks) {
  const before = await bidi.eval(context, `document.getElementById("vendor-pk").value`);
  await bidi.eval(context, `(() => {
    for (const [id, value] of [["rom-release", ${JSON.stringify(picks.rom.id)}], ["fw-release", ${JSON.stringify(picks.firmware.id)}]]) {
      const sel = document.getElementById(id);
      sel.value = value;
      sel.dispatchEvent(new Event("change", { bubbles: true }));
    }
    return true;
  })()`);
  for (let i = 0; i < 40; i++) {
    const st = await bidi.eval(context, `({
      rom: document.getElementById("rom-release-info").textContent,
      fw: document.getElementById("fw-release-info").textContent,
      vendor: document.getElementById("vendor-pk").value,
    })`);
    if (st.rom.includes(`ROM ${picks.rom.version} `) && st.fw.includes(`Runtime ${picks.firmware.version} `)) {
      console.log(`picked ROM ${picks.rom.version} and firmware ${picks.firmware.version}` +
        (st.vendor !== before ? "; vendor PK hash refilled from the bundle" : ""));
      return;
    }
    await sleep(250);
  }
  throw new Error(`picking ROM ${picks.rom.version} / firmware ${picks.firmware.version} did not take effect`);
}

// Send VERSION from the Mailbox panel, as a user would, and expect a decoded
// response.
async function checkMailboxPanel(bidi, context, name) {
  await bidi.eval(context, `(() => {
    const sel = document.getElementById("mbox-cmd");
    sel.value = "VERSION";
    sel.dispatchEvent(new Event("change", { bubbles: true }));
    document.getElementById("btn-mbox-send").click();
    return true;
  })()`);
  for (let i = 0; i < 60; i++) {
    await sleep(500);
    const out = await bidi.eval(context, `document.getElementById("mbox-response").textContent`);
    if (/Error/.test(out)) throw new Error(`${name}: mailbox VERSION failed:\n${out}`);
    if (/--- Decoded ---/.test(out)) {
      console.log(`  mailbox VERSION ok`);
      return;
    }
  }
  throw new Error(`${name}: mailbox VERSION got no response`);
}

// On releases with the PQ.DevID card enabled (1.x runtime 1.3+), provision
// the seed and read the public key and CSR through it.
async function checkPqDevId(bidi, context, name) {
  const card = await bidi.eval(context, `(() => {
    const card = document.getElementById("pq-card");
    return { shown: !card.hidden, enabled: !document.getElementById("pq-provision").disabled };
  })()`);
  if (!card.shown || !card.enabled) return;
  const steps = [
    ["pq-provision", "Provision seed", null],
    ["pq-info", "Public key", (out) => /public key \(2592 bytes\)/.test(out)],
    ["pq-csr", "CSR", (out) => /BEGIN CERTIFICATE REQUEST/.test(out)],
  ];
  for (const [button, label, check] of steps) {
    await bidi.eval(context, `(document.getElementById(${JSON.stringify(button)}).click(), true)`);
    const t0 = Date.now();
    for (;;) {
      await sleep(1000);
      const st = await bidi.eval(context, `({
        status: document.getElementById("pq-status").textContent,
        output: document.getElementById("pq-output").textContent,
        downloads: document.querySelectorAll("#pq-downloads a").length,
      })`);
      if (st.status.endsWith("failed")) throw new Error(`${name}: PQ.DevID ${label} failed:\n${st.output}`);
      if (st.status.startsWith(`${label}: done`)) {
        if (check && !check(st.output)) throw new Error(`${name}: PQ.DevID ${label} output unexpected:\n${st.output.slice(0, 300)}`);
        console.log(`  PQ.DevID ${st.status}${st.downloads ? `, ${st.downloads} download` : ""}`);
        break;
      }
      if (Date.now() - t0 > 180_000) throw new Error(`${name}: PQ.DevID ${label} did not finish in 180s (${st.status})`);
    }
  }
}

async function runMode(bidi, context, baseUrl, run, timeoutSecs, settleSecs, outDir, pageErrors) {
  const { release, mode, picks } = run;
  const spec = MODES[mode];
  const pickName = picks ? `-rom${picks.rom.version}-fw${picks.firmware.version}` : "";
  const name = `${release}-${mode}${pickName}`;
  const pickLabel = picks ? `, ROM ${picks.rom.version} + firmware ${picks.firmware.version}` : "";
  console.log(`\n=== Caliptra ${release}: ${spec.label} (${mode})${pickLabel} ===`);
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

  if (mode === "caliptra" && !picks) await checkReleaseUi(bidi, context, release);
  if (picks) {
    await pickReleases(bidi, context, picks);
    // PQ.DevID needs runtime 1.3; with an older runtime its card is disabled.
    const pq = await bidi.eval(context, `({
      shown: !document.getElementById("pq-card").hidden,
      disabled: document.getElementById("pq-provision").disabled,
    })`);
    const want = !picks.firmware.version.startsWith("1.3");
    if (pq.shown && pq.disabled !== want) {
      throw new Error(`${name}: PQ.DevID card ${pq.disabled ? "disabled" : "enabled"} with runtime ${picks.firmware.version}`);
    }
    if (pq.shown) console.log(`  PQ.DevID card ${pq.disabled ? "disabled" : "enabled"} for runtime ${picks.firmware.version}`);
  }

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
    const missing = spec.expect.filter((m) => ![].concat(m).some((alt) => seen(st.uart, alt)));
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
      await checkMailboxPanel(bidi, context, name);
      if (mode === "caliptra" && !picks) await checkPqDevId(bidi, context, name);
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
  const failed = await withBrowser(async (bidi, context, baseUrl, pageErrors) => {
    const releases = args.releases.length
      ? args.releases
      : JSON.parse(readFileSync(join(WWW, "versions.json"), "utf8")).releases;
    // Every release in each mode it supports; releases whose ROM and firmware
    // are picked from official releases (1.x) also boot the oldest pair
    // through the pickers.
    const runs = [];
    for (const release of releases) {
      const info = JSON.parse(readFileSync(join(WWW, `v${release}`, "build-info.json"), "utf8"));
      for (const mode of args.modes) {
        if (mode === "mcu" && info.features?.subsystem === false) continue;
        runs.push({ release, mode });
      }
      const fwPath = join(WWW, `v${release}`, "firmware.json");
      if (args.modes.includes("caliptra") && existsSync(fwPath)) {
        const fw = JSON.parse(readFileSync(fwPath, "utf8"));
        runs.push({ release, mode: "caliptra", picks: { rom: fw.roms[0], firmware: fw.firmware[0] } });
      }
    }
    let failed = false;
    for (const run of runs) {
      try {
        await runMode(bidi, context, baseUrl, run, args.timeout, args.settle, args.outDir, pageErrors);
      } catch (e) {
        failed = true;
        console.error(`FAIL ${e.message}`);
      }
    }
    return failed;
  });
  if (failed) process.exit(1);
  console.log("\nAll browser boot tests passed.");
}

main().catch((e) => {
  console.error(e.stack || String(e));
  process.exit(1);
});
