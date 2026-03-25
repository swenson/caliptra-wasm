// Caliptra WASM Emulator - JavaScript glue
import init, { CaliptraEmulator } from "./caliptra_wasm_demo.js";

// DOM elements
const romFileInput = document.getElementById("rom-file");
const romInfo = document.getElementById("rom-info");
const fwFileInput = document.getElementById("fw-file");
const fwInfo = document.getElementById("fw-info");
const socManifestFileInput = document.getElementById("soc-manifest-file");
const socManifestInfo = document.getElementById("soc-manifest-info");
const mcuFwFileInput = document.getElementById("mcu-fw-file");
const mcuFwInfo = document.getElementById("mcu-fw-info");
const vendorPkInput = document.getElementById("vendor-pk");
const ownerPkInput = document.getElementById("owner-pk");
const lifecycleSelect = document.getElementById("lifecycle");
const subsystemModeInput = document.getElementById("subsystem-mode");
const ocpLockInput = document.getElementById("ocp-lock");
const btnRun = document.getElementById("btn-run");
const btnStop = document.getElementById("btn-stop");
const btnReset = document.getElementById("btn-reset");
const statusEl = document.getElementById("status");
const statsEl = document.getElementById("stats");
const uartOutput = document.getElementById("uart-output");
const logOutput = document.getElementById("log-output");
const mboxCmdSelect = document.getElementById("mbox-cmd");
const btnMboxSend = document.getElementById("btn-mbox-send");
const mboxResponse = document.getElementById("mbox-response");
const mboxParams = document.getElementById("mbox-params");
const mboxShaAlgo = document.getElementById("mbox-sha-algo");
const mboxShaInput = document.getElementById("mbox-sha-input");

// Show/hide CM SHA params based on selected command
mboxCmdSelect.addEventListener("change", () => {
  mboxParams.style.display = mboxCmdSelect.value === "CM_SHA_HASH" ? "block" : "none";
});

// State
let emulator = null;
let running = false;
let animFrameId = null;
let defaultRom = null;
let customRom = null;
let defaultFw = null;
let customFw = null;
let customSocManifest = null;
let defaultSocManifest = null;
let defaultMcuFw = null;
let customMcuFw = null;
let startTime = 0;

// Steps per animation frame — balance between speed and UI responsiveness
const STEPS_PER_FRAME = 50_000;

// Initialize WASM module and load defaults
async function startup() {
  try {
    await init();
    setStatus("Loading defaults...", "");

    // Load default ROM, FW, and hash defaults in parallel
    const [romResp, fwResp, defaultsResp, socManifestResp, mcuFwResp] = await Promise.allSettled([
      fetch("default-rom.bin"),
      fetch("default-fw.bin"),
      fetch("defaults.json"),
      fetch("default-soc-manifest.bin"),
      fetch("default-mcu-fw.bin"),
    ]);

    if (romResp.status === "fulfilled" && romResp.value.ok) {
      defaultRom = new Uint8Array(await romResp.value.arrayBuffer());
      romInfo.textContent = `Default ROM loaded (${(defaultRom.length / 1024).toFixed(0)} KB)`;
    } else {
      romInfo.textContent = "No default ROM — please upload one";
    }

    if (fwResp.status === "fulfilled" && fwResp.value.ok) {
      defaultFw = new Uint8Array(await fwResp.value.arrayBuffer());
      fwInfo.textContent = `Default FW loaded (${(defaultFw.length / 1024).toFixed(0)} KB)`;
    } else {
      fwInfo.textContent = "(optional) No default FW";
    }

    if (defaultsResp.status === "fulfilled" && defaultsResp.value.ok) {
      const defaults = await defaultsResp.value.json();
      if (defaults.vendor_pk_hash) {
        vendorPkInput.value = defaults.vendor_pk_hash;
      }
      if (defaults.owner_pk_hash && defaults.owner_pk_hash !== "0".repeat(96)) {
        ownerPkInput.value = defaults.owner_pk_hash;
      }
    }

    if (socManifestResp.status === "fulfilled" && socManifestResp.value.ok) {
      defaultSocManifest = new Uint8Array(await socManifestResp.value.arrayBuffer());
    }

    if (mcuFwResp.status === "fulfilled" && mcuFwResp.value.ok) {
      defaultMcuFw = new Uint8Array(await mcuFwResp.value.arrayBuffer());
    }

    setStatus("Ready", "");
    btnRun.disabled = false;
    btnReset.disabled = false;
  } catch (err) {
    setStatus(`WASM init failed: ${err}`, "exited");
    console.error("WASM init error:", err);
  }
}

// Handle custom ROM file upload
romFileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    customRom = new Uint8Array(reader.result);
    romInfo.textContent = `${file.name} (${(customRom.length / 1024).toFixed(0)} KB)`;
  };
  reader.readAsArrayBuffer(file);
});

// Handle custom FW file upload
fwFileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    customFw = new Uint8Array(reader.result);
    fwInfo.textContent = `${file.name} (${(customFw.length / 1024).toFixed(0)} KB)`;
  };
  reader.readAsArrayBuffer(file);
});

// Handle SoC manifest file upload
socManifestFileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    customSocManifest = new Uint8Array(reader.result);
    socManifestInfo.textContent = `${file.name} (${(customSocManifest.length / 1024).toFixed(0)} KB)`;
  };
  reader.readAsArrayBuffer(file);
});

// Handle MCU firmware file upload
mcuFwFileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    customMcuFw = new Uint8Array(reader.result);
    mcuFwInfo.textContent = `${file.name} (${customMcuFw.length} bytes)`;
  };
  reader.readAsArrayBuffer(file);
});

// Get the ROM/FW to use (custom upload takes priority)
function getRom() {
  return customRom || defaultRom;
}
function getFw() {
  return customFw || defaultFw || null;
}
function getSocManifest() {
  return customSocManifest || defaultSocManifest || null;
}
function getMcuFw() {
  return customMcuFw || defaultMcuFw || null;
}

// Create emulator instance
function createEmulator() {
  const rom = getRom();
  if (!rom) {
    setStatus("No ROM loaded — upload a ROM file", "stopped");
    return false;
  }

  const vendorPk = vendorPkInput.value.trim();
  const ownerPk = ownerPkInput.value.trim();
  const fw = getFw();
  const socManifest = getSocManifest();
  const mcuFw = getMcuFw();
  const lifecycle = lifecycleSelect.value;
  const subsystemMode = subsystemModeInput.checked;
  const ocpLock = ocpLockInput.checked;

  try {
    // Free previous emulator if any
    if (emulator) {
      emulator.free();
      emulator = null;
    }
    emulator = new CaliptraEmulator(
      rom,
      vendorPk,
      ownerPk,
      fw,
      socManifest,
      lifecycle,
      subsystemMode,
      ocpLock,
      mcuFw
    );

    // Check for boot error — show logs even if boot failed
    const bootErr = emulator.boot_error();
    if (bootErr) {
      uartOutput.textContent = bootErr;
      const log = emulator.get_log();
      if (log) logOutput.textContent = log;
    } else {
      uartOutput.textContent = "";
      logOutput.textContent = "";
    }
    statsEl.textContent = "";
    btnMboxSend.disabled = false;
    return true;
  } catch (err) {
    setStatus(`Error: ${err}`, "exited");
    console.error("Emulator creation error:", err);
    return false;
  }
}

// Run loop using requestAnimationFrame
function runLoop() {
  if (!running || !emulator) return;

  const stillRunning = emulator.step(STEPS_PER_FRAME);

  // Collect output
  const uart = emulator.get_uart_output();
  if (uart) {
    uartOutput.textContent += uart;
    uartOutput.scrollTop = uartOutput.scrollHeight;
  }

  const log = emulator.get_log();
  if (log) {
    logOutput.textContent += log;
    logOutput.scrollTop = logOutput.scrollHeight;
  }

  // Update stats
  const steps = Number(emulator.total_steps());
  const elapsed = (performance.now() - startTime) / 1000;
  const mhz = (steps / elapsed / 1_000_000).toFixed(2);
  statsEl.textContent = `${steps.toLocaleString()} cycles | ${elapsed.toFixed(1)}s | ${mhz} MHz effective`;

  if (!stillRunning) {
    running = false;
    const passed = emulator.passed();
    setStatus(
      passed ? "Exited — PASSED ✓" : "Exited — FAILED ✗",
      passed ? "passed" : "exited"
    );
    btnRun.disabled = true;
    btnStop.disabled = true;
    return;
  }

  animFrameId = requestAnimationFrame(runLoop);
}

// Button handlers
btnRun.addEventListener("click", () => {
  if (running) return;

  if (!emulator) {
    if (!createEmulator()) return;
  }

  running = true;
  startTime = performance.now();
  setStatus("Running...", "running");
  btnRun.disabled = true;
  btnStop.disabled = false;
  romFileInput.disabled = true;
  fwFileInput.disabled = true;
  socManifestFileInput.disabled = true;
  mcuFwFileInput.disabled = true;
  vendorPkInput.disabled = true;
  ownerPkInput.disabled = true;
  lifecycleSelect.disabled = true;
  subsystemModeInput.disabled = true;
  ocpLockInput.disabled = true;

  animFrameId = requestAnimationFrame(runLoop);
});

btnStop.addEventListener("click", () => {
  running = false;
  if (animFrameId) {
    cancelAnimationFrame(animFrameId);
    animFrameId = null;
  }
  setStatus("Stopped", "stopped");
  btnRun.disabled = false;
  btnStop.disabled = true;
});

btnReset.addEventListener("click", () => {
  running = false;
  if (animFrameId) {
    cancelAnimationFrame(animFrameId);
    animFrameId = null;
  }
  if (emulator) {
    emulator.free();
    emulator = null;
  }
  uartOutput.textContent = "";
  logOutput.textContent = "";
  mboxResponse.textContent = "";
  statsEl.textContent = "";
  setStatus("Ready", "");
  btnRun.disabled = false;
  btnStop.disabled = true;
  btnMboxSend.disabled = true;
  romFileInput.disabled = false;
  fwFileInput.disabled = false;
  socManifestFileInput.disabled = false;
  mcuFwFileInput.disabled = false;
  vendorPkInput.disabled = false;
  ownerPkInput.disabled = false;
  lifecycleSelect.disabled = false;
  subsystemModeInput.disabled = false;
  ocpLockInput.disabled = false;
});

function setStatus(text, className) {
  statusEl.textContent = text;
  statusEl.className = "status" + (className ? " " + className : "");
}

// --- Mailbox command definitions ---

const MBOX_COMMANDS = {
  FW_INFO: {
    id: 0x494E464F,
    name: "FW_INFO",
    makeRequest: () => makeHeaderOnlyRequest(0x494E464F),
    formatResponse: formatFwInfoResp,
  },
  FIPS_VERSION: {
    id: 0x46505652,
    name: "FIPS_VERSION",
    makeRequest: () => makeHeaderOnlyRequest(0x46505652),
    formatResponse: formatFipsVersionResp,
  },
  CAPABILITIES: {
    id: 0x43415053,
    name: "CAPABILITIES",
    makeRequest: () => makeHeaderOnlyRequest(0x43415053),
    formatResponse: formatCapabilitiesResp,
  },
};

// Caliptra checksum: 0 - (SUM(cmd LE bytes) + SUM(payload after checksum field))
function calcChecksum(cmdId, payloadAfterChecksum) {
  let sum = 0;
  // Add command ID bytes (little-endian)
  for (let i = 0; i < 4; i++) {
    sum = (sum + ((cmdId >>> (i * 8)) & 0xff)) >>> 0;
  }
  // Add payload bytes after the checksum field
  for (const b of payloadAfterChecksum) {
    sum = (sum + b) >>> 0;
  }
  return (0x100000000 - sum) >>> 0;
}

function makeHeaderOnlyRequest(cmdId) {
  // MailboxReqHeader is just a 4-byte checksum; no payload after it
  const buf = new Uint8Array(4);
  const chksum = calcChecksum(cmdId, new Uint8Array(0));
  buf[0] = chksum & 0xff;
  buf[1] = (chksum >>> 8) & 0xff;
  buf[2] = (chksum >>> 16) & 0xff;
  buf[3] = (chksum >>> 24) & 0xff;
  return buf;
}

function writeU32LE(buf, offset, value) {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >>> 8) & 0xff;
  buf[offset + 2] = (value >>> 16) & 0xff;
  buf[offset + 3] = (value >>> 24) & 0xff;
}

function makeChecksummedRequest(cmdId, payloadAfterChecksum) {
  const buf = new Uint8Array(4 + payloadAfterChecksum.length);
  buf.set(payloadAfterChecksum, 4);
  const chksum = calcChecksum(cmdId, payloadAfterChecksum);
  writeU32LE(buf, 0, chksum);
  return buf;
}

// --- CM SHA constants ---
const CM_SHA_CONTEXT_SIZE = 200;
const CM_SHA_MAX_INPUT = 4096;
const CMD_CM_SHA_INIT   = 0x434D5349;
const CMD_CM_SHA_UPDATE = 0x434D5355;
const CMD_CM_SHA_FINAL  = 0x434D5346;

// Build a CM_SHA_INIT request: [chksum:4][hash_algorithm:4][input_size:4][input:N]
function makeCmShaInitReq(hashAlgo, inputBytes) {
  const payload = new Uint8Array(4 + 4 + inputBytes.length);
  writeU32LE(payload, 0, hashAlgo);
  writeU32LE(payload, 4, inputBytes.length);
  payload.set(inputBytes, 8);
  return makeChecksummedRequest(CMD_CM_SHA_INIT, payload);
}

// Build a CM_SHA_UPDATE request: [chksum:4][context:200][input_size:4][input:N]
function makeCmShaUpdateReq(context, inputBytes) {
  const payload = new Uint8Array(CM_SHA_CONTEXT_SIZE + 4 + inputBytes.length);
  payload.set(context, 0);
  writeU32LE(payload, CM_SHA_CONTEXT_SIZE, inputBytes.length);
  payload.set(inputBytes, CM_SHA_CONTEXT_SIZE + 4);
  return makeChecksummedRequest(CMD_CM_SHA_UPDATE, payload);
}

// Build a CM_SHA_FINAL request: [chksum:4][context:200][input_size:4][input:N]
function makeCmShaFinalReq(context, inputBytes) {
  const payload = new Uint8Array(CM_SHA_CONTEXT_SIZE + 4 + inputBytes.length);
  payload.set(context, 0);
  writeU32LE(payload, CM_SHA_CONTEXT_SIZE, inputBytes.length);
  payload.set(inputBytes, CM_SHA_CONTEXT_SIZE + 4);
  return makeChecksummedRequest(CMD_CM_SHA_FINAL, payload);
}

// Execute CM SHA INIT→(UPDATE)*→FINAL and return formatted result
function executeCmShaHash(emu) {
  const hashAlgo = parseInt(mboxShaAlgo.value);
  const algoName = hashAlgo === 1 ? "SHA-384" : "SHA-512";
  const digestLen = hashAlgo === 1 ? 48 : 64;
  const inputText = mboxShaInput.value;
  const inputBytes = new TextEncoder().encode(inputText);

  let s = `CM SHA Hash (${algoName})\n`;
  s += `  Input: "${inputText}" (${inputBytes.length} bytes)\n\n`;

  // Split input into chunks of CM_SHA_MAX_INPUT
  const chunks = [];
  for (let i = 0; i < inputBytes.length; i += CM_SHA_MAX_INPUT) {
    chunks.push(inputBytes.slice(i, i + CM_SHA_MAX_INPUT));
  }

  // INIT with first chunk (or empty if no data)
  const firstChunk = chunks.length > 0 ? chunks[0] : new Uint8Array(0);
  s += `  → CM_SHA_INIT (${firstChunk.length} bytes)...\n`;
  const initReq = makeCmShaInitReq(hashAlgo, firstChunk);
  const initResp = emu.mailbox_execute(CMD_CM_SHA_INIT, initReq);
  if (initResp == null || initResp.length < 8 + CM_SHA_CONTEXT_SIZE) {
    s += `  ✗ INIT failed (got ${initResp ? initResp.length : 0} bytes)\n`;
    return s;
  }
  const initBuf = new Uint8Array(initResp);
  const initFips = readU32LE(initBuf, 4);
  if (initFips !== 0) {
    s += `  ✗ INIT fips_status: ${initFips}\n`;
    return s;
  }
  let context = initBuf.slice(8, 8 + CM_SHA_CONTEXT_SIZE);
  s += `  ✓ INIT OK\n`;

  // UPDATE with middle chunks
  for (let i = 1; i < chunks.length - 1; i++) {
    s += `  → CM_SHA_UPDATE chunk ${i} (${chunks[i].length} bytes)...\n`;
    const updateReq = makeCmShaUpdateReq(context, chunks[i]);
    const updateResp = emu.mailbox_execute(CMD_CM_SHA_UPDATE, updateReq);
    if (updateResp == null || updateResp.length < 8 + CM_SHA_CONTEXT_SIZE) {
      s += `  ✗ UPDATE failed\n`;
      return s;
    }
    const updateBuf = new Uint8Array(updateResp);
    context = updateBuf.slice(8, 8 + CM_SHA_CONTEXT_SIZE);
    s += `  ✓ UPDATE OK\n`;
  }

  // FINAL with last chunk (or empty if only one chunk was used in INIT)
  const lastChunk = chunks.length > 1 ? chunks[chunks.length - 1] : new Uint8Array(0);
  s += `  → CM_SHA_FINAL (${lastChunk.length} bytes)...\n`;
  const finalReq = makeCmShaFinalReq(context, lastChunk);
  const finalResp = emu.mailbox_execute(CMD_CM_SHA_FINAL, finalReq);
  if (finalResp == null || finalResp.length < 12) {
    s += `  ✗ FINAL failed (got ${finalResp ? finalResp.length : 0} bytes)\n`;
    return s;
  }
  const finalBuf = new Uint8Array(finalResp);
  const finalFips = readU32LE(finalBuf, 4);
  if (finalFips !== 0) {
    s += `  ✗ FINAL fips_status: ${finalFips}\n`;
    return s;
  }
  // Response: [chksum:4][fips_status:4][data_len:4][hash:...]
  const dataLen = readU32LE(finalBuf, 8);
  const hash = finalBuf.slice(12, 12 + Math.min(dataLen, digestLen));
  s += `  ✓ FINAL OK\n\n`;
  s += `  ${algoName} digest (${hash.length} bytes):\n`;
  s += `  ${hexBytes(hash, 0, hash.length)}\n`;

  return s;
}

function readU32LE(buf, offset) {
  return (
    buf[offset] |
    (buf[offset + 1] << 8) |
    (buf[offset + 2] << 16) |
    (buf[offset + 3] << 24)
  ) >>> 0;
}

function hexBytes(buf, offset, len) {
  return Array.from(buf.slice(offset, offset + len))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexU32BE(words, offset, count) {
  let s = "";
  for (let i = 0; i < count; i++) {
    s += words[i + offset].toString(16).padStart(8, "0");
  }
  return s;
}

function readU32LEArray(buf, offset, count) {
  const result = [];
  for (let i = 0; i < count; i++) {
    result.push(readU32LE(buf, offset + i * 4));
  }
  return result;
}

function formatRespHeader(buf) {
  const chksum = readU32LE(buf, 0);
  const fipsStatus = readU32LE(buf, 4);
  return `  chksum:      0x${chksum.toString(16).padStart(8, "0")}\n` +
         `  fips_status: ${fipsStatus === 0 ? "APPROVED (0)" : fipsStatus}\n`;
}

function formatFwInfoResp(buf) {
  if (buf.length < 8) return "Error: response too short";
  let s = "FwInfoResp:\n" + formatRespHeader(buf);
  if (buf.length < 196) {
    s += `  (truncated — got ${buf.length} bytes, expected ≥196)\n`;
    s += `  raw: ${hexBytes(buf, 8, buf.length - 8)}\n`;
    return s;
  }
  let off = 8;
  s += `  pl0_pauser:              ${readU32LE(buf, off)}\n`; off += 4;
  s += `  fw_svn:                  ${readU32LE(buf, off)}\n`; off += 4;
  s += `  min_fw_svn:              ${readU32LE(buf, off)}\n`; off += 4;
  s += `  cold_boot_fw_svn:        ${readU32LE(buf, off)}\n`; off += 4;
  s += `  attestation_disabled:    ${readU32LE(buf, off)}\n`; off += 4;
  s += `  rom_revision:            ${hexBytes(buf, off, 20)}\n`; off += 20;
  s += `  fmc_revision:            ${hexBytes(buf, off, 20)}\n`; off += 20;
  s += `  runtime_revision:        ${hexBytes(buf, off, 20)}\n`; off += 20;
  const romDigest = readU32LEArray(buf, off, 8); off += 32;
  s += `  rom_sha256_digest:       ${hexU32BE(romDigest, 0, 8)}\n`;
  const fmcDigest = readU32LEArray(buf, off, 12); off += 48;
  s += `  fmc_sha384_digest:       ${hexU32BE(fmcDigest, 0, 12)}\n`;
  const rtDigest = readU32LEArray(buf, off, 12); off += 48;
  s += `  runtime_sha384_digest:   ${hexU32BE(rtDigest, 0, 12)}\n`;
  const ownerPk = readU32LEArray(buf, off, 12); off += 48;
  s += `  owner_pub_key_hash:      ${hexU32BE(ownerPk, 0, 12)}\n`;
  const authmanDigest = readU32LEArray(buf, off, 12); off += 48;
  s += `  authman_sha384_digest:   ${hexU32BE(authmanDigest, 0, 12)}\n`;
  s += `  most_recent_fw_error:    0x${readU32LE(buf, off).toString(16).padStart(8, "0")}\n`;
  return s;
}

function formatFipsVersionResp(buf) {
  if (buf.length < 8) return "Error: response too short";
  let s = "FipsVersionResp:\n" + formatRespHeader(buf);
  if (buf.length < 32) {
    s += `  (truncated — got ${buf.length} bytes)\n`;
    return s;
  }
  let off = 8;
  s += `  mode:     ${readU32LE(buf, off)}\n`; off += 4;
  const rev0 = readU32LE(buf, off); off += 4;
  const rev1 = readU32LE(buf, off); off += 4;
  const rev2 = readU32LE(buf, off); off += 4;
  s += `  fips_rev: [${rev0}, ${rev1}, ${rev2}]\n`;
  const nameBytes = buf.slice(off, off + 12);
  const name = new TextDecoder().decode(nameBytes).replace(/\0+$/, "");
  s += `  name:     "${name}"\n`;
  return s;
}

function formatCapabilitiesResp(buf) {
  if (buf.length < 8) return "Error: response too short";
  let s = "CapabilitiesResp:\n" + formatRespHeader(buf);
  if (buf.length < 24) {
    s += `  (truncated — got ${buf.length} bytes)\n`;
    return s;
  }
  s += `  capabilities: ${hexBytes(buf, 8, 16)}\n`;
  return s;
}

// --- Mailbox Send handler ---

btnMboxSend.addEventListener("click", () => {
  if (!emulator) {
    mboxResponse.textContent = "Error: no emulator instance";
    return;
  }

  const cmdKey = mboxCmdSelect.value;

  // Pause the run loop while executing the mailbox command
  const wasRunning = running;
  if (wasRunning) {
    running = false;
    if (animFrameId) {
      cancelAnimationFrame(animFrameId);
      animFrameId = null;
    }
  }

  try {
    if (cmdKey === "CM_SHA_HASH") {
      mboxResponse.textContent = executeCmShaHash(emulator);
    } else {
      const cmd = MBOX_COMMANDS[cmdKey];
      if (!cmd) {
        mboxResponse.textContent = `Unknown command: ${cmdKey}`;
        return;
      }
      mboxResponse.textContent = `Sending ${cmd.name} (0x${cmd.id.toString(16).padStart(8, "0")})...\n`;
      const reqData = cmd.makeRequest();
      const respData = emulator.mailbox_execute(cmd.id, reqData);

      if (respData == null) {
        mboxResponse.textContent += "Command succeeded (no response data)\n";
      } else {
        const buf = new Uint8Array(respData);
        mboxResponse.textContent += cmd.formatResponse(buf);
      }
    }

    // Drain any UART/log output produced during command execution
    const uart = emulator.get_uart_output();
    if (uart) {
      uartOutput.textContent += uart;
      uartOutput.scrollTop = uartOutput.scrollHeight;
    }
    const log = emulator.get_log();
    if (log) {
      logOutput.textContent += log;
      logOutput.scrollTop = logOutput.scrollHeight;
    }
  } catch (err) {
    mboxResponse.textContent += `Error: ${err}\n`;
  }

  // Resume the run loop if it was running
  if (wasRunning) {
    running = true;
    animFrameId = requestAnimationFrame(runLoop);
  }
});

// Start
startup();
