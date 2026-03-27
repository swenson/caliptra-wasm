// Caliptra WASM Emulator - JavaScript glue
import init, { CaliptraEmulator, McuEmulator } from "./caliptra_wasm_demo.js";

// DOM elements
const emuModeSelect = document.getElementById("emu-mode");
const romFileInput = document.getElementById("rom-file");
const romInfo = document.getElementById("rom-info");
const fwFileInput = document.getElementById("fw-file");
const fwInfo = document.getElementById("fw-info");
const socManifestFileInput = document.getElementById("soc-manifest-file");
const socManifestInfo = document.getElementById("soc-manifest-info");
const mcuFwFileInput = document.getElementById("mcu-fw-file");
const mcuFwInfo = document.getElementById("mcu-fw-info");
const mcuRomFileInput = document.getElementById("mcu-rom-file");
const mcuRomInfo = document.getElementById("mcu-rom-info");
const mcuRomRow = document.getElementById("mcu-rom-row");
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
const mboxPayload = document.getElementById("mbox-payload");
const mboxFormFields = document.getElementById("mbox-form-fields");
const mboxRawInput = document.getElementById("mbox-raw-input");

function getInputMode() {
  const r = document.querySelector('input[name="mbox-input-mode"]:checked');
  return r ? r.value : "form";
}

function updateInputSection(cmdKey, mode) {
  const fields = COMMAND_FIELDS[cmdKey] || [];
  const hasFields = fields.length > 0;

  if (mode === "form") {
    mboxRawInput.style.display = "none";
    mboxFormFields.style.display = "block";
    renderFormFields(fields);
  } else {
    mboxFormFields.style.display = "none";
    mboxRawInput.style.display = "block";
    const cmd = COMMAND_INFO[cmdKey];
    if (hasFields || (cmd && cmd.hasInput)) {
      mboxPayload.placeholder = "Enter payload hex bytes after checksum (e.g., 01020304)";
      mboxPayload.disabled = false;
    } else {
      mboxPayload.placeholder = "Header-only command — no payload needed";
      mboxPayload.disabled = true;
    }
    mboxPayload.value = "";
  }
}

function renderFormFields(fields) {
  mboxFormFields.innerHTML = "";
  if (fields.length === 0) {
    const msg = document.createElement("div");
    msg.style.cssText = "color: var(--muted); font-size: 0.85rem; padding: 8px 0;";
    msg.textContent = "Header-only command \u2014 no additional parameters";
    mboxFormFields.appendChild(msg);
    return;
  }
  for (const field of fields) {
    const row = document.createElement("div");
    row.className = "form-row";
    row.style.marginBottom = "8px";

    const label = document.createElement("label");
    label.textContent = field.desc || field.name;
    label.title = `${field.name} (${field.type}${field.size ? ", " + field.size + " bytes" : ""})`;
    row.appendChild(label);

    let input;
    if (field.type === "u32") {
      input = document.createElement("input");
      input.type = "number";
      input.value = "0";
      input.min = "0";
      input.max = "4294967295";
      input.dataset.fieldName = field.name;
      input.dataset.fieldType = "u32";
    } else if (field.type === "enum") {
      input = document.createElement("select");
      for (const opt of field.options) {
        const o = document.createElement("option");
        o.value = opt.value;
        o.textContent = opt.label;
        input.appendChild(o);
      }
      input.dataset.fieldName = field.name;
      input.dataset.fieldType = "enum";
    } else if (field.type === "hex") {
      const placeholder = "00".repeat(Math.min(field.size, 8)) + (field.size > 8 ? "\u2026" : "");
      if (field.size > 32) {
        input = document.createElement("textarea");
        input.rows = Math.min(3, Math.ceil(field.size / 32));
        input.placeholder = placeholder;
      } else {
        input = document.createElement("input");
        input.type = "text";
        input.placeholder = placeholder;
      }
      input.spellcheck = false;
      input.dataset.fieldName = field.name;
      input.dataset.fieldType = "hex";
      input.dataset.fieldSize = field.size;
    }

    row.appendChild(input);
    mboxFormFields.appendChild(row);
  }
}

function serializeFormFields(cmdKey) {
  const fields = COMMAND_FIELDS[cmdKey] || [];
  if (fields.length === 0) return new Uint8Array(0);

  const parts = [];
  for (const field of fields) {
    const el = mboxFormFields.querySelector(`[data-field-name="${field.name}"]`);
    if (!el) throw new Error(`Form field not found: ${field.name}`);

    if (field.type === "u32") {
      const val = (parseInt(el.value) || 0) >>> 0;
      const buf = new Uint8Array(4);
      writeU32LE(buf, 0, val);
      parts.push(buf);
    } else if (field.type === "enum") {
      const val = (parseInt(el.value) || 0) >>> 0;
      const buf = new Uint8Array(4);
      writeU32LE(buf, 0, val);
      parts.push(buf);
    } else if (field.type === "hex") {
      const hexStr = (el.value || "").trim();
      const bytes = hexStr.length > 0 ? parseHexPayload(hexStr) : new Uint8Array(0);
      const buf = new Uint8Array(field.size);
      buf.set(bytes.slice(0, field.size));
      parts.push(buf);
    }
  }
  const totalLen = parts.reduce((s, p) => s + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

// Show/hide Caliptra-only vs MCU fields based on emulator mode
function updateModeVisibility() {
  const isMcu = emuModeSelect.value === "mcu";
  // MCU ROM row is only relevant in MCU mode
  mcuRomRow.style.display = isMcu ? "flex" : "none";
  // Caliptra-only options hidden in MCU mode (MCU handles these internally)
  vendorPkInput.closest(".form-row").style.display = isMcu ? "none" : "flex";
  ownerPkInput.closest(".form-row").style.display = isMcu ? "none" : "flex";
  lifecycleSelect.closest(".form-row").style.display = isMcu ? "none" : "flex";
  subsystemModeInput.closest(".form-row").style.display = isMcu ? "none" : "flex";
  ocpLockInput.closest(".form-row").style.display = isMcu ? "none" : "flex";
}
emuModeSelect.addEventListener("change", updateModeVisibility);
updateModeVisibility();

// Show/hide fields based on selected command and input mode
mboxCmdSelect.addEventListener("change", () => {
  const val = mboxCmdSelect.value;
  if (val === "CM_SHA_HASH") {
    mboxParams.style.display = "block";
    mboxRawInput.style.display = "none";
    mboxFormFields.style.display = "none";
  } else {
    mboxParams.style.display = "none";
    updateInputSection(val, getInputMode());
  }
});

document.querySelectorAll('input[name="mbox-input-mode"]').forEach(radio => {
  radio.addEventListener("change", () => {
    const val = mboxCmdSelect.value;
    if (val === "CM_SHA_HASH") return;
    updateInputSection(val, radio.value);
  });
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
let defaultMcuRom = null;
let customMcuFw = null;
let customMcuRom = null;
let startTime = 0;

// Steps per animation frame — balance between speed and UI responsiveness
const STEPS_PER_FRAME = 50_000;

// Initialize WASM module and load defaults
async function startup() {
  try {
    await init();
    setStatus("Loading defaults...", "");

    // Load default ROM, FW, and hash defaults in parallel
    const [romResp, fwResp, defaultsResp, socManifestResp, mcuFwResp, mcuRomResp] = await Promise.allSettled([
      fetch("default-rom.bin"),
      fetch("default-fw.bin"),
      fetch("defaults.json"),
      fetch("default-soc-manifest.bin"),
      fetch("default-mcu-fw.bin"),
      fetch("default-mcu-rom.bin"),
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

    if (mcuRomResp.status === "fulfilled" && mcuRomResp.value.ok) {
      defaultMcuRom = new Uint8Array(await mcuRomResp.value.arrayBuffer());
      mcuRomInfo.textContent = `Default MCU ROM loaded (${(defaultMcuRom.length / 1024).toFixed(1)} KB)`;
    } else {
      mcuRomInfo.textContent = "No default MCU ROM — upload one for MCU mode";
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

// Handle MCU ROM file upload
mcuRomFileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    customMcuRom = new Uint8Array(reader.result);
    mcuRomInfo.textContent = `${file.name} (${(customMcuRom.length / 1024).toFixed(1)} KB)`;
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
function getMcuRom() {
  return customMcuRom || defaultMcuRom || null;
}

// Create emulator instance
function createEmulator() {
  const rom = getRom();
  if (!rom) {
    setStatus("No Caliptra ROM loaded — upload a ROM file", "stopped");
    return false;
  }

  const mode = emuModeSelect.value;

  try {
    // Free previous emulator if any
    if (emulator) {
      emulator.free();
      emulator = null;
    }

    if (mode === "mcu") {
      // MCU + Caliptra mode
      const mcuRom = getMcuRom();
      if (!mcuRom) {
        setStatus("No MCU ROM loaded — upload an MCU ROM file", "stopped");
        return false;
      }
      const fw = getFw();
      const socManifest = getSocManifest();
      const mcuFw = getMcuFw();

      emulator = new McuEmulator(
        rom,
        fw || new Uint8Array(0),
        socManifest || new Uint8Array(0),
        mcuRom,
        mcuFw || new Uint8Array(0)
      );

      uartOutput.textContent = "";
      logOutput.textContent = "";
    } else {
      // Caliptra-only mode
      const vendorPk = vendorPkInput.value.trim();
      const ownerPk = ownerPkInput.value.trim();
      const fw = getFw();
      const socManifest = getSocManifest();
      const mcuFw = getMcuFw();
      const lifecycle = lifecycleSelect.value;
      const subsystemMode = subsystemModeInput.checked;
      const ocpLock = ocpLockInput.checked;

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
    }

    statsEl.textContent = "";
    btnMboxSend.disabled = (mode === "mcu"); // mailbox only for Caliptra-only mode for now
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

  const isMcu = emuModeSelect.value === "mcu";

  if (isMcu) {
    emulator.step(STEPS_PER_FRAME);
  } else {
    var stillRunning = emulator.step(STEPS_PER_FRAME);
  }

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

  if (!isMcu && !stillRunning) {
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
  emuModeSelect.disabled = true;
  romFileInput.disabled = true;
  fwFileInput.disabled = true;
  socManifestFileInput.disabled = true;
  mcuFwFileInput.disabled = true;
  mcuRomFileInput.disabled = true;
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
  emuModeSelect.disabled = false;
  romFileInput.disabled = false;
  fwFileInput.disabled = false;
  socManifestFileInput.disabled = false;
  mcuFwFileInput.disabled = false;
  mcuRomFileInput.disabled = false;
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

// --- Command registry: every mailbox command ---

const COMMAND_INFO = {
  // FIPS Commands
  VERSION:                { id: 0x46505652, hasInput: false },
  SELF_TEST_START:        { id: 0x46504C54, hasInput: false },
  SELF_TEST_GET_RESULTS:  { id: 0x46504C67, hasInput: false },
  SHUTDOWN:               { id: 0x46505344, hasInput: false },
  // Info / Status
  FW_INFO:                { id: 0x494E464F, hasInput: false },
  CAPABILITIES:           { id: 0x43415053, hasInput: false },
  GET_IMAGE_INFO:         { id: 0x494D4530, hasInput: true },
  GET_MCU_FW_SIZE:        { id: 0x474D4653, hasInput: false },
  // Certificate Commands (ECC384)
  GET_IDEV_ECC384_CERT:         { id: 0x49444543, hasInput: true },
  GET_IDEV_ECC384_INFO:         { id: 0x49444549, hasInput: false },
  POPULATE_IDEV_ECC384_CERT:    { id: 0x49444550, hasInput: true },
  GET_LDEV_ECC384_CERT:         { id: 0x4C444556, hasInput: true },
  GET_FMC_ALIAS_ECC384_CERT:    { id: 0x43455246, hasInput: true },
  GET_RT_ALIAS_ECC384_CERT:     { id: 0x43455252, hasInput: true },
  GET_IDEV_ECC384_CSR:          { id: 0x49444352, hasInput: true },
  GET_FMC_ALIAS_ECC384_CSR:     { id: 0x464D4352, hasInput: true },
  GET_ATTESTED_ECC384_CSR:      { id: 0x41454352, hasInput: true },
  // Certificate Commands (MLDSA87)
  GET_IDEV_MLDSA87_CERT:        { id: 0x49444D43, hasInput: true },
  GET_IDEV_MLDSA87_INFO:        { id: 0x49444D49, hasInput: false },
  POPULATE_IDEV_MLDSA87_CERT:   { id: 0x49444D50, hasInput: true },
  GET_LDEV_MLDSA87_CERT:        { id: 0x4C444D43, hasInput: true },
  GET_FMC_ALIAS_MLDSA87_CERT:   { id: 0x434D4346, hasInput: true },
  GET_RT_ALIAS_MLDSA87_CERT:    { id: 0x434D4352, hasInput: true },
  GET_IDEV_MLDSA87_CSR:         { id: 0x49444D52, hasInput: true },
  GET_FMC_ALIAS_MLDSA87_CSR:    { id: 0x464D4452, hasInput: true },
  GET_ATTESTED_MLDSA87_CSR:     { id: 0x414D4352, hasInput: true },
  // Signature Verification
  ECDSA384_SIGNATURE_VERIFY:    { id: 0x45435632, hasInput: true },
  LMS_SIGNATURE_VERIFY:         { id: 0x4C4D5632, hasInput: true },
  MLDSA87_SIGNATURE_VERIFY:     { id: 0x4D4C5632, hasInput: true },
  // Measurement / DPE
  STASH_MEASUREMENT:             { id: 0x4D454153, hasInput: true },
  INVOKE_DPE_ECC384:             { id: 0x44504543, hasInput: true },
  INVOKE_DPE_MLDSA87:            { id: 0x4450454D, hasInput: true },
  DPE_TAG_TCI:                   { id: 0x54514754, hasInput: true },
  DPE_GET_TAGGED_TCI:            { id: 0x47544744, hasInput: true },
  REALLOCATE_DPE_CONTEXT_LIMITS: { id: 0x52435458, hasInput: true },
  // PCR
  INCREMENT_PCR_RESET_COUNTER:   { id: 0x50435252, hasInput: true },
  QUOTE_PCRS_ECC384:             { id: 0x50435251, hasInput: true },
  QUOTE_PCRS_MLDSA87:            { id: 0x5043524D, hasInput: true },
  EXTEND_PCR:                    { id: 0x50435245, hasInput: true },
  GET_PCR_LOG:                   { id: 0x504C4F47, hasInput: false },
  // Attestation
  DISABLE_ATTESTATION:           { id: 0x4453424C, hasInput: false },
  ADD_SUBJECT_ALT_NAME:          { id: 0x414C544E, hasInput: true },
  CERTIFY_KEY_EXTENDED_ECC384:   { id: 0x434B4558, hasInput: true },
  CERTIFY_KEY_EXTENDED_MLDSA87:  { id: 0x434B584D, hasInput: true },
  // Firmware
  ACTIVATE_FIRMWARE:             { id: 0x41435446, hasInput: true },
  FIRMWARE_LOAD:                 { id: 0x46574C44, hasInput: true },
  FIRMWARE_VERIFY:               { id: 0x46575652, hasInput: false },
  // Auth Manifest
  SET_AUTH_MANIFEST:             { id: 0x41544D4E, hasInput: true },
  VERIFY_AUTH_MANIFEST:          { id: 0x4154564D, hasInput: true },
  AUTHORIZE_AND_STASH:           { id: 0x41545348, hasInput: true },
  // Recovery
  RI_DOWNLOAD_FIRMWARE:          { id: 0x52494644, hasInput: true },
  RI_DOWNLOAD_ENCRYPTED_FIRMWARE:{ id: 0x52494645, hasInput: true },
  // Key Management
  SIGN_WITH_EXPORTED_ECDSA:      { id: 0x53574545, hasInput: true },
  SIGN_WITH_EXPORTED_MLDSA:      { id: 0x53574D4C, hasInput: true },
  REVOKE_EXPORTED_CDI_HANDLE:    { id: 0x52564348, hasInput: true },
  INSTALL_OWNER_PK_HASH:         { id: 0x4F574E50, hasInput: true },
  ZEROIZE_UDS_FE:                { id: 0x5A455546, hasInput: true },
  FE_PROG:                       { id: 0x46455052, hasInput: true },
  // Crypto Manager (CM) — individual commands (composite CM_SHA_HASH handled separately)
  CM_STATUS:                     { id: 0x434D5354, hasInput: false },
  CM_IMPORT:                     { id: 0x434D494D, hasInput: true },
  CM_DELETE:                     { id: 0x434D444C, hasInput: true },
  CM_CLEAR:                      { id: 0x434D434C, hasInput: false },
  CM_SHA:                        { id: 0x434D5348, hasInput: true },
  CM_SHA_INIT:                   { id: 0x434D5349, hasInput: true },
  CM_SHA_UPDATE:                 { id: 0x434D5355, hasInput: true },
  CM_SHA_FINAL:                  { id: 0x434D5346, hasInput: true },
  CM_SHAKE256_INIT:              { id: 0x434D5849, hasInput: true },
  CM_SHAKE256_UPDATE:            { id: 0x434D5855, hasInput: true },
  CM_SHAKE256_FINAL:             { id: 0x434D5846, hasInput: true },
  CM_RANDOM_GENERATE:            { id: 0x434D5247, hasInput: true },
  CM_RANDOM_STIR:                { id: 0x434D5253, hasInput: true },
  CM_AES_ENCRYPT_INIT:           { id: 0x434D4149, hasInput: true },
  CM_AES_ENCRYPT_UPDATE:         { id: 0x434D4155, hasInput: true },
  CM_AES_DECRYPT_INIT:           { id: 0x434D414A, hasInput: true },
  CM_AES_DECRYPT_UPDATE:         { id: 0x434D4156, hasInput: true },
  CM_AES_GCM_ENCRYPT_INIT:       { id: 0x434D4749, hasInput: true },
  CM_AES_GCM_SPDM_ENCRYPT_INIT: { id: 0x434D5345, hasInput: true },
  CM_AES_GCM_ENCRYPT_UPDATE:     { id: 0x434D4755, hasInput: true },
  CM_AES_GCM_ENCRYPT_FINAL:      { id: 0x434D4746, hasInput: true },
  CM_AES_GCM_DECRYPT_INIT:       { id: 0x434D4449, hasInput: true },
  CM_AES_GCM_SPDM_DECRYPT_INIT: { id: 0x434D5344, hasInput: true },
  CM_AES_GCM_DECRYPT_UPDATE:     { id: 0x434D4455, hasInput: true },
  CM_AES_GCM_DECRYPT_FINAL:      { id: 0x434D4446, hasInput: true },
  CM_AES_GCM_DECRYPT_DMA:        { id: 0x434D4444, hasInput: true },
  CM_ECDH_GENERATE:              { id: 0x434D4547, hasInput: true },
  CM_ECDH_FINISH:                { id: 0x434D4546, hasInput: true },
  CM_HMAC:                       { id: 0x434D484D, hasInput: true },
  CM_HMAC_KDF_COUNTER:           { id: 0x434D4B43, hasInput: true },
  CM_HKDF_EXTRACT:               { id: 0x434D4B54, hasInput: true },
  CM_HKDF_EXPAND:                { id: 0x434D4B50, hasInput: true },
  CM_MLDSA_PUBLIC_KEY:           { id: 0x434D4D50, hasInput: true },
  CM_MLDSA_SIGN:                 { id: 0x434D4D53, hasInput: true },
  CM_MLDSA_VERIFY:               { id: 0x434D4D56, hasInput: true },
  CM_ECDSA_PUBLIC_KEY:           { id: 0x434D4550, hasInput: true },
  CM_ECDSA_SIGN:                 { id: 0x434D4553, hasInput: true },
  CM_ECDSA_VERIFY:               { id: 0x434D4556, hasInput: true },
  CM_DERIVE_STABLE_KEY:          { id: 0x494D4453, hasInput: true },
  CM_MLKEM_KEY_GEN:              { id: 0x434D4C4B, hasInput: true },
  CM_MLKEM_ENCAPSULATE:          { id: 0x434D4C45, hasInput: true },
  CM_MLKEM_DECAPSULATE:          { id: 0x434D4C44, hasInput: true },
  // Debug
  MANUF_DEBUG_UNLOCK_REQ_TOKEN:       { id: 0x4D445554, hasInput: true },
  PRODUCTION_AUTH_DEBUG_UNLOCK_REQ:    { id: 0x50445552, hasInput: true },
  PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN:  { id: 0x50445554, hasInput: true },
  EXTERNAL_MAILBOX_CMD:               { id: 0x4558544D, hasInput: true },
  // OCP Lock
  OCP_LOCK_REPORT_HEK_METADATA:      { id: 0x52484D54, hasInput: true },
  OCP_LOCK_GET_ALGORITHMS:            { id: 0x47414C47, hasInput: false },
  OCP_LOCK_INITIALIZE_MEK_SECRET:     { id: 0x494D4B53, hasInput: true },
  OCP_LOCK_MIX_MPK:                   { id: 0x4D4D504B, hasInput: true },
  OCP_LOCK_DERIVE_MEK:                { id: 0x444D454B, hasInput: true },
  OCP_LOCK_ENUMERATE_HPKE_HANDLES:    { id: 0x4548444C, hasInput: true },
  OCP_LOCK_ROTATE_HPKE_KEY:           { id: 0x5248504B, hasInput: true },
  OCP_LOCK_GENERATE_MEK:              { id: 0x474D454B, hasInput: true },
  OCP_LOCK_GET_HPKE_PUB_KEY:          { id: 0x4748504B, hasInput: true },
  OCP_LOCK_GENERATE_MPK:              { id: 0x474D504B, hasInput: true },
  OCP_LOCK_REWRAP_MPK:                { id: 0x52455750, hasInput: true },
  OCP_LOCK_ENABLE_MPK:                { id: 0x524D504B, hasInput: true },
  OCP_LOCK_TEST_ACCESS_KEY:           { id: 0x5441434B, hasInput: true },
  OCP_LOCK_CLEAR_KEY_CACHE:           { id: 0x434C4B43, hasInput: true },
  OCP_LOCK_GET_STATUS:                { id: 0x47535441, hasInput: false },
  OCP_LOCK_UNLOAD_MEK:                { id: 0x554D454B, hasInput: true },
  OCP_LOCK_LOAD_MEK:                  { id: 0x4C4D454B, hasInput: true },
};

// --- Field schemas for structured form input ---
const COMMAND_FIELDS = {
  // Header-only commands
  VERSION: [],
  SELF_TEST_START: [],
  SELF_TEST_GET_RESULTS: [],
  SHUTDOWN: [],
  FW_INFO: [],
  CAPABILITIES: [],
  GET_MCU_FW_SIZE: [],
  GET_IDEV_ECC384_INFO: [],
  GET_IDEV_MLDSA87_INFO: [],
  GET_PCR_LOG: [],
  DISABLE_ATTESTATION: [],
  FIRMWARE_VERIFY: [],
  CM_STATUS: [],
  CM_CLEAR: [],
  OCP_LOCK_GET_ALGORITHMS: [],
  OCP_LOCK_GET_STATUS: [],
  GET_LDEV_ECC384_CERT: [],
  GET_FMC_ALIAS_ECC384_CERT: [],
  GET_RT_ALIAS_ECC384_CERT: [],
  GET_IDEV_ECC384_CSR: [],
  GET_FMC_ALIAS_ECC384_CSR: [],
  GET_LDEV_MLDSA87_CERT: [],
  GET_FMC_ALIAS_MLDSA87_CERT: [],
  GET_RT_ALIAS_MLDSA87_CERT: [],
  GET_IDEV_MLDSA87_CSR: [],
  GET_FMC_ALIAS_MLDSA87_CSR: [],

  // Complex commands — use raw hex
  FIRMWARE_LOAD: [],
  RI_DOWNLOAD_FIRMWARE: [],
  RI_DOWNLOAD_ENCRYPTED_FIRMWARE: [],
  OCP_LOCK_INITIALIZE_MEK_SECRET: [],
  OCP_LOCK_MIX_MPK: [],
  OCP_LOCK_DERIVE_MEK: [],
  OCP_LOCK_GENERATE_MPK: [],
  OCP_LOCK_REWRAP_MPK: [],
  OCP_LOCK_ENABLE_MPK: [],
  OCP_LOCK_TEST_ACCESS_KEY: [],
  OCP_LOCK_UNLOAD_MEK: [],
  OCP_LOCK_LOAD_MEK: [],

  // --- Commands with fields ---

  ACTIVATE_FIRMWARE: [
    {name: "fw_id_count", type: "u32", desc: "Number of FW IDs"},
    {name: "fw_ids", type: "hex", size: 128, desc: "FW ID array (u32[32])"},
    {name: "mcu_fw_image_size", type: "u32", desc: "MCU FW image size"},
  ],

  GET_IDEV_ECC384_CERT: [
    {name: "tbs_size", type: "u32", desc: "TBS data size"},
    {name: "signature_r", type: "hex", size: 48, desc: "ECDSA signature R"},
    {name: "signature_s", type: "hex", size: 48, desc: "ECDSA signature S"},
    {name: "tbs", type: "hex", size: 512, desc: "TBS certificate data"},
  ],

  GET_IDEV_MLDSA87_CERT: [
    {name: "tbs_size", type: "u32", desc: "TBS data size"},
    {name: "signature", type: "hex", size: 4628, desc: "MLDSA87 signature"},
    {name: "tbs", type: "hex", size: 512, desc: "TBS certificate data"},
  ],

  POPULATE_IDEV_ECC384_CERT: [
    {name: "cert_size", type: "u32", desc: "Certificate size"},
    {name: "cert", type: "hex", size: 1024, desc: "Certificate data"},
  ],

  POPULATE_IDEV_MLDSA87_CERT: [
    {name: "cert_size", type: "u32", desc: "Certificate size"},
    {name: "cert", type: "hex", size: 1024, desc: "Certificate data"},
  ],

  GET_ATTESTED_ECC384_CSR: [
    {name: "key_id", type: "u32", desc: "Key ID"},
    {name: "nonce", type: "hex", size: 32, desc: "Nonce (32 bytes)"},
  ],

  GET_ATTESTED_MLDSA87_CSR: [
    {name: "key_id", type: "u32", desc: "Key ID"},
    {name: "nonce", type: "hex", size: 32, desc: "Nonce (32 bytes)"},
  ],

  ECDSA384_SIGNATURE_VERIFY: [
    {name: "pub_key_x", type: "hex", size: 48, desc: "Public key X"},
    {name: "pub_key_y", type: "hex", size: 48, desc: "Public key Y"},
    {name: "signature_r", type: "hex", size: 48, desc: "Signature R"},
    {name: "signature_s", type: "hex", size: 48, desc: "Signature S"},
    {name: "hash", type: "hex", size: 48, desc: "SHA-384 hash to verify"},
  ],

  LMS_SIGNATURE_VERIFY: [
    {name: "pub_key_tree_type", type: "u32", desc: "Tree type"},
    {name: "pub_key_ots_type", type: "u32", desc: "OTS type"},
    {name: "pub_key_id", type: "hex", size: 16, desc: "Public key ID"},
    {name: "pub_key_digest", type: "hex", size: 24, desc: "Public key digest"},
    {name: "signature_q", type: "u32", desc: "Signature Q"},
    {name: "signature_ots", type: "hex", size: 1252, desc: "OTS signature"},
    {name: "signature_tree_type", type: "u32", desc: "Signature tree type"},
    {name: "signature_tree_path", type: "hex", size: 360, desc: "Tree path"},
    {name: "hash", type: "hex", size: 48, desc: "Hash to verify"},
  ],

  MLDSA87_SIGNATURE_VERIFY: [
    {name: "pub_key", type: "hex", size: 2592, desc: "MLDSA87 public key"},
    {name: "signature", type: "hex", size: 4628, desc: "MLDSA87 signature"},
    {name: "message_size", type: "u32", desc: "Message size"},
    {name: "message", type: "hex", size: 4096, desc: "Message"},
  ],

  STASH_MEASUREMENT: [
    {name: "metadata", type: "hex", size: 4, desc: "Metadata"},
    {name: "measurement", type: "hex", size: 48, desc: "Measurement (SHA-384)"},
    {name: "context", type: "hex", size: 48, desc: "Context (SHA-384)"},
    {name: "svn", type: "u32", desc: "Security Version Number"},
  ],

  INVOKE_DPE_ECC384: [
    {name: "data_size", type: "u32", desc: "DPE command data size"},
    {name: "data", type: "hex", size: 512, desc: "DPE command data"},
  ],

  INVOKE_DPE_MLDSA87: [
    {name: "flags", type: "u32", desc: "Flags"},
    {name: "axi_addr_lo", type: "u32", desc: "AXI response address (low)"},
    {name: "axi_addr_hi", type: "u32", desc: "AXI response address (high)"},
    {name: "data_size", type: "u32", desc: "DPE command data size"},
    {name: "data", type: "hex", size: 512, desc: "DPE command data"},
  ],

  EXTEND_PCR: [
    {name: "pcr_idx", type: "u32", desc: "PCR index"},
    {name: "data", type: "hex", size: 48, desc: "Data to extend (SHA-384)"},
  ],

  ADD_SUBJECT_ALT_NAME: [
    {name: "dmtf_device_info_size", type: "u32", desc: "Device info size"},
    {name: "dmtf_device_info", type: "hex", size: 128, desc: "DMTF device info"},
  ],

  DPE_TAG_TCI: [
    {name: "handle", type: "hex", size: 16, desc: "DPE context handle"},
    {name: "tag", type: "u32", desc: "Tag value"},
  ],

  DPE_GET_TAGGED_TCI: [
    {name: "tag", type: "u32", desc: "Tag to look up"},
  ],

  INCREMENT_PCR_RESET_COUNTER: [
    {name: "index", type: "u32", desc: "PCR index"},
  ],

  QUOTE_PCRS_ECC384: [
    {name: "nonce", type: "hex", size: 32, desc: "Nonce (32 bytes)"},
  ],

  QUOTE_PCRS_MLDSA87: [
    {name: "nonce", type: "hex", size: 32, desc: "Nonce (32 bytes)"},
  ],

  AUTHORIZE_AND_STASH: [
    {name: "fw_id", type: "hex", size: 4, desc: "Firmware ID"},
    {name: "measurement", type: "hex", size: 48, desc: "Image digest (SHA-384)"},
    {name: "context", type: "hex", size: 48, desc: "Context (SHA-384)"},
    {name: "svn", type: "u32", desc: "Security Version Number"},
    {name: "flags", type: "u32", desc: "Flags"},
    {name: "source", type: "u32", desc: "Image source"},
    {name: "image_size", type: "u32", desc: "Image size in bytes"},
  ],

  GET_IMAGE_INFO: [
    {name: "fw_id", type: "hex", size: 4, desc: "Firmware ID"},
  ],

  INSTALL_OWNER_PK_HASH: [
    {name: "digest", type: "hex", size: 48, desc: "Owner PK hash (u32[12])"},
  ],

  REALLOCATE_DPE_CONTEXT_LIMITS: [
    {name: "pl0_context_limit", type: "u32", desc: "PL0 context limit"},
  ],

  ZEROIZE_UDS_FE: [
    {name: "flags", type: "u32", desc: "Flags"},
  ],

  FE_PROG: [
    {name: "partition", type: "u32", desc: "Partition"},
  ],

  MANUF_DEBUG_UNLOCK_REQ_TOKEN: [
    {name: "token", type: "hex", size: 32, desc: "Unlock token (32 bytes)"},
  ],

  EXTERNAL_MAILBOX_CMD: [
    {name: "command_id", type: "u32", desc: "Command ID"},
    {name: "command_size", type: "u32", desc: "Command size"},
    {name: "axi_address_start_low", type: "u32", desc: "AXI address (low)"},
    {name: "axi_address_start_high", type: "u32", desc: "AXI address (high)"},
  ],

  CERTIFY_KEY_EXTENDED_ECC384: [
    {name: "flags", type: "u32", desc: "CertifyKeyExtendedFlags"},
    {name: "certify_key_req", type: "hex", size: 72, desc: "Inner CertifyKey request data"},
  ],

  CERTIFY_KEY_EXTENDED_MLDSA87: [
    {name: "flags", type: "u32", desc: "CertifyKeyExtendedFlags"},
    {name: "axi_addr_lo", type: "u32", desc: "AXI response address (low)"},
    {name: "axi_addr_hi", type: "u32", desc: "AXI response address (high)"},
    {name: "certify_key_req", type: "hex", size: 72, desc: "Inner CertifyKey request data"},
  ],

  PRODUCTION_AUTH_DEBUG_UNLOCK_REQ: [
    {name: "length", type: "u32", desc: "Length (in DWORDs)"},
    {name: "unlock_level", type: "u32", desc: "Debug unlock level (1-8)"},
  ],

  PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN: [
    {name: "token_size", type: "u32", desc: "Token size"},
    {name: "token", type: "hex", size: 4096, desc: "Token data"},
  ],

  SET_AUTH_MANIFEST: [
    {name: "manifest_size", type: "u32", desc: "Manifest size"},
    {name: "manifest", type: "hex", size: 16384, desc: "Auth manifest data"},
  ],

  VERIFY_AUTH_MANIFEST: [
    {name: "manifest_size", type: "u32", desc: "Manifest size"},
    {name: "manifest", type: "hex", size: 16384, desc: "Auth manifest data"},
  ],

  SIGN_WITH_EXPORTED_ECDSA: [
    {name: "exported_cdi_handle", type: "hex", size: 64, desc: "Exported CDI handle"},
    {name: "tbs", type: "hex", size: 48, desc: "TBS digest"},
  ],

  SIGN_WITH_EXPORTED_MLDSA: [
    {name: "exported_cdi_handle", type: "hex", size: 64, desc: "Exported CDI handle"},
    {name: "tbs", type: "hex", size: 48, desc: "TBS digest"},
  ],

  REVOKE_EXPORTED_CDI_HANDLE: [
    {name: "exported_cdi_handle", type: "hex", size: 64, desc: "Exported CDI handle"},
  ],

  // --- Crypto Manager (CM) commands ---

  CM_IMPORT: [
    {name: "key_usage", type: "u32", desc: "Key usage flags"},
    {name: "input_size", type: "u32", desc: "Input size"},
    {name: "input", type: "hex", size: 128, desc: "Key data"},
  ],

  CM_DELETE: [
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
  ],

  CM_SHA_INIT: [
    {name: "hash_algorithm", type: "enum", desc: "Hash algorithm", options: [{value: 1, label: "SHA-384"}, {value: 2, label: "SHA-512"}]},
    {name: "input_size", type: "u32", desc: "Input data size"},
    {name: "input", type: "hex", size: 4096, desc: "Input data"},
  ],

  CM_SHA_UPDATE: [
    {name: "context", type: "hex", size: 200, desc: "SHA context (from INIT/previous UPDATE)"},
    {name: "input_size", type: "u32", desc: "Input data size"},
    {name: "input", type: "hex", size: 4096, desc: "Input data"},
  ],

  CM_SHA_FINAL: [
    {name: "context", type: "hex", size: 200, desc: "SHA context"},
    {name: "input_size", type: "u32", desc: "Input data size"},
    {name: "input", type: "hex", size: 4096, desc: "Input data"},
  ],

  CM_SHA: [
    {name: "hash_algorithm", type: "enum", desc: "Hash algorithm", options: [{value: 1, label: "SHA-384"}, {value: 2, label: "SHA-512"}]},
    {name: "input_size", type: "u32", desc: "Input data size"},
    {name: "input", type: "hex", size: 262132, desc: "Input data"},
  ],

  CM_SHAKE256_INIT: [
    {name: "input_size", type: "u32", desc: "Input data size"},
    {name: "input", type: "hex", size: 4096, desc: "Input data"},
  ],

  CM_SHAKE256_UPDATE: [
    {name: "context", type: "hex", size: 44, desc: "SHAKE256 context"},
    {name: "input_size", type: "u32", desc: "Input data size"},
    {name: "input", type: "hex", size: 4096, desc: "Input data"},
  ],

  CM_SHAKE256_FINAL: [
    {name: "context", type: "hex", size: 44, desc: "SHAKE256 context"},
    {name: "input_size", type: "u32", desc: "Input data size"},
    {name: "input", type: "hex", size: 4096, desc: "Input data"},
  ],

  CM_RANDOM_GENERATE: [
    {name: "size", type: "u32", desc: "Number of random bytes to generate"},
  ],

  CM_RANDOM_STIR: [
    {name: "input_size", type: "u32", desc: "Entropy data size"},
    {name: "input", type: "hex", size: 4096, desc: "Entropy data"},
  ],

  CM_AES_ENCRYPT_INIT: [
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
    {name: "mode", type: "enum", desc: "AES mode", options: [{value: 0, label: "ECB"}, {value: 1, label: "CBC"}, {value: 2, label: "CTR"}]},
    {name: "plaintext_size", type: "u32", desc: "Plaintext size"},
    {name: "plaintext", type: "hex", size: 4096, desc: "Plaintext data"},
  ],

  CM_AES_ENCRYPT_UPDATE: [
    {name: "context", type: "hex", size: 156, desc: "AES context"},
    {name: "plaintext_size", type: "u32", desc: "Plaintext size"},
    {name: "plaintext", type: "hex", size: 4096, desc: "Plaintext data"},
  ],

  CM_AES_DECRYPT_INIT: [
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
    {name: "mode", type: "enum", desc: "AES mode", options: [{value: 0, label: "ECB"}, {value: 1, label: "CBC"}, {value: 2, label: "CTR"}]},
    {name: "iv", type: "hex", size: 16, desc: "Initialization vector"},
    {name: "ciphertext_size", type: "u32", desc: "Ciphertext size"},
    {name: "ciphertext", type: "hex", size: 4096, desc: "Ciphertext data"},
  ],

  CM_AES_DECRYPT_UPDATE: [
    {name: "context", type: "hex", size: 156, desc: "AES context"},
    {name: "ciphertext_size", type: "u32", desc: "Ciphertext size"},
    {name: "ciphertext", type: "hex", size: 4096, desc: "Ciphertext data"},
  ],

  CM_AES_GCM_ENCRYPT_INIT: [
    {name: "flags", type: "u32", desc: "Flags"},
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
    {name: "aad_size", type: "u32", desc: "AAD size"},
    {name: "aad", type: "hex", size: 4096, desc: "Additional authenticated data"},
  ],

  CM_AES_GCM_SPDM_ENCRYPT_INIT: [
    {name: "spdm_flags", type: "u32", desc: "SPDM flags"},
    {name: "spdm_counter", type: "hex", size: 8, desc: "SPDM counter"},
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
    {name: "aad_size", type: "u32", desc: "AAD size"},
    {name: "aad", type: "hex", size: 4096, desc: "Additional authenticated data"},
  ],

  CM_AES_GCM_ENCRYPT_UPDATE: [
    {name: "context", type: "hex", size: 128, desc: "AES-GCM context"},
    {name: "plaintext_size", type: "u32", desc: "Plaintext size"},
    {name: "plaintext", type: "hex", size: 4096, desc: "Plaintext data"},
  ],

  CM_AES_GCM_ENCRYPT_FINAL: [
    {name: "context", type: "hex", size: 128, desc: "AES-GCM context"},
    {name: "plaintext_size", type: "u32", desc: "Plaintext size"},
    {name: "plaintext", type: "hex", size: 4096, desc: "Plaintext data"},
  ],

  CM_AES_GCM_DECRYPT_INIT: [
    {name: "flags", type: "u32", desc: "Flags"},
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
    {name: "iv", type: "hex", size: 12, desc: "IV (u32[3])"},
    {name: "aad_size", type: "u32", desc: "AAD size"},
    {name: "aad", type: "hex", size: 4096, desc: "Additional authenticated data"},
  ],

  CM_AES_GCM_SPDM_DECRYPT_INIT: [
    {name: "spdm_flags", type: "u32", desc: "SPDM flags"},
    {name: "spdm_counter", type: "hex", size: 8, desc: "SPDM counter"},
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
    {name: "aad_size", type: "u32", desc: "AAD size"},
    {name: "aad", type: "hex", size: 4096, desc: "Additional authenticated data"},
  ],

  CM_AES_GCM_DECRYPT_UPDATE: [
    {name: "context", type: "hex", size: 128, desc: "AES-GCM context"},
    {name: "ciphertext_size", type: "u32", desc: "Ciphertext size"},
    {name: "ciphertext", type: "hex", size: 4096, desc: "Ciphertext data"},
  ],

  CM_AES_GCM_DECRYPT_FINAL: [
    {name: "context", type: "hex", size: 128, desc: "AES-GCM context"},
    {name: "tag_len", type: "u32", desc: "Tag length"},
    {name: "tag", type: "hex", size: 16, desc: "GCM tag (u32[4])"},
    {name: "ciphertext_size", type: "u32", desc: "Ciphertext size"},
    {name: "ciphertext", type: "hex", size: 4096, desc: "Ciphertext data"},
  ],

  CM_AES_GCM_DECRYPT_DMA: [
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
    {name: "iv", type: "hex", size: 12, desc: "IV (u32[3])"},
    {name: "tag", type: "hex", size: 16, desc: "GCM tag (u32[4])"},
    {name: "encrypted_data_sha384", type: "hex", size: 48, desc: "SHA-384 of encrypted data"},
    {name: "axi_addr_lo", type: "u32", desc: "AXI address (low)"},
    {name: "axi_addr_hi", type: "u32", desc: "AXI address (high)"},
    {name: "length", type: "u32", desc: "Data length"},
    {name: "aad_length", type: "u32", desc: "AAD length"},
    {name: "aad", type: "hex", size: 4096, desc: "Additional authenticated data"},
  ],

  CM_ECDH_GENERATE: [
    {name: "key_usage", type: "u32", desc: "Key usage flags"},
  ],

  CM_ECDH_FINISH: [
    {name: "context", type: "hex", size: 76, desc: "ECDH context"},
    {name: "key_usage", type: "u32", desc: "Key usage flags"},
    {name: "incoming_exchange_data", type: "hex", size: 96, desc: "Incoming ECDH exchange data"},
  ],

  CM_HMAC: [
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
    {name: "hash_algorithm", type: "enum", desc: "Hash algorithm", options: [{value: 1, label: "SHA-384"}, {value: 2, label: "SHA-512"}]},
    {name: "data_size", type: "u32", desc: "Data size"},
    {name: "data", type: "hex", size: 4096, desc: "Data to HMAC"},
  ],

  CM_HMAC_KDF_COUNTER: [
    {name: "kin", type: "hex", size: 128, desc: "Input key (CM Key handle)"},
    {name: "hash_algorithm", type: "enum", desc: "Hash algorithm", options: [{value: 1, label: "SHA-384"}, {value: 2, label: "SHA-512"}]},
    {name: "key_usage", type: "u32", desc: "Output key usage"},
    {name: "key_size", type: "u32", desc: "Output key size"},
    {name: "label_size", type: "u32", desc: "Label size"},
    {name: "label", type: "hex", size: 4096, desc: "KDF label"},
  ],

  CM_HKDF_EXTRACT: [
    {name: "hash_algorithm", type: "enum", desc: "Hash algorithm", options: [{value: 1, label: "SHA-384"}, {value: 2, label: "SHA-512"}]},
    {name: "salt", type: "hex", size: 128, desc: "Salt (CM Key handle)"},
    {name: "ikm", type: "hex", size: 128, desc: "Input keying material (CM Key handle)"},
  ],

  CM_HKDF_EXPAND: [
    {name: "prk", type: "hex", size: 128, desc: "PRK (CM Key handle)"},
    {name: "hash_algorithm", type: "enum", desc: "Hash algorithm", options: [{value: 1, label: "SHA-384"}, {value: 2, label: "SHA-512"}]},
    {name: "key_usage", type: "u32", desc: "Output key usage"},
    {name: "key_size", type: "u32", desc: "Output key size"},
    {name: "info_size", type: "u32", desc: "Info size"},
    {name: "info", type: "hex", size: 4096, desc: "HKDF info"},
  ],

  CM_MLDSA_PUBLIC_KEY: [
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
  ],

  CM_MLDSA_SIGN: [
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
    {name: "message_size", type: "u32", desc: "Message size"},
    {name: "message", type: "hex", size: 4096, desc: "Message to sign"},
  ],

  CM_MLDSA_VERIFY: [
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle (public key)"},
    {name: "signature", type: "hex", size: 4628, desc: "MLDSA87 signature"},
    {name: "message_size", type: "u32", desc: "Message size"},
    {name: "message", type: "hex", size: 4096, desc: "Message"},
  ],

  CM_ECDSA_PUBLIC_KEY: [
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
  ],

  CM_ECDSA_SIGN: [
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
    {name: "message_size", type: "u32", desc: "Message size"},
    {name: "message", type: "hex", size: 4096, desc: "Message to sign"},
  ],

  CM_ECDSA_VERIFY: [
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle (public key)"},
    {name: "signature_r", type: "hex", size: 48, desc: "Signature R"},
    {name: "signature_s", type: "hex", size: 48, desc: "Signature S"},
    {name: "message_size", type: "u32", desc: "Message size"},
    {name: "message", type: "hex", size: 4096, desc: "Message"},
  ],

  CM_DERIVE_STABLE_KEY: [
    {name: "key_type", type: "u32", desc: "Key type"},
    {name: "info", type: "hex", size: 32, desc: "Derivation info"},
  ],

  CM_MLKEM_KEY_GEN: [
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle (seed)"},
  ],

  CM_MLKEM_ENCAPSULATE: [
    {name: "key_usage", type: "u32", desc: "Key usage flags"},
    {name: "encaps_key", type: "hex", size: 1568, desc: "Encapsulation key"},
  ],

  CM_MLKEM_DECAPSULATE: [
    {name: "key_usage", type: "u32", desc: "Key usage flags"},
    {name: "cmk", type: "hex", size: 128, desc: "CM Key handle"},
    {name: "ciphertext", type: "hex", size: 1568, desc: "Ciphertext"},
  ],

  // --- OCP Lock commands ---

  OCP_LOCK_REPORT_HEK_METADATA: [
    {name: "reserved0", type: "u32", desc: "Reserved"},
    {name: "total_slots", type: "u32", desc: "Total slots (u16) + Active slots (u16)"},
    {name: "seed_state", type: "u32", desc: "Seed state (u16) + padding (u16)"},
  ],

  OCP_LOCK_ENUMERATE_HPKE_HANDLES: [
    {name: "reserved", type: "u32", desc: "Reserved (0)"},
  ],

  OCP_LOCK_ROTATE_HPKE_KEY: [
    {name: "reserved", type: "u32", desc: "Reserved (0)"},
    {name: "hpke_handle", type: "u32", desc: "HPKE handle"},
  ],

  OCP_LOCK_GENERATE_MEK: [
    {name: "reserved", type: "u32", desc: "Reserved (0)"},
  ],

  OCP_LOCK_GET_HPKE_PUB_KEY: [
    {name: "reserved", type: "u32", desc: "Reserved (0)"},
    {name: "hpke_handle", type: "u32", desc: "HPKE handle"},
  ],

  OCP_LOCK_CLEAR_KEY_CACHE: [
    {name: "reserved", type: "u32", desc: "Reserved (0)"},
    {name: "cmd_timeout", type: "u32", desc: "Command timeout"},
  ],
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
  s += formatRawRequest(initReq);
  const initResp = emu.mailbox_execute(CMD_CM_SHA_INIT, initReq);
  if (initResp == null || initResp.length < 8 + CM_SHA_CONTEXT_SIZE) {
    s += `  ✗ INIT failed (got ${initResp ? initResp.length : 0} bytes)\n`;
    if (initResp) s += formatRawResponse(new Uint8Array(initResp));
    return s;
  }
  const initBuf = new Uint8Array(initResp);
  s += formatRawResponse(initBuf);
  const initFips = readU32LE(initBuf, 4);
  if (initFips !== 0) {
    s += `  ✗ INIT fips_status: ${initFips}\n`;
    return s;
  }
  let context = initBuf.slice(8, 8 + CM_SHA_CONTEXT_SIZE);
  s += `  ✓ INIT OK\n\n`;

  // UPDATE with middle chunks
  for (let i = 1; i < chunks.length - 1; i++) {
    s += `  → CM_SHA_UPDATE chunk ${i} (${chunks[i].length} bytes)...\n`;
    const updateReq = makeCmShaUpdateReq(context, chunks[i]);
    s += formatRawRequest(updateReq);
    const updateResp = emu.mailbox_execute(CMD_CM_SHA_UPDATE, updateReq);
    if (updateResp == null || updateResp.length < 8 + CM_SHA_CONTEXT_SIZE) {
      s += `  ✗ UPDATE failed\n`;
      if (updateResp) s += formatRawResponse(new Uint8Array(updateResp));
      return s;
    }
    const updateBuf = new Uint8Array(updateResp);
    s += formatRawResponse(updateBuf);
    context = updateBuf.slice(8, 8 + CM_SHA_CONTEXT_SIZE);
    s += `  ✓ UPDATE OK\n\n`;
  }

  // FINAL with last chunk (or empty if only one chunk was used in INIT)
  const lastChunk = chunks.length > 1 ? chunks[chunks.length - 1] : new Uint8Array(0);
  s += `  → CM_SHA_FINAL (${lastChunk.length} bytes)...\n`;
  const finalReq = makeCmShaFinalReq(context, lastChunk);
  s += formatRawRequest(finalReq);
  const finalResp = emu.mailbox_execute(CMD_CM_SHA_FINAL, finalReq);
  if (finalResp == null || finalResp.length < 12) {
    s += `  ✗ FINAL failed (got ${finalResp ? finalResp.length : 0} bytes)\n`;
    if (finalResp) s += formatRawResponse(new Uint8Array(finalResp));
    return s;
  }
  const finalBuf = new Uint8Array(finalResp);
  s += formatRawResponse(finalBuf);
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

// Custom formatters keyed by command ID
const CUSTOM_FORMATTERS = {
  0x494E464F: formatFwInfoResp,
  0x46505652: formatFipsVersionResp,
  0x43415053: formatCapabilitiesResp,
};

// Raw request/response display helpers
function formatRawRequest(reqBuf) {
  const n = reqBuf.length;
  let s = `Request (${n} bytes):\n`;
  if (n >= 4) {
    const chksum = readU32LE(reqBuf, 0);
    s += `  chksum: 0x${chksum.toString(16).padStart(8, "0")}\n`;
  }
  if (n > 4) {
    s += `  payload: ${hexBytes(reqBuf, 4, n - 4)}\n`;
  }
  return s;
}

function formatRawResponse(respBuf) {
  if (!respBuf || respBuf.length === 0) {
    return "Response: (empty)\n";
  }
  const n = respBuf.length;
  let s = `Response (${n} bytes):\n`;
  if (n >= 4) {
    const chksum = readU32LE(respBuf, 0);
    s += `  chksum: 0x${chksum.toString(16).padStart(8, "0")}\n`;
  }
  if (n >= 8) {
    const fips = readU32LE(respBuf, 4);
    s += `  fips_status: ${fips === 0 ? "APPROVED (0)" : `0x${fips.toString(16).padStart(8, "0")} (${fips})`}\n`;
  }
  if (n > 8) {
    s += `  data: ${hexBytes(respBuf, 8, n - 8)}\n`;
  }
  return s;
}

function parseHexPayload(hexStr) {
  const cleaned = hexStr.replace(/[\s,]/g, "");
  if (cleaned.length === 0) return new Uint8Array(0);
  if (cleaned.length % 2 !== 0) throw new Error("Hex string must have even number of characters");
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    const b = parseInt(cleaned.substring(i, i + 2), 16);
    if (isNaN(b)) throw new Error(`Invalid hex at position ${i}: "${cleaned.substring(i, i + 2)}"`);
    bytes[i / 2] = b;
  }
  return bytes;
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
      const cmd = COMMAND_INFO[cmdKey];
      if (!cmd) {
        mboxResponse.textContent = `Unknown command: ${cmdKey}`;
        return;
      }

      let output = `Sending ${cmdKey} (0x${cmd.id.toString(16).padStart(8, "0")})...\n\n`;

      // Build request
      let reqData;
      const inputMode = getInputMode();
      const fields = COMMAND_FIELDS[cmdKey] || [];

      if (inputMode === "form" && fields.length > 0) {
        const payloadBytes = serializeFormFields(cmdKey);
        reqData = makeChecksummedRequest(cmd.id, payloadBytes);
      } else if (inputMode === "raw" || fields.length === 0) {
        if (cmd.hasInput || fields.length > 0) {
          const payloadHex = mboxPayload.value.trim();
          const payloadBytes = parseHexPayload(payloadHex);
          reqData = makeChecksummedRequest(cmd.id, payloadBytes);
        } else {
          reqData = makeHeaderOnlyRequest(cmd.id);
        }
      } else {
        reqData = makeHeaderOnlyRequest(cmd.id);
      }

      output += formatRawRequest(reqData);
      output += "\n";

      // Execute
      const respData = emulator.mailbox_execute(cmd.id, reqData);

      if (respData == null) {
        output += "Response: (no data returned)\n";
      } else {
        const buf = new Uint8Array(respData);
        output += formatRawResponse(buf);

        // Decoded fields for commands with custom formatters
        const formatter = CUSTOM_FORMATTERS[cmd.id];
        if (formatter) {
          output += "\n--- Decoded ---\n" + formatter(buf);
        }
      }

      mboxResponse.textContent = output;
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

// Render initial form fields for the default selected command
updateInputSection(mboxCmdSelect.value, getInputMode());
