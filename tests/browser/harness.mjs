// Licensed under the Apache-2.0 license
//
// Shared by the browser tests: a static server for www/, a headless Firefox
// driven over WebDriver BiDi (built into Firefox, so no npm packages or
// driver binaries are needed), and small helpers.
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
import { createReadStream, existsSync, mkdirSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { homedir, tmpdir } from "node:os";
import { dirname, extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const WWW = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "www");

export const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));
export const tail = (s, n = 3000) => (s.length > n ? "…" + s.slice(-n) : s);

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

export function serveWww() {
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

export async function launchFirefox() {
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

export class Bidi {
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

// Starts the server and the browser, runs `fn(bidi, context, baseUrl,
// pageErrors)`, and cleans up. `pageErrors` collects the page's console
// errors as they happen.
export async function withBrowser(fn) {
  if (typeof WebSocket === "undefined") throw new Error("Node 22+ is required (global WebSocket)");
  if (!existsSync(join(WWW, "versions.json"))) {
    throw new Error("www/versions.json is missing; run ./build-wasm.sh first");
  }
  const server = await serveWww();
  const baseUrl = `http://127.0.0.1:${server.address().port}/`;
  console.log(`serving ${WWW} at ${baseUrl}`);
  const ff = await launchFirefox();
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
    const result = await fn(bidi, tree.contexts[0].context, baseUrl, pageErrors);
    await bidi.send("session.end").catch(() => {});
    return result;
  } finally {
    ff.cleanup();
    server.close();
  }
}
