// Headless-Chromium check that the sandboxed mail frame works under the nonce CSP.
// Bundles the real src/lib/remote-images/frame.ts and src/lib/security/headers.ts, renders the frame
// inside a parent served with buildCsp(nonce) exactly as the app does, with a fixture mail that has a
// long body, an inline cid image and a remote image. Proves the hash-allowed measuring script runs
// (auto-size), the cid/remote images render as parent-fetched blobs, the sandbox attribute is exact,
// the frame origin is opaque, and no CSP violation is reported. Run: node scripts/browser-check-mail-frame.mjs
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(join(root, "package.json"));
const esbuild = await import("esbuild");
const { chromium } = require("playwright");

const tmp = mkdtempSync(join(tmpdir(), "mf-frame-check-"));

async function bundle(entry, outName, browser) {
  const outfile = join(tmp, outName);
  await esbuild.build({
    entryPoints: [join(root, entry)],
    outfile,
    bundle: true,
    platform: browser ? "browser" : "node",
    format: "esm",
    logLevel: "silent",
    alias: { "@": join(root, "src") },
  });
  return outfile;
}

const frameFile = await bundle("src/lib/remote-images/frame.ts", "frame.js", true);
const headersFile = await bundle("src/lib/security/headers.ts", "headers.mjs", false);
const { buildCsp } = await import(pathToFileURL(headersFile).href);
const frameSrc = readFileSync(frameFile, "utf8");
const harnessJs = readFileSync(join(root, "scripts", "browser-check-frame-harness.js"), "utf8");

// A valid 1x1 transparent PNG, served for both the cid and the remote image.
const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=", "base64");

const nonce = randomUUID().replace(/-/g, "");
const csp = buildCsp(nonce);

const server = createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  if (url.pathname === "/") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff" });
    res.end("<!doctype html><html><head><meta charset='utf-8'><title>frame check</title></head><body><script type='module' src='/harness.js'></script></body></html>");
  } else if (url.pathname === "/frame.js") {
    res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8", "X-Content-Type-Options": "nosniff" });
    res.end(frameSrc);
  } else if (url.pathname === "/harness.js") {
    res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8", "X-Content-Type-Options": "nosniff" });
    res.end(harnessJs);
  } else if (url.pathname === "/cid.png" || url.pathname === "/remote.png") {
    res.writeHead(200, { "Content-Type": "image/png", "Cross-Origin-Resource-Policy": "same-origin", "X-Content-Type-Options": "nosniff" });
    res.end(png);
  } else {
    res.writeHead(404);
    res.end("not found");
  }
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const port = server.address().port;
const base = "http://127.0.0.1:" + port;

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
const consoleMessages = [];
page.on("console", (msg) => consoleMessages.push({ type: msg.type(), text: msg.text() }));
page.on("pageerror", (err) => consoleMessages.push({ type: "pageerror", text: String(err) }));

let result;
try {
  await page.goto(base + "/", { waitUntil: "load" });
  await page.waitForFunction(() => window.__MAILFRAME_RESULT, null, { timeout: 15000 });
  result = await page.evaluate(() => window.__MAILFRAME_RESULT);
  for (const f of page.frames()) {
    let el = null;
    try { el = await f.frameElement(); } catch (e) { el = null; }
    if (!el) continue;
    let phase = null;
    try { phase = await el.getAttribute("data-phase"); } catch (e) { phase = null; }
    if (!phase) continue;
    let cid = null;
    try { cid = await f.locator('img[alt="cid"]').getAttribute("src"); } catch (e) { cid = null; }
    let remoteCount = 0;
    try { remoteCount = await f.locator('img[alt="remote"]').count(); } catch (e) { remoteCount = 0; }
    let remote = null;
    if (remoteCount) { try { remote = await f.locator('img[alt="remote"]').getAttribute("src"); } catch (e) { remote = null; } }
    const phaseResult = result.phases.find((p) => p.includeRemote === (phase === "remote-on"));
    if (phaseResult) { phaseResult.cidSrc = cid; phaseResult.remoteSrc = remote; phaseResult.remoteImgCount = remoteCount; }
  }
} finally {
  await browser.close();
  server.close();
}

const cspErrors = consoleMessages.filter((m) => /Content Security Policy|Refused to|violates the following/i.test(m.text));
console.log(JSON.stringify({ cspHeaderHasNonce: csp.indexOf("'nonce-" + nonce + "'") >= 0, phases: result.phases, parentViolations: result.violations, consoleMessageCount: consoleMessages.length, cspErrorsInConsole: cspErrors }, null, 2));

let ok = true;
for (const p of result.phases) {
  if (p.maxHeight <= 150) { ok = false; console.error("FAIL: frame did not grow: " + p.maxHeight); }
  if (p.sandbox !== "allow-scripts allow-popups allow-popups-to-escape-sandbox") { ok = false; console.error("FAIL: sandbox=" + p.sandbox); }
  if (p.opacity !== "SecurityError") { ok = false; console.error("FAIL: frame not opaque: " + p.opacity); }
  if (!p.cidSrc || p.cidSrc.indexOf("blob:") !== 0) { ok = false; console.error("FAIL: cid not blob: " + p.cidSrc); }
}
const on = result.phases.find((p) => p.includeRemote);
const off = result.phases.find((p) => !p.includeRemote);
if (!off || off.remoteFetched !== 0) { ok = false; console.error("FAIL: remote fetched before reader asked"); }
if (!on || on.remoteFetched !== 1 || on.remoteImgCount !== 1 || !on.remoteSrc || on.remoteSrc.indexOf("blob:") !== 0) { ok = false; console.error("FAIL: remote image did not render"); }
if (result.violations.length) { ok = false; console.error("FAIL: violations: " + JSON.stringify(result.violations)); }
if (cspErrors.length) { ok = false; console.error("FAIL: CSP console errors: " + JSON.stringify(cspErrors)); }
console.log(ok ? "RESULT: PASS" : "RESULT: FAIL");
process.exit(ok ? 0 : 1);
