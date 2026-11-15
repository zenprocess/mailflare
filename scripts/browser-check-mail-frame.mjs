// Headless-Chromium check that the sandboxed mail frame works under the REAL nonce CSP served by
// the built Worker. Loads the actual mail view (/inbox/<id>) from a wrangler dev --local Worker: it
// seeds one user + session + message with an inline cid image directly into the local D1 (and the
// attachment bytes into local R2), opens the message in Chromium with the session cookie, and
// asserts the frame auto-sizes, the cid image arrives as a parent-fetched blob, the sandbox is
// exact, the frame origin is opaque, and there are zero CSP violations under the nonce policy the
// Worker actually sends.
//
//   node scripts/browser-check-mail-frame.mjs
//
// Local only; no Cloudflare network, no deploy. Remote images are not exercised here (they need a
// public host for the proxy's SSRF guard).

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(join(root, "package.json"));
const { chromium } = require("playwright");

const port = 8787 + Math.floor(Math.random() * 500);
const base = "http://127.0.0.1:" + port;
const persistTo = mkdtempSync(join(tmpdir(), "mf3-frame-check-"));
const wranglerBin = join(root, "node_modules", ".bin", "wrangler");

const token = "sess_mf3checkmwhtyldq";
const tokenHash = createHash("sha256").update(token).digest("hex");
const blobBytes = "cid";

function longBody() {
  let h = "";
  for (let i = 0; i < 80; i++) h += "<p>Paragraph " + i + " makes this body much taller than the default iframe height of 150 pixels.</p>";
  return h;
}

// A message body with all three hostile-image shapes: an inline cid image (with a matching
// attachment), a remote image, and a sender-chosen relative "../" same-origin path. Before the reader
// clicks "Allow remote content" none of the remote/sender requests may leave the top document.
const REMOTE_HOST = "img.example.net";
const REMOTE_IMAGE_URL = "https://" + REMOTE_HOST + "/six.png";
const SENDER_PATH = "/api/attachments/x?preview=1";

function hostileBody() {
  return longBody()
    + '<img src="cid:logo" alt="cid" width="8" height="8">'
    + '<img src="' + REMOTE_IMAGE_URL + '" alt="remote">'
    + '<img src="../api/attachments/x?preview=1" alt="bogus">';
}

function isRemoteRequest(url) {
  try { return new URL(url).hostname === REMOTE_HOST; } catch { return url.includes(REMOTE_HOST); }
}
function isSenderRequest(url) {
  return url.includes(SENDER_PATH);
}
function isProxyRequest(url) {
  return url.includes("/api/remote-images");
}

function runWrangler(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(wranglerBin, args, { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => { out += d.toString(); });
    child.stderr.on("data", (d) => { out += d.toString(); });
    child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve(out) : reject(new Error("wrangler " + args.join(" ") + " exited " + code)));
  });
}

let dev = null;
let devLog = "";

async function waitForReady(timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(base + "/favicon.ico", { redirect: "manual" });
      if (res.status > 0) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error("wrangler dev did not become ready");
}

async function main() {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 86400;
  const htmlBody = hostileBody();
  const insertSql = [
    "INSERT INTO users (id, email, password_hash, name, remote_content_mode, created_at) VALUES ('mf3-user', 'check@example.test', 'x', 'Check', 'ask', " + now + ");",
    "INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at) VALUES ('mf3-sess', 'mf3-user', '" + tokenHash + "', " + exp + ", " + now + ");",
    "INSERT INTO domains (id, user_id, hostname, zone_id, created_at) VALUES ('mf3-domain', 'mf3-user', 'example.test', 'mf3-zone', " + now + ");",
    "INSERT INTO mailboxes (id, user_id, domain_id, local_part, created_at) VALUES ('mf3-mbox', 'mf3-user', 'mf3-domain', 'check', " + now + ");",
    "INSERT INTO messages (id, user_id, mailbox_id, direction, from_addr, to_addr, status, html_body, text_body, created_at) VALUES ('mf3-msg', 'mf3-user', 'mf3-mbox', 'inbound', 'a@example.test', 'check@example.test', 'received', '" + htmlBody + "', 'cid check', " + now + ");",
    "INSERT INTO message_attachments (id, message_id, filename, content_type, size, disposition, content_id, r2_key, created_at) VALUES ('mf3-att', 'mf3-msg', 'cid.png', 'image/png', " + blobBytes.length + ", 'inline', 'logo', 'mf3-cid-blob', " + now + ");",
  ].join(" ");

  console.log("applying D1 migrations (local)...");
  await runWrangler(["d1", "migrations", "apply", "DB", "--local", "--persist-to", persistTo]);
  console.log("seeding user + session + message + cid attachment (local D1 + R2)...");
  await runWrangler(["d1", "execute", "DB", "--local", "--persist-to", persistTo, "--command", insertSql]);
  const blobFile = join(persistTo, "cid.bin");
  writeFileSync(blobFile, blobBytes);
  await runWrangler(["r2", "object", "put", "mailflare-raw/mf3-cid-blob", "--local", "--persist-to", persistTo, "--file", blobFile]);

  console.log("starting wrangler dev --local...");
  dev = spawn(wranglerBin, ["dev", "--local", "--ip", "127.0.0.1", "--port", String(port), "--persist-to", persistTo, "--var", "MAILFLARE_ACCESS_MODE:off", "--show-interactive-dev-session", "false"], { cwd: root, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, NODE_ENV: "production" } });
  dev.stdout.on("data", (d) => { devLog += d.toString(); });
  dev.stderr.on("data", (d) => { devLog += d.toString(); });
  await waitForReady(60000);

  const pageRes = await fetch(base + "/inbox/mf3-msg", { redirect: "manual", headers: { Cookie: "ep_session=" + token } });
  const csp = pageRes.headers.get("content-security-policy") || "";
  const scriptSrc = /script-src([^;]*)/.exec(csp);
  const ss = scriptSrc ? scriptSrc[1].trim() : "";
  console.log("mail view CSP script-src: " + ss);
  const failures = [];
  const check = (cond, msg) => { console.log((cond ? "PASS " : "FAIL ") + msg); if (!cond) failures.push(msg); };
  check(ss.includes("'nonce-"), "real Worker CSP has a nonce");
  check(!ss.includes("'unsafe-inline'"), "real Worker CSP script-src has no 'unsafe-inline'");

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  await context.addCookies([{ name: "ep_session", value: token, domain: "127.0.0.1", path: "/" }]);
  const page = await context.newPage();
  const consoleMessages = [];
  page.on("console", (msg) => consoleMessages.push({ type: msg.type(), text: msg.text() }));
  page.on("pageerror", (err) => consoleMessages.push({ type: "pageerror", text: String(err) }));

  // Log every request the page (top document or frame) attempts, so the regression can assert that
  // the remote host and the sender-chosen path are never hit before consent.
  const requests = [];
  page.on("request", (req) => requests.push(req.url()));

  // Mock the remote-image proxy so the SSRF-guarded fetch (DoH to Cloudflare) is never needed in
  // this local run. The parent still issues the proxied request after consent — that is what the
  // after-click assertion checks — but the response is a local 1×1 PNG instead of a network fetch.
  const onePxPng = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==", "base64");
  await page.route("**/api/remote-images*", (route) => route.fulfill({ status: 200, contentType: "image/png", body: onePxPng }));

  await page.goto(base + "/inbox/mf3-msg", { waitUntil: "load", timeout: 30000 });
  await page.waitForSelector('iframe[title="message"]', { timeout: 20000 });
  await page.waitForTimeout(2500);

  // ---- P1-A regression: requests BEFORE the reader clicks "Allow remote content" ----
  const beforeClick = requests.slice();
  const beforeRemote = beforeClick.filter(isRemoteRequest);
  const beforeSender = beforeClick.filter(isSenderRequest);
  const beforeProxy = beforeClick.filter(isProxyRequest);
  console.log("requests before 'Allow remote content': " + beforeClick.length + " (remote " + beforeRemote.length + ", sender " + beforeSender.length + ", proxy " + beforeProxy.length + ")");
  check(beforeRemote.length === 0, "zero requests to the remote host before consent (" + beforeRemote.join(", ") + ")");
  check(beforeSender.length === 0, "zero requests to the sender-chosen path before consent (" + beforeSender.join(", ") + ")");
  check(beforeProxy.length === 0, "no proxied remote fetch before consent (got " + beforeProxy.length + ")");

  const frameHandle = await page.$('iframe[title="message"]');
  const sandbox = await frameHandle.getAttribute("sandbox");
  const height = await page.evaluate(() => { const f = document.querySelector('iframe[title="message"]'); return f ? parseInt(f.style.height || "0", 10) : 0; });

  // Opaque origin: the parent page cannot read the frame's document (no allow-same-origin).
  const opacity = await page.evaluate(() => {
    const f = document.querySelector('iframe[title="message"]');
    if (!f) return "no-frame";
    try { const d = f.contentWindow.document; void d; return "readable"; } catch (e) { return e.name; }
  });

  // Playwright can still reach the frame through the debugging protocol, so read the cid src there.
  let cidSrc = null;
  for (const f of page.frames()) {
    let el = null;
    try { el = await f.frameElement(); } catch (e) { el = null; }
    if (!el) continue;
    let t = null;
    try { t = await el.getAttribute("title"); } catch (e) { t = null; }
    if (t !== "message") continue;
    try { cidSrc = await f.locator('img[alt="cid"]').getAttribute("src"); } catch (e) { cidSrc = null; }
  }

  check(sandbox === "allow-scripts allow-popups allow-popups-to-escape-sandbox", "sandbox is exact (got: " + sandbox + ")");
  check(height > 150, "frame auto-sized above 150px (got: " + height + ")");
  check(cidSrc !== null && cidSrc.indexOf("blob:") === 0, "cid image rendered as a parent-fetched blob (got: " + cidSrc + ")");
  check(opacity === "SecurityError", "frame origin is opaque (contentWindow.document threw " + opacity + ")");

  // ---- P1-A regression: click "Allow remote content", then exactly the proxied fetch appears ----
  const allowButton = page.getByRole("button", { name: "Allow remote content" });
  const hasAllow = (await allowButton.count()) > 0;
  check(hasAllow, "'Allow remote content' button is present (message has remote content)");
  if (hasAllow) {
    await allowButton.click();
    await page.waitForTimeout(2500);
  }
  const afterClick = requests.slice();
  const afterRemote = afterClick.filter(isRemoteRequest);
  const afterSender = afterClick.filter(isSenderRequest);
  const afterProxy = afterClick.filter(isProxyRequest);
  console.log("requests after 'Allow remote content': " + afterClick.length + " (remote " + afterRemote.length + ", sender " + afterSender.length + ", proxy " + afterProxy.length + ")");
  check(afterRemote.length === 0, "still zero direct requests to the remote host after consent (" + afterRemote.join(", ") + ")");
  check(afterSender.length === 0, "still zero requests to the sender-chosen path after consent (" + afterSender.join(", ") + ")");
  check(afterProxy.length >= 1, "remote image fetched through the proxy after consent (got " + afterProxy.length + ")");

  // ---- Composer path: replying quotes the original without loading its images ----
  let replyClicked = false;
  try {
    const inlineReply = page.getByRole("button", { name: "Reply", exact: true });
    if ((await inlineReply.count()) > 0) {
      await inlineReply.click();
    } else {
      // Narrow viewport: the reply action overflowed into the "More actions" menu.
      await page.getByRole("button", { name: "More actions" }).click();
      await page.waitForTimeout(300);
      await page.getByRole("menuitem", { name: "Reply" }).click();
    }
    replyClicked = true;
  } catch (error) {
    console.log("reply click skipped: " + error.message);
  }
  await page.waitForTimeout(2500);
  const afterReply = requests.slice();
  const replyRemote = afterReply.filter(isRemoteRequest);
  const replySender = afterReply.filter(isSenderRequest);
  console.log("requests after clicking Reply: " + afterReply.length + " (remote " + replyRemote.length + ", sender " + replySender.length + ")");
  check(replyClicked, "reply action is reachable in the message view");
  check(replyRemote.length === 0, "reply composer never requests the remote host (" + replyRemote.join(", ") + ")");
  check(replySender.length === 0, "reply composer never requests the sender-chosen path (" + replySender.join(", ") + ")");

  const cspErrors = consoleMessages.filter((m) => /Content Security Policy|Refused to|violates the following/i.test(m.text));
  check(cspErrors.length === 0, "zero CSP console errors (got " + cspErrors.length + ")");
  console.log("console messages: " + consoleMessages.length + ", csp errors: " + cspErrors.length);

  await browser.close();
  dev.kill("SIGTERM");
  rmSync(persistTo, { recursive: true, force: true });
  console.log(failures.length ? "RESULT: FAIL (" + failures.length + ")" : "RESULT: PASS");
  process.exit(failures.length ? 1 : 0);
}

main().catch((error) => {
  console.error("ERROR:", error);
  if (dev) dev.kill("SIGTERM");
  rmSync(persistTo, { recursive: true, force: true });
  process.exit(2);
});
