// Asserts the P1-A fix on the BUILT Worker under wrangler dev --local: HTML documents carry the
// nonce CSP (script-src has a nonce, no 'unsafe-inline'), and a sandbox-CSP file route keeps its
// own policy. Run after: npm run build && node scripts/bundle-worker.mjs
//
//   node scripts/check-built-worker-csp.mjs
//
// Starts wrangler dev --local on 127.0.0.1 with MAILFLARE_ACCESS_MODE=off and isolated persistence
// under a temp dir, seeds one shared-file link (local D1 + R2 only), then fetches /, /setup, /inbox,
// a 404 and the shared-file link. No Cloudflare network, no deploy.

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const port = 8787 + Math.floor(Math.random() * 500);
const base = "http://127.0.0.1:" + port;
const persistTo = mkdtempSync(join(tmpdir(), "mf3-worker-csp-"));
const wranglerBin = join(root, "node_modules", ".bin", "wrangler");

function runWrangler(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(wranglerBin, args, { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => { out += d.toString(); });
    child.stderr.on("data", (d) => { out += d.toString(); });
    child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve(out) : reject(new Error("wrangler " + args.join(" ") + " exited " + code + ":\n" + out.slice(-2000))));
  });
}

const now = Math.floor(Date.now() / 1000);
const exp = now + 86400;
const insertSql = [
  "INSERT INTO users (id, email, password_hash, name, created_at) VALUES ('mf3-user', 'check@example.test', 'x', 'Check', " + now + ");",
  "INSERT INTO domains (id, user_id, hostname, zone_id, created_at) VALUES ('mf3-domain', 'mf3-user', 'example.test', 'mf3-zone', " + now + ");",
  "INSERT INTO mailboxes (id, user_id, domain_id, local_part, created_at) VALUES ('mf3-mbox', 'mf3-user', 'mf3-domain', 'check', " + now + ");",
  "INSERT INTO messages (id, user_id, direction, from_addr, to_addr, mailbox_id, status, created_at) VALUES ('mf3-msg', 'mf3-user', 'inbound', 'a@example.test', 'check@example.test', 'mf3-mbox', 'received', " + now + ");",
  "INSERT INTO message_attachments (id, message_id, filename, content_type, size, r2_key, created_at) VALUES ('mf3-att', 'mf3-msg', 'check.txt', 'text/plain', 4, 'mf3-check-blob', " + now + ");",
  "INSERT INTO shared_attachment_links (id, attachment_id, expires_at, created_at) VALUES ('mf3-check', 'mf3-att', " + exp + ", " + now + ");",
].join(" ");

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
  throw new Error("wrangler dev did not become ready:\n" + devLog.slice(-4000));
}

async function head(path) {
  const res = await fetch(base + path, { redirect: "manual" });
  const csp = res.headers.get("content-security-policy") || "";
  const ct = res.headers.get("content-type") || "";
  return { status: res.status, csp, ct, location: res.headers.get("location") || "" };
}

function scriptSrcOf(csp) {
  const m = /script-src([^;]*)/.exec(csp);
  return m ? m[1].trim() : "";
}

function imgSrcOf(csp) {
  const m = /img-src([^;]*)/.exec(csp);
  return m ? m[1].trim() : "";
}

const failures = [];
function check(cond, msg) {
  console.log((cond ? "PASS " : "FAIL ") + msg);
  if (!cond) failures.push(msg);
}

async function main() {
  console.log("applying D1 migrations (local)...");
  await runWrangler(["d1", "migrations", "apply", "DB", "--local", "--persist-to", persistTo]);
  console.log("seeding one shared-file link (local D1 + R2)...");
  await runWrangler(["d1", "execute", "DB", "--local", "--persist-to", persistTo, "--command", insertSql]);
  const blobFile = join(persistTo, "blob.txt");
  writeFileSync(blobFile, "ok");
  await runWrangler(["r2", "object", "put", "mailflare-raw/mf3-check-blob", "--local", "--persist-to", persistTo, "--file", blobFile]);

  console.log("starting wrangler dev --local...");
  dev = spawn(wranglerBin, ["dev", "--local", "--ip", "127.0.0.1", "--port", String(port), "--persist-to", persistTo, "--var", "MAILFLARE_ACCESS_MODE:off", "--show-interactive-dev-session", "false"], { cwd: root, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, NODE_ENV: "production" } });
  dev.stdout.on("data", (d) => { devLog += d.toString(); });
  dev.stderr.on("data", (d) => { devLog += d.toString(); });
  await waitForReady(60000);

  for (const path of ["/", "/setup", "/inbox", "/this-route-does-not-exist-404"]) {
    const r = await head(path);
    console.log(path + " -> " + r.status + " " + r.ct + " | " + r.csp);
    let doc = r;
    if (r.status >= 300 && r.status < 400 && r.location) {
      const followed = await head(r.location);
      console.log("  (redirect -> " + followed.status + " " + followed.ct + " | " + followed.csp + ")");
      doc = followed;
    }
    const html = (doc.ct || "").split(";", 1)[0].trim().toLowerCase() === "text/html";
    if (!html) {
      console.log("  (" + path + " ends on a non-HTML response; not asserting nonce here)");
      continue;
    }
    const ss = scriptSrcOf(doc.csp);
    check(ss.includes("'nonce-"), path + ": script-src has a nonce (got: " + ss + ")");
    check(!ss.includes("'unsafe-inline'"), path + ": script-src has no 'unsafe-inline' (got: " + ss + ")");
    const isrc = imgSrcOf(doc.csp);
    check(!/https:/.test(isrc), path + ": img-src has no https (got: " + isrc + ")");
    check(isrc.includes("'self'") && isrc.includes("blob:"), path + ": img-src keeps 'self' and blob: (got: " + isrc + ")");
  }

  const shared = await head("/api/shared-files/mf3-check");
  console.log("/api/shared-files/mf3-check -> " + shared.status + " " + shared.ct + " | " + shared.csp);
  check(shared.status === 200, "shared-files link returns 200 (got " + shared.status + ")");
  check(shared.csp.includes("sandbox"), "shared-files keeps its sandbox CSP (got: " + shared.csp + ")");
  check(!shared.csp.includes("nonce"), "shared-files CSP has no nonce (got: " + shared.csp + ")");
  check(!scriptSrcOf(shared.csp).includes("'unsafe-inline'"), "shared-files script-src has no 'unsafe-inline'");

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
