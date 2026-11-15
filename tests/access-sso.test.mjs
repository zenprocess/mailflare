// Cloudflare Access sign-in (zp/access-sso): JWT verification, JWKS rotation and the Worker gate.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import test, { after, beforeEach } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = mkdtempSync(join(root, "tests", ".tmp-access-sso-"));
after(() => rmSync(outDir, { recursive: true, force: true }));

await build({
	stdin: {
		contents: [
			'export { verifyAccessJwt, clearAccessJwksCache, JWKS_TTL_MS, JWKS_MIN_REFRESH_MS } from "./src/lib/auth/access/jwt.ts";',
			'export { applyAccessGate, readAccessConfig, pathMatches, normalizeGatePath, withAccessSessionCookie } from "./src/lib/auth/access/gate.ts";',
			'export { getUserFromSession } from "./src/lib/auth/session.ts";',
			'export { SqliteDatabase } from "./server/runtime/sqlite-database.ts";',
			'export { applyMigrations } from "./server/runtime/migrate.ts";',
		].join("\n"),
		resolveDir: root,
		sourcefile: "access-sso-entry.ts",
	},
	outfile: join(outDir, "entry.mjs"),
	bundle: true,
	platform: "node",
	format: "esm",
	target: "node22",
	tsconfig: join(root, "tsconfig.json"),
	packages: "external",
	alias: { "cloudflare:workers": "./server/runtime/cloudflare-workers.ts" },
	logLevel: "silent",
});

const {
	verifyAccessJwt,
	clearAccessJwksCache,
	JWKS_TTL_MS,
	JWKS_MIN_REFRESH_MS,
	applyAccessGate,
	readAccessConfig,
	pathMatches,
	normalizeGatePath,
	withAccessSessionCookie,
	getUserFromSession,
	SqliteDatabase,
	applyMigrations,
} = await import(pathToFileURL(join(outDir, "entry.mjs")).href);

const TEAM = "zp-test.cloudflareaccess.com";
const AUD = "aud-tag-123";
const CERTS = "https://" + TEAM + "/cdn-cgi/access/certs";
const te = new TextEncoder();

function b64url(bytes) {
	return Buffer.from(bytes).toString("base64url");
}

async function makeKey(kid) {
	const pair = await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	);
	const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
	return { kid, privateKey: pair.privateKey, jwk: { ...jwk, kid, alg: "RS256", use: "sig" } };
}

const keyA = await makeKey("kid-a");
const keyB = await makeKey("kid-b");
const keyEvil = await makeKey("kid-a");

async function sign(key, payload, header = {}) {
	const h = b64url(te.encode(JSON.stringify({ alg: "RS256", kid: key.kid, typ: "JWT", ...header })));
	const p = b64url(te.encode(JSON.stringify(payload)));
	const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key.privateKey, te.encode(h + "." + p)));
	return h + "." + p + "." + b64url(sig);
}

const NOW = 1_800_000_000_000;
const nowS = Math.floor(NOW / 1000);
const claims = (extra = {}) => ({
	iss: "https://" + TEAM,
	aud: [AUD],
	sub: "sub-1",
	email: "Owner@One.test",
	iat: nowS - 10,
	nbf: nowS - 10,
	exp: nowS + 600,
	...extra,
});

/** A JWKS endpoint whose key set the test can rotate; counts fetches. */
function jwksServer(keys) {
	const server = {
		keys,
		calls: 0,
		fetcher: async (url) => {
			server.calls += 1;
			assert.equal(url, CERTS);
			return Response.json({ keys: server.keys.map((k) => k.jwk) });
		},
	};
	return server;
}

const opts = (server, extra = {}) => ({ teamDomain: TEAM, aud: AUD, fetcher: server.fetcher, now: () => NOW, ...extra });

beforeEach(() => clearAccessJwksCache());

// ---------------------------------------------------------------- verifier

test("a valid assertion verifies and yields email/sub", async () => {
	const server = jwksServer([keyA]);
	const result = await verifyAccessJwt(await sign(keyA, claims()), opts(server));
	assert.equal(result.ok, true);
	assert.equal(result.claims.email, "Owner@One.test");
	assert.equal(result.claims.sub, "sub-1");
	// team domain given with scheme / trailing slash / string aud still works
	const again = await verifyAccessJwt(await sign(keyA, claims({ aud: AUD })), opts(server, { teamDomain: "https://" + TEAM + "/" }));
	assert.equal(again.ok, true);
});

test("wrong aud, wrong or missing iss, expired, not-yet-valid are rejected", async () => {
	const server = jwksServer([keyA]);
	const reason = async (payload) => (await verifyAccessJwt(await sign(keyA, payload), opts(server))).reason;
	assert.equal(await reason(claims({ aud: ["other-aud"] })), "aud");
	assert.equal(await reason(claims({ aud: [] })), "aud");
	assert.equal(await reason(claims({ iss: "https://evil.cloudflareaccess.com" })), "iss");
	assert.equal(await reason(claims({ iss: undefined })), "iss");
	assert.equal(await reason(claims({ exp: nowS - 31 })), "expired");
	assert.equal(await reason(claims({ exp: undefined })), "expired");
	assert.equal(await reason(claims({ nbf: nowS + 31 })), "not_yet_valid");
	assert.equal(await reason(claims({ email: "" })), "identity");
	assert.equal(await reason(claims({ sub: undefined })), "identity");
	// within the 30 s skew
	assert.equal((await verifyAccessJwt(await sign(keyA, claims({ exp: nowS - 5, nbf: nowS + 5 })), opts(server))).ok, true);
});

test("bad signature, foreign key with a known kid, alg none and malformed tokens are rejected", async () => {
	const server = jwksServer([keyA]);
	const good = await sign(keyA, claims());
	const [h, p, s] = good.split(".");
	const tampered = h + "." + b64url(te.encode(JSON.stringify(claims({ email: "admin@one.test" })))) + "." + s;
	assert.equal((await verifyAccessJwt(tampered, opts(server))).reason, "signature");
	assert.equal((await verifyAccessJwt(h + "." + p + "." + s.slice(0, -4) + "AAAA", opts(server))).reason, "signature");
	assert.equal((await verifyAccessJwt(await sign(keyEvil, claims()), opts(server))).reason, "signature");
	const none = b64url(te.encode(JSON.stringify({ alg: "none", kid: "kid-a" }))) + "." + p + "." + s;
	assert.equal((await verifyAccessJwt(none, opts(server))).reason, "alg");
	const hs = b64url(te.encode(JSON.stringify({ alg: "HS256", kid: "kid-a" }))) + "." + p + "." + s;
	assert.equal((await verifyAccessJwt(hs, opts(server))).reason, "alg");
	assert.equal((await verifyAccessJwt("not-a-jwt", opts(server))).reason, "malformed");
	assert.equal((await verifyAccessJwt(null, opts(server))).reason, "missing");
});

test("unknown kid is rejected; JWKS outage is rejected", async () => {
	const server = jwksServer([keyA]);
	assert.equal((await verifyAccessJwt(await sign(keyB, claims()), opts(server))).reason, "unknown_kid");
	clearAccessJwksCache();
	const down = { fetcher: async () => new Response("down", { status: 503 }) };
	assert.equal((await verifyAccessJwt(await sign(keyA, claims()), opts(down))).reason, "jwks_unavailable");
	const broken = { fetcher: async () => { throw new Error("network"); } };
	assert.equal((await verifyAccessJwt(await sign(keyA, claims()), opts(broken))).reason, "jwks_unavailable");
});

test("JWKS rotation: cache is reused, an unknown kid refetches (rate limited), retired keys stop working", async () => {
	const server = jwksServer([keyA]);
	let now = NOW;
	const o = () => opts(server, { now: () => now });
	assert.equal((await verifyAccessJwt(await sign(keyA, claims()), o())).ok, true);
	assert.equal((await verifyAccessJwt(await sign(keyA, claims()), o())).ok, true);
	assert.equal(server.calls, 1, "second verification uses the cache");

	// Cloudflare rotates: B is published next to A.
	server.keys = [keyA, keyB];
	// Inside the min-refresh window an unknown kid does not refetch (forged kids cannot hammer the endpoint).
	assert.equal((await verifyAccessJwt(await sign(keyB, claims()), o())).reason, "unknown_kid");
	assert.equal(server.calls, 1);
	now += JWKS_MIN_REFRESH_MS;
	assert.equal((await verifyAccessJwt(await sign(keyB, claims()), o())).ok, true, "unknown kid forces a refresh");
	assert.equal(server.calls, 2);

	// A is retired; once the cache expires, A-signed tokens are refused.
	server.keys = [keyB];
	now += JWKS_TTL_MS;
	assert.equal((await verifyAccessJwt(await sign(keyA, claims()), o())).reason, "unknown_kid");
	assert.equal((await verifyAccessJwt(await sign(keyB, claims()), o())).ok, true);
});

// ---------------------------------------------------------------- gate

async function fixture(t, vars = {}) {
	clearAccessJwksCache();
	const database = new SqliteDatabase(":memory:");
	t.after(() => database.db.close());
	await applyMigrations(database, join(root, "drizzle/migrations"));
	const insert = database.db.prepare("INSERT INTO users (id, email, name, password_hash, role, disabled, created_at) VALUES (?, ?, ?, 'x', ?, ?, 1)");
	insert.run("u-admin", "owner@one.test", "Owner", "admin", 0);
	insert.run("u-bob", "bob@one.test", "Bob", "user", 0);
	insert.run("u-off", "off@one.test", "Off", "user", 1);
	const server = jwksServer([keyA]);
	const env = { DB: database, ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD, ...vars };
	const gate = (request) => applyAccessGate(request, env, { fetcher: server.fetcher, now: () => NOW });
	return { database, env, server, gate };
}

async function req(path, { token, email, headers = {}, method = "GET", html = false } = {}) {
	const h = new Headers(headers);
	if (token !== undefined) h.set("Cf-Access-Jwt-Assertion", token);
	else if (email) h.set("Cf-Access-Jwt-Assertion", await sign(keyA, claims({ email })));
	if (html) h.set("Accept", "text/html");
	return new Request("https://mail.example.test" + path, { method, headers: h });
}

function sessionFrom(setCookie) {
	return decodeURIComponent(/ep_session=([^;]+)/.exec(setCookie)[1]);
}

test("Access mode fails closed when unconfigured, unless MAILFLARE_ACCESS_MODE=off", async (t) => {
	assert.equal(readAccessConfig({}), null);
	assert.equal(readAccessConfig({ ACCESS_TEAM_DOMAIN: TEAM }), "misconfigured");

	// Both vars unset, no opt-out: every request is 503 "Access not configured".
	const unconfigured = await applyAccessGate(await req("/inbox"), { DB: null });
	assert.equal(unconfigured.kind, "response");
	assert.equal(unconfigured.response.status, 503);
	assert.match(unconfigured.response.headers.get("X-Mailflare-Access"), /access_not_configured/);

	// The built-in mail-ingest webhooks stay reachable even when Access is unconfigured.
	const inbound = await applyAccessGate(await req("/api/inbound/ses"), { DB: null });
	assert.equal(inbound.kind, "pass");

	// Half-configured (one var set) still fails closed with 503.
	const { gate } = await fixture(t, { ACCESS_AUD: "" });
	const res = await gate(await req("/inbox"));
	assert.equal(res.kind, "response");
	assert.equal(res.response.status, 503);
	assert.equal(res.response.headers.get("X-Mailflare-Access"), "access_misconfigured");

	// Explicit MAILFLARE_ACCESS_MODE=off restores upstream open behaviour.
	const off = await applyAccessGate(await req("/inbox"), { DB: null, MAILFLARE_ACCESS_MODE: "off" });
	assert.equal(off.kind, "off");
});

test("valid assertion for an existing user (any case) creates a normal session, then reuses it", async (t) => {
	const { env, gate } = await fixture(t);
	const first = await gate(await req("/inbox", { email: "OWNER@one.TEST", html: true }));
	assert.equal(first.kind, "pass");
	assert.equal(first.userId, "u-admin");
	assert.match(first.setCookie, /^ep_session=.+; Path=\/; HttpOnly; SameSite=Lax; Max-Age=2592000; Secure$/);
	const token = sessionFrom(first.setCookie);
	assert.equal((await getUserFromSession(env, token)).id, "u-admin");
	// the app sees the session on this very request
	assert.match(first.request.headers.get("Cookie"), /ep_session=/);

	const second = await gate(await req("/inbox", { email: "owner@one.test", headers: { Cookie: "ep_session=" + encodeURIComponent(token) } }));
	assert.equal(second.kind, "pass");
	assert.equal(second.setCookie, undefined, "existing session reused");

	const response = withAccessSessionCookie(new Response("ok"), first.setCookie);
	assert.match(response.headers.get("Set-Cookie"), /ep_session=/);
});

test("missing / invalid assertions are 401; the unsigned email header is never trusted", async (t) => {
	const { gate } = await fixture(t);
	const status = async (request) => {
		const r = await gate(request);
		return r.kind === "response" ? r.response.status : 200;
	};
	assert.equal(await status(await req("/inbox")), 401);
	assert.equal(await status(await req("/inbox", { headers: { "Cf-Access-Authenticated-User-Email": "owner@one.test" } })), 401);
	assert.equal(await status(await req("/api/messages", { token: await sign(keyA, claims({ aud: ["x"] })) })), 401);
	assert.equal(await status(await req("/api/messages", { token: await sign(keyA, claims({ iss: "https://x.cloudflareaccess.com" })) })), 401);
	assert.equal(await status(await req("/api/messages", { token: await sign(keyA, claims({ exp: nowS - 120 })) })), 401);
	assert.equal(await status(await req("/api/messages", { token: await sign(keyEvil, claims()) })), 401);
	assert.equal(await status(await req("/api/messages", { token: await sign(keyB, claims()) })), 401);
	assert.equal(await status(await req("/api/realtime", { token: "garbage" })), 401);
	const html = await gate(await req("/inbox", { html: true }));
	assert.match(html.response.headers.get("Content-Type"), /text\/html/);
	assert.match(await html.response.text(), /Sign-in required/);
});

test("valid assertion with no Mailflare user is 403 'ask an admin'; disabled users are 403", async (t) => {
	const { gate, database } = await fixture(t);
	const unknown = await gate(await req("/inbox", { email: "stranger@gmail.com", html: true }));
	assert.equal(unknown.response.status, 403);
	assert.match(await unknown.response.text(), /Ask an administrator/);
	assert.equal(database.db.prepare("SELECT count(*) AS n FROM users").get().n, 3, "no auto-provisioning by default");
	const disabled = await gate(await req("/inbox", { email: "off@one.test" }));
	assert.equal(disabled.response.status, 403);
});

test("ACCESS_AUTO_PROVISION=true creates a passwordless user for an unknown identity", async (t) => {
	const { gate, database } = await fixture(t, { ACCESS_AUTO_PROVISION: "true" });
	const result = await gate(await req("/inbox", { email: "New.Person@one.test" }));
	assert.equal(result.kind, "pass");
	const row = database.db.prepare("SELECT email, role, password_hash FROM users WHERE id = ?").get(result.userId);
	assert.deepEqual({ ...row }, { email: "new.person@one.test", role: "user", password_hash: "!passkey-only" });
});

test("a session or Bearer token of another user does not survive a different Access identity", async (t) => {
	const { env, gate } = await fixture(t);
	const bob = sessionFrom((await gate(await req("/inbox", { email: "bob@one.test", html: true }))).setCookie);
	// Cookie for Bob, Access says Owner: a fresh Owner session replaces it.
	const swapped = await gate(await req("/inbox", { email: "owner@one.test", html: true, headers: { Cookie: "ep_session=" + bob + "; theme=dark" } }));
	assert.equal(swapped.kind, "pass");
	assert.equal(swapped.userId, "u-admin");
	assert.equal((await getUserFromSession(env, sessionFrom(swapped.setCookie))).id, "u-admin");
	assert.match(swapped.request.headers.get("Cookie"), /theme=dark/);
	assert.doesNotMatch(swapped.request.headers.get("Cookie"), new RegExp(bob));
	// Bearer session for Bob with an Owner assertion: refused.
	const bearer = await gate(await req("/api/messages", { email: "owner@one.test", headers: { Authorization: "Bearer " + bob } }));
	assert.equal(bearer.response.status, 403);
	// Bearer that is not a session (API key) is left to the route.
	const apiKey = await gate(await req("/api/v1/messages", { email: "owner@one.test", headers: { Authorization: "Bearer ep_notasession" } }));
	assert.equal(apiKey.kind, "pass");
});

test("bypass paths: mail ingest built in, ACCESS_BYPASS_PATHS honoured with segment matching", async (t) => {
	const { gate } = await fixture(t, { ACCESS_BYPASS_PATHS: "/book, /api/public/booking /c/ /api/i/*" });
	for (const path of ["/api/inbound", "/api/inbound/ses", "/book/u1/e1", "/api/public/booking/e1", "/c/alice/meet", "/api/i/pixel.gif"]) {
		const result = await gate(await req(path));
		assert.equal(result.kind, "pass", path);
		assert.equal(result.setCookie, undefined, path);
	}
	for (const path of ["/bookings", "/api/public/bookingx", "/inbox", "/api/inboundx", "/"]) {
		const result = await gate(await req(path));
		assert.equal(result.kind, "response", path);
		assert.equal(result.response.status, 401, path);
	}
	assert.equal(pathMatches("/book", "/book"), true);
	assert.equal(pathMatches("/api/i/x", "/api/i/*"), true);
	assert.equal(pathMatches("/x", "x"), false);
});

test("/setup needs a valid assertion AND an email in ACCESS_SETUP_EMAILS", async (t) => {
	const { gate } = await fixture(t, { ACCESS_SETUP_EMAILS: "owner@one.test, Root@Zp.test" });
	for (const path of ["/setup", "/setup/passkey", "/register", "/api/setup/status", "/api/auth/register"]) {
		assert.equal((await gate(await req(path))).response.status, 401, path + " without assertion");
		assert.equal((await gate(await req(path, { email: "bob@one.test" }))).response.status, 403, path + " non-setup email");
		assert.equal((await gate(await req(path, { email: "owner@one.test" }))).kind, "pass", path + " setup email");
	}
	// Not listed at all: setup is closed.
	const { gate: closed } = await fixture(t);
	assert.equal((await closed(await req("/setup", { email: "owner@one.test" }))).response.status, 403);
});

test("first run (no users yet): a setup email reaches the app without a session; others are refused", async (t) => {
	const database = new SqliteDatabase(":memory:");
	t.after(() => database.db.close());
	await applyMigrations(database, join(root, "drizzle/migrations"));
	const server = jwksServer([keyA]);
	const env = { DB: database, ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD, ACCESS_SETUP_EMAILS: "root@zp.test" };
	const gate = (request) => applyAccessGate(request, env, { fetcher: server.fetcher, now: () => NOW });
	const root1 = await gate(await req("/", { email: "root@zp.test" }));
	assert.equal(root1.kind, "pass");
	assert.equal(root1.setCookie, undefined);
	assert.equal((await gate(await req("/setup", { email: "root@zp.test" }))).kind, "pass");
	assert.equal((await gate(await req("/api/auth/register", { email: "root@zp.test", method: "POST" }))).kind, "pass");
	assert.equal((await gate(await req("/", { email: "someone@zp.test" }))).response.status, 403);
	assert.equal((await gate(await req("/setup", { email: "someone@zp.test" }))).response.status, 403);
	// Empty database (no tables at all) does not crash the gate.
	const empty = new SqliteDatabase(":memory:");
	t.after(() => empty.db.close());
	const emptyEnv = { ...env, DB: empty };
	const r = await applyAccessGate(await req("/setup", { email: "root@zp.test" }), emptyEnv, { fetcher: server.fetcher, now: () => NOW });
	assert.equal(r.kind, "pass");
});

test("ACCESS_EMAIL_MAP binds a differing IdP identity to a Mailflare account (operator controlled)", async (t) => {
	const { gate } = await fixture(t, { ACCESS_EMAIL_MAP: "Val@Corp.test=owner@one.test, junk, a=b", ACCESS_SETUP_EMAILS: "val@corp.test" });
	const mapped = await gate(await req("/inbox", { email: "val@corp.test" }));
	assert.equal(mapped.kind, "pass");
	assert.equal(mapped.userId, "u-admin");
	// setup gating checks the Access identity, not the mapped account
	assert.equal((await gate(await req("/setup", { email: "val@corp.test" }))).kind, "pass");
	assert.equal((await gate(await req("/inbox", { email: "other@corp.test" }))).response.status, 403);
	assert.equal(readAccessConfig({ ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD, ACCESS_EMAIL_MAP: "junk, a=b" }).emailMap.size, 0);
});

test("password sign-in is disabled in Access mode unless ACCESS_ALLOW_PASSWORD_LOGIN=true", async (t) => {
	const { gate } = await fixture(t);
	for (const path of ["/api/auth/login", "/api/auth/password-reset/request", "/api/auth/password-reset/confirm"]) {
		const r = await gate(await req(path, { email: "owner@one.test", method: "POST" }));
		assert.equal(r.response.status, 403, path);
		assert.equal(r.response.headers.get("X-Mailflare-Access"), "password_login_disabled");
	}
	// step-up (passkey for admin actions) is untouched
	assert.equal((await gate(await req("/api/auth/step-up/options", { email: "owner@one.test", method: "POST" }))).kind, "pass");
	const { gate: allowed } = await fixture(t, { ACCESS_ALLOW_PASSWORD_LOGIN: "true" });
	assert.equal((await allowed(await req("/api/auth/login", { email: "owner@one.test", method: "POST" }))).kind, "pass");
});

test("the gate normalises the path like the router and rejects encoded separators / dot segments", async (t) => {
	assert.equal(normalizeGatePath("/api/auth/%72egister"), "/api/auth/register");
	assert.equal(normalizeGatePath("//api/auth/register"), "/api/auth/register");
	assert.equal(normalizeGatePath("/api/%73etup/prepare"), "/api/setup/prepare");
	assert.equal(normalizeGatePath("/api/auth/%2fregister"), null);
	assert.equal(normalizeGatePath("/api/auth/%5cregister"), null);
	assert.equal(normalizeGatePath("/api/%2e%2e/setup"), null);
	assert.equal(normalizeGatePath("/api/../setup"), null);
	assert.equal(normalizeGatePath("/api/./setup"), null);
	// NUL and other control bytes are rejected with 400 (the router 404s them).
	assert.equal(normalizeGatePath("/api/setup/status%00"), null);
	assert.equal(normalizeGatePath("/api/setup/status\u0000"), null);
	assert.equal(normalizeGatePath("/api/setup%1fstatus"), null);
	assert.equal(normalizeGatePath("/api/setup/status%7f"), null);

	// Bypass strings reach the gated route through the normalised path, not the raw one.
	const { gate } = await fixture(t, { ACCESS_SETUP_EMAILS: "owner@one.test" });
	for (const path of ["/api/auth/%72egister", "//api/auth/register", "/api/%73etup/prepare"]) {
		assert.equal((await gate(await req(path))).response.status, 401, path + " needs an assertion");
		assert.equal((await gate(await req(path, { email: "bob@one.test" }))).response.status, 403, path + " non-setup email");
	}
	// Encoded separators are rejected outright with 400. (The URL parser resolves literal and
	// %2e%2e dot segments before the gate ever sees them, so those are covered by the direct
	// normalizeGatePath assertions above.)
	for (const path of ["/api/auth/%2fregister", "/api/auth/%5cregister", "/api/setup/status%00"]) {
		assert.equal((await gate(await req(path, { email: "owner@one.test" }))).response.status, 400, path);
	}
});

test("a session is minted only for navigations and API calls, not subresources", async (t) => {
	const { database, gate } = await fixture(t);
	const count = () => database.db.prepare("SELECT count(*) AS n FROM sessions").get().n;

	// A navigation (Accept: text/html) mints a session.
	const nav = await gate(await req("/inbox", { email: "owner@one.test", html: true }));
	assert.equal(nav.kind, "pass");
	assert.ok(nav.setCookie);
	assert.equal(count(), 1);

	// An API call mints a session too.
	const api = await gate(await req("/api/messages", { email: "owner@one.test" }));
	assert.equal(api.kind, "pass");
	assert.ok(api.setCookie);
	assert.equal(count(), 2);

	// A subresource request (no html Accept, not /api) verifies the identity but mints nothing.
	const sub = await gate(await req("/favicon.ico", { email: "owner@one.test" }));
	assert.equal(sub.kind, "pass");
	assert.equal(sub.setCookie, undefined);
	assert.equal(sub.userId, "u-admin");
	assert.equal(count(), 2);
});

test("a foreign session cookie is stripped on requests that do not mint a session", async (t) => {
	const { env, gate } = await fixture(t);
	const bob = sessionFrom((await gate(await req("/inbox", { email: "bob@one.test", html: true }))).setCookie);
	const bobCookie = "ep_session=" + bob;

	// RSC subresource shape (Accept: */*, not /api) with Bob's cookie and Owner's Access identity.
	const rsc = await gate(await req("/inbox?_rsc=abc", { email: "owner@one.test", headers: { Cookie: bobCookie + "; theme=dark", RSC: "1", Accept: "*/*" } }));
	assert.equal(rsc.kind, "pass");
	assert.equal(rsc.userId, "u-admin");
	assert.equal(rsc.setCookie, undefined, "no session minted for a subresource");
	assert.doesNotMatch(rsc.request.headers.get("Cookie") ?? "", new RegExp(bob));
	assert.match(rsc.request.headers.get("Cookie") ?? "", /theme=dark/);

	// Server-action shape (POST, Accept: text/x-component) also strips the foreign session.
	const action = await gate(await req("/inbox", { email: "owner@one.test", method: "POST", headers: { Cookie: bobCookie, Accept: "text/x-component" } }));
	assert.equal(action.kind, "pass");
	assert.equal(action.userId, "u-admin");
	assert.doesNotMatch(action.request.headers.get("Cookie") ?? "", new RegExp(bob));

	// A navigation still mints a fresh Owner session and replaces the foreign cookie.
	const nav = await gate(await req("/inbox", { email: "owner@one.test", html: true, headers: { Cookie: bobCookie } }));
	assert.equal(nav.kind, "pass");
	assert.equal(nav.userId, "u-admin");
	assert.equal((await getUserFromSession(env, sessionFrom(nav.setCookie))).id, "u-admin");
});

test("duplicate, spaced-name and case-variant session cookies are reduced to exactly one verified session", async (t) => {
	const { env, gate } = await fixture(t);
	const owner = sessionFrom((await gate(await req("/inbox", { email: "owner@one.test", html: true }))).setCookie);
	const bob = sessionFrom((await gate(await req("/inbox", { email: "bob@one.test", html: true }))).setCookie);

	// The gate reads the first ep_session and the app reads the last, so two session cookies let a
	// foreign token reach the app. The rewrite must collapse every ep_session part (any trimmed-name
	// case variant) into exactly one verified session, whichever order or spelling the attacker sends.
	for (const cookie of [
		"ep_session=" + bob + "; ep_session=" + owner,
		"ep_session=" + owner + "; ep_session=" + bob,
		"ep_session =" + bob,
		"EP_SESSION=" + bob,
		"ep_session=" + bob + "; ep_session =" + owner + "; EP_SESSION=" + bob + "; theme=dark",
	]) {
		const result = await gate(await req("/inbox", { email: "owner@one.test", html: true, headers: { Cookie: cookie } }));
		assert.equal(result.kind, "pass", cookie);
		assert.equal(result.userId, "u-admin", cookie);
		const outCookie = result.request.headers.get("Cookie") ?? "";
		const sessionParts = outCookie.split(";").map((part) => part.trim()).filter((part) => /^ep_session=/i.test(part));
		assert.equal(sessionParts.length, 1, cookie + " -> " + outCookie);
		assert.doesNotMatch(outCookie, new RegExp(bob), cookie);
		const token = decodeURIComponent(sessionParts[0].slice(sessionParts[0].indexOf("=") + 1));
		assert.equal((await getUserFromSession(env, token)).id, "u-admin", cookie);
	}

	// Subresource requests strip the foreign/spaced/case cookie without minting a session.
	const rsc = await gate(await req("/inbox?_rsc=abc", { email: "owner@one.test", headers: { Cookie: "ep_session =" + bob + "; EP_SESSION=" + bob + "; theme=dark", RSC: "1", Accept: "*/*" } }));
	assert.equal(rsc.kind, "pass");
	assert.equal(rsc.userId, "u-admin");
	assert.equal(rsc.setCookie, undefined);
	const rscCookie = rsc.request.headers.get("Cookie") ?? "";
	assert.doesNotMatch(rscCookie, new RegExp(bob));
	assert.doesNotMatch(rscCookie, /ep_session/i);
	assert.match(rscCookie, /theme=dark/);
});
