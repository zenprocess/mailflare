import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test, { after } from "node:test";
import { loadFixture } from "./helpers/fixtures.mjs";

const fixture = await loadFixture({ name: "security-headers", entryPoint: "src/lib/security/headers.ts", mocks: {} });
const { buildCsp, getSecurityHeaders, shouldApplyNonceCsp, withNonceCsp } = await fixture.import();
const frameFixture = await loadFixture({ name: "security-headers-frame", entryPoint: "src/lib/remote-images/frame.ts", mocks: {} });
const { MAIL_FRAME_MEASURE_SCRIPT, MAIL_FRAME_MEASURE_SCRIPT_SHA256 } = await frameFixture.import();
const splashFixture = await loadFixture({ name: "security-headers-splash", entryPoint: "src/lib/security/splash-script.ts", mocks: {} });
const { SPLASH_GUARD_SCRIPT, SPLASH_GUARD_SCRIPT_SHA256 } = await splashFixture.import();
after(() => { fixture.dispose(); frameFixture.dispose(); splashFixture.dispose(); });

const sha256 = (value) => "sha256-" + createHash("sha256").update(value).digest("base64");

test("the two hash constants match the exact inline-script text", () => {
	assert.equal(MAIL_FRAME_MEASURE_SCRIPT_SHA256, sha256(MAIL_FRAME_MEASURE_SCRIPT));
	assert.equal(SPLASH_GUARD_SCRIPT_SHA256, sha256(SPLASH_GUARD_SCRIPT));
});

test("a nonce CSP drops unsafe-inline from script-src and allows the two fixed scripts by hash", () => {
	const csp = buildCsp("n123");
	assert.ok(csp.includes("script-src 'self' 'nonce-n123' https://challenges.cloudflare.com '" + MAIL_FRAME_MEASURE_SCRIPT_SHA256 + "' '" + SPLASH_GUARD_SCRIPT_SHA256 + "'"), csp);
	assert.ok(!csp.includes("script-src 'self' 'unsafe-inline'"), "script-src has no unsafe-inline: " + csp);
});

test("connect-src is restricted to self (no ws:/wss: wildcard)", () => {
	const csp = buildCsp("n123");
	assert.ok(csp.includes("connect-src 'self' https://challenges.cloudflare.com"), csp);
	assert.ok(!csp.includes("ws:") && !csp.includes("wss:"), "no ws:/wss: host wildcards: " + csp);
	assert.ok(!csp.includes("ws:") && !csp.includes("wss:"), "no ws:/wss: host wildcards: " + csp);
});

test("without a nonce the legacy inline-script CSP remains", () => {
	assert.ok(buildCsp().includes("script-src 'self' 'unsafe-inline'"));
});

test("getSecurityHeaders carries the nonce CSP", () => {
	const csp = getSecurityHeaders("n123").find((header) => header.key === "Content-Security-Policy");
	assert.ok(csp);
	assert.ok(csp.value.includes("'nonce-n123'"));
	assert.ok(!csp.value.includes("script-src 'self' 'unsafe-inline'"));
});

test("getSecurityHeaders without a nonce keeps the static CSP", () => {
	const csp = getSecurityHeaders().find((header) => header.key === "Content-Security-Policy");
	assert.ok(csp);
	assert.ok(csp.value.includes("script-src 'self' 'unsafe-inline'"));
});

test("the nonce CSP applies only to HTML documents without their own CSP", () => {
	const csp = buildCsp("n1");
	const html = new Response("<html></html>", { headers: { "Content-Type": "text/html; charset=utf-8" } });
	assert.equal(shouldApplyNonceCsp(html), true);
	const applied = withNonceCsp(html, csp);
	assert.equal(applied.headers.get("Content-Security-Policy"), csp);

	// A response that already carries its own (sandbox) CSP is never overwritten.
	const sandboxed = new Response("<html></html>", { headers: { "Content-Type": "text/html", "Content-Security-Policy": "default-src 'none'; sandbox" } });
	assert.equal(shouldApplyNonceCsp(sandboxed), false);
	assert.equal(withNonceCsp(sandboxed, csp).headers.get("Content-Security-Policy"), "default-src 'none'; sandbox");

	// Non-HTML responses (attachments, avatars, the image proxy, Drive, JMAP downloads) get no app CSP.
	for (const type of ["image/png", "application/pdf", "application/json", "text/plain"]) {
		const response = new Response(new Uint8Array([1, 2, 3]), { headers: { "Content-Type": type } });
		assert.equal(shouldApplyNonceCsp(response), false, type);
		assert.equal(withNonceCsp(response, csp), response, "unchanged identity for " + type);
	}

	// A response with no Content-Type gets no CSP either.
	const typeless = new Response("ok");
	assert.equal(shouldApplyNonceCsp(typeless), false);
});
