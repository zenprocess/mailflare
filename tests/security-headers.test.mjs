import assert from "node:assert/strict";
import test, { after } from "node:test";
import { loadFixture } from "./helpers/fixtures.mjs";

const fixture = await loadFixture({ name: "security-headers", entryPoint: "src/lib/security/headers.ts", mocks: {} });
const { buildCsp, getSecurityHeaders } = await fixture.import();
after(() => fixture.dispose());

test("a nonce CSP drops unsafe-inline from script-src", () => {
	const csp = buildCsp("n123");
	assert.ok(csp.includes("script-src 'self' 'nonce-n123' https://challenges.cloudflare.com"), csp);
	assert.ok(!csp.includes("script-src 'self' 'unsafe-inline'"), "script-src has no unsafe-inline: " + csp);
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
