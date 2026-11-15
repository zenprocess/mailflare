import assert from "node:assert/strict";
import test, { after } from "node:test";
import { loadFixture } from "./helpers/fixtures.mjs";

const fixture = await loadFixture({ name: "mail-frame", entryPoint: "src/lib/remote-images/frame.ts", mocks: {} });
const { buildMailFrameCsp, buildMailFrameDocument, parseMailFrameMessage, MAIL_FRAME_MESSAGE_SOURCE } = await fixture.import();
after(() => fixture.dispose());

test("frame CSP is nonce-based and allows no unsafe-inline script", () => {
	const csp = buildMailFrameCsp("abc123");
	assert.match(csp, /default-src 'none'/);
	assert.match(csp, /script-src 'nonce-abc123'/);
	assert.ok(!/script-src[^;]*unsafe-inline/.test(csp), "no unsafe-inline for scripts");
	assert.match(csp, /img-src https: data: blob:/);
	assert.match(csp, /base-uri 'none'/);
});

test("frame document wraps the body and carries the nonce and CSP", () => {
	const doc = buildMailFrameDocument("<p>hi</p>", "n1", false);
	assert.match(doc, /<meta http-equiv="Content-Security-Policy" content="[^"]*nonce-n1/);
	assert.match(doc, /<script nonce="n1">/);
	assert.match(doc, /<p>hi<\/p>/);
	assert.match(buildMailFrameDocument("<p>x</p>", "n1", true), /class="mf-dark"/);
});

test("message parser accepts only well-formed height reports", () => {
	assert.deepEqual(parseMailFrameMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "height", height: 42 }), { height: 42 });
	assert.equal(parseMailFrameMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "height", height: -1 }), null);
	assert.equal(parseMailFrameMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "height", height: "42" }), null);
	assert.equal(parseMailFrameMessage({ source: "other", type: "height", height: 42 }), null);
	assert.equal(parseMailFrameMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "ping" }), null);
	assert.equal(parseMailFrameMessage(null), null);
});
