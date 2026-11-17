import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test, { after } from "node:test";
import { loadFixture } from "./helpers/fixtures.mjs";

const fixture = await loadFixture({ name: "mail-frame", entryPoint: "src/lib/remote-images/frame.ts", mocks: {} });
const { buildMailFrameCsp, buildMailFrameDocument, parseMailFrameMessage, MAIL_FRAME_MESSAGE_SOURCE, MAIL_FRAME_MEASURE_SCRIPT, MAIL_FRAME_MEASURE_SCRIPT_SHA256, MIN_MAIL_FRAME_HEIGHT, MAX_MAIL_FRAME_HEIGHT } = await fixture.import();
after(() => fixture.dispose());

const sha256 = (value) => "sha256-" + createHash("sha256").update(value).digest("base64");

test("frame CSP allows the measuring script by hash and no unsafe-inline script", () => {
	const csp = buildMailFrameCsp();
	assert.match(csp, /default-src 'none'/);
	assert.ok(csp.includes("script-src '" + MAIL_FRAME_MEASURE_SCRIPT_SHA256 + "'"), csp);
	assert.ok(!/script-src[^;]*unsafe-inline/.test(csp), "no unsafe-inline for scripts");
	assert.ok(!/script-src[^;]*nonce/.test(csp), "no nonce for scripts");
	assert.match(csp, /img-src data: blob:/);
	assert.ok(!/img-src[^;]*https:/.test(csp), "frame never fetches remote https images");
	assert.match(csp, /base-uri 'none'/);
});

test("the hash constant matches the exact script text (recomputed at test time)", () => {
	assert.equal(MAIL_FRAME_MEASURE_SCRIPT_SHA256, sha256(MAIL_FRAME_MEASURE_SCRIPT));
});

test("frame document wraps the body and carries the CSP and hash-allowed script", () => {
	const doc = buildMailFrameDocument("<p>hi</p>", false);
	assert.match(doc, /<meta http-equiv="Content-Security-Policy" content="[^"]*sha256-/);
	assert.ok(doc.includes("<script>" + MAIL_FRAME_MEASURE_SCRIPT + "</script>"), "script is hash-allowed, not nonce'd");
	assert.ok(doc.includes("<p>hi</p>"));
	assert.match(buildMailFrameDocument("<p>x</p>", true), /class="mf-dark"/);
});

test("message parser accepts only well-formed height reports and clamps them", () => {
	assert.deepEqual(parseMailFrameMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "height", height: 42 }), { height: 42 });
	assert.equal(parseMailFrameMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "height", height: -1 }), null);
	assert.equal(parseMailFrameMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "height", height: "42" }), null);
	assert.equal(parseMailFrameMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "height", height: Number.NaN }), null);
	assert.equal(parseMailFrameMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "height", height: Number.POSITIVE_INFINITY }), null);
	assert.equal(parseMailFrameMessage({ source: "other", type: "height", height: 42 }), null);
	assert.equal(parseMailFrameMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "ping" }), null);
	assert.equal(parseMailFrameMessage(null), null);
	// clamp: a fractional height rounds up; an absurd height is capped; a tiny positive stays >= MIN.
	assert.deepEqual(parseMailFrameMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "height", height: 40.2 }), { height: 41 });
	assert.deepEqual(parseMailFrameMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "height", height: 10_000_000 }), { height: MAX_MAIL_FRAME_HEIGHT });
	assert.deepEqual(parseMailFrameMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "height", height: 0.5 }), { height: MIN_MAIL_FRAME_HEIGHT });
});
