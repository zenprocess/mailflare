import assert from "node:assert/strict";
import test, { after } from "node:test";
import { loadFixture } from "./helpers/fixtures.mjs";

const fixture = await loadFixture({ name: "remote-image-signature", entryPoint: "src/lib/remote-images/signature.ts", mocks: {} });
const { signRemoteImageUrl, verifyRemoteImageSignature } = await fixture.import();
after(() => fixture.dispose());

const secret = "test-secret";
const now = 1_800_000_000;

test("a signed URL verifies within its window", async () => {
	const exp = now + 600;
	const sig = await signRemoteImageUrl("https://example.com/a.png", secret, exp);
	assert.equal(await verifyRemoteImageSignature("https://example.com/a.png", exp, sig, secret, now), true);
});

test("an expired signature is rejected", async () => {
	const exp = now + 600;
	const sig = await signRemoteImageUrl("https://example.com/a.png", secret, exp);
	assert.equal(await verifyRemoteImageSignature("https://example.com/a.png", exp, sig, secret, exp + 1), false);
});

test("a tampered URL, signature or secret is rejected", async () => {
	const exp = now + 600;
	const sig = await signRemoteImageUrl("https://example.com/a.png", secret, exp);
	assert.equal(await verifyRemoteImageSignature("https://example.com/b.png", exp, sig, secret, now), false);
	assert.equal(await verifyRemoteImageSignature("https://example.com/a.png", exp, sig + "x", secret, now), false);
	assert.equal(await verifyRemoteImageSignature("https://example.com/a.png", exp, sig, "wrong-secret", now), false);
});

test("signatures differ per URL and expiry", async () => {
	const a = await signRemoteImageUrl("https://a.test/x.png", secret, now + 600);
	const b = await signRemoteImageUrl("https://b.test/x.png", secret, now + 600);
	const c = await signRemoteImageUrl("https://a.test/x.png", secret, now + 700);
	assert.notEqual(a, b);
	assert.notEqual(a, c);
});

test("a malformed or empty signature is rejected", async () => {
	assert.equal(await verifyRemoteImageSignature("https://a.test/x.png", now + 600, "", secret, now), false);
	assert.equal(await verifyRemoteImageSignature("https://a.test/x.png", 1.5, "x", secret, now), false);
});
