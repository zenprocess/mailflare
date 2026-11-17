import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";

const bundle = await build({ entryPoints: ["src/components/messages/email-html-renderer-utils.ts"], bundle: true, write: false, platform: "neutral", format: "esm" });
const { ATTACHMENT_PREVIEW, attachmentPreviewUrl, forcedImageMime, fetchFrameImages, MAX_FRAME_IMAGES, MAX_IMAGE_BYTES, MAX_TOTAL_IMAGE_BYTES } = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString("base64")}`);

test("attachment preview URLs are rebuilt from validated ids, never from the raw src", () => {
	assert.equal(attachmentPreviewUrl("/api/messages/msg_AbC123/attachments/att_xyz-9?preview=1"), "/api/messages/msg_AbC123/attachments/att_xyz-9?preview=1");
	assert.equal(attachmentPreviewUrl("/api/messages/a/attachments/b?preview=1"), "/api/messages/a/attachments/b?preview=1");

	// Dot segments and other crafted path shapes are rejected (not fetched).
	for (const src of [
		"/api/messages/../attachments/x?preview=1",
		"/api/messages/msg/attachments/..?preview=1",
		"/api/messages/msg/attachments/x?preview=1&download=1",
		"/api/messages/msg/attachments/x",
		"/api/messages/msg/attachments/x%2e%2e?preview=1",
		"/api/messages/msg/attachments/x/extra?preview=1",
		"/api/attachments/x?preview=1",
		"/api/messages//attachments/x?preview=1",
	]) {
		assert.equal(attachmentPreviewUrl(src), null, src);
		assert.equal(ATTACHMENT_PREVIEW.test(src), false, src);
	}
});

test("only allow-listed image types are forced; SVG and text/html are never admitted", () => {
	assert.equal(forcedImageMime("image/png"), "image/png");
	assert.equal(forcedImageMime("image/jpeg; name=x"), "image/jpeg");
	assert.equal(forcedImageMime("image/gif"), "image/gif");
	assert.equal(forcedImageMime("image/webp"), "image/webp");
	assert.equal(forcedImageMime("image/avif"), "image/avif");
	assert.equal(forcedImageMime("image/bmp"), "image/bmp");
	assert.equal(forcedImageMime("IMAGE/PNG"), "image/png");

	for (const type of ["image/svg+xml", "text/html", "application/pdf", "application/json", "text/plain", "text/csv", "application/octet-stream", "", null, undefined]) {
		assert.equal(forcedImageMime(type), null, String(type));
	}
});

test("the fetch budget constants are the agreed caps", () => {
	assert.equal(MAX_FRAME_IMAGES, 50);
	assert.equal(MAX_IMAGE_BYTES, 5 * 1024 * 1024);
	assert.equal(MAX_TOTAL_IMAGE_BYTES, 20 * 1024 * 1024);
});

test("the image budget is reserved before each fetch, so in-flight bodies cannot overshoot", async () => {
	let fetched = 0;
	const fetcher = async () => {
		fetched += 1;
		return new Response(new Uint8Array(3 * 1024 * 1024), { headers: { "content-type": "image/png", "content-length": String(3 * 1024 * 1024) } });
	};
	const urls = Array.from({ length: 12 }, (_, i) => "https://img.example/" + i + ".png");
	const blobs = await fetchFrameImages(urls, fetcher);
	// 6 × 3 MiB = 18 MiB ≤ 20 MiB; a seventh would exceed the cap.
	assert.equal(blobs.length, 6);
	// The per-fetch cap is reserved up front, so the loader stops after the six that fit — the old
	// "check after download" loop fetched ten of the twelve before noticing the budget was spent.
	assert.ok(fetched <= 6, "fetched " + fetched + " (expected at most 6)");
	assert.ok(blobs.reduce((sum, entry) => sum + entry.blob.size, 0) <= MAX_TOTAL_IMAGE_BYTES);
});

test("a declared Content-Length over the caps is rejected before the body is read", async () => {
	const fetcher = async () => ({
		ok: true,
		headers: { get: (name) => (name === "content-type" ? "image/png" : String(MAX_IMAGE_BYTES + 1)) },
		arrayBuffer: () => { throw new Error("body read despite oversized Content-Length"); },
	});
	const blobs = await fetchFrameImages(["https://img.example/big.png"], fetcher);
	assert.equal(blobs.length, 0);
});
