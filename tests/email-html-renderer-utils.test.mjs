import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";

const bundle = await build({ entryPoints: ["src/components/messages/email-html-renderer-utils.ts"], bundle: true, write: false, platform: "neutral", format: "esm" });
const { ATTACHMENT_PREVIEW, attachmentPreviewUrl, forcedImageMime, MAX_FRAME_IMAGES, MAX_IMAGE_BYTES, MAX_TOTAL_IMAGE_BYTES } = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString("base64")}`);

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
