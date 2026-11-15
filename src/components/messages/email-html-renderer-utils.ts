// Pure helpers for the sandboxed mail frame's parent-side image fetch (email-html-renderer.tsx).
// Split out so they can be unit-tested without a DOM.

/**
 * cid: attachment preview URLs (see resolveInlineAttachmentUrls). The message and attachment ids
 * are strictly validated against nanoid's alphabet, so a sender-crafted src can never smuggle a
 * ".." segment (or any other path) that would make the reader's browser GET an arbitrary
 * same-origin path. The ids are captured and used to rebuild the URL, never the raw src string.
 */
export const ATTACHMENT_PREVIEW = /^\/api\/messages\/([A-Za-z0-9_-]+)\/attachments\/([A-Za-z0-9_-]+)\?preview=1$/;

/** Rebuilds a canonical preview URL from a src, or null when it is not a valid preview URL. */
export function attachmentPreviewUrl(src: string): string | null {
	const match = ATTACHMENT_PREVIEW.exec(src);
	return match ? `/api/messages/${match[1]}/attachments/${match[2]}?preview=1` : null;
}

/** Images the frame will accept. SVG is deliberately absent: it is active content, never a plain image. */
export const ALLOWED_IMAGE_TYPES: Record<string, string> = {
	"image/png": "image/png",
	"image/jpeg": "image/jpeg",
	"image/gif": "image/gif",
	"image/webp": "image/webp",
	"image/avif": "image/avif",
	"image/bmp": "image/bmp",
};

/** The forced image MIME for a response content type, or null when it is not an allowed image. */
export function forcedImageMime(contentType: string | null | undefined): string | null {
	if (!contentType) return null;
	const essence = contentType.split(";", 1)[0].trim().toLowerCase();
	return ALLOWED_IMAGE_TYPES[essence] ?? null;
}

export const MAX_FRAME_IMAGES = 50;
/** Per-image byte cap, matching the remote-image proxy's REMOTE_IMAGE_MAX_BYTES. */
export const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
/** Total bytes of image data one message may pull into the reader's tab. */
export const MAX_TOTAL_IMAGE_BYTES = 20 * 1024 * 1024;
export const FRAME_FETCH_CONCURRENCY = 4;

/** A fetch function the image loader calls once per URL; injectable for tests. */
export type FrameImageFetch = (url: string) => Promise<Response>;

/**
 * Fetches the frame images with the session cookie and hands back the bytes as re-wrapped Blobs for
 * the frame. The total is hard-capped at MAX_TOTAL_IMAGE_BYTES of committed *plus* in-flight bytes:
 * the per-image cap is reserved before each fetch, so a batch of concurrent bodies can never push the
 * running total past the budget (the old loop counted a body only after it had fully downloaded, which
 * let up to FRAME_FETCH_CONCURRENCY in-flight bodies overshoot by up to one cap each). A declared
 * Content-Length is also honoured up front, so an oversized body is rejected without being read.
 */
export async function fetchFrameImages(
	urls: string[],
	fetchImpl: FrameImageFetch,
): Promise<Array<{ index: number; blob: Blob }>> {
	const blobs: Array<{ index: number; blob: Blob }> = [];
	let totalBytes = 0;
	let reserved = 0;
	let cursor = 0;
	const worker = async () => {
		while (true) {
			if (cursor >= urls.length) return;
			// Reserve the worst-case bytes before issuing the fetch. The reservation and the cursor
			// advance are synchronous, so no other worker can interleave between the check and the claim.
			if (totalBytes + reserved + MAX_IMAGE_BYTES > MAX_TOTAL_IMAGE_BYTES) return;
			const index = cursor;
			cursor += 1;
			reserved += MAX_IMAGE_BYTES;
			try {
				const response = await fetchImpl(urls[index]);
				if (!response.ok) { reserved -= MAX_IMAGE_BYTES; continue; }
				const type = forcedImageMime(response.headers.get("content-type"));
				if (!type) { reserved -= MAX_IMAGE_BYTES; continue; }
				// Honour a declared Content-Length without downloading an oversized body.
				const declared = Number(response.headers.get("content-length"));
				if (Number.isFinite(declared) && (declared > MAX_IMAGE_BYTES || totalBytes + declared > MAX_TOTAL_IMAGE_BYTES)) {
					reserved -= MAX_IMAGE_BYTES;
					continue;
				}
				const buffer = await response.arrayBuffer();
				reserved -= MAX_IMAGE_BYTES;
				if (buffer.byteLength > MAX_IMAGE_BYTES) continue;
				if (totalBytes + buffer.byteLength > MAX_TOTAL_IMAGE_BYTES) break;
				totalBytes += buffer.byteLength;
				blobs.push({ index, blob: new Blob([buffer], { type }) });
			} catch {
				reserved -= MAX_IMAGE_BYTES;
			}
		}
	};
	await Promise.all(Array.from({ length: FRAME_FETCH_CONCURRENCY }, worker));
	return blobs;
}
