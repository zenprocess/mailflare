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
