/** Frame CSP, document shell and message shape for the sandboxed mail view. Pure (no DOM), so it is unit-testable. */

export const MAIL_FRAME_MESSAGE_SOURCE = "mailflare-frame";

/**
 * CSP for the srcdoc document. The frame has an opaque origin (no `allow-same-origin`) and
 * `allow-scripts` for exactly one nonce'd measuring script. Remote images load only through the
 * app-origin HTTPS proxy; `cid:` attachments become `blob:` URLs created inside the frame.
 */
export function buildMailFrameCsp(nonce: string): string {
	return [
		"default-src 'none'",
		"img-src https: data: blob:",
		"style-src 'unsafe-inline'",
		`script-src 'nonce-${nonce}'`,
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
		"object-src 'none'",
	].join("; ");
}

/** The one script the frame is allowed to run. It measures height and creates blob: URLs for cid attachments. */
export const MAIL_FRAME_MEASURE_SCRIPT = `(function () {
	"use strict";
	var measure = function () {
		var root = document.documentElement;
		var height = Math.max(root ? root.scrollHeight : 0, document.body ? document.body.scrollHeight : 0);
		parent.postMessage({ source: ${JSON.stringify(MAIL_FRAME_MESSAGE_SOURCE)}, type: "height", height: height }, "*");
	};
	window.addEventListener("message", function (event) {
		if (event.source !== parent) return;
		var data = event.data;
		if (!data || data.source !== ${JSON.stringify(MAIL_FRAME_MESSAGE_SOURCE)}) return;
		if (data.type === "blobs" && Array.isArray(data.blobs)) {
			for (var i = 0; i < data.blobs.length; i++) {
				var item = data.blobs[i];
				var url = URL.createObjectURL(item.blob);
				var imgs = document.querySelectorAll('img[data-mf-blob="' + item.index + '"]');
				for (var j = 0; j < imgs.length; j++) imgs[j].src = url;
			}
			measure();
		}
	});
	if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", measure);
	else measure();
	window.addEventListener("load", measure);
	window.addEventListener("resize", measure);
})();`;

const FRAME_BASE_STYLE = `html { background: transparent; }
body { margin: 0; font: 14px/1.5 Arial, sans-serif; color: #202124; background: #fff; color-scheme: light; word-wrap: break-word; }
html.mf-dark body { background: transparent; color: #e8eaed; }
html.mf-dark img, html.mf-dark video, html.mf-dark picture { filter: invert(1) hue-rotate(180deg); }
html.mf-dense p { margin-top: 0; }
.mf-quote-toggle > summary { cursor: pointer; }`;

/** Build the complete srcdoc for one mail body. `bodyHtml` is already sanitised. */
export function buildMailFrameDocument(bodyHtml: string, nonce: string, dark: boolean, dense = false): string {
	const csp = buildMailFrameCsp(nonce);
	const frameClass = [dark ? "mf-dark" : "", dense ? "mf-dense" : ""].filter(Boolean).join(" ");
	return `<!doctype html><html lang="" dir="auto" class="${frameClass}"><head><meta charset="utf-8">` +
		`<meta http-equiv="Content-Security-Policy" content="${csp}"><style>${FRAME_BASE_STYLE}</style></head>` +
		`<body>${bodyHtml}<script nonce="${nonce}">${MAIL_FRAME_MEASURE_SCRIPT}</script></body></html>`;
}

/**
 * Validate a message received in the parent from the frame. Returns the height to apply, or null
 * when the message is not a well-formed height report from this frame.
 */
export function parseMailFrameMessage(data: unknown): { height: number } | null {
	if (typeof data !== "object" || data === null) return null;
	const message = data as Record<string, unknown>;
	if (message.source !== MAIL_FRAME_MESSAGE_SOURCE || message.type !== "height") return null;
	const height = typeof message.height === "number" && Number.isFinite(message.height) && message.height > 0 ? Math.ceil(message.height) : null;
	return height === null ? null : { height };
}
