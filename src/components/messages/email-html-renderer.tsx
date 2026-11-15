"use client";

import { useLanguage } from "@/components/language-provider";
import { useEffect, useRef, useState } from "react";
import { prepareReaderEmailHtml } from "@/lib/remote-images/reader";
import { collapseQuotedEmailHtml } from "@/app/(dashboard)/inbox/[messageId]/quote-collapse-utils";
import { buildMailFrameDocument, MAIL_FRAME_MESSAGE_SOURCE, parseMailFrameMessage } from "@/lib/remote-images/frame";

const BLANK_IMAGE = "data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=";
// cid: attachments arrive as the reader's preview URL (see resolveInlineAttachmentUrls).
const ATTACHMENT_PREVIEW = /^\/api\/messages\/[^/]+\/attachments\/[^/?]+\?preview=1$/;
// Remote images are rewritten by prepareReaderEmailHtml to this cookie-less-able proxy path.
const REMOTE_PROXY_PATH = /\/api\/remote-images\?url=[^"'\s<>&]+/;

function collectRemoteProxyPaths(html: string): string[] {
	const seen = new Set<string>();
	for (const match of html.matchAll(new RegExp(REMOTE_PROXY_PATH.source, "g"))) seen.add(match[0]);
	return [...seen];
}

/**
 * Replaces cid preview URLs and remote-image proxy paths with a blank placeholder that the frame
 * later fills from a blob: URL the parent posts. Both are served on the app origin with the session
 * cookie, which the sandboxed (opaque-origin) frame cannot send, so the parent fetches them here.
 */
function collectBlobImages(html: string, remotePaths: string[]): { html: string; urls: string[] } {
	const urls: string[] = [];
	const remote = new Set(remotePaths);
	const template = document.createElement("template");
	template.innerHTML = html;
	for (const img of template.content.querySelectorAll("img")) {
		const src = img.getAttribute("src") ?? "";
		if (!ATTACHMENT_PREVIEW.test(src) && !remote.has(src)) continue;
		let index = urls.indexOf(src);
		if (index === -1) {
			index = urls.length;
			urls.push(src);
		}
		img.setAttribute("data-mf-blob", String(index));
		img.setAttribute("src", BLANK_IMAGE);
	}
	return { html: template.innerHTML, urls };
}

export function EmailHtmlRenderer({ html, className, dense = false, preserveLeadingQuote = false, autoAllowRemote = false, onAllowRemote }: {
	html: string; className?: string;
	/** Tighter block spacing for short internal text such as notes. */
	dense?: boolean;
	preserveLeadingQuote?: boolean;
	/** Load remote content without a click; the reader can still block it. */
	autoAllowRemote?: boolean;
	/** Called when the reader chooses to load remote content. */
	onAllowRemote?: () => void;
}) {
	const { t } = useLanguage();
	const quoteToggleLabel = t("message.quote.toggle");
	const frameRef = useRef<HTMLIFrameElement>(null);
	const [choice, setChoice] = useState<{ source: string; allow: boolean } | null>(null);
	const [hasRemote, setHasRemote] = useState(false);
	const [dark, setDark] = useState(false);
	const [height, setHeight] = useState<number | null>(null);
	const [srcdoc, setSrcdoc] = useState<string>("");
	const [blobUrls, setBlobUrls] = useState<string[]>([]);
	const allowRemote = choice?.source === html ? choice.allow : autoAllowRemote;

	// Track dark theme; the frame content is a separate document, so re-render the srcdoc on change.
	useEffect(() => {
		const root = document.documentElement;
		const sync = () => setDark(root.classList.contains("dark"));
		sync();
		const observer = new MutationObserver(sync);
		observer.observe(root, { attributes: true, attributeFilter: ["class"] });
		return () => observer.disconnect();
	}, []);

	useEffect(() => {
		let cancelled = false;
		const proxyRemote = document.documentElement.dataset.remoteImageProxy !== "disabled";
		(async () => {
			const prepared = prepareReaderEmailHtml(html, { reader: true, allowRemote, proxyRemote });
			if (cancelled) return;
			setHasRemote(prepared.hasRemote);
			let bodyHtml = collapseQuotedEmailHtml(prepared.html, preserveLeadingQuote, quoteToggleLabel) ?? "";
			// Remote content is only rewritten to the proxy after the reader asks; until then there is
			// nothing to collect, so remote images load only after the reader asks.
			const remotePaths = allowRemote ? collectRemoteProxyPaths(bodyHtml) : [];
			const blobs = collectBlobImages(bodyHtml, remotePaths);
			if (cancelled) return;
			setBlobUrls(blobs.urls);
			setSrcdoc(buildMailFrameDocument(blobs.html, dark, dense));
		})();
		return () => { cancelled = true; };
	}, [html, allowRemote, dark, preserveLeadingQuote, quoteToggleLabel, dense]);

	// Height reports from the frame, accepted only from this iframe with a well-formed, clamped shape.
	useEffect(() => {
		const onMessage = (event: MessageEvent) => {
			if (event.source !== frameRef.current?.contentWindow) return;
			const parsed = parseMailFrameMessage(event.data);
			if (parsed) setHeight(parsed.height);
		};
		window.addEventListener("message", onMessage);
		return () => window.removeEventListener("message", onMessage);
	}, []);

	// Fetch cid attachments and remote images with the session cookie (the parent origin has it) and
	// hand the bytes to the frame, which creates blob: URLs in its own (opaque) origin.
	const handleFrameLoad = () => {
		const frame = frameRef.current;
		if (!frame || !blobUrls.length) return;
		void (async () => {
			const blobs: Array<{ index: number; blob: Blob }> = [];
			for (let index = 0; index < blobUrls.length; index++) {
				try {
					const response = await fetch(blobUrls[index]);
					if (!response.ok) continue;
					blobs.push({ index, blob: await response.blob() });
				} catch { /* keep the placeholder */ }
			}
			if (blobs.length) frame.contentWindow?.postMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "blobs", blobs }, "*");
		})();
	};

	return <div className={`min-w-0 max-w-full ${className ?? ""}`}>
		{hasRemote && <div className="mb-2 flex justify-end">
			<button type="button" aria-pressed={allowRemote} className="rounded px-2 py-1 text-xs text-blue-600 hover:bg-blue-50"
				onClick={() => {
					if (!allowRemote) onAllowRemote?.();
					setChoice({ source: html, allow: !allowRemote });
				}}>
				{allowRemote ? null : t("message.allowRemote")}
			</button>
		</div>}
		<iframe
			ref={frameRef}
			title="message"
			className={`block w-full max-w-full border-0${dense ? " mf-dense" : ""}`}
			style={{ height: height != null ? `${height}px` : undefined }}
			srcDoc={srcdoc}
			sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox"
			referrerPolicy="no-referrer"
			onLoad={handleFrameLoad}
			tabIndex={-1}
		/>
	</div>;
}
