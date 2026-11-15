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
const REMOTE_PROXY_PATH = /\/api\/remote-images\?url=[^"'\s<>&]+/g;

/** A fresh nonce per frame document; the frame CSP allows only this script. */
function newNonce(): string {
	if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID().replace(/-/g, "");
	return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function collectRemoteProxyPaths(html: string): string[] {
	const seen = new Set<string>();
	for (const match of html.matchAll(REMOTE_PROXY_PATH)) seen.add(match[0]);
	return [...seen];
}

/** Replaces cid preview URLs with a placeholder that the frame fills with a blob: URL from the stored attachment. */
function collectAttachmentImages(html: string): { html: string; urls: string[] } {
	const urls: string[] = [];
	const template = document.createElement("template");
	template.innerHTML = html;
	for (const img of template.content.querySelectorAll("img")) {
		const src = img.getAttribute("src") ?? "";
		if (!ATTACHMENT_PREVIEW.test(src)) continue;
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

async function signRemoteImages(envProxyEnabled: boolean, paths: string[]): Promise<Record<string, string | null>> {
	if (!paths.length || !envProxyEnabled) return {};
	try {
		const response = await fetch("/api/remote-images/sign", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ urls: paths }),
		});
		if (!response.ok) return {};
		const data = (await response.json()) as { signed?: Record<string, string | null> };
		return data.signed ?? {};
	} catch {
		return {};
	}
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
	const [attachmentUrls, setAttachmentUrls] = useState<string[]>([]);
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
			const attachments = collectAttachmentImages(bodyHtml);
			bodyHtml = attachments.html;
			const signed = await signRemoteImages(proxyRemote, collectRemoteProxyPaths(bodyHtml));
			for (const [path, signedPath] of Object.entries(signed)) {
				if (signedPath) bodyHtml = bodyHtml.split(path).join(signedPath);
			}
			if (cancelled) return;
			const nonce = newNonce();
			setAttachmentUrls(attachments.urls);
			setSrcdoc(buildMailFrameDocument(bodyHtml, nonce, dark, dense));
		})();
		return () => { cancelled = true; };
	}, [html, allowRemote, dark, preserveLeadingQuote, quoteToggleLabel, dense]);

	// Height reports from the frame, accepted only from this iframe with a well-formed shape.
	useEffect(() => {
		const onMessage = (event: MessageEvent) => {
			if (event.source !== frameRef.current?.contentWindow) return;
			const parsed = parseMailFrameMessage(event.data);
			if (parsed) setHeight(parsed.height);
		};
		window.addEventListener("message", onMessage);
		return () => window.removeEventListener("message", onMessage);
	}, []);

	// Fetch cid attachments with the session cookie (the parent origin has it) and hand the bytes
	// to the frame, which creates blob: URLs in its own (opaque) origin.
	const handleFrameLoad = () => {
		const frame = frameRef.current;
		if (!frame || !attachmentUrls.length) return;
		void (async () => {
			const blobs: Array<{ index: number; blob: Blob }> = [];
			for (let index = 0; index < attachmentUrls.length; index++) {
				try {
					const response = await fetch(attachmentUrls[index]);
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
