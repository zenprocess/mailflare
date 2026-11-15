import { MAIL_FRAME_MEASURE_SCRIPT_SHA256 } from "@/lib/remote-images/frame";
import { SPLASH_GUARD_SCRIPT_SHA256 } from "@/lib/security/splash-script";

// Dev tooling (HMR, source maps) evaluates strings; production never needs to.
const scriptEval = process.env.NODE_ENV === "production" ? "" : " 'unsafe-eval'";
// Inline scripts are allowed only in development, where the Worker's nonce stamping does not run.
// Production HTML documents are always stamped with a per-request nonce, so the static fallback
// (non-HTML responses and the replace-comparison in shouldApplyNonceCsp) carries no 'unsafe-inline'.
// This is what keeps 'unsafe-inline' out of the production bundle's script-src entirely.
const scriptInline = process.env.NODE_ENV === "production" ? "" : " 'unsafe-inline'";

/**
 * The app Content-Security-Policy. When a per-request nonce is supplied (the Workers runtime, see
 * worker.ts), `script-src` drops `'unsafe-inline'` in favour of the nonce, which Next/vinext stamps
 * onto its inline bootstrap scripts and the root layout stamps onto its two bootstrap scripts.
 *
 * Two fixed inline scripts are additionally allowed by their exact SHA-256 hash (never by nonce or
 * `'unsafe-inline'`): the sandboxed mail frame's measuring script (MAIL_FRAME_MEASURE_SCRIPT_SHA256),
 * because the srcdoc inherits this document's CSP, and the splash guard (SPLASH_GUARD_SCRIPT_SHA256).
 * Neither runs unsandboxed in this document in a way an attacker could exploit.
 *
 * `style-src` keeps `'unsafe-inline'`: vinext/RSC and Tailwind emit inline `<style>` for the app
 * document, and unlike scripts a `<style>` cannot execute code, so the residual risk is CSS
 * injection only. Mail HTML is confined to a sandboxed iframe whose own hash CSP is in
 * src/lib/remote-images/frame.ts, so it never touches this document.
 */
export function buildCsp(nonce?: string): string {
	const scriptSrc = nonce
		? `'self' 'nonce-${nonce}' https://challenges.cloudflare.com '${MAIL_FRAME_MEASURE_SCRIPT_SHA256}' '${SPLASH_GUARD_SCRIPT_SHA256}'`
		: `'self'${scriptInline}${scriptEval} https://challenges.cloudflare.com`;
	return [
		"default-src 'self'",
		`script-src ${scriptSrc}`,
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: blob: https:",
		"font-src 'self' data:",
		// 'self' also covers the same-origin wss: upgrade to the realtime endpoint (CSP3).
		"connect-src 'self' https://challenges.cloudflare.com",
		// 'self' lets the Drive preview show PDFs and text files in an iframe.
		"frame-src 'self' https://challenges.cloudflare.com",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
		"frame-ancestors 'self'",
		"upgrade-insecure-requests",
	].join("; ");
}

export function getSecurityHeaders(nonce?: string) {
	return [
		{ key: "X-Robots-Tag", value: "noindex, nofollow, noarchive, nosnippet, noimageindex" },
		{ key: "Content-Security-Policy", value: buildCsp(nonce) },
		{ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
		{ key: "X-Content-Type-Options", value: "nosniff" },
		{ key: "X-Frame-Options", value: "SAMEORIGIN" },
		// No window the app opens or that opens the app keeps a reference to it.
		{ key: "Cross-Origin-Opener-Policy", value: "same-origin" },
		{ key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
		{
			key: "Permissions-Policy",
			value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
		},
	];
}

/**
 * Whether the nonce CSP may be stamped on a response. Only HTML documents get it. The static app
 * policy that next.config.ts adds to every response (buildCsp() with no nonce) is NOT a route's
 * own sandbox policy, so the Worker replaces it with the nonce policy. A response that carries any
 * *other* Content-Security-Policy (attachments, Drive, shared files, avatars, the remote-image
 * proxy, JMAP downloads) is never overwritten — those sandbox policies are deliberately stricter
 * and must survive.
 */
export function shouldApplyNonceCsp(response: Response): boolean {
	const contentType = response.headers.get("content-type") ?? "";
	if (contentType.split(";", 1)[0]!.trim().toLowerCase() !== "text/html") return false;
	const own = response.headers.get("content-security-policy");
	if (own !== null && own !== buildCsp()) return false;
	return true;
}

/** Stamps `csp` on `response` only when shouldApplyNonceCsp allows it; otherwise returns `response` unchanged. */
export function withNonceCsp(response: Response, csp: string): Response {
	if (!shouldApplyNonceCsp(response)) return response;
	const copy = new Response(response.body, response);
	copy.headers.set("Content-Security-Policy", csp);
	return copy;
}
