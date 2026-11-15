// Dev tooling (HMR, source maps) evaluates strings; production never needs to.
const scriptEval = process.env.NODE_ENV === "production" ? "" : " 'unsafe-eval'";

/**
 * The app Content-Security-Policy. When a per-request nonce is supplied (the Workers runtime, see
 * worker.ts), `script-src` drops `'unsafe-inline'` in favour of the nonce, which Next/vinext stamps
 * onto its inline bootstrap scripts and the root layout stamps onto its two bootstrap scripts.
 *
 * `style-src` keeps `'unsafe-inline'`: vinext/RSC and Tailwind emit inline `<style>` for the app
 * document, and unlike scripts a `<style>` cannot execute code, so the residual risk is CSS
 * injection only. Mail HTML is confined to a sandboxed iframe whose own nonce CSP is in
 * src/lib/remote-images/frame.ts, so it never touches this document.
 */
export function buildCsp(nonce?: string): string {
	const scriptSrc = nonce
		? `'self' 'nonce-${nonce}' https://challenges.cloudflare.com`
		: `'self' 'unsafe-inline'${scriptEval} https://challenges.cloudflare.com`;
	return [
		"default-src 'self'",
		`script-src ${scriptSrc}`,
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: blob: https:",
		"font-src 'self' data:",
		"connect-src 'self' ws: wss: https://challenges.cloudflare.com",
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
