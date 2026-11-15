/**
 * HMAC signatures for the remote-image proxy. The proxy is cookie-authenticated on the app origin,
 * but the inbox now renders mail in a sandboxed iframe with an opaque origin (no `allow-same-origin`),
 * so its subresource requests carry no session cookie. Signed URLs let the parent pre-authorise a
 * specific image for a short window instead.
 *
 * A signature is `base64url(HMAC-SHA256(secret, url + "\n" + exp))` over the exact URL the proxy
 * will fetch and a whole-seconds expiry. Verification is constant-time.
 */
const encoder = new TextEncoder();

async function hmac(secret: string, data: string): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(data)));
}

function toBase64Url(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function signRemoteImageUrl(url: string, secret: string, expiresAt: number): Promise<string> {
	return toBase64Url(await hmac(secret, `${url}\n${expiresAt}`));
}

/** Returns true when `signature` is a valid signature for `url` that has not expired. */
export async function verifyRemoteImageSignature(
	url: string,
	expiresAt: number,
	signature: string,
	secret: string,
	nowSeconds = Math.floor(Date.now() / 1000),
): Promise<boolean> {
	if (!Number.isInteger(expiresAt) || expiresAt <= nowSeconds) return false;
	if (typeof signature !== "string" || signature.length === 0) return false;
	const expected = encoder.encode(await signRemoteImageUrl(url, secret, expiresAt));
	const actual = encoder.encode(signature);
	if (expected.length !== actual.length) return false;
	let diff = 0;
	for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ actual[i];
	return diff === 0;
}

/** How long a signed proxy URL stays valid. Long enough for the reader to load a page of mail. */
export const REMOTE_IMAGE_SIGNATURE_TTL_SECONDS = 600;
