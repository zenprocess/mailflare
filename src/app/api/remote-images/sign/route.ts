import { requireSessionUser } from "@/lib/api/auth";
import { getEnv } from "@/lib/cloudflare";
import { parseRemoteImageUrl } from "@/lib/remote-images/fetch";
import { REMOTE_IMAGE_SIGNATURE_TTL_SECONDS, signRemoteImageUrl } from "@/lib/remote-images/signature";

const MAX_SIGN_URLS = 100;

/**
 * Pre-authorise remote images for the sandboxed reader. The reader has no session cookie, so it
 * cannot call the cookie-authenticated proxy directly; the parent (which does have a session) asks
 * here for short-lived signed proxy URLs. Each value is validated with the proxy's own SSRF guard
 * before it is signed, so a private/blocked/self URL is never signed (it maps to null).
 */
export async function POST(request: Request) {
	const env = getEnv();
	const auth = await requireSessionUser(env, request);
	if (auth.error) return auth.error;
	const secret = env.REMOTE_IMAGES_HMAC_SECRET;
	if (!secret) {
		return Response.json({ error: "Remote image signing is not configured" }, { status: 503, headers: { "Cache-Control": "no-store" } });
	}

	const requestUrl = new URL(request.url);
	const body = (await request.json().catch(() => null)) as { urls?: unknown } | null;
	const values = Array.isArray(body?.urls) ? (body.urls as unknown[]).filter((value): value is string => typeof value === "string").slice(0, MAX_SIGN_URLS) : [];

	const expiresAt = Math.floor(Date.now() / 1000) + REMOTE_IMAGE_SIGNATURE_TTL_SECONDS;
	const signed: Record<string, string | null> = {};
	for (const value of values) {
		try {
			const candidate = value.startsWith("/api/remote-images?") ? new URL(value, requestUrl.origin).searchParams.get("url") ?? "" : value;
			const url = parseRemoteImageUrl(candidate, [requestUrl.origin]);
			const signature = await signRemoteImageUrl(url.href, secret, expiresAt);
			signed[value] = `/api/remote-images?url=${encodeURIComponent(url.href)}&exp=${expiresAt}&sig=${signature}`;
		} catch {
			signed[value] = null;
		}
	}
	return Response.json({ signed }, { headers: { "Cache-Control": "no-store" } });
}
