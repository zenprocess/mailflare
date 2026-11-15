import { requireSessionUser } from "@/lib/api/auth";
import { getEnv } from "@/lib/cloudflare";
import { fetchRemoteImage, RemoteImageError } from "@/lib/remote-images/fetch";
import { allowRemoteImageRequest } from "@/lib/remote-images/rate-limit";

const IMAGE_HEADERS = {
	"Cache-Control": "private, no-store",
	"Content-Security-Policy": "default-src 'none'; sandbox",
	"Cross-Origin-Resource-Policy": "same-origin",
	"X-Content-Type-Options": "nosniff",
};

export async function GET(request: Request) {
	const env = getEnv();
	const requestUrl = new URL(request.url);
	const remoteUrl = requestUrl.searchParams.get("url") ?? "";

	// The parent (same-origin, already past Access) fetches proxied images with the session cookie;
	// the sandboxed reader has an opaque origin and never calls this route directly. There is no
	// signed-URL path: the reader no longer needs one.
	const auth = await requireSessionUser(env, request);
	if (auth.error) return auth.error;
	const rateKey = auth.user.id;
	if (!allowRemoteImageRequest(rateKey)) {
		return Response.json({ error: "Too many remote image requests" }, { status: 429, headers: { "Cache-Control": "no-store", "Retry-After": "60" } });
	}

	try {
		const image = await fetchRemoteImage(remoteUrl, { blockedOrigins: [requestUrl.origin] });
		const body = new ArrayBuffer(image.body.byteLength);
		new Uint8Array(body).set(image.body);
		return new Response(body, {
			headers: { ...IMAGE_HEADERS, "Content-Type": image.contentType },
		});
	} catch (error) {
		if (error instanceof RemoteImageError) {
			return Response.json({ error: error.message }, { status: error.status, headers: { "Cache-Control": "no-store" } });
		}
		return Response.json({ error: "Could not fetch remote image" }, { status: 502, headers: { "Cache-Control": "no-store" } });
	}
}
