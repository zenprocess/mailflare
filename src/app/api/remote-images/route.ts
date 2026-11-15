import { requireSessionUser } from "@/lib/api/auth";
import { getEnv } from "@/lib/cloudflare";
import { fetchRemoteImage, RemoteImageError } from "@/lib/remote-images/fetch";
import { allowRemoteImageRequest } from "@/lib/remote-images/rate-limit";
import { verifyRemoteImageSignature } from "@/lib/remote-images/signature";

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
	const secret = env.REMOTE_IMAGES_HMAC_SECRET;
	const signature = requestUrl.searchParams.get("sig");
	const expiresAt = Number(requestUrl.searchParams.get("exp") ?? "0");

	// The sandboxed reader has an opaque origin and sends no session cookie, so a valid HMAC
	// signature authorises the fetch. Otherwise the normal session check applies.
	const signed = !!(secret && signature && Number.isInteger(expiresAt) && expiresAt > 0 && await verifyRemoteImageSignature(remoteUrl, expiresAt, signature, secret));

	let rateKey: string;
	if (signed) {
		// Key on the signature: it is stable for its (short) validity window and scopes the
		// limit to one pre-authorised image, so a replay cannot amplify across many URLs.
		rateKey = signature!;
	} else {
		const auth = await requireSessionUser(env, request);
		if (auth.error) return auth.error;
		rateKey = auth.user.id;
	}
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
