/**
 * Cloudflare Access (Zero Trust) application token verification.
 *
 * Access puts a signed JWT on every request it lets through, in the
 * "Cf-Access-Jwt-Assertion" header. It is RS256-signed with the team's keys, published at
 * https://<team>.cloudflareaccess.com/cdn-cgi/access/certs. Nothing else Access adds to a
 * request (notably "Cf-Access-Authenticated-User-Email") is signed, so identity is taken
 * from the verified token only.
 *
 * Checks: alg RS256 with a kid; signature against the JWKS key with that kid;
 * iss equals https://<team domain>; aud (string or array) contains the application
 * AUD tag; exp and nbf with a small clock skew; non-empty email and sub.
 *
 * Logic follows the Konsilo verifier (packages/core/src/access-jwt.ts) plus a short JWKS
 * cache, a forced refresh on an unknown kid (key rotation), and a required iss.
 */

export type AccessJwtOptions = {
	/** Team domain, e.g. "example.cloudflareaccess.com" (scheme optional). */
	teamDomain: string;
	/** Application audience (AUD) tag. */
	aud: string;
	/** Allowed clock skew in seconds for exp / nbf. Default 30. */
	skewSeconds?: number;
	/** Fetches the JWKS. Defaults to global fetch. */
	fetcher?: (url: string) => Promise<Response>;
	/** Current time in milliseconds. Defaults to Date.now(). */
	now?: () => number;
};

export type AccessClaims = {
	email: string;
	sub: string;
	aud: string[];
	iss: string;
	exp: number;
	iat?: number;
	nbf?: number;
};

export type AccessJwtFailure =
	| "missing"
	| "malformed"
	| "alg"
	| "aud"
	| "iss"
	| "expired"
	| "not_yet_valid"
	| "identity"
	| "jwks_unavailable"
	| "unknown_kid"
	| "signature";

export type AccessJwtResult = { ok: true; claims: AccessClaims } | { ok: false; reason: AccessJwtFailure };

type Jwk = JsonWebKey & { kid?: string };
type JwksCacheEntry = { keys: Jwk[]; fetchedAt: number };

/** Keys are reused for this long before the JWKS is fetched again. */
export const JWKS_TTL_MS = 5 * 60 * 1000;
/** An unknown kid forces a refetch, but not more often than this, so forged kids cannot hammer the certs endpoint. */
export const JWKS_MIN_REFRESH_MS = 30 * 1000;

const jwksCache = new Map<string, JwksCacheEntry>();

/** Test hook: forget every cached key set. */
export function clearAccessJwksCache(): void {
	jwksCache.clear();
}

export function normalizeTeamDomain(value: string): string {
	return value.trim().replace(/^https?:\/\//i, "").replace(/\/+$/, "").toLowerCase();
}

export function accessCertsUrl(teamDomain: string): string {
	return "https://" + normalizeTeamDomain(teamDomain) + "/cdn-cgi/access/certs";
}

function b64urlDecode(segment: string): Uint8Array<ArrayBuffer> {
	if (!/^[A-Za-z0-9_-]*$/.test(segment)) throw new Error("bad base64url");
	const b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
	const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
	const binary = atob(padded);
	const out = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
	return out;
}

function decodeJson<T>(segment: string): T {
	return JSON.parse(new TextDecoder().decode(b64urlDecode(segment))) as T;
}

async function fetchJwks(url: string, fetcher: (url: string) => Promise<Response>, now: number): Promise<JwksCacheEntry | null> {
	try {
		const res = await fetcher(url);
		if (!res.ok) return null;
		const body = (await res.json()) as { keys?: unknown };
		if (!Array.isArray(body.keys)) return null;
		const entry = { keys: body.keys.filter((k): k is Jwk => !!k && typeof k === "object"), fetchedAt: now };
		jwksCache.set(url, entry);
		return entry;
	} catch {
		return null;
	}
}

/** The JWKS key for kid, refetching on a stale cache or on an unknown kid (rotation). */
async function findKey(url: string, kid: string, fetcher: (url: string) => Promise<Response>, now: number): Promise<Jwk | "unavailable" | null> {
	let entry = jwksCache.get(url);
	if (!entry || now - entry.fetchedAt >= JWKS_TTL_MS) {
		entry = (await fetchJwks(url, fetcher, now)) ?? undefined;
		if (!entry) return "unavailable";
	}
	let key = entry.keys.find((k) => k.kid === kid);
	if (!key && now - entry.fetchedAt >= JWKS_MIN_REFRESH_MS) {
		const refreshed = await fetchJwks(url, fetcher, now);
		if (!refreshed) return "unavailable";
		key = refreshed.keys.find((k) => k.kid === kid);
	}
	return key ?? null;
}

export async function verifyAccessJwt(assertion: string | null | undefined, options: AccessJwtOptions): Promise<AccessJwtResult> {
	if (!assertion) return { ok: false, reason: "missing" };
	const teamDomain = normalizeTeamDomain(options.teamDomain);
	const skew = options.skewSeconds ?? 30;
	const nowMs = (options.now ?? Date.now)();
	const now = Math.floor(nowMs / 1000);
	const fetcher = options.fetcher ?? ((url: string) => fetch(url));

	const parts = assertion.trim().split(".");
	if (parts.length !== 3 || parts.some((part) => part.length === 0)) return { ok: false, reason: "malformed" };
	const [h, p, s] = parts as [string, string, string];
	let header: { alg?: unknown; kid?: unknown };
	let payload: Record<string, unknown>;
	let signature: Uint8Array<ArrayBuffer>;
	try {
		header = decodeJson(h);
		payload = decodeJson(p);
		signature = b64urlDecode(s);
	} catch {
		return { ok: false, reason: "malformed" };
	}
	if (!header || typeof header !== "object" || !payload || typeof payload !== "object") return { ok: false, reason: "malformed" };
	if (header.alg !== "RS256" || typeof header.kid !== "string" || header.kid === "") return { ok: false, reason: "alg" };

	if (payload.iss !== "https://" + teamDomain) return { ok: false, reason: "iss" };
	const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
	if (!options.aud || !auds.some((a) => typeof a === "string" && a === options.aud)) return { ok: false, reason: "aud" };
	if (typeof payload.exp !== "number" || now >= payload.exp + skew) return { ok: false, reason: "expired" };
	if (payload.nbf !== undefined && (typeof payload.nbf !== "number" || now + skew < payload.nbf)) {
		return { ok: false, reason: "not_yet_valid" };
	}
	if (typeof payload.email !== "string" || payload.email.trim() === "") return { ok: false, reason: "identity" };
	if (typeof payload.sub !== "string" || payload.sub === "") return { ok: false, reason: "identity" };

	const key = await findKey(accessCertsUrl(teamDomain), header.kid, fetcher, nowMs);
	if (key === "unavailable") return { ok: false, reason: "jwks_unavailable" };
	if (!key) return { ok: false, reason: "unknown_kid" };
	try {
		const cryptoKey = await crypto.subtle.importKey(
			"jwk",
			{ kty: key.kty, n: key.n, e: key.e },
			{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
			false,
			["verify"],
		);
		const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, new TextEncoder().encode(h + "." + p));
		if (!valid) return { ok: false, reason: "signature" };
	} catch {
		return { ok: false, reason: "signature" };
	}

	return {
		ok: true,
		claims: {
			email: payload.email.trim(),
			sub: payload.sub,
			aud: auds.filter((a): a is string => typeof a === "string"),
			iss: payload.iss,
			exp: payload.exp,
			...(typeof payload.iat === "number" ? { iat: payload.iat } : {}),
			...(typeof payload.nbf === "number" ? { nbf: payload.nbf } : {}),
		},
	};
}
