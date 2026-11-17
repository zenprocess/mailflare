import { eq, sql } from "drizzle-orm";
import { getDb } from "@/db";
import { users } from "@/db/schema";
import { recordAuthActivity } from "@/lib/auth/activity";
import { PASSWORDLESS_PASSWORD_HASH } from "@/lib/auth/password";
import { createSession, getUserFromSession, SESSION_COOKIE } from "@/lib/auth/session";
import { hasAdminAccount } from "@/lib/auth/setup";
import { isMissingUsersTableError } from "@/lib/auth/setup-utils";
import { newId } from "@/lib/ids";
import { getAccountSeatError } from "@/lib/licenses/seats";
import { verifyAccessJwt, type AccessJwtFailure } from "./jwt";

/**
 * Cloudflare Access (Zero Trust) sign-in for the Worker's fetch handler.
 *
 * Access mode is ON when both ACCESS_TEAM_DOMAIN and ACCESS_AUD are set. Then every web
 * request, except the mail-ingest webhooks and the paths in ACCESS_BYPASS_PATHS, must carry a
 * valid Cf-Access-Jwt-Assertion (see ./jwt.ts):
 *
 * - missing or invalid assertion: 401;
 * - valid assertion whose email matches a Mailflare user (case-insensitive): that user's normal
 *   session is reused or created (no password prompt);
 * - valid assertion with no matching user: 403 "ask an admin" (or a new passwordless account
 *   when ACCESS_AUTO_PROVISION=true);
 * - /setup, /register, /api/setup/* and first-run /api/auth/register additionally need the
 *   email in ACCESS_SETUP_EMAILS;
 * - password sign-in and password reset answer 403 unless ACCESS_ALLOW_PASSWORD_LOGIN=true.
 *
 * Cf-Access-Authenticated-User-Email is never read. Email Routing uses the email() handler and
 * never reaches this gate. Passkey step-up for admin actions is unchanged.
 */

export type AccessEnv = {
	ACCESS_TEAM_DOMAIN?: string;
	ACCESS_AUD?: string;
	ACCESS_BYPASS_PATHS?: string;
	ACCESS_SETUP_EMAILS?: string;
	ACCESS_AUTO_PROVISION?: string;
	ACCESS_ALLOW_PASSWORD_LOGIN?: string;
	ACCESS_EMAIL_MAP?: string;
	/** "off" disables the Access gate entirely; any other value (or absent) leaves it fail-closed when unconfigured. */
	MAILFLARE_ACCESS_MODE?: string;
};

export type AccessConfig = {
	teamDomain: string;
	aud: string;
	bypassPaths: string[];
	setupEmails: Set<string>;
	autoProvision: boolean;
	allowPasswordLogin: boolean;
	/** Access identity email (lower case) -> Mailflare account email, from ACCESS_EMAIL_MAP. */
	emailMap: Map<string, string>;
};

export type AccessGateOptions = {
	fetcher?: (url: string) => Promise<Response>;
	now?: () => number;
};

export type AccessGateResult =
	| { kind: "off" }
	| { kind: "pass"; request: Request; setCookie?: string; userId?: string }
	| { kind: "response"; response: Response };

/** Mail-ingest webhooks (SES, Resend) authenticate with their own signatures; always outside Access. */
export const BUILTIN_BYPASS_PATHS = ["/api/inbound"];
const SETUP_PATHS = ["/setup", "/register", "/api/setup", "/api/auth/register"];
const PASSWORD_PATHS = ["/api/auth/login", "/api/auth/password-reset"];

function isTrue(value: string | undefined): boolean {
	return /^(1|true|yes|on)$/i.test((value ?? "").trim());
}

function splitList(value: string | undefined): string[] {
	return (value ?? "")
		.split(/[\s,]+/)
		.map((entry) => entry.trim())
		.filter(Boolean);
}

/**
 * "google@corp.example=alice@mail.example, ..." maps an Access identity to a Mailflare account
 * whose address differs (e.g. Google Workspace on one domain, mailboxes on another). Operator
 * controlled only: users cannot change it.
 */
export function parseEmailMap(value: string | undefined): Map<string, string> {
	const map = new Map<string, string>();
	for (const entry of splitList(value)) {
		const [from, to] = entry.split("=").map((part) => part?.trim().toLowerCase());
		if (from && to && from.includes("@") && to.includes("@")) map.set(from, to);
	}
	return map;
}

/** null when Access mode is off; "misconfigured" when only one of the two required vars is set. */
export function readAccessConfig(env: AccessEnv): AccessConfig | "misconfigured" | null {
	const teamDomain = (env.ACCESS_TEAM_DOMAIN ?? "").trim();
	const aud = (env.ACCESS_AUD ?? "").trim();
	if (!teamDomain && !aud) return null;
	if (!teamDomain || !aud) return "misconfigured";
	return {
		teamDomain,
		aud,
		bypassPaths: [...BUILTIN_BYPASS_PATHS, ...splitList(env.ACCESS_BYPASS_PATHS)],
		setupEmails: new Set(splitList(env.ACCESS_SETUP_EMAILS).map((email) => email.toLowerCase())),
		autoProvision: isTrue(env.ACCESS_AUTO_PROVISION),
		allowPasswordLogin: isTrue(env.ACCESS_ALLOW_PASSWORD_LOGIN),
		emailMap: parseEmailMap(env.ACCESS_EMAIL_MAP),
	};
}

/**
 * "/a/b" matches the path "/a/b" and everything below it ("/a/b/c"), not "/a/bc".
 * A trailing "*" ("/a/b*") is a plain string prefix.
 */
export function pathMatches(pathname: string, pattern: string): boolean {
	if (!pattern.startsWith("/")) return false;
	if (pattern.endsWith("*")) return pathname.startsWith(pattern.slice(0, -1));
	const base = pattern.length > 1 ? pattern.replace(/\/+$/, "") : pattern;
	return pathname === base || pathname.startsWith(base === "/" ? "/" : base + "/");
}

function matchesAny(pathname: string, patterns: string[]): boolean {
	return patterns.some((pattern) => pathMatches(pathname, pattern));
}

function wantsHtml(request: Request): boolean {
	return (request.headers.get("Accept") ?? "").includes("text/html");
}

function escapeHtml(value: string): string {
	return value.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

export function accessErrorResponse(request: Request, status: 400 | 401 | 403 | 503, code: string, title: string, detail: string): Response {
	const headers = { "Cache-Control": "no-store", "X-Mailflare-Access": code };
	if (!wantsHtml(request)) {
		return Response.json({ error: title, code, detail }, { status, headers });
	}
	const html = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
		+ "<title>" + escapeHtml(title) + "</title><style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1.5rem;color:#1f2937}h1{font-size:1.4rem}p{line-height:1.5}</style></head>"
		+ "<body><h1>" + escapeHtml(title) + "</h1><p>" + escapeHtml(detail) + "</p></body></html>";
	return new Response(html, { status, headers: { ...headers, "Content-Type": "text/html; charset=utf-8" } });
}

const UNAUTHORIZED_DETAIL: Partial<Record<AccessJwtFailure, string>> = {
	missing: "This page is only reachable through Cloudflare Access. Open it through the organisation sign-in.",
	jwks_unavailable: "The Cloudflare Access signing keys could not be loaded. Try again in a moment.",
};

function unauthorized(request: Request, reason: AccessJwtFailure): Response {
	return accessErrorResponse(
		request,
		401,
		"access_" + reason,
		"Sign-in required",
		UNAUTHORIZED_DETAIL[reason] ?? "Your Cloudflare Access sign-in could not be verified. Sign in again through Cloudflare Access.",
	);
}

function askAnAdmin(request: Request): Response {
	return accessErrorResponse(
		request,
		403,
		"access_no_account",
		"No Mailflare account for this sign-in",
		"You signed in successfully, but there is no Mailflare account for this email address. Ask an administrator to create one for you.",
	);
}

/** The trimmed name of a Cookie-header part: the text before the first "=", or the whole trimmed part. */
function cookieName(part: string): string {
	const index = part.indexOf("=");
	return (index === -1 ? part : part.slice(0, index)).trim();
}

/** Whether a Cookie-header part is the session cookie: its trimmed name equals it, case-insensitively. */
function isSessionCookie(part: string): boolean {
	return cookieName(part).toLowerCase() === SESSION_COOKIE.toLowerCase();
}

function readCookie(request: Request, name: string): string | undefined {
	for (const part of (request.headers.get("Cookie") ?? "").split(";")) {
		const index = part.indexOf("=");
		if (index === -1 || part.slice(0, index).trim().toLowerCase() !== name.toLowerCase()) continue;
		const value = part.slice(index + 1).trim();
		if (!value) return undefined;
		try {
			return decodeURIComponent(value);
		} catch {
			return value;
		}
	}
	return undefined;
}

function bearerToken(request: Request): string | undefined {
	const authorization = request.headers.get("Authorization");
	if (!authorization?.startsWith("Bearer ")) return undefined;
	return authorization.slice(7).trim() || undefined;
}

type UserRow = typeof users.$inferSelect;

async function sessionUser(env: CloudflareEnv, token: string | undefined): Promise<UserRow | null> {
	if (!token) return null;
	try {
		return await getUserFromSession(env, token);
	} catch {
		// An empty database (before /setup) has no sessions table yet.
		return null;
	}
}

/** Users whose email equals this one case-insensitively, read from the primary. */
async function findUsersByEmail(env: CloudflareEnv, email: string): Promise<UserRow[]> {
	const db = getDb({ DB: env.DB_PRIMARY ?? env.DB });
	try {
		return await db.select().from(users).where(eq(sql`lower(${users.email})`, email.toLowerCase())).limit(2);
	} catch (error) {
		if (isMissingUsersTableError(error)) return [];
		throw error;
	}
}

async function adminExists(env: CloudflareEnv): Promise<boolean> {
	try {
		return await hasAdminAccount({ ...env, DB: env.DB_PRIMARY ?? env.DB } as CloudflareEnv);
	} catch {
		return false;
	}
}

/** Minimal passwordless account for ACCESS_AUTO_PROVISION=true; an admin still assigns mailboxes. */
async function provisionUser(env: CloudflareEnv, email: string): Promise<UserRow | null> {
	if (await getAccountSeatError(env)) return null;
	const db = getDb(env);
	const normalized = email.toLowerCase();
	await db.insert(users).values({
		id: newId("usr"),
		email: normalized,
		passwordHash: PASSWORDLESS_PASSWORD_HASH,
		name: normalized.split("@")[0] || normalized,
		role: "user",
		remoteContentMode: "ask",
	});
	const [user] = await findUsersByEmail(env, normalized);
	return user ?? null;
}

function sameEmail(a: string, b: string): boolean {
	return a.toLowerCase() === b.toLowerCase();
}

function isUsable(user: UserRow): boolean {
	return !user.disabled && !user.deletedAt;
}

function withSessionCookie(request: Request, token: string): Request {
	const kept = (request.headers.get("Cookie") ?? "")
		.split(";")
		.map((part) => part.trim())
		.filter((part) => part && !isSessionCookie(part));
	kept.push(SESSION_COOKIE + "=" + encodeURIComponent(token));
	const headers = new Headers(request.headers);
	headers.set("Cookie", kept.join("; "));
	return new Request(request, { headers });
}

function sessionSetCookie(request: Request, token: string): string {
	const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
	return SESSION_COOKIE + "=" + encodeURIComponent(token) + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + 60 * 60 * 24 * 30 + secure;
}

/**
 * Normalises a request pathname for gate matching the way the framework routes it: percent-decodes
 * and collapses repeated slashes. Encoded separators and dot segments are rejected (null) because the
 * router resolves them to paths the gate must not miss (a %-encoded /register would otherwise reach
 * first-run registration without matching SETUP_PATHS).
 */
export function normalizeGatePath(pathname: string): string | null {
	// Reject encoded slash, backslash and dot before any decoding.
	if (/%(?:2f|5c|2e)/i.test(pathname)) return null;
	let decoded: string;
	try {
		decoded = decodeURIComponent(pathname);
	} catch {
		return null;
	}
	if (decoded.includes("\\")) return null;
	// Reject NUL and the other C0 control bytes (and DEL). The router 404s them; they have no
	// legitimate use in a path and are a classic header/splitting probe, so answer 400 instead.
	if (/[\u0000-\u001f\u007f]/.test(decoded)) return null;
	const segments = decoded.split("/");
	for (const segment of segments) {
		if (segment === "." || segment === "..") return null;
	}
	return decoded.replace(/\/{2,}/g, "/") || "/";
}

/** Whether this request should get a freshly minted session when none exists yet (a navigation or an API call). */
function needsSession(request: Request, pathname: string): boolean {
	if (wantsHtml(request)) return true;
	return pathname.startsWith("/api/") || pathname.startsWith("/jmap") || pathname.startsWith("/.well-known/jmap");
}

// Logged once per isolate (cold start) so the operator can see which Access mode the Worker is in
// without a per-request log line. Never logs a secret — only the derived mode name.
let accessModeLogged = false;

export async function applyAccessGate(request: Request, env: CloudflareEnv, options: AccessGateOptions = {}): Promise<AccessGateResult> {
	const accessEnv = env as unknown as AccessEnv;
	const config = readAccessConfig(accessEnv);
	if (!accessModeLogged) {
		accessModeLogged = true;
		const mode = config === null
			? ((accessEnv.MAILFLARE_ACCESS_MODE ?? "").trim().toLowerCase() === "off" ? "off" : "fail-closed (unconfigured)")
			: config === "misconfigured"
				? "misconfigured"
				: "on";
		console.log("[mailflare] Cloudflare Access mode: " + mode);
	}
	const pathname = normalizeGatePath(new URL(request.url).pathname);
	if (pathname === null) {
		return {
			kind: "response",
			response: accessErrorResponse(request, 400, "invalid_path", "Bad request path", "The request path contains encoded slashes or dot segments."),
		};
	}
	if (config === null) {
		// Access mode is opt-out, not opt-in: an unconfigured server must not fall back to upstream's
		// open first-run registration. Only MAILFLARE_ACCESS_MODE=off disables the gate explicitly.
		if ((accessEnv.MAILFLARE_ACCESS_MODE ?? "").trim().toLowerCase() === "off") return { kind: "off" };
		if (matchesAny(pathname, BUILTIN_BYPASS_PATHS)) return { kind: "pass", request };
		return {
			kind: "response",
			response: accessErrorResponse(request, 503, "access_not_configured", "Access not configured", "This server is not configured for Cloudflare Access sign-in. Set ACCESS_TEAM_DOMAIN and ACCESS_AUD, or MAILFLARE_ACCESS_MODE=off to run without Access."),
		};
	}
	if (config !== "misconfigured" && matchesAny(pathname, config.bypassPaths)) return { kind: "pass", request };
	if (matchesAny(pathname, BUILTIN_BYPASS_PATHS)) return { kind: "pass", request };
	if (config === "misconfigured") {
		return {
			kind: "response",
			response: accessErrorResponse(request, 503, "access_misconfigured", "Sign-in is not configured", "Cloudflare Access sign-in needs both ACCESS_TEAM_DOMAIN and ACCESS_AUD."),
		};
	}

	const verified = await verifyAccessJwt(request.headers.get("Cf-Access-Jwt-Assertion"), {
		teamDomain: config.teamDomain,
		aud: config.aud,
		fetcher: options.fetcher,
		now: options.now,
	});
	if (!verified.ok) return { kind: "response", response: unauthorized(request, verified.reason) };
	const identity = verified.claims.email;
	const isSetupEmail = config.setupEmails.has(identity.toLowerCase());
	// The Mailflare account this identity signs in to (same address unless ACCESS_EMAIL_MAP says otherwise).
	const email = config.emailMap.get(identity.toLowerCase()) ?? identity;

	if (matchesAny(pathname, SETUP_PATHS) && !isSetupEmail) {
		return {
			kind: "response",
			response: accessErrorResponse(request, 403, "access_setup_forbidden", "Setup is restricted", "Only the administrators listed for setup can open this page."),
		};
	}
	if (!config.allowPasswordLogin && matchesAny(pathname, PASSWORD_PATHS)) {
		return {
			kind: "response",
			response: accessErrorResponse(request, 403, "password_login_disabled", "Password sign-in is turned off", "This server signs you in through Cloudflare Access."),
		};
	}

	// A Bearer session (mobile/desktop apps) must belong to the Access identity. A Bearer that is
	// not a session (an API key) is left for the route's own authentication.
	const bearer = bearerToken(request);
	const bearerUser = await sessionUser(env, bearer);
	if (bearerUser) {
		if (sameEmail(bearerUser.email, email) && isUsable(bearerUser)) {
			// The Bearer is the verified session; strip any cookie session so the app cannot disagree.
			return { kind: "pass", request: stripSession(request), userId: bearerUser.id };
		}
		return {
			kind: "response",
			response: accessErrorResponse(request, 403, "access_identity_mismatch", "Signed in as someone else", "This session does not belong to your Cloudflare Access sign-in."),
		};
	}

	const cookieToken = readCookie(request, SESSION_COOKIE);
	const cookieUser = await sessionUser(env, cookieToken);
	if (cookieUser && sameEmail(cookieUser.email, email) && isUsable(cookieUser)) {
		// Exactly one verified session cookie reaches the app: drop every duplicate or case-variant
		// ep_session (the gate reads the first, the app reads the last — this removes the ambiguity).
		return { kind: "pass", request: withSessionCookie(request, cookieToken!), userId: cookieUser.id };
	}

	const matches = await findUsersByEmail(env, email);
	let user: UserRow | null = matches.length === 1 ? matches[0]! : null;
	if (matches.length > 1) return { kind: "response", response: askAnAdmin(request) };
	if (!user) {
		// First run: let a setup administrator reach /setup (the app redirects there) without a session.
		if (isSetupEmail && !(await adminExists(env))) return { kind: "pass", request: stripSession(request) };
		if (config.autoProvision) user = await provisionUser(env, email);
		if (!user) return { kind: "response", response: askAnAdmin(request) };
	}
	if (!isUsable(user)) {
		return {
			kind: "response",
			response: accessErrorResponse(request, 403, "account_disabled", "Account disabled", "Your Mailflare account is disabled. Ask an administrator."),
		};
	}

	// Only a navigation or an API call needs a fresh session. Subresource requests (static assets,
	// avatars, the opaque mail frame, RSC payloads) would otherwise mint a 30-day session each — and
	// a Lax Set-Cookie is refused for cross-site subresources anyway. Pass them through with the
	// verified identity, without minting. A session cookie that does not belong to the Access identity
	// (a foreign or unusable user) is stripped here so the app never sees the other user.
	if (!needsSession(request, pathname)) return { kind: "pass", request: stripSession(request), userId: user.id };

	const token = await createSession(env, user.id);
	await recordAuthActivity(env, { action: "auth.login", userId: user.id, request });
	return { kind: "pass", request: withSessionCookie(request, token), setCookie: sessionSetCookie(request, token), userId: user.id };
}

/** Drops every session cookie (any trimmed-name case variant), so the app treats the request as signed out. */
function stripSession(request: Request): Request {
	const parts = (request.headers.get("Cookie") ?? "")
		.split(";")
		.map((part) => part.trim())
		.filter(Boolean);
	if (!parts.some(isSessionCookie)) return request;
	const kept = parts.filter((part) => !isSessionCookie(part));
	const headers = new Headers(request.headers);
	if (kept.length) headers.set("Cookie", kept.join("; "));
	else headers.delete("Cookie");
	return new Request(request, { headers });
}

/** Adds the freshly minted session cookie to the app's response (WebSocket upgrades are left untouched). */
export function withAccessSessionCookie(response: Response, setCookie: string | undefined): Response {
	if (!setCookie || response.status === 101 || (response as Response & { webSocket?: unknown }).webSocket) return response;
	const copy = new Response(response.body, response);
	copy.headers.append("Set-Cookie", setCookie);
	return copy;
}
