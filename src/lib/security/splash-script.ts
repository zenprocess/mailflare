/**
 * The splash guard inline script and the entry paths it embeds. The script runs while the server
 * HTML is parsed, before first paint, to stop an in-app full-page load from flashing the splash.
 * It has no per-request nonce; the app CSP allows it by its exact SHA-256 hash (see buildCsp).
 * Pure (no DOM) so it can be imported by both the CSP builder and the client component.
 */

export const SPLASH_ENTRY_PATHS = ["/", "/login", "/setup"];

export const SPLASH_GUARD_SCRIPT = `try{var r=document.referrer;if(r){var u=new URL(r);if(u.origin===location.origin&&${JSON.stringify(SPLASH_ENTRY_PATHS)}.indexOf(u.pathname)<0)document.documentElement.setAttribute("data-splash-seen","")}}catch(e){}`;

/** SHA-256 (CSP 'sha256-…' form) of SPLASH_GUARD_SCRIPT; recomputed by tests/security-headers.test.mjs. */
export const SPLASH_GUARD_SCRIPT_SHA256 = "sha256-SjPwYFQYbs2O4u9Kwlx/Cy0KurNxdbMv2fJzin2qW4Y=";
