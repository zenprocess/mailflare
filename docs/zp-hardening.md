# Zen Labs fork: hardening applied (MAILFLARE-REVIEW.md section 8)

Pinned upstream commit: `f4a17bd98d8ad9dbcf95be911ac21cea1e471d91`. Never merge upstream wholesale. Review every upstream change, then pick it in.

| Review item | Status in `zp/access-sso` |
|---|---|
| 8.2 Critical/high CVEs | Done. Bumped `next` 16.3.3 → 16.4.6, `react`/`react-dom`/`react-server-dom-webpack` → ^19.3.1, `dompurify` → ^3.4.18, `@modelcontextprotocol/server` → ^2.4.0, `nodemailer` → ^10.5.0, `mailauth` 4 → ^8.0.6 (Node runtime only), `zod` → ^4.6.7, plus `npm audit fix` (sharp, source-map-js, miniflare). `npm audit --omit=dev` now reports **0 critical, 0 high** and 5 moderate, all in vinext/@vercel/og/satori; the only fix for those is a vinext downgrade. |
| 8.3 Self-update | Done. Deleted `.github/workflows/deploy-update.yml`, and `POST /api/admin/update` answers 410. Never set `GITHUB_UPDATE_TOKEN`/`GITHUB_UPDATE_REPO`, and never connect Workers Builds. |
| 8.4 First-run window | Done. `/setup`, `/register`, `/api/setup/*` and `/api/auth/register` require a valid Access JWT **and** an identity in `ACCESS_SETUP_EMAILS` (see [zp-access.md](zp-access.md)). First run never takes `replaceMxRecords` from the body (it is forced to false). The domain can be pinned with `MAILFLARE_SETUP_DOMAINS`. Turnstile fails closed in production when `TURNSTILE_SECRET_KEY` is unset. **Not done:** the `hasAdminAccount()` → insert race. It is mitigated because only setup emails can reach the route. |
| 3 / routing cleanup | Done. Removing a domain, or turning Cloudflare receiving off, now deletes only the routing rules whose every action is the `mailflare` Worker, which are the only rules Mailflare creates. Email Routing is left on when the zone still has rules Mailflare did not create, such as the registry forwards for security@ and friends. Tests: `tests/routing-cleanup.test.mjs`. |
| 3.7 Inbox HTML in a sandboxed iframe; mail-view CSP without `unsafe-inline` | **Not done in this PR.** See "Open item" below. |
| 8.5 Token | See "Minimal CF_TOKEN" below. |

## Minimal CF_TOKEN

Create a **new** API token (My Profile → API Tokens → Custom), store it in Infisical `/infrastructure`, and never paste it into chat.

- **Zone resources:** Include → *Specific zone* → the pilot zone(s) only, e.g. `konsilo.shop`. **Never** All zones, and never `.app`, `.eu` or `.net` until the mail decision is made.
- **Permissions (all Zone-level):**
  - Zone → Zone → Read
  - Zone → DNS → Edit
  - Zone → Zone Settings → Edit. This is the only permission Cloudflare accepts for `/email/routing/dns` (enabling Email Routing). It is broader than mail, so it is the main reason the token stays zone-scoped.
  - Zone → Email Routing Rules → Edit
  - Zone → Email Sending → Edit (only if outbound mail is wanted)
- **Not needed:** the account permissions *DNS Settings* and *Email Routing Addresses*, and the Global API Key (`CF_EMAIL`+`CF_API_KEY`).
- Optional hardening: limit client IPs to Cloudflare egress, and set a TTL with a rotation reminder. Rotating the token resets the forwarding loop-guard HMAC, which is minor.
- Never reuse `CLOUDFLARE_WORKERS_API_TOKEN`, which reaches 26 zones.

## Open item: sandboxed mail view

Today the reader renders sanitised HTML into an open shadow root on the app origin, and the app CSP allows `script-src 'unsafe-inline'`. vinext/RSC needs that for its inline bootstrap, so removing it means a nonce-based CSP.

The target is an `<iframe sandbox="allow-popups allow-popups-to-escape-sandbox">`, with neither `allow-scripts` nor `allow-same-origin`. It would load from `srcdoc` with a meta CSP of `default-src 'none'; img-src https: data:; style-src 'unsafe-inline'; font-src https: data:`.

This is not a drop-in change. A frame without `allow-same-origin` has an opaque origin, which causes three problems:

- the parent can't measure its height to auto-size it;
- `SameSite=Lax` cookies aren't sent on its subresource requests, so the authenticated remote-image proxy and cid: attachment URLs break unless they move to signed, cookie-less URLs;
- quote-collapse, fragment navigation and dark-mode inversion have to move into static CSS.

It needs browser testing, so it is tracked as a follow-up PR. Until then, the DOMPurify bump is the mitigation.
