# Zen Labs fork: Cloudflare Access sign-in

This fork (`zenprocess/mailflare`, branch `zp/access-sso`, pinned at upstream `f4a17bd`) signs people in with **Cloudflare Access (Zero Trust) using Google as the identity provider**. Operator decision 2026-11-14: "B": our own fork, and the Access JWT is trusted from the start.

Code: `src/lib/auth/access/jwt.ts` (verifier), `src/lib/auth/access/gate.ts` (gate), wired in `worker.ts` before any route runs. Tests: `tests/access-sso.test.mjs`.

## How it works

Access mode is **on when both `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are set**. If only one of them is set, every gated route answers 503, so a half configuration fails closed. If neither is set, the fork behaves like upstream.

In Access mode, every web request gets the following treatment. That includes pages, `/api/*`, `/mcp`, `/jmap` and the `/api/realtime` WebSocket.

1. **Bypass paths pass untouched.** These are `/api/inbound` (the mail-ingest relay webhooks, which check their own signatures) and anything listed in `ACCESS_BYPASS_PATHS`. Inbound mail from Cloudflare Email Routing goes through the Worker's `email()` handler and never reaches this gate.
2. **The request must carry a valid `Cf-Access-Jwt-Assertion`.** The checks are:
   - the token is RS256 and its `kid` selects the key from `https://<ACCESS_TEAM_DOMAIN>/cdn-cgi/access/certs`;
   - `iss` equals `https://<ACCESS_TEAM_DOMAIN>`;
   - `aud` contains `ACCESS_AUD`;
   - `exp` and `nbf` hold, with 30 s of clock skew allowed;
   - `email` and `sub` are not empty.

   The JWKS is cached for 5 minutes. A token with an unknown `kid` forces a refetch, at most once every 30 s; that is how key rotation is handled. If the token is missing or invalid, the request gets **401**.

   `Cf-Access-Authenticated-User-Email` is **never** read.
3. **The token's email is matched to a Mailflare user, case-insensitively.** `ACCESS_EMAIL_MAP` can map it to a different account first (see below).
   - If a user matches, their normal `ep_session` session is reused, or created and set as a cookie. There is no password prompt.
   - If a Bearer *session* token belongs to a different user, the request gets 403. A Bearer API key is left for the route to authenticate.
   - If no user matches, the request gets **403 "ask an admin"**. With `ACCESS_AUTO_PROVISION=true`, the gate instead creates a passwordless `user` account. That account gets no mailbox, so an admin still has to assign one.
   - A disabled or deleted account gets 403.
4. **Setup pages need a setup email.** `/setup`, `/setup/*`, `/register`, `/api/setup/*` and `/api/auth/register` also require the Access identity to be listed in `ACCESS_SETUP_EMAILS`. If the list is empty, setup is closed. On first run (no admin yet), a setup email reaches the app **without** a session, so the registration flow can run.
5. **Password sign-in is off.** `/api/auth/login` and `/api/auth/password-reset/*` answer 403 unless `ACCESS_ALLOW_PASSWORD_LOGIN=true`.
6. **Passkey step-up for admin actions is unchanged** (`/api/auth/step-up/*`).

Known limits:

- Access mode is enforced by the **Worker** entry (`worker.ts`). The Node/Docker runtime (`server/index.ts`) is not gated.
- The account switcher can't hold more than one identity in a browser: the Access identity always wins.
- To sign out, use `https://mail.konsilo.app/cdn-cgi/access/logout`. Mailflare's own logout only drops the session, and the next request creates a new one from the Access token.
- `/setup/passkey` recovery links are subject to the setup-email rule.

## Worker variables

Set these through the registry (see Deploy). `wrangler.jsonc` has `keep_vars: true` and declares none of them.

| Variable | Value | Notes |
|---|---|---|
| `ACCESS_TEAM_DOMAIN` | `zenprocess.cloudflareaccess.com` | The Zen team domain. It is already used by the Konsilo API (`ACCESS_AUTH_DOMAIN` in konsilo `apps/api/wrangler.jsonc`) and by the Access apps "konsilo staff" (admin) and `konsilo-verify` (godkb lesson `konsilo-034-verification-records-merge-deploy-2026-11-11`). Confirm it in Zero Trust → Settings → Custom pages / team domain before setting it. |
| `ACCESS_AUD` | AUD tag of the new Access application | Zero Trust → Access → Applications → *mailflare* → Overview → "Application Audience (AUD) Tag". **The operator must supply it.** |
| `ACCESS_SETUP_EMAILS` | e.g. the operator's Google address | Comma- or space-separated. Only these identities may open `/setup`. |
| `ACCESS_EMAIL_MAP` | `google-id@konsilo.app=val@<mail domain>` | Optional. Use it when the Google identity differs from the Mailflare address, for example when Workspace is on konsilo.app and the pilot mailboxes are on another zone. Only the operator controls it. |
| `ACCESS_BYPASS_PATHS` | e.g. `/book /api/public/booking` | Optional. Path prefixes that skip Access, matched by segment (`/book` matches `/book/x` but not `/bookx`); a trailing `*` makes it a plain prefix. **Every path listed here needs a matching Bypass policy in Access**, and the reverse is also true. |
| `ACCESS_AUTO_PROVISION` | unset (= false) | Set to `true` to create accounts for unknown identities. |
| `ACCESS_ALLOW_PASSWORD_LOGIN` | unset (= false) | Set to `true` to keep password sign-in as a fallback. |
| `MAILFLARE_SETUP_DOMAINS` | the pilot zone, e.g. `konsilo.shop` | Optional. First-run registration accepts only these domains. |
| `TURNSTILE_SECRET_KEY` / `NEXT_PUBLIC_TURNSTILE_SITE_KEY` | Turnstile widget keys | Required. In this fork, Turnstile **fails closed** in production when the secret is missing, so first-run registration will not work without it. The site key is set at build time. |

## Access application (Zero Trust dashboard)

Set this up before the first deploy. It is an operator task: no agent token can create it in this task.

1. **Identity provider.** Settings → Authentication → Login methods → Google (or Google Workspace). Reuse the existing one if the team already has it.
2. **Application.** Access → Applications → Add → *Self-hosted*.
   - Name: `mailflare`. Domain: `mail.konsilo.app`, with an empty path so it covers the whole host.
   - Session duration: 24h is suggested.
   - Identity providers: Google only. Turn on instant auth.
   - Copy the **AUD tag** into `ACCESS_AUD`.
3. **Allow policy.**
   - Action *Allow*.
   - Include: *Emails* is the explicit list of people who get Mailflare accounts. *Emails ending in* `@konsilo.app` also works, but then the Mailflare 403 page becomes the second gate.
   - Optionally require the Google login method.
4. **Bypass policies (optional, only for public features you want).** Create a second self-hosted application on `mail.konsilo.app/book`, and on `mail.konsilo.app/api/public/booking` if you need it, with an action *Bypass* policy and Include *Everyone*. Add the same paths to `ACCESS_BYPASS_PATHS`.
   - Public surfaces in this codebase that are candidates for a bypass: `/book` and `/api/public/booking` (booking pages), `/c/` (public booking/calendar profile pages), `/d/` (shared Drive links, token-protected), and `/api/i/` (the read-receipt pixel; it fails silently when blocked). Bypass only the ones you use.
   - Calendar invite replies arrive as mail (the `email()` handler) and need no bypass.
   - Outbound webhooks need no bypass.
   - Inbound `/api/inbound` is used only in relay/Docker mode; it is bypassed in the Worker. Give Access a matching Bypass application only if you use that mode.
   - API keys, MCP (`/mcp`) and JMAP (`/jmap`) clients can't complete a browser login. Either give them an Access **service token** (and send `CF-Access-Client-Id`/`-Secret`; Access then issues the JWT, which the gate verifies), or list them as bypass paths. A bypassed path still requires the route's own API-key authentication.
5. **CORS / "Same site" cookie:** keep the defaults. **Do not enable "Bypass options requests"** unless you need it.

## First run

1. Deploy (below) with `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`, `ACCESS_SETUP_EMAILS`, `MAILFLARE_SETUP_DOMAINS` and Turnstile set.
2. The operator opens `https://mail.konsilo.app/setup` and signs in with Google through Access, then registers the first admin. "Replace MX" is ignored on first run in this fork.
3. If the registered address (`<username>@<domain>`) is not the operator's Google email, add an `ACCESS_EMAIL_MAP` entry. Otherwise the next request answers 403.

## Deploy

**Do not use `npm run deploy`, `wrangler deploy`, the Deploy button or Workers Builds.** Deploys go through the registry control plane, **consul.zp.digital** (`POST /workers`, with `workers_dev=false`). The registry needs to express the whole bundle: assets, the RealtimeHub Durable Object, D1, R2, queues, crons, `send_email`, AI, Images, rate limits and the self service binding. See MAILFLARE-REVIEW.md section 7. If it can't, stop and escalate; do not fall back to wrangler. The first deploy on `mail.konsilo.app` will also hit the brand-kit gate (`428 brand_kit_required`).

Build: `npm ci --ignore-scripts`, then run the esbuild and workerd install steps explicitly if the build needs them, then `npm run build`.

See also [zp-hardening.md](zp-hardening.md).
