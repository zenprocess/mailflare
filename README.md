<img src="public/icon-192.png" alt="Mailflare" width="96" />


# Mailflare

A self-hosted alternative to Google Workspace. Setup **custom domain Emails**, **Calendar, Drive, Booking** and **built-in AI agents**.

Run it on Cloudflare or Docker. Send and receive with Cloudflare, Resend or Amazon SES. Store files in R2, Backblaze B2 or AWS S3. Use D1, Postgres, MySQL or Turso for the database.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/hieunc229/mailflare)

## Screenshots

<table>
  <tr>
    <td align="center"><img src="screenshots/1.png" alt="Inbox" width="320"><br>Inbox</td>
    <td align="center"><img src="screenshots/2.png" alt="Manage domains" width="320"><br>Domains</td>
    <td align="center"><img src="screenshots/3.png" alt="Manage inboxes" width="320"><br>Mailboxes</td>
  </tr>
  <tr>
    <td align="center"><img src="screenshots/4.png" alt="Calendar" width="320"><br>Calendar</td>
    <td align="center"><img src="screenshots/5.png" alt="Booking" width="320"><br>Booking</td>
    <td align="center"><img src="screenshots/6.png" alt="Drive" width="320"><br>Drive</td>
  </tr>
</table>

### Sponsors

<a target="_blank" href="https://sequenzy.com/?ref=hieunc229/mailflare"><img height="80" src="sponsors/sequenzy.png" alt="Sequenzy"></a>
&nbsp;
<a target="_blank" href="https://drivemug.com/?ref=hieunc229/mailflare"><img height="80" src="sponsors/drivemug.png" alt="Drivemug"></a>

Want to support Mailflare? [Become a sponsor](https://store.paymug.co/buy/mailflare-sponsor).

## Features

### Apps

- **Email**: Custom domain mailboxes, personal or shared, with access you control. Send and receive with Cloudflare Email, Resend or Amazon SES.
- **Routing rules**: Store, forward, reject or sort incoming mail.
- **Calendar**: Repeating events with time zones. Attendees get email invitations.
- **Booking**: Share a public link so anyone can book a free time on your calendar.
- **Drive**: Store and share files.
- **AI agents**: Search mail, draft replies and manage events. Connect other AI tools over MCP.

### Technical

- **Databases**: Cloudflare D1 (default), PostgreSQL, MySQL, Turso / libSQL, or a local SQLite file. Set `DATABASE_URL` to switch. Works with Supabase, Neon, PlanetScale, TiDB and more. See [Databases](docs/databases.md).
- **File storage**: Cloudflare R2, Backblaze B2 or AWS S3.
- **Hosting**: Cloudflare Workers or a single Docker container.
- **Admin**: Users, API keys, webhooks, audit logs and backups.
- **Import**: Bring in mail from IMAP, Gmail Takeout, `.eml` and `.mbox` files.

Mailflare currently supports 34 languages, including English, Português (Brasil), Português (Portugal), Español, Français, Deutsch, Italiano, Nederlands, Polski, Українська, Русский, Türkçe, 中文（简体）, 日本語, 한국어, Bahasa Indonesia, Bahasa Melayu, Tiếng Việt, ไทย, हिन्दी, বাংলা, मराठी, తెలుగు, தமிழ், ગુજરાતી, ಕನ್ನಡ, മലയാളം, ਪੰਜਾਬੀ, සිංහල, Kiswahili, Hausa, plus العربية, اردو and فارسی (right-to-left).

## Cost

You can receive and send mail for free.

- **Receiving**: Cloudflare Email Routing is free.
- **Sending**: Use the free tier of Resend (3,000 emails a month) or Amazon SES. Cloudflare's own sending needs the $5/month Paid Worker plan.

New Amazon SES accounts start in a sandbox. Ask AWS for production access to lift it. Prices change, so check [Resend](https://resend.com/pricing), [Amazon SES](https://aws.amazon.com/ses/pricing/) and [Cloudflare](https://developers.cloudflare.com/workers/platform/pricing/).

## Deploy

1. **Deploy the app.** Click **Deploy to Cloudflare**. Keep the app name `mailflare`, or it will break.
2. **Finish setup.** Open the app at `/setup` and create your admin account.
3. **Connect a domain.** Add a domain from the same Cloudflare account, then create your first mailbox.

> **`CF_TOKEN` is required.** Create a scoped [Cloudflare API token](https://github.com/hieunc229/mailflare/issues/24#issuecomment-5523686105) with these permissions:
>
> - All accounts: Email Sending:Edit, DNS Settings:Edit, Email Routing Addresses:Edit
> - All zones: DNS Settings:Edit, Email Routing Rules:Edit, Zone Settings:Edit, DNS:Edit

More options: [deployment guide](docs/deployment.md).

### Deploy with an AI agent

Paste this into an AI agent that has terminal access (Claude Code, Codex, Cursor and similar):

```text
Install Mailflare for me from https://github.com/hieunc229/mailflare on my Cloudflare account.

1. Read README.md, docs/deployment.md and wrangler.jsonc first.
2. Ask me for my Cloudflare account ID and two API tokens, using a secret input:
   a deploy token (for Wrangler) and a runtime token (the Worker secret CF_TOKEN).
   Never print them, commit them, or pass them as command arguments.
3. Keep the Worker name exactly "mailflare". Create or reuse the D1 database
   "mailflare", the R2 bucket "mailflare-raw", and the queues "mailflare-inbound",
   "mailflare-outbound" and "mailflare-agent".
4. Install dependencies, run `npm run deploy`, and set CF_TOKEN as a Worker secret.
   Do not run remote database migrations yourself. The /setup page does that.
5. Give me the app URL and anything I still need to do. I will open /setup, create
   the admin account and connect my domain.
```

Token permissions and more options: [deployment guide](docs/deployment.md#deploy-with-an-ai-coding-agent).

### Deploy through the ZenInfra registry

The Zen Labs estate deploys Workers through `POST https://consul.zp.digital/workers`, which takes a **single ESM script** — not the 797 code-split modules `vp build` emits. Bundle first, then declare the whole binding list in the deploy request.

```bash
npm run build                      # vp build -> dist/server/index.js + dist/client
node scripts/bundle-worker.mjs     # dist/mailflare-worker.mjs (one ESM file) + size
```

**Bindings to declare** (the registry takes them verbatim; no `WORKER_SELF_REFERENCE`):

- D1 `DB` (`d1`), R2 `BUCKET` (`r2_bucket`), three queue producers `INBOUND_QUEUE`/`OUTBOUND_QUEUE`/`AGENT_QUEUE` (`mailflare-inbound`/`-outbound`/`-agent`) and their consumers (script `mailflare`).
- Durable Object `REALTIME` (`class_name: RealtimeHub`).
- `send_email` `EMAIL`, Workers AI `AI`, Images `IMAGES`.
- Three rate-limit bindings `LOGIN_RATE_LIMIT`/`DEVICE_LOGIN_RATE_LIMIT`/`AGENT_RATE_LIMIT` (pick namespace ids 2001+ to avoid konsilo's 1001-1005).
- `plain_text` vars: `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`, `ACCESS_SETUP_EMAILS`, `MAILFLARE_SETUP_DOMAINS`, `APP_URL`, `SPAM_DOMAIN_AGE_CHECK=off`.
- Two cron triggers `0 2 * * *` and `*/5 * * * *`, `observability`, plus `assets` + `assets_config` (pass `dist/client/_headers` in `assets_config`).

**One-time Durable Object migration.** Send `migrations:{"new_tag":"v1","new_sqlite_classes":["RealtimeHub"]}` **only on the first deploy**; a second send fails with Cloudflare error 10079. Check `GET /workers/durable-objects` for `mailflare_RealtimeHub` first.

**Values only the operator can supply** (names only — never put values in chat):

- The zone-scoped `CF_TOKEN` (one pilot zone only; Zone Read, DNS Edit, Zone Settings Edit, Email Routing Rules Edit, Email Sending Edit — never All zones, never the Global API Key). See `docs/zp-hardening.md` "Minimal CF_TOKEN".
- The Cloudflare Access application + its `AUD`, `ACCESS_TEAM_DOMAIN`, and `ACCESS_SETUP_EMAILS` (who may open `/setup`).
- Turnstile site key (build time `NEXT_PUBLIC_TURNSTILE_SITE_KEY`) and secret key (`TURNSTILE_SECRET_KEY`).
- `MAILFLARE_SETUP_DOMAINS` (the pilot mail domain) and the pilot subdomain itself.

**Access and remote-image options** (names only):

- `MAILFLARE_ACCESS_MODE` — set it to `off` only to run without Cloudflare Access. The default is **fail-closed**: with `ACCESS_TEAM_DOMAIN`/`ACCESS_AUD` unset and no `MAILFLARE_ACCESS_MODE=off`, every request answers 503 "Access not configured".
- `REMOTE_IMAGES_HMAC_SECRET` — **must stay unset**. The signed-URL path of `/api/remote-images` was removed; the parent fetches proxied images with the session cookie and posts Blobs to the sandboxed reader, so no signing secret exists.
- `ACCESS_AUTO_PROVISION` and `ACCESS_ALLOW_PASSWORD_LOGIN` **must stay unset** for the pilot.

**`keep_vars: true` and Access-only limits** (names only):

- `wrangler.jsonc` sets `keep_vars: true`, so **every plain-text var must be resent in full on every deploy** — a var set once in the dashboard survives a deploy that omits it. After each deploy, read the Worker's vars back and assert `MAILFLARE_ACCESS_MODE` is **absent** and both `ACCESS_*` vars are present.
- `MAILFLARE_ACCESS_MODE` must stay **absent** (never `off`), or the Access gate is disabled and the console falls back to open sign-in.
- Behind Cloudflare Access, the **open-tracking pixel** (`/api/i/<token>.gif`), **shared-file links** (`/api/shared-files/[id]`), the **booking pages** and **JMAP / API-key clients** cannot work: Access blocks them at the edge, and the fail-closed gate exempts only `/api/inbound`. Leave read receipts and shared links off so users are not misled.
- The Access gate exists **only in the Worker runtime** (`worker.ts`). The Node/Docker runtime (`server/`) has no gate, so a self-hosted build falls back to upstream's open first run — **do not run the Node runtime behind Access**.

The D1 schema is applied from `/api/setup/prepare` — do not run remote migrations. The worker name must stay `mailflare` (routing rules hard-code it). See `docs/zp-hardening.md` and `docs/zp-access.md` for the full pilot checklist.

### Self-host with Docker

Runs as one container on any server, with SQLite and local files.

```bash
cp .env.docker.example .env.docker
docker compose up -d --build
```

See [self-hosting](docs/self-hosting.md).

## Local development

```bash
cp .dev.vars.example .dev.vars
npm install
npm run db:migrate:local
npm run dev
```

Add your Cloudflare credentials to `.dev.vars`, then open [localhost:3000](http://localhost:3000). Run `npm run db:seed` to load sample data.

- `npm run build`: build the Worker
- `npm run deploy`: build and deploy
- `npm run lint`: lint and type check

A schema change needs a migration for each database type. See [Databases](docs/databases.md#migrations).

## Documentation

- [Deployment and configuration](docs/deployment.md)
- [Databases](docs/databases.md)
- [Sending and receiving providers](docs/providers.md)
- [API and integrations](docs/api.md)
- [Email assistant and MCP](docs/email-assistant-and-mcp.md)
- [Adding a language](docs/localization.md)
- [Troubleshooting](docs/troubleshooting.md)

## License

See [LICENSE](LICENSE).
