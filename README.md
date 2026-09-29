# nas-auth

English | [简体中文](README.zh-CN.md)

A small, self-hosted OAuth 2.1 authorization server (with DCR and a minimal
OIDC provider) for a home server or homelab. One login, many services; adding
a new service is a one-entry edit to `resources.json`.

It was built to put MCP servers such as
[obsidian-mcp](https://github.com/ZhengchenTao/obsidian-mcp) and
[gitea-mcp](https://github.com/ZhengchenTao/gitea-mcp) behind a real OAuth flow
(Claude.ai, ChatGPT, Grok, Cursor and other MCP clients register themselves via
DCR), and grew into a single sign-on for self-hosted web apps (Gitea, Immich,
Grafana, …). Any resource server that validates JWTs against `iss` / `aud` /
`scope` works. Access tokens are **RS256 by default and verified through
JWKS** — resource servers hold no shared secret (HS256 remains as a legacy /
transition mode).

Built with .NET 10, SQLite and server-side rendered pages; no frontend
framework, no external CDN.

## Features

- **OAuth 2.1**: Authorization Code + PKCE (S256 only), refresh token rotation,
  RFC 8414 metadata, RFC 7591 Dynamic Client Registration (with redirect-URI
  rules and optional allowlists), RFC 8707 resource indicators, RFC 7009
  revocation, RFC 7662 introspection, RFC 9728 protected-resource metadata
- **Minimal OIDC provider** for web apps: discovery, RS256 `id_token`, JWKS,
  `/userinfo`, RP-initiated logout (`end_session_endpoint`)
- **Upstream sign-in** with Google and Microsoft (personal accounts). New
  external identities stay **pending until an admin approves** them — no
  auto-provisioning. Local passwords (argon2id) remain as a fallback and can
  be disabled globally or per user
- **Per-user resource grants**: which user may use which resource, up to
  which scopes
- **`/proxy/{aud}` translation layer** for upstreams that only accept a static
  token: nas-auth validates its own JWT, swaps in the upstream bearer token and
  streams the request through (YARP)
- **Account center** (`/account`) and **admin console** (`/admin`): users,
  approvals, grants, sessions (sign out everywhere / force sign-out), OAuth
  clients, audit log, password-login switch, key rotation hints. English and
  Simplified Chinese UI
- Hardened HTTP layer: `__Host-` cookies, cross-origin write blocking, CSP
  without inline scripts, rate limits, per-account lockout (see
  [Security notes](#security-notes))

## Architecture

```
                         auth.example.com
                         ┌──────────────────────────────┐
  Google / Microsoft ──▶ │ nas-auth                      │
  (upstream sign-in)     │  /.well-known/…  /register    │
                         │  /authorize  /token           │
  MCP clients ─────────▶ │  /revoke  /introspect         │
  (PKCE + DCR)           │  /userinfo  /logout           │
                         │  /account  /admin             │
  web apps (OIDC) ─────▶ │  /proxy/{aud}/…               │
                         │  SQLite + RSA key (/app/data) │
                         └──────────────┬───────────────┘
                                        │ RS256 JWT (aud=<resource>, typ=at+jwt)
                                        ▼
               obsidian-mcp / gitea-mcp / Gitea / Immich / Grafana / …
               (each verifies the signature via JWKS + iss + aud + exp + scope)
```

## Endpoints

| Endpoint | Purpose |
|---|---|
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `/.well-known/openid-configuration` | OIDC discovery |
| `/.well-known/jwks.json` | RSA public keys (current + previous) for access tokens and id_tokens |
| `/register` | Dynamic Client Registration (RFC 7591), rate limited |
| `/authorize` | Authorization Code + PKCE; sign-in / consent page |
| `/token` | Code → access + refresh token; refresh rotation; `id_token` when `openid` is requested |
| `/revoke` | RFC 7009 token revocation |
| `/introspect` | RFC 7662 token introspection |
| `/userinfo` | OIDC UserInfo (`sub`, `email`, `name`, `preferred_username`) |
| `/logout` | Sign out; OIDC RP-initiated logout (`post_logout_redirect_uri`, `state`, `client_id`) |
| `/login` | Sign-in page (password and/or Google / Microsoft) |
| `/external/{provider}/start` | Start Google / Microsoft sign-in (callbacks: `/signin/google`, `/signin/microsoft`) |
| `/account` | Account center for every user: authorized apps, bindings, password, sessions |
| `/admin` | Admin console (404 for non-admins) |
| `/proxy/{aud}/…` | Token-translating reverse proxy for resources with a `proxy` block |
| `/proxy/{aud}/.well-known/oauth-protected-resource` | RFC 9728 metadata for proxied resources |
| `/healthz` | Health check |

## Quick start (Docker Compose)

```yaml
# docker-compose.yml
services:
  nas-auth:
    build: .                      # or an image you built and pushed yourself
    restart: unless-stopped
    ports:
      - "9091:8080"               # put an HTTPS reverse proxy in front of this
    volumes:
      - ./data:/app/data          # SQLite, RSA signing key, DataProtection keys — back this up
      - ./resources.json:/app/resources.json:ro
      - ./clients.preset.json:/app/clients.preset.json:ro
    env_file: .env                # secrets: admin password, IdP credentials, proxy tokens
    environment:
      - Auth__Issuer=https://auth.example.com
      - Auth__Admin__Username=admin
```

```dotenv
# .env (never commit this)
Auth__Admin__Password=change-me
# Optional upstream sign-in (callbacks: https://auth.example.com/signin/google | /signin/microsoft)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
MS_CLIENT_ID=
MS_CLIENT_SECRET=
# Optional: upstream token for a resource with "proxy.bearer_env": "EZBK_MCP_TOKEN"
EZBK_MCP_TOKEN=
```

1. `cp resources.example.json resources.json` and
   `cp clients.preset.example.json clients.preset.json`, then edit both (see
   below). Only keep the resources / clients you actually run.
2. Make `./data` writable by the container's non-root user (`appuser`, see the
   `Dockerfile`; `docker compose run --rm --entrypoint id nas-auth` prints its
   uid).
3. `docker compose up -d`, then publish `https://auth.example.com` through
   your reverse proxy. Sessions require HTTPS (see
   [Security notes](#security-notes)).
4. Sign in at `https://auth.example.com/login` as `admin`.
5. To use Google / Microsoft sign-in: once any provider is configured,
   password sign-in only works for users with *Allow password sign-in*
   checked, and the bootstrapped admin starts with it unchecked. So on the
   first start leave the `GOOGLE_*` / `MS_*` variables empty, check *Allow
   password sign-in* for `admin` under `/admin/users`, then add the provider
   credentials and restart. Bind your accounts under *Account → Sign-in &
   security*, and afterwards you can uncheck password sign-in again.

## Configuration

Settings come from environment variables (double underscore = nested
section) or `appsettings*.json`. Secrets belong in the environment only.

| Variable | Required | Default | Description |
|---|---|---|---|
| `Auth__Issuer` | ✅ | `https://auth.example.com` (`appsettings.json`) | Public base URL; the `iss` claim. Startup fails if empty |
| `Auth__Database` | ✅ | `Data Source=/app/data/auth.db` | SQLite connection string. The RSA key (`oidc_rs256_*.pem`) and DataProtection keys (`dp-keys/`) are stored in the same directory |
| `Auth__ResourcesPath` | ✅ | `/app/resources.json` | Loaded at startup; missing or invalid file → startup fails |
| `Auth__ClientsPresetPath` | ❌ | `/app/clients.preset.json` | Preset clients, upserted at startup; skipped if the file is missing |
| `Auth__Admin__Username` | ❌ | `admin` | Admin username (bootstrapped at startup, always `is_admin`) |
| `Auth__Admin__Password` | ⚠️ | *(empty)* | Plaintext, hashed at startup then discarded; superseded by `PasswordHash` if both are set |
| `Auth__Admin__PasswordHash` | ⚠️ | *(empty)* | argon2id hash string, takes precedence over `Password` |
| `Auth__PasswordLogin__Enabled` | ❌ | `true` | Master switch for password sign-in. `false` hides the password form and returns 404 from the password endpoints; an admin can override it at runtime under `/admin/system`. Forced on while neither Google nor Microsoft is configured, so you cannot lock yourself out. On top of it, each user has an *Allow password sign-in* flag |
| `Auth__Dcr__AllowedRedirectHosts__0`, `__1`, … | ❌ | *(empty)* | Host allowlist for `https` redirect_uris of dynamically registered (`/register`) clients, enforced at `/register` and again at `/authorize`. Exact match; an entry starting with `.` matches subdomains only (`.example.com`). Setting this or `AllowedCustomSchemes` turns on allowlist mode, where **both** lists apply (an empty list then allows nothing of that kind); with both empty any host / scheme passes the shape rules. Loopback `http` is always allowed. Non-ASCII (IDN) URIs are always rejected. Example: `claude.ai`, `chatgpt.com`, `grok.com` |
| `Auth__Dcr__AllowedCustomSchemes__0`, `__1`, … | ❌ | *(empty)* | Private-use scheme allowlist for DCR redirect_uris (e.g. `cursor`), exact, case-insensitive; applies in allowlist mode. Browser / OS launcher schemes (`microsoft-edge`, `googlechrome`, `x-safari-*`, `ms-*`, `search-ms`, `intent`, …) and schemes embedding another URL are always rejected, but that blocklist cannot be complete — the allowlist is the real control |
| `Jwt__AccessTokenAlgorithm` | ❌ | `RS256` | `RS256` (JWKS, recommended) or `HS256` (legacy shared key); empty = `RS256`, anything else fails startup |
| `Jwt__SigningKey__Current` | ⚠️ | *(empty)* | HS256 key, ≥ 32 bytes. Required only when `AccessTokenAlgorithm=HS256`; in RS256 mode optional and used **only** to keep validating already-issued HS256 tokens |
| `Jwt__SigningKey__Previous` | ❌ | *(empty)* | Old HS256 key, ≥ 32 bytes, verification only (HS256 rotation / RS256 transition) |
| `Jwt__LegacyHs256NotAfter` | ⚠️ | *(empty)* | ISO 8601 UTC deadline for accepting legacy HS256 tokens in RS256 mode. **Required** if any `Jwt__SigningKey__*` is set in RS256 mode (startup fails otherwise); only tokens with `exp` ≤ it are accepted, and after it every HS256 token is rejected. Ignored in HS256 mode |
| `Jwt__AccessTokenLifetimeDays` | ❌ | `30` | Access token TTL |
| `Jwt__RefreshTokenLifetimeDays` | ❌ | `90` | Refresh token TTL |
| `Jwt__AuthCodeLifetimeMinutes` | ❌ | `10` | Authorization code TTL |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | ❌ | *(empty)* | Google OAuth client (Web). Redirect URI `<issuer>/signin/google`. Both set → *Continue with Google* appears; otherwise the provider is off |
| `MS_CLIENT_ID` / `MS_CLIENT_SECRET` | ❌ | *(empty)* | Microsoft app registration for **personal Microsoft accounts only** (nas-auth uses the `/consumers/` endpoints). Redirect URI `<issuer>/signin/microsoft` |
| *value of `proxy.bearer_env`* | per resource | — | Upstream bearer token for a proxied resource (e.g. `EZBK_MCP_TOKEN`); must be non-empty or startup fails |
| `ASPNETCORE_ENVIRONMENT` | ❌ | `Production` | `Development` loads `appsettings.Development.json` (dev admin password, example resource files, local SQLite) |

⚠️ At least one of `Password` / `PasswordHash` must be set; if both are empty
and no admin user exists in SQLite, startup fails. The admin password is
rewritten from the configuration on every start.

In production the container listens on `0.0.0.0:8080`. `X-Forwarded-For` /
`X-Forwarded-Proto` are trusted from private-network and loopback proxies
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`,
`fc00::/7`), hop by hop, to find the real client IP for rate limiting and the
audit log — publish the service only through your reverse proxy.

### `resources.json`

Loaded once at startup (no hot reload; restart to apply). Defines which
audiences exist and which scopes they expose. See
[`resources.example.json`](resources.example.json).

```json
[
  {
    "aud": "obsidian",
    "resource_url": "https://obsidian-mcp.example.com",
    "display_name": "Obsidian Vault",
    "scopes": ["read:obsidian", "write:obsidian"]
  },
  {
    "aud": "immich",
    "resource_url": "https://photos.example.com",
    "display_name": "Immich",
    "scopes": ["openid", "email", "profile"]
  },
  {
    "aud": "ezbookkeeping",
    "resource_url": "https://auth.example.com/proxy/ezbookkeeping",
    "display_name": "ezBookkeeping",
    "scopes": ["read:ezbookkeeping", "write:ezbookkeeping"],
    "proxy": { "upstream": "http://ezbookkeeping:8080", "bearer_env": "EZBK_MCP_TOKEN" }
  }
]
```

- `resource_url` is the RFC 8707 resource identifier clients send. Trailing
  slashes and sub-paths (e.g. `…/mcp`) of a configured URL are accepted.
- `proxy` (optional) turns the entry into a `/proxy/{aud}` resource:
  `upstream` must be a host root (no path), `bearer_env` names the environment
  variable holding the upstream token. Point MCP clients at
  `https://auth.example.com/proxy/<aud>/<upstream path>`. Startup fails if
  that variable is unset or empty — this also applies to the bundled
  `resources.example.json` (`EZBK_MCP_TOKEN`).
- OIDC web apps get their own resource entry with `openid email profile`
  scopes and a preset client whose `default_resource` points at it.

### `clients.preset.json`

Clients that cannot register themselves (web apps using OIDC, or MCP clients
with a fixed callback). Upserted at startup, never auto-cleaned. See
[`clients.preset.example.json`](clients.preset.example.json).

| Field | Description |
|---|---|
| `client_id`, `client_name` | Identifier and display name |
| `client_secret` | Confidential clients only; store a high-entropy value and give the same value to the app |
| `redirect_uris` | Exact-match list; custom schemes such as `app.immich:///oauth-callback` are allowed here |
| `token_endpoint_auth_method` | `none` (public, PKCE required) or `client_secret_post` |
| `default_resource` | Resource URL used when the client does not send `resource` (most OIDC apps) |

Dynamically registered clients are removed after 30 days without use (unless
they still hold a valid refresh token).

### Users, approvals and grants

- The admin from `Auth__Admin__*` is created on startup. Other users are
  created by the admin (local password, must change it on first sign-in) or
  by approving an external identity.
- The first time someone signs in with Google / Microsoft, the identity is
  stored as **pending** and no session is created. The admin approves it
  under `/admin/approvals` — binding it to an existing user or creating a new
  one — and picks which resources the user may use. Rejected identities stay
  rejected.
- A signed-in user can bind additional Google / Microsoft accounts to
  themselves without approval.
- `/authorize` and every refresh check the user's grant for each requested
  resource and scope; revoking a grant takes effect at the next refresh.
- Each user can have an email address, which is what downstream apps (e.g.
  Immich) receive in the `email` claim to match their own accounts. Without
  one, the first bound external identity's email is used.

## Token signing and verification

**RS256 (default).** Access tokens are signed with the same RSA key nas-auth
uses for OIDC id_tokens, with header `kid` and `typ: at+jwt` (RFC 9068).
Claims: `iss`, `sub`, `aud` (string, or array for multi-resource tokens),
`client_id`, `scope`, `resource`, `iat`, `nbf`, `exp`, `jti`. Resource servers
hold no secret; they verify like this:

1. `GET <issuer>/.well-known/openid-configuration` (or
   `oauth-authorization-server`) → `jwks_uri` = `<issuer>/.well-known/jwks.json`
2. verify the signature with the JWKS key matching `kid`, allowing only `RS256`
   (never use keys or URLs from the token header — `jwk` / `jku` / `x5u`)
3. validate `iss` = `Auth__Issuer`, `aud` contains the server's own audience,
   `exp` / `nbf`
4. **must** require `typ` ∈ {`at+jwt`, `application/at+jwt`}
   (case-insensitive). id_tokens are signed by the same key (`typ: JWT`,
   `aud` = client_id), and a client and a resource can share a name
   (e.g. `gitea-web`, `immich`; nas-auth logs a warning at startup for every
   such collision) — without the `typ` check an id_token would pass as an
   access token
5. check the `scope` claim (space-separated) against the operation

With ASP.NET Core JwtBearer this is `Authority = <issuer>` plus the usual
issuer / audience checks and `ValidTypes`.
[obsidian-mcp](https://github.com/ZhengchenTao/obsidian-mcp) and
[gitea-mcp](https://github.com/ZhengchenTao/gitea-mcp) are complete example
resource servers (`Jwt__Algorithm=RS256`, `Jwt__Issuer=<issuer>`,
`Jwt__Audience=<aud>`). nas-auth's own `/introspect`, `/userinfo` and
`/proxy/{aud}` accept RS256 tokens only with `typ: at+jwt`; the one other path
is legacy HS256 (below), which in RS256 mode is capped by
`Jwt__LegacyHs256NotAfter`.

**Key files and rotation.** `oidc_rs256_current.pem` /
`oidc_rs256_previous.pem` live next to `auth.db` (generated on first start,
created with mode 600). To rotate: rename current → previous (replacing the
old one) and restart nas-auth; a new current key is generated. The previous
key stays in JWKS so outstanding tokens keep validating — **keep it for at
least `Jwt__AccessTokenLifetimeDays`** before deleting it or rotating again.
JwtBearer refetches JWKS when it sees an unknown `kid`, so resource servers
need no restart. An unreadable PEM fails startup with the file name; restore
it from backup rather than deleting it.

**HS256 (legacy).** `Jwt__AccessTokenAlgorithm=HS256` signs with
`Jwt__SigningKey__Current`, a symmetric key every resource server must also
hold — so any compromised resource server can mint tokens for every audience.
Kept only for rollback. In HS256 mode nas-auth still accepts RS256 access
tokens it issued earlier.

**Migrating from HS256.** Switch nas-auth and every resource server **in the
same window**: a resource server that accepts only one algorithm rejects
nas-auth's new RS256 tokens until it is switched, and after the switch it
rejects the old HS256 tokens clients still hold. Between the two restarts
requests fail with 401; MCP clients then use their refresh token (opaque,
unaffected) to get an RS256 token, others re-authorize.

1. nas-auth: `Jwt__AccessTokenAlgorithm=RS256` (the default) and **remove**
   `Jwt__SigningKey__Current` / `Previous`. This is the recommended path: the
   old key has lived on every resource server and possibly in a shared env
   file, so anyone holding it could otherwise forge HS256 tokens for `/proxy`
   and `/userinfo`.
2. Every resource server: `Jwt__Algorithm=RS256`, remove the shared key,
   require `typ` as above.
3. Retire the old shared secret everywhere.

If you must keep accepting old HS256 tokens at nas-auth's own endpoints for a
while, keep `Jwt__SigningKey__*` **only in nas-auth's environment** (not in a
shared env file that resource servers read) and set
`Jwt__LegacyHs256NotAfter` (mandatory; e.g. switch time +
`Jwt__AccessTokenLifetimeDays`). Only HS256 tokens with `exp` ≤ that time are
accepted, none after it; then remove both settings.

## Local development

```bash
# 1. Run (Development profile: admin / devpassword, example resource and
#    client files, SQLite + RSA key under ./data). resources.example.json has a
#    proxied resource whose bearer_env must be set, so pass a dummy value:
EZBK_MCP_TOKEN=dev dotnet run --urls http://localhost:5000
#    PowerShell: $env:EZBK_MCP_TOKEN = "dev"; dotnet run --urls http://localhost:5000

# 2. Browse:
#    http://localhost:5000/login         (admin / devpassword)
#    http://localhost:5000/.well-known/oauth-authorization-server
#    http://localhost:5000/account
```

Use Chrome or Firefox: session cookies are `__Host-` / `Secure`, which those
browsers accept on `http://localhost` (Safari does not).

**Getting a JWT to test a downstream MCP:** run the OAuth flow (MCP Inspector
works) — RS256 tokens can only be signed with the private key in
`oidc_rs256_current.pem`. For an HS256-mode downstream, `dotnet user-jwts`
or jwt.io with the same `Jwt:SigningKey:Current` still works:

```bash
dotnet user-jwts create \
  --issuer https://auth.example.com \
  --audience obsidian \
  --name admin \
  --claim sub=admin \
  --claim scope="read:obsidian"
```

## Tests

```bash
dotnet test tests/nas-auth.Tests
```

xUnit, about 390 tests, no external services (each test uses a temporary
SQLite database). They cover:

- **Protocol**: PKCE, DCR registration rules and rate limits, redirect-URI
  policy, multi-resource (multi-`aud`) tokens, refresh rotation, RS256 /
  legacy-HS256 signing and validation (including `typ` and algorithm
  confusion), OIDC keys and id_tokens, RP-initiated logout redirects
- **Accounts**: external sign-in state machine and approvals, identity
  binding, per-user grants, per-user password switch and lockout, session
  invalidation, audit log, admin bootstrap and schema upgrades
- **HTTP layer**: an in-process integration suite (`WebApplicationFactory`)
  runs the real pipeline — cross-origin write blocking, security headers,
  `__Host-` cookies, return-URL checks, flash-message tamper resistance, the
  resource proxy, and a full `/authorize` → `/token` → `/userinfo` flow
- **Pages**: template contracts (form field names, admin-only menus) and a
  guard that no page contains inline scripts or handlers

## Docker and CI

```bash
docker build -t nas-auth:dev .

docker run -p 9091:8080 \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/resources.json:/app/resources.json:ro" \
  -e Auth__Issuer=https://auth.example.com \
  -e Auth__Admin__Password=change-me \
  nas-auth:dev
```

The RSA signing key is created in the `/app/data` volume on first start; keep
that volume, or every issued token becomes invalid. The image never contains
`resources.json`, `clients.preset.json`, `.env` files, databases or keys
(see `.dockerignore`).

The included `.gitea/workflows/build-image.yml` is a Gitea Actions workflow
that builds the image, pushes it as `<REGISTRY>/<IMAGE_OWNER>/nas-auth:<short sha>`
and `:latest`, then optionally triggers a redeploy over SSH. It expects these
repository Variables / Secrets:

- `vars.REGISTRY` — registry hostname (e.g. `git.example.com` for the Gitea
  Container Registry)
- `vars.IMAGE_OWNER` — registry owner / namespace (also the login user)
- `secrets.AIFACELY_REGISTRY_TOKEN` — registry push token (`write:package`)
- `vars.DEPLOY_SERVICE` — *(optional)* service name passed to the deploy host
  as `deploy <service>`; leave empty to only build & push
- `secrets.NAS_CI_SSH_KEY`, `secrets.NAS_SSH_HOST`, `secrets.NAS_SSH_KNOWN_HOSTS`
  — only needed with `DEPLOY_SERVICE`: the SSH key (restricted on the host to a
  forced deploy command), the host, and its pinned host key line

The action references and build proxy lines point at the author's CI setup;
adjust them in a fork.

## Security notes

Operator-visible behavior of the HTTP hardening (2026-09-29; details in
`docs/design/external-auth.md` §十七):

- **Session cookies** are `__Host-nas-auth-session` and `__Host-nas-auth-external`:
  `Secure`, `Path=/`, no `Domain`, `HttpOnly`, `SameSite=Lax`. Sibling subdomains
  can't overwrite them. Upgrading from the old `nas-auth-session` name signs
  everyone out once. A session only works over HTTPS: going straight to the
  container's plain-HTTP port won't keep you signed in. `http://localhost` works
  in Chrome / Firefox (treated as a secure context), not in Safari.
- **CSRF**: browser `POST` / `PUT` / `PATCH` / `DELETE` requests must come from
  nas-auth's own origin (`Sec-Fetch-Site`, else `Origin`, else `Referer`;
  requests carrying none of them, e.g. curl, pass). Cross-origin ones get a
  plain-text 403. Exempt: `/token`, `/revoke`, `/introspect`, `/register`,
  `/userinfo`, `/proxy/*`, `/logout` (RP-initiated logout may be a cross-site
  form POST).
- **CSP**: `script-src 'self'` (no inline scripts), `frame-ancestors 'none'`,
  plus `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: same-origin`. `/proxy/*` responses are passed through
  untouched. Keep CDN features that inject scripts (e.g. Cloudflare Rocket
  Loader / auto-injected analytics) **off** for the auth hostname — the CSP
  blocks injected scripts.
- **Caching**: pages and `/token` responses are `Cache-Control: no-store`;
  `/.well-known/*` (discovery, JWKS) is `public, max-age=300`; static assets
  keep normal caching. No HSTS is sent (TLS terminates at the proxy; set HSTS
  there).
- **Redirect targets**: `return_url` must be a local path (printable ASCII,
  no `//`, `/\`, or control characters); anything else falls back to
  `/account`. Binding an external account is `POST /external/{provider}/bind`
  and always shows the IdP's account picker (`prompt=select_account`).
  `post_logout_redirect_uri` must match the origin of a preset client's
  redirect URI.
- **Notices**: `/login?notice=` only accepts known keys (`signed_out`);
  dashboard notices are DataProtection-protected and expire after 10 minutes,
  so hand-crafted `?notice=` / `?error=` text is never displayed.
- **Brute force**: `POST /login`, `POST /authorize` and `/token` are limited to
  5 requests per minute per client IP (IPv6 per /64); `/register` to 10 per hour
  per IP plus 200 per hour globally; 10 consecutive failed passwords lock an
  account for 15 minutes.

## What's implemented / what's not

✅ Authorization Code + PKCE / DCR / RFC 8707 resources / refresh token
   rotation / revoke / introspect / RS256 access tokens via JWKS (HS256 legacy
   mode) / minimal OIDC (discovery, id_token, userinfo, RP-initiated logout) /
   Google & Microsoft sign-in with admin approval / per-user grants /
   `/proxy` token translation / account center & admin console / audit log /
   argon2id / SQLite / background cleanup / rate limits / manual key rotation.

❌ Long-lived PAT issuance, TOTP, generic OIDC upstream providers,
   `resources.json` hot reload, RBAC / groups (out of scope).

The design notes (in Chinese) are in
[`docs/design/external-auth.md`](docs/design/external-auth.md).

## License

MIT
