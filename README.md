# nas-auth

English | [简体中文](README.zh-CN.md)

A small OAuth 2.1 / OpenID Connect server for a home server. I wrote it
because I wanted Claude, ChatGPT and friends to reach a couple of my own MCP
servers through a proper OAuth flow, and Keycloak felt like far too much for
one household. It later took over sign-in for the other self-hosted apps too
(Gitea, Immich, Grafana).

It is one .NET 10 process with a SQLite file and server-rendered pages. No
frontend build, nothing loaded from a CDN.

## How the three repos fit together

- [nas-auth](https://github.com/ZhengchenTao/nas-auth): the authorization
  server. Signs users in and issues tokens.
- [obsidian-mcp](https://github.com/ZhengchenTao/obsidian-mcp): MCP server for
  an Obsidian vault (read and write).
- [gitea-mcp](https://github.com/ZhengchenTao/gitea-mcp): MCP server for a
  Gitea instance (read-only).

An MCP client finds the authorization server through the MCP server's
metadata, registers itself, lets the user sign in, and gets a token that is
only valid for that one MCP server. The MCP servers check the token against
nas-auth's public keys. They never see a password or a shared secret. Each
repo also works on its own: the MCP servers accept tokens from any standard
OAuth server, and nas-auth can front any service that verifies JWTs.

## What it does

- Authorization Code + PKCE (S256 only), refresh token rotation, Dynamic
  Client Registration (RFC 7591), resource indicators (RFC 8707), revocation
  and introspection, protected-resource metadata (RFC 9728).
- A minimal OIDC provider for web apps: discovery, `id_token`, JWKS,
  `/userinfo`, RP-initiated logout.
- Sign-in with Google or a personal Microsoft account. A new external account
  waits for an admin to approve it; nobody gets an account just by signing in.
  The admin can also register someone's email ahead of time, so that their
  first sign-in is linked straight to a chosen user. Local passwords (argon2id)
  are the fallback and can be turned off.
- A user id that never changes, which downstream apps use to recognise the
  user, and a separate nickname and avatar that can be edited and are sent to
  apps as `name` / `picture`.
- Per-user grants: which user may use which resource, and with which scopes.
- `/proxy/{aud}`: for an upstream that only understands one static token.
  nas-auth checks its own JWT, swaps in the upstream token and streams the
  request through.
- `/account` for every user (authorized apps, nickname and avatar, linked
  accounts, password, sessions) and `/admin` for the admin (users, approvals, clients, audit log).
  English and Simplified Chinese.

Access tokens are RS256 JWTs with `typ: at+jwt`, verifiable through
`/.well-known/jwks.json`. A symmetric HS256 mode still exists for old setups.

```
                          auth.example.com
                         ┌────────────────────────────┐
  Google / Microsoft ──▶ │ nas-auth                    │
  MCP clients (DCR) ───▶ │  /authorize /token /register │
  web apps (OIDC) ─────▶ │  /userinfo /logout /proxy    │
                         │  SQLite + RSA key            │
                         └─────────────┬──────────────┘
                                       │ RS256 JWT, aud = one resource
                                       ▼
              obsidian-mcp, gitea-mcp, Gitea, Immich, Grafana …
              (each checks the signature via JWKS, then iss / aud / exp / scope)
```

## Quick start

```yaml
# docker-compose.yml
services:
  nas-auth:
    build: .                      # or an image you built yourself
    restart: unless-stopped
    ports:
      - "9091:8080"               # put an HTTPS reverse proxy in front
    volumes:
      - ./data:/app/data          # SQLite, RSA key, cookie keys, avatars. Back this up.
      # mount the directory, not the two files: a single-file bind mount keeps
      # pointing at the old file once an editor or `mv` replaces it
      - ./config:/app/config:ro
    env_file: .env
    environment:
      - Auth__ResourcesPath=/app/config/resources.json
      - Auth__ClientsPresetPath=/app/config/clients.preset.json
      - Auth__Issuer=https://auth.example.com
      - Auth__Admin__Username=admin
```

```dotenv
# .env  (keep out of git)
Auth__Admin__Password=change-me
# optional, callbacks are <issuer>/signin/google and <issuer>/signin/microsoft
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
MS_CLIENT_ID=
MS_CLIENT_SECRET=
# only if a resource in resources.json has "bearer_env": "EZBK_MCP_TOKEN"
EZBK_MCP_TOKEN=
```

1. Copy `resources.example.json` to `config/resources.json` and
   `clients.preset.example.json` to `config/clients.preset.json`, and keep only
   what you run. Both are read once at startup: restart after editing them.
2. Make `./data` writable by the container user (`appuser`;
   `docker compose run --rm --entrypoint id nas-auth` prints its uid).
3. `docker compose up -d` and publish it over HTTPS. Sessions do not work over
   plain HTTP.
4. Sign in at `https://auth.example.com/login` as `admin`.

If you want Google or Microsoft sign-in, do it in this order. Once a provider
is configured, only users with "Allow password sign-in" can still use a
password, and the admin starts without it. So: start without the `GOOGLE_*` /
`MS_*` variables, tick "Allow password sign-in" for `admin` under
`/admin/users`, add the credentials and restart, link your Google or Microsoft
account under Account → Sign-in & security, then untick the password option if
you like.

## Configuration

Environment variables, with `__` for nesting (`Auth__Issuer` is `Auth:Issuer`).
`appsettings*.json` works too, but keep secrets in the environment.

| Variable | Default | Notes |
|---|---|---|
| `Auth__Issuer` | – | Public base URL, used as `iss`. Required. |
| `Auth__Database` | `Data Source=/app/data/auth.db` | The RSA key (`oidc_rs256_*.pem`), cookie keys (`dp-keys/`) and avatars (`avatars/`) are kept next to it. |
| `Auth__ResourcesPath` | `/app/resources.json` | Required; read once at startup. |
| `Auth__ClientsPresetPath` | `/app/clients.preset.json` | Optional. |
| `Auth__Admin__Username` | `admin` | Created at startup, always an admin. |
| `Auth__Admin__Password` / `__PasswordHash` | – | One of them is needed on first start. The hash (argon2id) wins if both are set. Reapplied on every start. |
| `Auth__PasswordLogin__Enabled` | `true` | Master switch for passwords; also toggled at runtime in `/admin/system`. Always on while no Google/Microsoft is configured, so you can't lock yourself out. |
| `Auth__Dcr__AllowedRedirectHosts__N` | – | See below. |
| `Auth__Dcr__AllowedCustomSchemes__N` | – | See below. |
| `Jwt__AccessTokenAlgorithm` | `RS256` | `RS256` or `HS256`. |
| `Jwt__AccessTokenLifetimeDays` | `30` | |
| `Jwt__RefreshTokenLifetimeDays` | `90` | |
| `Jwt__AuthCodeLifetimeMinutes` | `10` | |
| `Jwt__SigningKey__Current` / `__Previous` | – | HS256 only (at least 32 bytes). See "Legacy HS256". |
| `Jwt__LegacyHs256NotAfter` | – | See "Legacy HS256". |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | – | Google web client; set both to show the button. |
| `MS_CLIENT_ID` / `MS_CLIENT_SECRET` | – | Microsoft app for personal accounts only (uses the `/consumers/` endpoints). |
| value of `proxy.bearer_env` | – | Upstream token for a proxied resource. Startup fails if it is empty. |

**Who may register.** `/register` is open by design, because that is how MCP
clients connect. Registration rejects obviously bad redirect URIs (non-HTTPS
except loopback, fragments, user info, non-ASCII, browser and OS launcher
schemes such as `microsoft-edge:`). If you only use a few known clients, list
them and everything else is refused:

```
Auth__Dcr__AllowedRedirectHosts__0=claude.ai
Auth__Dcr__AllowedRedirectHosts__1=chatgpt.com
Auth__Dcr__AllowedRedirectHosts__2=grok.com
Auth__Dcr__AllowedRedirectHosts__3=www.cursor.com
Auth__Dcr__AllowedCustomSchemes__0=cursor
```

A leading dot (`.example.com`) matches subdomains only. Once either list is
set, both apply, and loopback `http://localhost:…` is always allowed. Clients
registered earlier are checked against the same rules at `/authorize`.

**Reverse proxy.** The container listens on 8080 and trusts
`X-Forwarded-For` / `X-Forwarded-Proto` from private and loopback addresses, so
only expose it through your proxy.

### resources.json

What can be asked for. Read at startup; restart to apply changes.

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
    "admin_only": true,
    "proxy": { "upstream": "http://ezbookkeeping:8080", "bearer_env": "EZBK_MCP_TOKEN" }
  }
]
```

`resource_url` is what clients send as `resource`; a trailing slash or a
sub-path such as `/mcp` still matches. An entry with `proxy` is served under
`/proxy/<aud>/…`; `upstream` has to be a bare host. A web app that signs in
through OIDC gets an entry with `openid email profile` and a preset client
pointing at it. `"admin_only": true` means the resource can only be granted to
admins: use it when the resource server talks to its upstream with one fixed
credential of yours (a personal access token, a single ledger token), so that
granting it to someone else would hand them your data. Non-admins can't be
granted it in the dashboard, and `/authorize` and refresh turn them away even if
an old grant row is still there.

### clients.preset.json

For clients that can't register themselves, usually web apps using OIDC.
Applied at startup.

| Field | |
|---|---|
| `client_id`, `client_name` | |
| `client_secret` | Confidential clients only. Put the same value into the app. |
| `redirect_uris` | Exact match. Custom schemes such as `app.immich:///oauth-callback` are fine here. |
| `token_endpoint_auth_method` | `none` (public, PKCE required), `client_secret_post` or `client_secret_basic`. A client with a secret may send it either way (form field or `Authorization: Basic` header), whichever is listed here. |
| `default_resource` | Used when the client sends no `resource`, which most OIDC apps don't. |

Self-registered clients are deleted after 30 days without use, unless they
still hold a valid refresh token.

### Users

The admin is created from the configuration. Other users come from one of
three places:

- **An approved Google/Microsoft sign-in.** The first sign-in only files a
  request. The admin approves it under `/admin/approvals`, attaching it to an
  existing user or a new one and choosing which resources that user gets.
- **A user the admin sets up in advance.** Create the user without "Allow
  password sign-in": it has no password and can only sign in through Google or
  Microsoft. Fill in "Pre-bind sign-in email" at the same time. The first time
  someone signs in with an account for that email, it is linked to this user
  directly, with no approval step.
- **A password user created by the admin.** Tick "Allow password sign-in" and
  set a password. By default that is the user's password from then on; tick
  "Must change password on first sign-in" if they should pick their own. The
  same choice is offered when the admin resets a password.

A pre-bound email only counts when the provider vouches that the person owns
it: Google must report `email_verified`, and for Microsoft the sign-in name
must be that email. Otherwise the sign-in files a request as usual. A
pre-bound email is removed once it has been used. A signed-in user can link
more Google/Microsoft accounts to themselves.

The user id is what downstream apps receive as `sub` and
`preferred_username`. It can't be changed, and the id of a deleted user can't
be used again: apps find their account by it, so a new user with an old id
would land in the old user's account in every app. The nickname (`name`) and
avatar (`picture`) are separate from the id. Users edit them under `/account`
and the admin can edit them for anyone; when they are not set, they come from
the linked Google/Microsoft account. Avatars must be PNG, JPEG or WebP, up to
2 MB, and are served from `/avatars/<file>` without sign-in, because
downstream apps fetch them from their servers.

Grants are checked on every `/authorize` and every refresh, so taking one away
takes effect at the next refresh. The email a user has in nas-auth is what
downstream apps see in the `email` claim; Immich, for example, uses it to find
the matching account.

Downstream apps can turn on their own OIDC auto-provisioning, so adding a
person is done once, in nas-auth. Admission is decided here: an unapproved
external account gets no token at all, and an approved user without a grant
for that resource is turned away at `/authorize`. Turn off the app's own
registration and password sign-in.

## Verifying tokens in a resource server

1. Read `<issuer>/.well-known/openid-configuration` and fetch `jwks_uri`.
2. Verify the signature with the key whose `kid` matches. Allow only RS256, and
   never use a key or URL taken from the token header.
3. Check `iss`, that `aud` contains your audience, and `exp` / `nbf`.
4. Require `typ` to be `at+jwt` (or `application/at+jwt`). id_tokens are
   signed with the same key, and a client can share its name with a resource,
   so skipping this check would let an id_token pass as an access token.
   nas-auth warns at startup when a client id and a resource `aud` collide.
5. Check `scope` against the operation.

In ASP.NET Core that is JwtBearer with `Authority = <issuer>`, the usual
issuer/audience settings and `ValidTypes`. obsidian-mcp and gitea-mcp do
exactly this with `Jwt__Algorithm=RS256` and `Jwt__ValidTypes__0=at+jwt`.

Token claims: `iss`, `sub`, `aud` (a string, or an array when one token covers
several resources), `client_id`, `scope`, `resource`, `iat`, `nbf`, `exp`,
`jti`.

The `id_token` and `/userinfo` carry the user's details: `sub` and
`preferred_username` (both the user id), `email`, `name` (the nickname) and
`picture` (the avatar URL).

**Rotating the key.** Rename `oidc_rs256_current.pem` to
`oidc_rs256_previous.pem` and restart; a new key is generated. The old one
stays in JWKS, so keep it at least as long as an access token lives (30 days by
default) before rotating again. Resource servers pick up the new key on their
own.

**Legacy HS256.** With `Jwt__AccessTokenAlgorithm=HS256` tokens are signed with
`Jwt__SigningKey__Current`, which every resource server must also hold. It is
there for rollback only. To move from HS256 to RS256, switch nas-auth and all
resource servers at the same time and drop the shared key. Clients get one 401
and then refresh. If nas-auth itself must keep accepting old HS256 tokens for a
while, keep the key only in nas-auth's environment and set
`Jwt__LegacyHs256NotAfter` to a UTC time; without it, RS256 mode refuses to
start with an HS256 key configured.

## Security behaviour you will notice

- Cookies are `__Host-nas-auth-session` and `__Host-nas-auth-external`:
  Secure, HttpOnly, SameSite=Lax, no Domain. They only work over HTTPS
  (`http://localhost` is fine in Chrome and Firefox, not in Safari).
- Browser form posts from other origins get a 403, including from sibling
  subdomains. `/token`, `/revoke`, `/introspect`, `/register`, `/userinfo`,
  `/proxy/*` and `/logout` are exempt.
- Pages send a CSP with `script-src 'self'` and `frame-ancestors 'none'`. If a
  CDN injects scripts into pages (Cloudflare Rocket Loader, web analytics),
  turn that off for this hostname; it will be blocked anyway.
- Sign-in, consent and `/token` allow 5 requests per minute per IP (per /64
  for IPv6). `/register` allows 10 per hour per IP and 200 per hour in total.
  Ten wrong passwords in a row lock an account for 15 minutes.
- After sign-in you are only ever sent to a local path. The logout redirect
  must point at the origin of a preset client.

## Endpoints

| Path | |
|---|---|
| `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration` | Metadata |
| `/.well-known/jwks.json` | Public keys |
| `/register` | Dynamic client registration |
| `/authorize`, `/token` | Authorization code flow, refresh |
| `/revoke`, `/introspect` | RFC 7009 / RFC 7662 |
| `/userinfo`, `/logout` | OIDC |
| `/login`, `/account`, `/admin` | Pages |
| `/avatars/{file}` | Avatars (public, fetched by downstream apps) |
| `/external/{provider}/start` | Google / Microsoft sign-in |
| `/proxy/{aud}/…` | Token-swapping proxy (plus its RFC 9728 metadata) |
| `/healthz` | Health check |

## Development

```bash
# Development profile: admin / devpassword, example config files, ./data
EZBK_MCP_TOKEN=dev dotnet run --urls http://localhost:5000
# PowerShell: $env:EZBK_MCP_TOKEN = "dev"; dotnet run --urls http://localhost:5000

dotnet test tests/nas-auth.Tests
```

`EZBK_MCP_TOKEN` is only there because the example resources include a proxied
entry. Open `http://localhost:5000/login` in Chrome or Firefox. To get a token
for testing an MCP server, run the real flow, for example with MCP Inspector.

The test suite (xUnit, about 450 tests) needs nothing external. It covers the
protocol pieces, accounts and approvals, the page templates, and the full HTTP
pipeline through `WebApplicationFactory`.

## Image and CI

```bash
docker build -t nas-auth .
```

The image contains no config, database or keys. The RSA key is created in
`/app/data` on first start; if you lose that volume, every issued token stops
working.

`.gitea/workflows/build-image.yml` builds and pushes
`<REGISTRY>/<IMAGE_OWNER>/nas-auth` on every push to `main` and can then
trigger a redeploy over SSH. It reads `vars.REGISTRY`, `vars.IMAGE_OWNER`,
`secrets.AIFACELY_REGISTRY_TOKEN`, and for the deploy step
`vars.DEPLOY_SERVICE`, `secrets.NAS_CI_SSH_KEY`, `secrets.NAS_SSH_HOST`,
`secrets.NAS_SSH_KNOWN_HOSTS`. The action URLs and build proxy match my own CI;
change them in a fork.

## Not planned

Long-lived personal access tokens, TOTP, arbitrary OIDC upstreams, hot reload
of `resources.json`, roles and groups.

Design notes (Chinese): [docs/design/external-auth.md](docs/design/external-auth.md).

## License

MIT
