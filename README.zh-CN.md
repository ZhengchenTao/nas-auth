# nas-auth

[English](README.md) | 简体中文

给家用服务器 / homelab 用的小型自托管 OAuth 2.1 授权服务器（带 DCR 和最小 OIDC Provider）。一处登录，多处通行；加新服务只改 `resources.json` 一条记录。

最初是为了把 [obsidian-mcp](https://github.com/ZhengchenTao/obsidian-mcp)、[gitea-mcp](https://github.com/ZhengchenTao/gitea-mcp) 这类 MCP server 放到真正的 OAuth 流程后面（Claude.ai、ChatGPT、Grok、Cursor 等 MCP 客户端通过 DCR 自助注册），后来长成了自托管 Web 应用（Gitea、Immich、Grafana……）的单点登录。任何按 `iss` / `aud` / `scope` 验 JWT 的 resource server 都能对接。access token **默认 RS256、走 JWKS 验签**，资源服务器不持有任何共享密钥（HS256 保留为遗留 / 过渡模式）。

.NET 10 + SQLite + 服务端渲染页面；不引前端框架，不依赖外部 CDN。

## 功能

- **OAuth 2.1**：Authorization Code + PKCE（只收 S256）、refresh token rotation、RFC 8414 元数据、RFC 7591 动态注册（带回调地址规则与可选白名单）、RFC 8707 resource indicator、RFC 7009 吊销、RFC 7662 introspection、RFC 9728 受保护资源元数据
- **最小 OIDC Provider**（给 Web 应用）：discovery、RS256 `id_token`、JWKS、`/userinfo`、RP-Initiated Logout（`end_session_endpoint`）
- **上游登录**：Google 与 Microsoft（个人账号）。新的外部身份在**管理员批准前一直是 pending**，不做 auto-provisioning。本地密码（argon2id）作为兜底保留，可全局关闭，也可按用户关闭
- **按用户的资源授权**：哪个用户能用哪个资源、最大到哪些 scope
- **`/proxy/{aud}` 翻译层**：给只认固定 token 的上游用 —— nas-auth 验自己签的 JWT，换成上游 bearer token 后流式转发（YARP）
- **个人中心**（`/account`）与**管理后台**（`/admin`）：用户、待批申请、授权、会话（退出其他设备 / 强制下线）、OAuth 客户端、审计日志、密码登录总闸、密钥轮换说明。界面有英文与简体中文
- 加固过的 HTTP 层：`__Host-` cookie、跨源写拦截、无内联脚本的 CSP、限速、按账号锁定（见[安全说明](#安全说明)）

## 架构

```
                         auth.example.com
                         ┌──────────────────────────────┐
  Google / Microsoft ──▶ │ nas-auth                      │
  （上游登录）            │  /.well-known/…  /register    │
                         │  /authorize  /token           │
  MCP 客户端 ──────────▶ │  /revoke  /introspect         │
  （PKCE + DCR）          │  /userinfo  /logout           │
                         │  /account  /admin             │
  Web 应用（OIDC）─────▶ │  /proxy/{aud}/…               │
                         │  SQLite + RSA 钥（/app/data） │
                         └──────────────┬───────────────┘
                                        │ RS256 JWT (aud=<resource>, typ=at+jwt)
                                        ▼
               obsidian-mcp / gitea-mcp / Gitea / Immich / Grafana / …
               （各自经 JWKS 验签名 + iss + aud + exp + scope）
```

## 端点

| 端点 | 用途 |
|---|---|
| `/.well-known/oauth-authorization-server` | RFC 8414 元数据 |
| `/.well-known/openid-configuration` | OIDC discovery |
| `/.well-known/jwks.json` | RSA 公钥（current + previous），验 access token 与 id_token |
| `/register` | 动态注册（RFC 7591），有限速 |
| `/authorize` | Authorization Code + PKCE；登录 / 授权确认页 |
| `/token` | code → access + refresh token；refresh rotation；请求了 `openid` 时附带 `id_token` |
| `/revoke` | RFC 7009 token 吊销 |
| `/introspect` | RFC 7662 token introspection |
| `/userinfo` | OIDC UserInfo（`sub`、`email`、`name`、`preferred_username`） |
| `/logout` | 退出；OIDC RP-Initiated Logout（`post_logout_redirect_uri`、`state`、`client_id`） |
| `/login` | 登录页（密码和 / 或 Google / Microsoft） |
| `/external/{provider}/start` | 发起 Google / Microsoft 登录（回调：`/signin/google`、`/signin/microsoft`） |
| `/account` | 所有用户的个人中心：已授权应用、账号绑定、密码、会话 |
| `/admin` | 管理后台（非管理员一律 404） |
| `/proxy/{aud}/…` | 带 `proxy` 配置的资源的换 token 反代 |
| `/proxy/{aud}/.well-known/oauth-protected-resource` | 反代资源的 RFC 9728 元数据 |
| `/healthz` | 健康检查 |

## 快速开始（Docker Compose）

```yaml
# docker-compose.yml
services:
  nas-auth:
    build: .                      # 或者用你自己构建并推送的镜像
    restart: unless-stopped
    ports:
      - "9091:8080"               # 前面要挂一个 HTTPS 反向代理
    volumes:
      - ./data:/app/data          # SQLite、RSA 签名钥、DataProtection 密钥 —— 要备份
      - ./resources.json:/app/resources.json:ro
      - ./clients.preset.json:/app/clients.preset.json:ro
    env_file: .env                # 机密：管理员密码、IdP 凭证、反代上游 token
    environment:
      - Auth__Issuer=https://auth.example.com
      - Auth__Admin__Username=admin
```

```dotenv
# .env（绝不提交）
Auth__Admin__Password=change-me
# 可选：上游登录（回调：https://auth.example.com/signin/google | /signin/microsoft）
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
MS_CLIENT_ID=
MS_CLIENT_SECRET=
# 可选：resources.json 里 "proxy.bearer_env": "EZBK_MCP_TOKEN" 的资源要用的上游 token
EZBK_MCP_TOKEN=
```

1. `cp resources.example.json resources.json`、`cp clients.preset.example.json clients.preset.json`，按下文改好；只留你真正在跑的资源 / 客户端。
2. 让容器里的非 root 用户（`appuser`，见 `Dockerfile`）能写 `./data`（`docker compose run --rm --entrypoint id nas-auth` 可以看它的 uid）。
3. `docker compose up -d`，再经反向代理对外发布 `https://auth.example.com`。会话只在 HTTPS 下有效（见[安全说明](#安全说明)）。
4. 用 `admin` 登录 `https://auth.example.com/login`。
5. 要用 Google / Microsoft 登录：只要配了任一 provider，密码登录就只对勾了「允许密码登录」的用户有效，而启动时引导出来的管理员默认不勾。所以第一次启动先别填 `GOOGLE_*` / `MS_*`，在 `/admin/users` 给 `admin` 勾上「允许密码登录」，再补上 provider 凭证重启；到「个人中心 → 登录与安全」绑定账号，之后可以再把密码登录取消勾选。

## 配置

配置项来自环境变量（双下划线 = 嵌套节）或 `appsettings*.json`。机密只放环境变量。

| 变量 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `Auth__Issuer` | ✅ | `https://auth.example.com`（`appsettings.json`） | 对外的根 URL，即 `iss` claim。为空启动失败 |
| `Auth__Database` | ✅ | `Data Source=/app/data/auth.db` | SQLite 连接串。RSA 钥（`oidc_rs256_*.pem`）与 DataProtection 密钥（`dp-keys/`）放在同一目录 |
| `Auth__ResourcesPath` | ✅ | `/app/resources.json` | 启动时加载，不存在或不合法 → 启动失败 |
| `Auth__ClientsPresetPath` | ❌ | `/app/clients.preset.json` | 预置客户端，启动时 upsert；文件不存在则跳过 |
| `Auth__Admin__Username` | ❌ | `admin` | 管理员用户名（启动时引导，始终 `is_admin`） |
| `Auth__Admin__Password` | ⚠️ | *(空)* | 明文密码，启动时 hash 后丢弃；若同时设置 `PasswordHash` 则以后者为准 |
| `Auth__Admin__PasswordHash` | ⚠️ | *(空)* | 已 hash（argon2id）的字符串，优先于 `Password` |
| `Auth__PasswordLogin__Enabled` | ❌ | `true` | 密码登录总闸。`false` 时登录页不显示密码框、密码端点返回 404；管理员可在 `/admin/system` 运行时覆盖。Google、Microsoft 都没配时强制视为开，免得把自己锁在外面。总闸之上每个用户还有「允许密码登录」开关 |
| `Auth__Dcr__AllowedRedirectHosts__0`、`__1`… | ❌ | *(空)* | 动态注册（`/register`）客户端 `https` 回调地址的主机白名单，`/register` 与 `/authorize` 都校验。精确匹配；以 `.` 开头的条目只匹配子域（`.example.com`）。它与 `AllowedCustomSchemes` 任一非空即进入白名单模式，**两张表同时生效**（另一张空 = 那一类一个都不许）；都空则只校验形态。环回 `http` 始终放行；含非 ASCII（IDN）的地址一律拒。示例：`claude.ai`、`chatgpt.com`、`grok.com` |
| `Auth__Dcr__AllowedCustomSchemes__0`、`__1`… | ❌ | *(空)* | DCR 回调的私有 scheme 白名单（如 `cursor`），精确匹配、忽略大小写，白名单模式下生效。浏览器 / 系统启动器类 scheme（`microsoft-edge`、`googlechrome`、`x-safari-*`、`ms-*`、`search-ms`、`intent` 等）和内嵌另一个 URL 的一律拒，但黑名单列不全，真正的控制是这张白名单 |
| `Jwt__AccessTokenAlgorithm` | ❌ | `RS256` | `RS256`（JWKS，推荐）或 `HS256`（遗留共享密钥）；空值 = `RS256`，其他值启动失败 |
| `Jwt__SigningKey__Current` | ⚠️ | *(空)* | HS256 密钥，≥ 32 字节。仅 `AccessTokenAlgorithm=HS256` 时必填；RS256 模式下可选，**只**用来继续验已签出的 HS256 token |
| `Jwt__SigningKey__Previous` | ❌ | *(空)* | 上一代 HS256 密钥，≥ 32 字节，仅用于校验（HS256 轮换 / RS256 过渡期） |
| `Jwt__LegacyHs256NotAfter` | ⚠️ | *(空)* | RS256 模式下接受遗留 HS256 token 的截止时间（ISO 8601 UTC）。RS256 模式只要配了任一 `Jwt__SigningKey__*` 就**必填**（否则启动失败）；只收 `exp` ≤ 它的 token，过了它一律拒绝。HS256 模式忽略 |
| `Jwt__AccessTokenLifetimeDays` | ❌ | `30` | access token TTL |
| `Jwt__RefreshTokenLifetimeDays` | ❌ | `90` | refresh token TTL |
| `Jwt__AuthCodeLifetimeMinutes` | ❌ | `10` | 授权码 TTL |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | ❌ | *(空)* | Google OAuth 客户端（Web 应用类型），回调 `<issuer>/signin/google`。两个都配了才出现「Continue with Google」，否则该 provider 关闭 |
| `MS_CLIENT_ID` / `MS_CLIENT_SECRET` | ❌ | *(空)* | Microsoft 应用注册，账号类型选**仅个人 Microsoft 账户**（nas-auth 走 `/consumers/` 端点），回调 `<issuer>/signin/microsoft` |
| *`proxy.bearer_env` 指定的变量* | 按资源 | — | 反代资源的上游 bearer token（如 `EZBK_MCP_TOKEN`）；必须非空，否则启动失败 |
| `ASPNETCORE_ENVIRONMENT` | ❌ | `Production` | `Development` 加载 `appsettings.Development.json`（开发用管理员密码、示例资源文件、本地 SQLite） |

⚠️ `Password` / `PasswordHash` 至少给一个；都为空且 SQLite 中也没有该用户 → 启动失败。管理员密码每次启动都按配置重写。

生产环境容器监听 `0.0.0.0:8080`。来自私网与环回地址（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`127.0.0.0/8`、`::1`、`fc00::/7`）的代理的 `X-Forwarded-For` / `X-Forwarded-Proto` 会被逐跳信任，用来找出真实访客 IP 给限速与审计日志用 —— 只通过反向代理对外发布这个服务。

### `resources.json`

启动时一次性加载（不热加载，改了要重启），定义有哪些 audience、各自有哪些 scope。完整示例见 [`resources.example.json`](resources.example.json)。

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

- `resource_url` 是客户端发来的 RFC 8707 资源标识符。配置值加尾斜杠、或其子路径（如 `…/mcp`）也认。
- `proxy`（可选）把这一项变成 `/proxy/{aud}` 资源：`upstream` 只能是 host root（不带路径），`bearer_env` 是存上游 token 的环境变量名。MCP 客户端连 `https://auth.example.com/proxy/<aud>/<上游路径>`。该环境变量没设或为空时启动失败 —— 自带的 `resources.example.json`（`EZBK_MCP_TOKEN`）也一样。
- OIDC Web 应用各自一条资源（scope 为 `openid email profile`），再配一个 `default_resource` 指向它的预置客户端。

### `clients.preset.json`

没法自助注册的客户端（走 OIDC 的 Web 应用，或回调地址固定的 MCP 客户端）。启动时 upsert，永不自动清理。示例见 [`clients.preset.example.json`](clients.preset.example.json)。

| 字段 | 说明 |
|---|---|
| `client_id`、`client_name` | 标识与显示名 |
| `client_secret` | 仅 confidential 客户端；用高熵随机串，应用那边配同一个值 |
| `redirect_uris` | 精确匹配；这里可以用私有 scheme，如 `app.immich:///oauth-callback` |
| `token_endpoint_auth_method` | `none`（public，强制 PKCE）或 `client_secret_post` |
| `default_resource` | 客户端不发 `resource` 时用的资源 URL（大多数 OIDC 应用都不发） |

动态注册的客户端 30 天没用过会被清理（仍持有有效 refresh token 的除外）。

### 用户、审批与授权

- `Auth__Admin__*` 指定的管理员在启动时创建。其他用户由管理员建（本地密码，首次登录强制改密），或在审批外部身份时建。
- 有人第一次用 Google / Microsoft 登录时，身份记为 **pending**，不建会话。管理员在 `/admin/approvals` 批准 —— 绑到已有用户或新建用户 —— 并勾选他能用哪些资源。被拒的身份保持拒绝。
- 已登录用户可以把更多 Google / Microsoft 账号直接绑到自己名下，不用审批。
- `/authorize` 与每次 refresh 都按请求的每个资源、scope 查该用户的授权；撤销授权在下一次 refresh 生效。
- 每个用户可以设邮箱，下游应用（如 Immich）收到的 `email` claim 就是它，用来对上应用自己的账号。没设时用第一条已绑定外部身份的邮箱。

## Token 签名与验签

**RS256（默认）。** access token 与 OIDC id_token 用同一把 RSA 私钥签，header 带 `kid` 与 `typ: at+jwt`（RFC 9068）。claims：`iss`、`sub`、`aud`（单资源为字符串，多资源为数组）、`client_id`、`scope`、`resource`、`iat`、`nbf`、`exp`、`jti`。资源服务器不持有密钥，按下面验：

1. `GET <issuer>/.well-known/openid-configuration`（或 `oauth-authorization-server`）→ `jwks_uri` = `<issuer>/.well-known/jwks.json`
2. 按 `kid` 取 JWKS 里的公钥验签，只允许 `RS256`（绝不用 token header 里的 `jwk` / `jku` / `x5u` 给的钥或地址）
3. 验 `iss` = `Auth__Issuer`、`aud` 含自己的 audience、`exp` / `nbf`
4. **必须**要求 `typ` ∈ {`at+jwt`, `application/at+jwt`}（大小写不敏感）。id_token 也是这把钥签的（`typ: JWT`，`aud` = client_id），而 client 与 resource 可能同名（如 `gitea-web`、`immich`；nas-auth 启动时对每个同名都会打 warning）—— 不查 `typ`，id_token 就能冒充 access token
5. 按操作检查 `scope` claim（空格分隔）

ASP.NET Core JwtBearer 里就是 `Authority = <issuer>` 加常规的 issuer / audience 校验和 `ValidTypes`。[obsidian-mcp](https://github.com/ZhengchenTao/obsidian-mcp) 与 [gitea-mcp](https://github.com/ZhengchenTao/gitea-mcp) 是完整的资源服务器示例（`Jwt__Algorithm=RS256`、`Jwt__Issuer=<issuer>`、`Jwt__Audience=<aud>`）。nas-auth 自己的 `/introspect`、`/userinfo`、`/proxy/{aud}` 收 RS256 token 时只认 `typ: at+jwt`；唯一的另一条路是下面的遗留 HS256，RS256 模式下它受 `Jwt__LegacyHs256NotAfter` 封顶。

**密钥文件与轮换。** `oidc_rs256_current.pem` / `oidc_rs256_previous.pem` 放在 `auth.db` 同目录（首次启动生成，创建时即为 600 权限）。轮换：把 current 改名为 previous（覆盖旧的），重启 nas-auth，自动生成新 current。previous 仍留在 JWKS 里，在途 token 照常能验 —— **至少保留 `Jwt__AccessTokenLifetimeDays` 天**再删或再次轮换。JwtBearer 遇到未知 `kid` 会重新拉 JWKS，资源服务器不用重启。PEM 读不出来会启动失败并点名文件，优先从备份恢复，别直接删。

**HS256（遗留）。** `Jwt__AccessTokenAlgorithm=HS256` 用 `Jwt__SigningKey__Current` 签，这把对称密钥每个资源服务器都得持有 —— 任何一个资源服务器被攻破，就能给所有 audience 伪造 token。只为回滚保留。HS256 模式下 nas-auth 仍接受之前签出的 RS256 access token。

**从 HS256 迁移。** nas-auth 与所有资源服务器**必须在同一窗口切换**：只认一种算法的资源服务器，没切之前会拒 nas-auth 新签的 RS256 token，切了之后会拒客户端手里的旧 HS256 token。两次重启之间请求会 401；MCP 客户端随后用 refresh token（不透明串，不受影响）换到 RS256 token，其他客户端重新授权。

1. nas-auth：`Jwt__AccessTokenAlgorithm=RS256`（默认值），并**去掉** `Jwt__SigningKey__Current` / `Previous`。推荐这样做：旧密钥在每个资源服务器上、可能还在共用 env 文件里都放过，留着它，任何拿到它的人都能伪造 HS256 token 打 `/proxy` 和 `/userinfo`。
2. 各资源服务器：`Jwt__Algorithm=RS256`，删掉共享密钥，按上面要求校验 `typ`。
3. 各处作废旧共享密钥。

如果确实要让 nas-auth 自己的端点再接受一段时间旧 HS256 token：`Jwt__SigningKey__*` **只放在 nas-auth 自己的环境里**（不要放在资源服务器也读的共用 env 文件），并设置 `Jwt__LegacyHs256NotAfter`（必填，例如切换时间 + `Jwt__AccessTokenLifetimeDays`）。只收 `exp` ≤ 该时间的 HS256 token，过了一律拒绝；之后把两项配置都删掉。

## 本地开发

```bash
# 1. 跑起来（Development 配置：admin / devpassword、示例资源与客户端文件、SQLite 与 RSA 钥放 ./data）。
#    resources.example.json 里有一个反代资源，它的 bearer_env 必须有值，随便给个占位值即可：
EZBK_MCP_TOKEN=dev dotnet run --urls http://localhost:5000
#    PowerShell：$env:EZBK_MCP_TOKEN = "dev"; dotnet run --urls http://localhost:5000

# 2. 浏览器访问
#    http://localhost:5000/login         （admin / devpassword）
#    http://localhost:5000/.well-known/oauth-authorization-server
#    http://localhost:5000/account
```

用 Chrome 或 Firefox：会话 cookie 是 `__Host-` / `Secure`，这两个浏览器在 `http://localhost` 下接受，Safari 不接受。

**拿 JWT 测下游 MCP：** 走一遍 OAuth 流程（MCP Inspector 即可）—— RS256 token 只能用 `oidc_rs256_current.pem` 里的私钥签。下游还在 HS256 模式时，仍可用 `dotnet user-jwts` 或 jwt.io 配同一个 `Jwt:SigningKey:Current` 手搓：

```bash
dotnet user-jwts create \
  --issuer https://auth.example.com \
  --audience obsidian \
  --name admin \
  --claim sub=admin \
  --claim scope="read:obsidian"
```

## 测试

```bash
dotnet test tests/nas-auth.Tests
```

xUnit，约 390 个用例，不依赖外部服务（每个用例用临时 SQLite 库）。覆盖：

- **协议**：PKCE、DCR 注册规则与限速、回调地址策略、多资源（多 `aud`）token、refresh rotation、RS256 / 遗留 HS256 的签发与验签（含 `typ` 与算法混淆）、OIDC 密钥与 id_token、RP-Initiated Logout 回跳校验
- **账号**：外部登录状态机与审批、身份绑定、按用户授权、按用户的密码开关与锁定、会话作废、审计日志、管理员引导与老库升级
- **HTTP 层**：进程内集成测试（`WebApplicationFactory`）跑真实管线 —— 跨源写拦截、安全响应头、`__Host-` cookie、回跳地址校验、提示文案防伪造、资源反代，以及完整的 `/authorize` → `/token` → `/userinfo` 流程
- **页面**：模板契约（表单字段名、仅管理员可见的菜单），以及页面里不得出现内联脚本 / 事件属性的守卫

## Docker 与 CI

```bash
docker build -t nas-auth:dev .

docker run -p 9091:8080 \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/resources.json:/app/resources.json:ro" \
  -e Auth__Issuer=https://auth.example.com \
  -e Auth__Admin__Password=change-me \
  nas-auth:dev
```

RSA 签名密钥首次启动时生成在 `/app/data` 卷里；这个卷要保留，否则已签出的 token 全部失效。镜像里不会带 `resources.json`、`clients.preset.json`、`.env`、数据库或任何密钥（见 `.dockerignore`）。

仓库内的 `.gitea/workflows/build-image.yml` 是 Gitea Actions 工作流：构建镜像，推成 `<REGISTRY>/<IMAGE_OWNER>/nas-auth:<短 sha>` 与 `:latest`，然后可选地经 SSH 触发重新部署。需要这些仓库 Variables / Secrets：

- `vars.REGISTRY` —— registry 主机名（例如 Gitea Container Registry 的 `git.example.com`）
- `vars.IMAGE_OWNER` —— registry 下的 owner / 命名空间（也是登录用户名）
- `secrets.AIFACELY_REGISTRY_TOKEN` —— registry 推送 token（`write:package`）
- `vars.DEPLOY_SERVICE` —— *（可选）* 以 `deploy <service>` 传给部署主机的服务名；留空则只构建、推送
- `secrets.NAS_CI_SSH_KEY`、`secrets.NAS_SSH_HOST`、`secrets.NAS_SSH_KNOWN_HOSTS` —— 仅配了 `DEPLOY_SERVICE` 时需要：SSH 私钥（在目标机上限定为强制部署命令）、主机、固定的 host key 行

工作流里的 action 引用与构建代理指向作者自己的 CI 环境，fork 后请自行调整。

## 安全说明

2026-09-29 HTTP 层加固后，运维能感知到的行为（细节见 `docs/design/external-auth.md` §十七）：

- **会话 cookie** 叫 `__Host-nas-auth-session` / `__Host-nas-auth-external`：`Secure`、`Path=/`、不带 `Domain`、`HttpOnly`、`SameSite=Lax`，兄弟子域没法覆盖。从旧名 `nas-auth-session` 升级时所有人掉线一次。会话只在 HTTPS 下有效：直连容器的纯 HTTP 端口登录后保不住会话。`http://localhost` 在 Chrome / Firefox 下可用（视作安全上下文），Safari 不行。
- **CSRF**：浏览器发来的 `POST` / `PUT` / `PATCH` / `DELETE` 必须来自 nas-auth 自己的来源（依次看 `Sec-Fetch-Site`、`Origin`、`Referer`；三个头都没有的请求，如 curl，放行），跨源的回 403 纯文本。豁免：`/token`、`/revoke`、`/introspect`、`/register`、`/userinfo`、`/proxy/*`、`/logout`（RP-Initiated Logout 可能是跨站表单 POST）。
- **CSP**：`script-src 'self'`（无内联脚本）、`frame-ancestors 'none'`，另有 `X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: same-origin`。`/proxy/*` 的响应原样透传不加头。auth 子域上**不要开** CDN 的脚本注入类功能（如 Cloudflare Rocket Loader / 自动注入的统计脚本）—— CSP 会把注入的脚本拦掉。
- **缓存**：页面和 `/token` 响应 `Cache-Control: no-store`；`/.well-known/*`（发现文档、JWKS）`public, max-age=300`；静态资源照常缓存。不发 HSTS（TLS 在反代终结，HSTS 在那一层配）。
- **回跳地址**：`return_url` 只收站内路径（可打印 ASCII，不许 `//`、`/\`、控制字符），其余一律回落 `/account`。绑定外部账号是 `POST /external/{provider}/bind`，且每次都弹 IdP 的账号选择器（`prompt=select_account`）。`post_logout_redirect_uri` 必须与某个预置客户端回调地址同源。
- **提示文案**：`/login?notice=` 只认固定 key（`signed_out`）；后台提示经 DataProtection 加密签名、10 分钟过期，手拼的 `?notice=` / `?error=` 文本一律不显示。
- **暴力破解**：`POST /login`、`POST /authorize`、`/token` 每个来源 IP（IPv6 按 /64）每分钟 5 次；`/register` 每 IP 每小时 10 次、全局每小时 200 次；连续 10 次密码错误锁定该账号 15 分钟。

## 已实现 / 不实现

✅ Authorization Code + PKCE / DCR / RFC 8707 资源 / refresh token rotation / revoke / introspect / RS256 access token + JWKS（HS256 遗留模式）/ 最小 OIDC（discovery、id_token、userinfo、RP-Initiated Logout）/ Google 与 Microsoft 登录 + 管理员审批 / 按用户授权 / `/proxy` 换 token 反代 / 个人中心与管理后台 / 审计日志 / argon2id / SQLite / 后台清理 / 限速 / 签名密钥手动轮换。

❌ 长期 PAT、TOTP、通用 OIDC 上游 provider、`resources.json` 热加载、RBAC / 分组（不做）。

设计笔记见 [`docs/design/external-auth.md`](docs/design/external-auth.md)。

## License

MIT
