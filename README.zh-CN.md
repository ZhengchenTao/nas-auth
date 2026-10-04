# nas-auth

[English](README.md) | 简体中文

一个给家用服务器用的小型 OAuth 2.1 / OpenID Connect 服务。起因是想让 Claude、ChatGPT 这些客户端通过正规的 OAuth 流程访问我自己写的几个 MCP 服务，而一家人用 Keycloak 实在太重。后来 Gitea、Immich、Grafana 这些自建应用的登录也交给了它。

整个服务就是一个 .NET 10 进程加一个 SQLite 文件，页面在服务端渲染，没有前端构建，也不从 CDN 加载任何东西。

## 三个仓怎么配合

- [nas-auth](https://github.com/ZhengchenTao/nas-auth)：授权服务，负责登录和签发 token。
- [obsidian-mcp](https://github.com/ZhengchenTao/obsidian-mcp)：Obsidian 笔记库的 MCP 服务（可读写）。
- [gitea-mcp](https://github.com/ZhengchenTao/gitea-mcp)：Gitea 的 MCP 服务（只读）。

MCP 客户端从 MCP 服务的元数据里找到授权服务，自己注册，让用户登录，拿到一个只对这一个 MCP 服务有效的 token。MCP 服务用 nas-auth 公布的公钥验 token，碰不到密码，也不需要和谁共享密钥。三个仓也可以单独用：两个 MCP 服务能接任何标准的 OAuth 服务，nas-auth 也能给任何会验 JWT 的服务做登录。

## 能做什么

- 授权码 + PKCE（只支持 S256）、refresh token 轮换、动态客户端注册（RFC 7591）、资源指示（RFC 8707）、撤销和内省、受保护资源元数据（RFC 9728）。
- 给网页应用用的最小 OIDC：发现文档、`id_token`、JWKS、`/userinfo`、RP 发起的退出。
- 用 Google 或微软个人账号登录。新的外部账号要管理员批准，不会因为登录一次就自动开户；管理员也可以提前登记对方的邮箱，对方第一次登录就直接绑到指定用户上。本地密码（argon2id）作为兜底，可以关掉。
- 用户 id 和显示用的昵称、头像分开：id 固定不变，下游应用按它认人；昵称和头像可以改，随 `name` / `picture` 下发给应用。
- 按用户授权：哪个用户能用哪个资源、到哪些 scope。
- `/proxy/{aud}`：上游只认一个固定 token 时用。nas-auth 先验自己的 JWT，再换成上游 token 流式转发。
- 每个用户都有 `/account`（已授权应用、昵称与头像、绑定的账号、密码、登录会话），管理员另有 `/admin`（用户、审批、客户端、审计日志）。界面有中英文。

access token 是 RS256 签名的 JWT，`typ: at+jwt`，可以用 `/.well-known/jwks.json` 验证。对称密钥的 HS256 模式还留着，给老部署用。

```
                          auth.example.com
                         ┌────────────────────────────┐
  Google / 微软 ───────▶ │ nas-auth                    │
  MCP 客户端（DCR）────▶ │  /authorize /token /register │
  网页应用（OIDC）─────▶ │  /userinfo /logout /proxy    │
                         │  SQLite + RSA 私钥           │
                         └─────────────┬──────────────┘
                                       │ RS256 JWT，aud = 单个资源
                                       ▼
              obsidian-mcp、gitea-mcp、Gitea、Immich、Grafana …
              （各自用 JWKS 验签名，再查 iss / aud / exp / scope）
```

## 快速开始

```yaml
# docker-compose.yml
services:
  nas-auth:
    build: .                      # 或者用你自己构建的镜像
    restart: unless-stopped
    ports:
      - "9091:8080"               # 前面要有 HTTPS 反代
    volumes:
      - ./data:/app/data          # SQLite、RSA 私钥、cookie 密钥、头像，记得备份
      # 挂目录而不是挂这两个文件：单文件挂载在编辑器或 `mv` 替换文件后，容器里看到的还是旧文件
      - ./config:/app/config:ro
    env_file: .env
    environment:
      - Auth__ResourcesPath=/app/config/resources.json
      - Auth__ClientsPresetPath=/app/config/clients.preset.json
      - Auth__Issuer=https://auth.example.com
      - Auth__Admin__Username=admin
```

```dotenv
# .env（别进 git）
Auth__Admin__Password=change-me
# 可选，回调地址是 <issuer>/signin/google 和 <issuer>/signin/microsoft
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
MS_CLIENT_ID=
MS_CLIENT_SECRET=
# resources.json 里有资源写了 "bearer_env": "EZBK_MCP_TOKEN" 时才需要
EZBK_MCP_TOKEN=
```

1. 把 `resources.example.json` 复制成 `config/resources.json`，`clients.preset.example.json` 复制成 `config/clients.preset.json`，只留自己在用的条目。两个文件都只在启动时读一次，改完要重启。
2. 让容器用户（`appuser`）能写 `./data`，`docker compose run --rm --entrypoint id nas-auth` 可以看它的 uid。
3. `docker compose up -d`，通过 HTTPS 对外。纯 HTTP 下登录会话存不住。
4. 用 `admin` 登录 `https://auth.example.com/login`。

要用 Google 或微软登录，按这个顺序来。一旦配了外部登录，只有勾了「允许密码登录」的用户还能用密码，而管理员默认没勾。所以：先不配 `GOOGLE_*` / `MS_*` 启动，在 `/admin/users` 给 `admin` 勾上「允许密码登录」，再加上凭据重启，到「账号 → 登录与安全」绑定自己的 Google 或微软账号，之后想关密码登录再取消勾选。

## 配置

用环境变量，`__` 表示层级（`Auth__Issuer` 就是 `Auth:Issuer`）。也可以写在 `appsettings*.json` 里，但密钥只放环境变量。

| 变量 | 默认值 | 说明 |
|---|---|---|
| `Auth__Issuer` | – | 对外地址，也是 `iss`。必填。 |
| `Auth__Database` | `Data Source=/app/data/auth.db` | RSA 私钥（`oidc_rs256_*.pem`）、cookie 密钥（`dp-keys/`）和头像（`avatars/`）放在同一个目录。 |
| `Auth__ResourcesPath` | `/app/resources.json` | 必须有，启动时读一次。 |
| `Auth__ClientsPresetPath` | `/app/clients.preset.json` | 可选。 |
| `Auth__Admin__Username` | `admin` | 启动时创建，始终是管理员。 |
| `Auth__Admin__Password` / `__PasswordHash` | – | 首次启动至少给一个，两个都给时以 hash（argon2id）为准。每次启动都会重新写入。 |
| `Auth__PasswordLogin__Enabled` | `true` | 密码登录总开关，`/admin/system` 里也能临时切换。没配 Google / 微软时强制打开，免得把自己锁在外面。 |
| `Auth__Dcr__AllowedRedirectHosts__N` | – | 见下文。 |
| `Auth__Dcr__AllowedCustomSchemes__N` | – | 见下文。 |
| `Jwt__AccessTokenAlgorithm` | `RS256` | `RS256` 或 `HS256`。 |
| `Jwt__AccessTokenLifetimeDays` | `30` | |
| `Jwt__RefreshTokenLifetimeDays` | `90` | |
| `Jwt__AuthCodeLifetimeMinutes` | `10` | |
| `Jwt__SigningKey__Current` / `__Previous` | – | 只有 HS256 用（至少 32 字节），见「遗留的 HS256」。 |
| `Jwt__LegacyHs256NotAfter` | – | 见「遗留的 HS256」。 |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | – | Google 网页客户端，两个都配了才显示按钮。 |
| `MS_CLIENT_ID` / `MS_CLIENT_SECRET` | – | 只支持微软个人账号的应用注册（走 `/consumers/` 端点）。 |
| `proxy.bearer_env` 指定的变量 | – | 代理资源的上游 token，为空时启动失败。 |

**谁能注册。** `/register` 是公开的，MCP 客户端就是靠它接进来。注册时会挡掉明显有问题的回调地址：除本机外不是 HTTPS 的、带 fragment 或用户信息的、含非 ASCII 字符的，以及 `microsoft-edge:` 这类会拉起浏览器或系统程序的 scheme。如果只用固定的几个客户端，把它们列出来，其他一律拒绝：

```
Auth__Dcr__AllowedRedirectHosts__0=claude.ai
Auth__Dcr__AllowedRedirectHosts__1=chatgpt.com
Auth__Dcr__AllowedRedirectHosts__2=grok.com
Auth__Dcr__AllowedRedirectHosts__3=www.cursor.com
Auth__Dcr__AllowedCustomSchemes__0=cursor
```

以 `.` 开头（`.example.com`）只匹配子域。两个列表只要配了一个，就两个都生效；本机回调 `http://localhost:…` 始终放行。之前注册过的客户端在 `/authorize` 时也按同样规则检查。

**反代。** 容器监听 8080，信任来自内网和本机地址的 `X-Forwarded-For` / `X-Forwarded-Proto`，所以只通过反代对外暴露。

### resources.json

定义有哪些资源可以申请。启动时读取，改完要重启。

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

`resource_url` 就是客户端传的 `resource`，末尾多个斜杠或带 `/mcp` 这样的子路径也能匹配上。带 `proxy` 的条目挂在 `/proxy/<aud>/…` 下，`upstream` 只能写到主机。用 OIDC 登录的网页应用，建一个 scope 为 `openid email profile` 的条目，再配一个指向它的预置客户端。`"admin_only": true` 表示这个资源只能授给管理员：资源服务拿你的一把固定凭据访问上游（个人访问令牌、唯一的账本 token）时就该这么标，否则授给别人就等于把你的数据交出去。后台不能把它授给非管理员；就算库里还留着旧的授权行，`/authorize` 和刷新也会拒绝非管理员。

### clients.preset.json

给没法自己注册的客户端用，一般是走 OIDC 的网页应用。启动时写入。

| 字段 | |
|---|---|
| `client_id`、`client_name` | |
| `client_secret` | 只有机密客户端需要，应用那边填同一个值。 |
| `redirect_uris` | 精确匹配，可以用 `app.immich:///oauth-callback` 这类自定义 scheme。 |
| `token_endpoint_auth_method` | `none`（公共客户端，必须 PKCE）或 `client_secret_post`。 |
| `default_resource` | 客户端不传 `resource` 时用它，大多数 OIDC 应用都不传。 |

自己注册的客户端 30 天没用就会被清掉，除非手里还有有效的 refresh token。

### 用户

管理员按配置创建。其他用户有三个来源：

- **批准一次 Google / 微软登录。** 外部账号第一次登录只会生成一条申请，管理员在 `/admin/approvals` 里批准，绑到已有用户或新建用户，同时勾选这个用户能用哪些资源。
- **管理员先建好，等对方来登。** 新建用户时不勾「允许密码登录」，这个用户就没有密码，只能用 Google / 微软登录；同时填上「预绑定登录邮箱」。对方第一次用这个邮箱的账号登录时直接绑到这个用户上，不经过审批。
- **管理员建一个用密码的用户。** 勾「允许密码登录」并设一个密码。默认这就是正式密码；想让对方自己另设，再勾「首次登录必须改密」。重置密码时同样可选。

预绑定只在登录服务商能证明对方拥有这个邮箱时生效：Google 要求 `email_verified`，微软要求登录名就是这个邮箱。对不上就照常生成一条申请。一条预绑定用一次就删除。已登录的用户可以自己再绑定别的 Google / 微软账号。

用户 id 就是下游应用拿到的 `sub` 和 `preferred_username`，建好不能改，删掉的 id 也不能再用：应用按它认账号，同名的新用户会进到旧用户在各应用里的账号。昵称（`name`）和头像（`picture`）与 id 分开，用户在 `/account` 里改，管理员也能替人改；没设过的，取绑定的 Google / 微软账号的名字和头像。头像只收 PNG、JPEG、WebP，不超过 2 MB，通过 `/avatars/<文件名>` 提供，不需要登录，因为下游应用的服务端要来拉。

每次 `/authorize` 和每次刷新都会重新检查授权，所以撤掉授权后，下次刷新就生效。用户在 nas-auth 里的邮箱，就是下游应用在 `email` claim 里看到的值，比如 Immich 靠它找对应账号。

下游应用可以打开自己的 OIDC 自动建号，这样加人只需要在 nas-auth 里做一次。能不能进由这里把关：没批准的外部账号拿不到任何 token，批准了但没授这个资源的用户在 `/authorize` 就被拒。应用自带的注册和密码登录入口要关掉。

## 资源服务怎么验 token

1. 读 `<issuer>/.well-known/openid-configuration`，取 `jwks_uri` 拉公钥。
2. 用 `kid` 对应的公钥验签名。只接受 RS256，不要用 token 头里带的密钥或地址。
3. 检查 `iss`、`aud` 里包含自己、`exp` / `nbf`。
4. 要求 `typ` 是 `at+jwt`（或 `application/at+jwt`）。id_token 用的是同一把钥，而客户端和资源可能重名，不查这一项，id_token 就能冒充 access token。nas-auth 启动时发现客户端 id 和资源 `aud` 重名会打警告。
5. 按操作检查 `scope`。

在 ASP.NET Core 里就是 JwtBearer 配 `Authority = <issuer>`，加上常规的 issuer / audience 检查和 `ValidTypes`。obsidian-mcp 和 gitea-mcp 正是这么做的：`Jwt__Algorithm=RS256`，`Jwt__ValidTypes__0=at+jwt`。

token 里的 claim：`iss`、`sub`、`aud`（字符串；一个 token 覆盖多个资源时是数组）、`client_id`、`scope`、`resource`、`iat`、`nbf`、`exp`、`jti`。

`id_token` 和 `/userinfo` 里是用户信息：`sub` 和 `preferred_username`（都是用户 id）、`email`、`name`（昵称）、`picture`（头像地址）。

**换密钥。** 把 `oidc_rs256_current.pem` 改名成 `oidc_rs256_previous.pem` 后重启，会生成新的。旧钥仍在 JWKS 里，至少留满一个 access token 的有效期（默认 30 天）再换下一次。资源服务会自己拿到新公钥。

**遗留的 HS256。** `Jwt__AccessTokenAlgorithm=HS256` 时用 `Jwt__SigningKey__Current` 签名，每个资源服务都得持有这把钥，只建议用来回滚。从 HS256 换到 RS256 时，nas-auth 和所有资源服务要同时切，共享密钥直接删掉；客户端会遇到一次 401，然后自动刷新。如果 nas-auth 自己还得接受一段时间的旧 HS256 token，那把钥只放在 nas-auth 的环境变量里，并设置 `Jwt__LegacyHs256NotAfter`（UTC 时间）；RS256 模式下配了 HS256 密钥却不设这个，服务会拒绝启动。

## 会感觉到的安全行为

- cookie 叫 `__Host-nas-auth-session` 和 `__Host-nas-auth-external`：Secure、HttpOnly、SameSite=Lax，不带 Domain。只在 HTTPS 下有效（`http://localhost` 在 Chrome、Firefox 里可以，Safari 不行）。
- 其他来源发来的浏览器表单提交一律 403，同一主域下的其他子域也算。`/token`、`/revoke`、`/introspect`、`/register`、`/userinfo`、`/proxy/*`、`/logout` 不受限。
- 页面带 CSP：`script-src 'self'`、`frame-ancestors 'none'`。CDN 往页面里注入脚本的功能（Cloudflare Rocket Loader、网页统计之类）对这个域名关掉，反正会被拦。
- 登录、授权确认和 `/token` 每个 IP 每分钟 5 次（IPv6 按 /64 算）；`/register` 每个 IP 每小时 10 次、全局每小时 200 次；连续输错 10 次密码锁 15 分钟。
- 登录后只会跳转到站内路径；退出后的回跳地址必须是某个预置客户端的来源。

## 端点

| 路径 | |
|---|---|
| `/.well-known/oauth-authorization-server`、`/.well-known/openid-configuration` | 元数据 |
| `/.well-known/jwks.json` | 公钥 |
| `/register` | 动态注册 |
| `/authorize`、`/token` | 授权码流程、刷新 |
| `/revoke`、`/introspect` | RFC 7009 / RFC 7662 |
| `/userinfo`、`/logout` | OIDC |
| `/login`、`/account`、`/admin` | 页面 |
| `/avatars/{file}` | 头像（公开，供下游应用拉取） |
| `/external/{provider}/start` | Google / 微软登录 |
| `/proxy/{aud}/…` | 换 token 的反代（及其 RFC 9728 元数据） |
| `/healthz` | 健康检查 |

## 本地开发

```bash
# Development 配置：admin / devpassword，用示例配置文件，数据在 ./data
EZBK_MCP_TOKEN=dev dotnet run --urls http://localhost:5000
# PowerShell：$env:EZBK_MCP_TOKEN = "dev"; dotnet run --urls http://localhost:5000

dotnet test tests/nas-auth.Tests
```

`EZBK_MCP_TOKEN` 只是因为示例资源里有一个代理条目。用 Chrome 或 Firefox 打开 `http://localhost:5000/login`。要拿 token 测 MCP 服务，就走一遍真实流程，比如用 MCP Inspector。

测试（xUnit，约 430 个）不依赖任何外部服务，覆盖协议细节、账号与审批、页面模板，并用 `WebApplicationFactory` 跑完整的 HTTP 管线。

## 镜像与 CI

```bash
docker build -t nas-auth .
```

镜像里不含配置、数据库和密钥。RSA 私钥在首次启动时生成在 `/app/data` 里，这个卷丢了，已经发出去的 token 就全部失效。

`.gitea/workflows/build-image.yml` 在每次推送到 `main` 时构建并推送 `<REGISTRY>/<IMAGE_OWNER>/nas-auth`，然后可以经 SSH 触发重新部署。用到 `vars.REGISTRY`、`vars.IMAGE_OWNER`、`secrets.AIFACELY_REGISTRY_TOKEN`，部署步骤另外用 `vars.DEPLOY_SERVICE`、`secrets.NAS_CI_SSH_KEY`、`secrets.NAS_SSH_HOST`、`secrets.NAS_SSH_KNOWN_HOSTS`。里面的 action 地址和构建代理是按我自己的 CI 写的，fork 后改成你的。

## 不打算做

长期有效的个人访问令牌、TOTP、任意 OIDC 上游、`resources.json` 热加载、角色和分组。

设计笔记：[docs/design/external-auth.md](docs/design/external-auth.md)。

## 许可

MIT
