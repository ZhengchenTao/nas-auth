# 外部认证与多用户设计（Google / Microsoft 上游登录 + Gitea 下游 SSO）

> 状态：✅ 已完成（2026-06-11：P1–P6 全部落地并验收，含无代理设备验 Microsoft）。
> 立场不变：家用 / 自托管规模，够用就好，不滑向 Keycloak。

---

## 一、背景与动机

当前 nas-auth 登录只有单账号（管理员）+ argon2id 密码，存在三个诉求：

1. **登录体验**：`/authorize` 公网可达，密码是唯一通道，既是暴力破解面，输起来也烦。希望点一下 Google 就登录。
2. **准入与授权**：将来家人 / 其他成员要用时，需要"新账号审批"与"这个人能用哪些资源"两层控制，目前完全没有。
3. **Gitea web 登录统一**（本期最高优先级）：Gitea 是日常使用频率最高的服务，希望 web 端走 nas-auth SSO；但**不干掉 Gitea 本地密码**——git over HTTP 的 PAT / 密码链路保持原样，OAuth 只接管 web 登录。

早期设计把 OIDC 和社会化登录列为非目标，本文**正式推翻这两条**，但范围收窄：

- 社会化登录只做 Google（主）+ Microsoft（兜底，Google 不可达的网络下也能直连），不做通用 provider 框架
- OIDC 只做 Gitea 作为 RP 所需的最小子集（discovery + RS256 id_token + JWKS + userinfo），不做完整 OIDC CP

## 二、目标与非目标

### 目标

1. 上游联合登录：Google 为主、Microsoft 兜底，两者绑定到同一个 user（如管理员）
2. 保留密码登录作为永久兜底（IdP 全挂 / 断网内网场景仍能进 `/account`）
3. 新外部账号"先 pending、管理员点批准"的准入流，禁止 auto-provisioning
4. 用户级资源授权：`user_resources` 控制"某用户能访问哪些 aud、最大 scope"
5. nas-auth 作为 IdP 给 Gitea 提供 web SSO（最小 OIDC），Gitea 本地密码 / PAT 不动

### 非目标

- 不做通用 OIDC Provider（只满足 Gitea / 同类 go-oidc RP 的最小要求）
- 不做 RBAC / 组 / 角色，`user_resources` 的 (user, aud, scopes) 粒度封顶
- 不做微信 / Gitee 等其他 IdP
- 不动 MCP 链路：access token 仍是 HS256 JWT，aud / scope / proxy 翻译层全部不变
  - > 2026-09-29 更新：access token 已默认改为 RS256（与 id_token 同一把 RSA 钥、typ=at+jwt、JWKS 验签），HS256 降为遗留 / 过渡模式，见 §7.2 末尾说明。aud / scope / proxy 翻译层仍不变。

## 三、总体架构

```
                    上游身份（认证：你是谁）
   ┌──────────┐  ┌────────────┐  ┌──────────────┐
   │ 密码(兜底) │  │ Google(主) │  │ Microsoft(兜底)│
   └─────┬────┘  └─────┬──────┘  └──────┬───────┘
         └─────────────┼────────────────┘
                       ▼
            external_identities 白名单/审批
                       ▼
                 users (admin, ...)
                       ▼
            user_resources（用户级授权）
                       ▼
        ┌──────────────┴───────────────────┐
        ▼ OAuth2 + RS256 JWT（JWKS 验签）    ▼ 最小 OIDC + RS256 id_token（新增）
   obsidian-mcp / gitea-mcp / ezbk proxy   Gitea web SSO
```

认证（上游三通道）与授权（下游 client/resource/scope）解耦：本期所有改动都在认证侧和"用户级授权"这一新增层，token 签发给 MCP 的链路零改动。

## 四、数据模型

```sql
-- 外部身份绑定 + 审批状态
CREATE TABLE external_identities (
  provider   TEXT NOT NULL,            -- 'google' / 'microsoft'
  subject    TEXT NOT NULL,            -- Google sub / Microsoft oid（绝不用 email 当主键，email 可变可回收）
  user_id    TEXT,                     -- → users.user_id；pending 时为 NULL
  email      TEXT,                     -- 仅展示用
  display_name TEXT,                   -- 仅展示用
  status     TEXT NOT NULL DEFAULT 'pending',  -- pending / active / rejected
  created_at INTEGER NOT NULL,
  approved_at INTEGER,
  PRIMARY KEY (provider, subject)
);

-- 用户级资源授权
CREATE TABLE user_resources (
  user_id TEXT NOT NULL,
  aud     TEXT NOT NULL,               -- resources.json 里的 aud
  scopes  TEXT NOT NULL,               -- 授予的最大 scope，空格分隔
  PRIMARY KEY (user_id, aud)
);
```

- `users` 表加一列 `is_admin INTEGER DEFAULT 0`——这就是全部的权限模型，**不做 RBAC**。admin 能看管理区（用户/审批/资源授权），普通用户只能看自己的已授权应用
- 迁移 seed：管理员置 `is_admin=1`；给**迁移时刻全部既有用户**（不只管理员）插入 user_resources 全量行（每个已注册 aud 的全部 scope）——升级前没有用户级检查，任何既有用户都能授权任何资源，只 seed 管理员会在 P4 上线时悄悄切断其余用户，违反"升级后行为不变"。seed 仅跑一次（settings 标志位），之后管理员手动收窄不被重启覆盖（P1 实现时修正，2026-06-10）

## 五、登录与审批流程

### 5.1 登录页

`/authorize` 登录页从"单密码框"改为三选项：**Continue with Google** / **Continue with Microsoft** / 密码登录（折叠为次要入口）。

### 5.2 外部登录回调逻辑（两个 provider 共用）

```
回调拿到 (provider, subject)
├─ 查 external_identities
│  ├─ status=active  → 取 user_id，建立会话，回到 OAuth 流程（与密码登录成功后路径完全一致）
│  ├─ status=pending → 展示"等待管理员批准"页，不签发任何 token
│  ├─ status=rejected→ 403
│  └─ 不存在        → 插入 status='pending' 行（含 email/display_name 供审批辨认），展示等待页
```

**不变量：禁止 auto-provisioning。** 查不到 active 行就绝不进入 OAuth 后续流程。

### 5.3 自绑定（bootstrap，解决"第一个管理员"）

已登录用户（密码登进 `/account`）→ "绑定外部账号"按钮 → 跳对应 IdP → 回调时**因为存在已登录会话**，直接写入 `(provider, subject, user_id=当前用户, status='active')`，不走审批。管理员用这条路径绑 Google 和 Microsoft 各一次。

> 2026-09-29 安全加固（§十七）：「绑定外部账号」按钮改为 **POST 表单**（`POST /external/{provider}/bind`，GET 返回 405），受跨源写拦截保护；跳 IdP 时带 `prompt=select_account`，每次绑定都弹账号选择器。原先是 GET 链接：任何站点都能把已登录的管理员导航过去，IdP 静默同意后就把浏览器里当前那个 Google / 微软账号绑到管理员头上。

### 5.4 管理后台（`/account` 改造为 admin dashboard 风格）

现有 `/account` 单页升级为管理后台布局（左侧 sidebar + 内容区），纯服务端渲染保持现状（`Pages/HtmlTemplates.cs`），不引入前端框架；样式向通用 admin dashboard 靠（深色 sidebar / 卡片 / 表格 / 状态 badge），一套手写 CSS 即可。

**视觉语言约定（2026-09-29 起）**：页面样式用 **[Basecoat](https://basecoatui.com/) 1.0.2**（shadcn/ui 的纯 CSS 实现，MIT），整包放在 `wwwroot/vendor/basecoat-1.0.2/`，**不走 CDN**（登录页在 OAuth 重定向链路上，CDN 挂了或被墙就登录不了）；自家布局与少量补充写在 `wwwroot/app.css`（Basecoat 的 CDN 版不含 Tailwind 工具类，布局手写）。
- 仍是纯服务端渲染、无构建步骤、不引前端框架；模板在 `Pages/HtmlTemplates.cs`（登录 / 授权 / 改密等单卡片页）、`Pages/DashboardTemplates.cs`（后台）、公共件（资源引用、图标、提示条）在 `Pages/Ui.cs`。
- JS 只有两处，都是本地文件：`wwwroot/theme.js`（跟随系统暗色，Basecoat 认 `<html class="dark">`，放 head 同步加载防闪）；后台的 Basecoat `basecoat.min.js` + `sidebar.min.js`（手机宽度下侧边栏开合）。sidebar 在 HTML 里预置 `data-sidebar-initialized`，JS 没加载时菜单照样可见。
- `app.css` / `theme.js` 的 URL 带内容哈希（`Ui.InitAssets` 启动时算），部署后不会拿旧样式配新 HTML；改了这两个文件要重启进程哈希才变。
- 后台「用户管理」拆成列表 + 单用户编辑页（同日稍后随 §十六 搬到 `/admin/users/edit?user=`），原 `/account/users/resources` 跳转到编辑页；由 `tests/.../TemplateContractTests.cs` 守住授权页、登录页的字段名与三种入口。
- 换掉 Ant Design 约定的原因：约定的出发点是与另一个内部管理面板视觉对齐，该面板已于 2026-09-29 退役；原手写样式偏简陋（后台用户表一行塞五个表单、邮箱框漏了样式、后台没有暗色）。选型对比过 Tabler / Pico / Basecoat，最终选定 Basecoat。

~~**视觉语言统一约定**~~（2026-06 至 2026-09-29，已被上一段取代，原文保留）：手写 CSS 按 **Ant Design 5 的设计 token** 写（与当时另一个 AntD 技术栈的内部管理面板视觉对齐，两个项目看起来一家人）：主色 `#1677ff`、圆角 `6px`、字体栈 `-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Noto Sans', sans-serif`、AntD 风格的间距（8px 基准网格）/ 卡片阴影 / 表格与 Tag/Badge 样式。登录页同样适用。**只是借设计语言，不引入 antd 依赖、不引入 React**——OAuth 登录页在重定向链路上，必须保持轻量无前端框架。

> **2026-09-29 起菜单改为「个人中心 `/account` / 管理后台 `/admin`」两个空间，现行菜单表见 §十六**；下表是拆分前的原设计，保留备查。

| Sidebar 菜单 | 可见性 | 内容 |
|---|---|---|
| 我的授权 | 所有用户 | 现有"已授权应用列表 + 吊销"（搬过来） |
| 账号绑定 | 所有用户 | 绑定/解绑 Google / Microsoft、改密码 |
| 用户管理 | **仅 `is_admin`** | 用户列表、每用户的 user_resources checkbox 编辑 |
| 待批申请 | **仅 `is_admin`** | pending 列表：provider / email / display_name / 申请时间；批准（绑现有用户或新建 user_id + 勾资源）/ 拒绝（status='rejected'，记录保留防刷屏） |
| 客户端 | **仅 `is_admin`** | clients 表只读视图（DCR 注册的 + 预置的） |
| 系统 | **仅 `is_admin`** | JWT 密钥轮换、审计日志尾部查看 |

可见性控制就一条规则：非 admin 请求管理区路由一律 404（不是 403，不暴露存在性）。

### 5.5 /authorize 的用户级授权检查

现有"resource 在 resources.json 里"检查之后追加：

```
user_resources 里 (当前用户, 请求的 aud) 存在
且 请求 scope ⊆ 授予 scopes，否则 403 access_denied
```

## 六、上游 IdP 配置

| | Google | Microsoft |
|---|---|---|
| 控制台 | console.cloud.google.com → OAuth client (Web) | portal.azure.com → App registrations |
| 账号类型 | — | **Personal Microsoft accounts**（或 personal+org） |
| 回调 | `https://auth.example.com/signin/google` | `https://auth.example.com/signin/microsoft` |
| 身份主键 | `sub` claim | `oid`（fallback `sub`） |
| scope | `openid email profile` | `openid email profile` |
| 费用 | 免费 | 免费 |
| Google 被屏蔽的网络直连 | ❌（设备需有代理） | ✅ |

.NET 侧：`AddAuthentication().AddGoogle(...).AddMicrosoftAccount(...)`，secrets 只从环境变量读（`GOOGLE_CLIENT_ID/SECRET`、`MS_CLIENT_ID/SECRET`，例如 compose 的 `env_file`）。

> **验收硬性要求**：用一台**不挂代理**的设备完整走一遍 Microsoft 登录，确保兜底通道不只存在于纸面。

## 七、Gitea 下游 SSO（最小 OIDC）

### 7.1 为什么必须 OIDC 而不是裸 OAuth2

Gitea 自定义认证源走 "OpenID Connect" 类型，底层 go-oidc 要求 discovery 文档 + **RS256** 签名的 id_token。现有 HS256 对称密钥方案对外部 RP 不适用（不能把对称密钥发给 Gitea）。

### 7.2 nas-auth 需新增

| 端点 / 能力 | 说明 |
|---|---|
| `GET /.well-known/openid-configuration` | OIDC discovery（与现有 oauth-authorization-server 并存） |
| RS256 密钥对 | 仅用于签 id_token；持久化到 `/app/data`，access token 仍 HS256 |
| `GET /.well-known/jwks.json` | 发布 RS256 公钥 |
| id_token 签发 | `/token` 在 scope 含 `openid` 时附带；claims：`sub`(user_id) / `email` / `name` / `preferred_username` |
| `GET /userinfo` | 返回同上 claims（Gitea 会调） |
| resources.json 新条目 | `aud=gitea-web`（与 MCP 的 `aud=gitea` 区分），scopes `openid email profile` |
| clients 预置 | `gitea-web` confidential client（client_secret，非 PKCE public） |

> **2026-09-29 更新：access token 也改 RS256。** 上表「仅用于签 id_token，access token 仍 HS256」已过时：
> access token 默认（`Jwt__AccessTokenAlgorithm=RS256`）用同一把 RSA 钥签，header 带 `kid` 与 `typ: at+jwt`（RFC 9068），
> 资源服务器（obsidian-mcp / gitea-mcp，`Jwt__Algorithm=RS256`）从 `jwks_uri` 取公钥验签，不再持有共享对称密钥
> （原方案下任一资源服务器被攻破即可给所有 aud 伪造 token）。RFC 8414 元数据同步补了 `jwks_uri`。
> nas-auth 自验（/introspect、/userinfo、/proxy）收 RS256 token 时只认 `typ=at+jwt`，id_token 不能冒充 access token；
> 另一条路是遗留 HS256：RS256 模式下 `Jwt__SigningKey__*` 若仍配置，只用于验切换前签出的 HS256 token，
> 且必须配 `Jwt__LegacyHs256NotAfter`（没配启动失败；只收 exp ≤ 它的 token，过了一律拒），防拿到旧共享密钥的人自签远期 token。
> 推荐迁移时直接去掉 HS256 密钥（客户端 401 后用 refresh token 换 RS256）；nas-auth 与只认一种算法的资源服务器须同一窗口切换，其间请求 401。
> 资源服务器**必须**校验 `typ` ∈ {at+jwt, application/at+jwt}：client_id 与 resource aud 同名（gitea-web、immich）时 id_token 的 aud 会撞，启动期对同名打 warning。
> 连带影响：`oidc_rs256_previous.pem` 的保留期从 id_token 的 1h 变为 access token 寿命（默认 30 天），见 §九。

### 7.3 Gitea 侧配置

Admin → Identity & Access → Authentication sources → Add → OpenID Connect：

- **Authentication Name: `nas-auth`**（已定，决定回调路径；登录页按钮显示这个名字）
- Auto Discovery URL: `https://auth.example.com/.well-known/openid-configuration`
- Client ID / Secret: 预置的 `gitea-web`
- 回调 URI 由名称推导：`https://git.example.com/user/oauth2/nas-auth/callback`——**必须与 nas-auth 侧 `gitea-web` 预置 client 的 redirect_uri 精确一致**（redirect_uri 是精确匹配不做前缀）
- 账号关联：开启 `ENABLE_AUTO_REGISTRATION=false`（沿用 Gitea 现有本地账号，首次 OIDC 登录时用"关联已有账号"输一次密码完成 link）
- 认证源可用 CLI 配置免去 UI 手点：`docker exec gitea gitea admin auth add-oauth --name nas-auth --provider openidConnect --key gitea-web --secret <secret> --auto-discover-url https://auth.example.com/.well-known/openid-configuration`

### 7.4 密码 / PAT 保持

- Gitea 本地密码不删：git over HTTP、API、紧急 web 登录全部照旧
- gitea-mcp 的 admin PAT 链路不受任何影响
- 效果 = web 登录多一个 "Sign in with nas-auth" 按钮，其余一切不变

## 八、实施阶段

| 阶段 | 内容 | 触点 | 量级 |
|---|---|---|---|
| P1 | `external_identities` / `user_resources` 表 + repository + 既有用户 seed | `Data/`（AuthDb / Models / 新 Repository×2） | 0.5d |
| P2 | Google + Microsoft 登录、回调、pending 流、登录页改造 | `Program.cs`、`Endpoints/AuthorizationEndpoints.cs`、新 `Endpoints/ExternalLoginEndpoints.cs`、`Pages/HtmlTemplates.cs` | 1d |
| P3 | 自绑定 + `/account` 管理后台改造（sidebar 布局 + is_admin 门禁 + 用户/审批/客户端/系统五个管理区） | `Endpoints/AccountEndpoints.cs`、`Pages/HtmlTemplates.cs` | 1.5d |
| P4 | `/authorize` 用户级授权检查 | `AuthorizationEndpoints.cs` | 0.5d |
| P5 | 最小 OIDC：discovery / JWKS / id_token / userinfo + RS256 密钥管理 | `Services/JwtIssuer.cs`、`Endpoints/DiscoveryEndpoints.cs`、新 `OidcEndpoints` | 1–1.5d |
| P6 | Gitea 接入 + 双端验收（含无代理设备验 Microsoft） | Gitea admin 配置 | 0.5d |

P1–P4 与 P5–P6 可独立上线；最想要的 Gitea SSO 依赖 P5–P6，但 P5 不依赖 P2–P4（只要 P1 之后即可做）。

> ✅ 全部阶段已于 2026-06-11 完成并验收（Gitea web 走 nas-auth SSO、Microsoft 无代理通道实测通过）。
> 后补的两个增量（2026-06-11）：
> 1. **refresh 路径的用户级授权检查**（`TokenEndpoints.HandleRefresh`）：P4 原范围只挡 `/authorize`，
>    长寿命 refresh token 会让撤销形同虚设——admin 撤销资源授权后下一次 refresh 即 `invalid_grant`。
> 2. **密码登录运行时开关**（见 §十 修订）。

## 九、安全清单（增量）

- [x] 外部回调严格校验 `state`（防 CSRF）与 redirect 白名单
- [x] 身份匹配只认 `sub`/`oid`，绝不用 email 匹配账号
- [x] pending / rejected 状态下不建立会话、不签发任何 token
- [x] 自绑定必须要求已有活跃会话，且绑定结果页二次展示绑定到了哪个 user
  - > 2026-09-29：自绑定只收 POST（受跨源写拦截保护），并强制 `prompt=select_account`（§十七）。
- [x] RS256 私钥落盘权限 600，且支持与 HS256 同样的 Current/Previous 轮换
  - > 2026-09-29：access token 改 RS256 后，previous 至少保留一个 access token 寿命（默认 30 天）再删或再次轮换（§7.2 末尾）。
- [x] id_token 短寿命（≤1h）；Gitea 会话由 Gitea 自管，不依赖长寿命 id_token
- [x] 审批操作写审计日志（谁批了哪个 provider/subject → 哪个 user_id）
- [x] 管理区路由对非 admin 返回 404（不暴露存在性）；is_admin 判定基于会话内 user_id 实时查库，不进 JWT claim（避免提权后旧 token 失效问题）
- [x] Google/Microsoft client secret 只进部署环境（如 `.env`），不进 git

## 十、密码退役计划（分两期）

- **一期（P1–P3 上线）**：密码登录保持原样——自绑定流程依赖"密码登录后的活跃会话"识别绑定目标，这是 bootstrap 硬依赖
- **二期（管理员绑定 Google + Microsoft 并各自真实登录验证后）**：加配置开关 `Auth__PasswordLogin__Enabled`（默认 true），置 false 后登录页隐藏密码入口、密码 endpoint 返回 404 ✅
- **运行时覆盖（2026-06-11 增量）**：配置开关之上叠一层 settings 表 override（键 `auth.password_login.override`，
  `Services/PasswordLoginGate.cs`）。admin 在 `/account/system`（2026-09-29 起为 `/admin/system`）一键"临时开启 / 停用 / 恢复跟随配置"，
  立即生效不用重启；典型用法是配置常关、临时放一个人走密码通道、用完恢复。
  防锁死兜底：Google/Microsoft 都未配置时强制视为开。生效优先级：防锁死 > override > 配置
- **禁用而非删除**：`password_hash` 留库。break-glass 场景（Google 需代理 + Microsoft 账号被锁/服务故障同时发生）下，在宿主机上改 env 重启容器即恢复密码通道；nas-auth 是 Claude→MCP 全链路的根，必须保留最后一条不依赖任何外部方的进入路径
- 对公网的效果与"干掉"等价：密码暴力破解面消失

## 十一、部署步骤：需要人工完成的事项

以下几步依赖真实账号或人工判断，部署时逐项完成：

- 在 Google Cloud Console / Azure Portal 注册 OAuth 应用，取 client id / secret（需要真实账号 + 2FA），写入部署环境（如 `.env`）
- 在 Gitea 配置 OIDC 认证源（UI 或 `gitea admin auth add-oauth` CLI，见 §7.3）
- 首次用 OIDC 登录 Gitea 时做一次「关联已有账号」（输一次本地密码）
- 用真实 Google / Microsoft 账号走一遍自绑定流程验收；Microsoft 通道用一台不挂代理的设备验证
- 以上都验证通过后，再决定是否把密码登录总闸置为 false（§十 二期）

## 十二、Open Questions
- [x] Immich 是否复用 P5 的最小 OIDC 接入？—— 已接入，见 §十四「Immich 接入」
- [ ] 其他成员账号的 user_resources 默认模板（建议默认全空，批准时手动勾）

## 十三、DCR 客户端多 aud 回退（Grok 等非 RFC 8707 客户端）

### 背景

nas-auth 一个 issuer 后面挂多个资源（obsidian / gitea / ezbookkeeping），每个资源的 token 用 `aud` 绑死（RFC 8707 Resource Indicators）。Claude.ai / Codex 等合规客户端会从 PRM（`/.well-known/oauth-protected-resource`）拿到 `resource` 标识符，在 `/authorize` 带上 `resource=<url>`，nas-auth 据此签**单 aud** token。

**Grok 的 MCP 连接器是普通 OAuth2 客户端**，不实现 RFC 8707：

- `/authorize` **不带 `resource`** 参数；
- 它读的是 AS 元数据 `/.well-known/oauth-authorization-server` 的 `scopes_supported`（= 全部资源 scope 并集），于是**一次性请求所有资源的 scope**（外加 `openid email profile`）；
- 想用**一个 token 通吃**它配的所有 MCP 连接。

旧逻辑下 `/authorize` 因 `resource` 缺失直接 `400 invalid_request: resource is required`，Grok 连不上。

### 取舍

为兼容这类客户端，对 **DCR / auto-registered 的 public client**（且未显式带 resource、无 default_resource）开一条回退：**按请求 scope 反推资源集合，签多 aud token**。

代价：放弃 RFC 8707 的跨资源 audience 隔离 —— 一个 token 对多个资源同时有效，confused-deputy 风险面回来了。收口两条：

1. **只对 auto-registered client 开**（`auto_registered != 0`）；预置 / confidential client（gitea-web SSO 等）仍走严格单 aud。
2. **剔除 OIDC scope**（`openid` / `email` / `profile`）后再反推，避免把 gitea-web SSO 资源拉进 MCP token 的 aud。
3. token 短命（`AccessTokenLifetimeDays`）压缩泄漏窗口。

单租户、资源服务器与客户端由同一个运营者管理，confused-deputy 风险可接受。

### 实现链路（代码位置）

| 环节 | 位置 | 行为 |
|---|---|---|
| 反推资源 | `ResourceCatalog.ResourcesForScopes` | 返回拥有任一请求 scope 的资源（去重保序） |
| `/authorize` 校验 | `AuthorizationEndpoints.ValidateAuthorizeParams` | resource 缺失 + `auto_registered` → 剔除 OIDC scope 后反推 `List<ResourceConfig>`；非 DCR 仍报 `resource is required` |
| consent / 授权 | `AuthorizationEndpoints` POST | scope 校验对**并集**做；逐资源查 `user_resources`，保留被授权的（downscope），全被丢才 403；auth code 的 `resource` 列存**空格拼接的多 resource_url**，`scope` 存 downscope 后并集 |
| 签 token | `JwtIssuer.IssueAccessToken(IReadOnlyList<string> auds, …)` | 多个 `aud` claim → JWT 序列化成数组；单个 → 字符串 |
| `/token` 还原 | `TokenEndpoints.ResolveResources/ResolveAuds` | split auth code / refresh token 的 resource 列 → 逐个 `FindByUrl` → aud 列表；refresh 路径逐资源复查授权（撤一个即 downscope） |
| proxy 校验 | `ProxyEndpoints` | aud 匹配由 `FirstOrDefault()==aud` 改为 `jwt.Audiences.Contains(aud)` |

### 下游 MCP server 无需改动

obsidian-mcp / gitea-mcp 用标准 `TokenValidationParameters { ValidateAudience = true, ValidAudience = <自己的 aud> }`。.NET 的 audience 校验是「token 的 aud 集合**包含**配置值即通过」，数组 aud 天然吃。scope 门禁是 `RequireScope`（存在即放行），并集里的多余 scope 无害。**只有 nas-auth 自带的 ezbk proxy 因为之前用 `FirstOrDefault` 才需要改成 `Contains`。**

## 十四、统一账号中心：按用户的密码登录、用户邮箱、按账号锁定（2026-09-29）

### 背景

Immich 自身没有登录失败锁定，把它的登录统一收到 IdP 上，锁定与限速就一并由 nas-auth 负责。要让 Immich 走 nas-auth 登录，需要解决三件事：

1. 密码登录是**全局开关**（§十），常见做法是关闭。要给某个人开密码（只用密码的账号、没有 Google / 微软账号的家人），就得连管理员一起开
2. `users` 表没有邮箱。id_token / userinfo 的 `email` 取第一条外部身份（google 优先）→ 同时绑了 Google 与微软的用户下发的是 Google 那条邮箱，它可能恰好是 Immich 里另一个账号的邮箱；Immich 按邮箱关联已有账号，会关联错
3. 纯本地密码用户没有外部身份，也就没有 `email` 可发

### 设计

| 项 | 做法 |
|---|---|
| 按用户的密码登录 | `users.allow_password_login`（默认 0）。生效 = 总闸（§十 的配置 / 运行时 override，含义不变）**且** 用户开关。防锁死兜底（没配任何外部 provider）优先于两者：所有人放行。管理员新建本地用户默认勾上；审批外部身份建出来的用户不勾（密码本来就不可用） |
| 判定点 | `Services/PasswordSignIn`：`POST /login` 与 `POST /authorize` 密码分支共用。不允许密码的用户即使密码正确也回「用户名或密码错误」，并计入失败次数 —— 不暴露「密码其实是对的」；用户不存在时也空跑一次 argon2，不靠响应时间枚举用户名 |
| 按账号锁定 | `users.failed_login_count` / `locked_until`：连续 10 次失败锁 15 分钟，成功清零。锁定期间单独提示（否则正常用户以为自己一直输错）。与按 IP 的 `auth-sensitive` 限速互补：限速挡单一来源的高频，锁定挡分布式慢速撞库 |
| 用户邮箱 | `users.email`（存小写）。`OidcEndpoints.ResolveProfile` 优先它，没设才退回外部身份。管理后台「用户管理」可编辑 |
| 真实访客 IP | `ForwardedHeaders` 信任私网段、`ForwardLimit = null`，从右往左剥掉私网里的反向代理 / 隧道，取第一个公网地址。此前默认只剥一跳，拿到的是上一层代理的私网地址：所有外网访客共用一个限速桶，审计日志也看不到真实 IP |
| 会话密钥持久化 | DataProtection 密钥落 `auth.db` 同目录的 `dp-keys/`。此前在容器内 `/app/.aspnet`，每次 CI 部署重建容器即丢，30 天滑动会话全员作废。**不要 `SetApplicationName`**：会改变 purpose 鉴别串，已发出的 cookie 全部失效 |

**不做**：强制每次重新选账号。授权页本来就不自动放行，每次都列出「以 xx 授权 / Google / 微软 / 密码」，同一浏览器切换账号不会串号。

> 2026-09-29 补注：上面这条只针对**登录**（`/external/{provider}/start`）。**自绑定**（§5.3）例外：绑定会把外部身份直接写成 active，所以跳 IdP 时一律带 `prompt=select_account`，见 §十七。

### 迁移

- 老库启动时 `ALTER TABLE users ADD COLUMN` 四列，全员 `allow_password_login = 0` —— 与升级前「总闸关」的实际行为一致
- 首次部署前把容器里现有的 DataProtection 密钥拷到数据卷 `dp-keys/`（属主 = 容器用户），新容器读同一把钥匙，现有会话不失效

### Break-glass

管理员的密码仍在库（每次启动由 `Auth__Admin__Password` 重写）。Google / 微软同时不可用时：在宿主机上对 `auth.db` 执行 `UPDATE users SET allow_password_login = 1 WHERE user_id = '<管理员>'`，且总闸开着（配置或 `/admin/system` override）即可密码登录。

### Immich 接入

- `resources.json`：`aud = immich`，scopes `openid email profile`
- `clients.preset.json`：`immich`，confidential、`client_secret_post`，`default_resource` 指 immich 资源；redirect 登记 web 的 `/auth/login`、`/user-settings`（有多个入口域名 / 端口就各登记一套）与手机 App 的 `app.immich:///oauth-callback`
- Immich 按 `email` 关联已有账号：每个用户的 `users.email` 设成他在 Immich 里的账号邮箱。Immich 不开自动注册

## 十五、RP-Initiated Logout（2026-09-29）

### 背景

2026-09-29 review 查出：nas-auth 会话 30 天滑动，而所有下游（Immich / Gitea / Grafana / 内部应用）退出时都只清自己的会话。在别人电脑上登过一次，退出应用后 nas-auth 还登着，下一个人点「用 nas-auth 登录」看到的是「以管理员身份授权」—— 一键进管理员账号，同一会话还能进其他下游应用。根子在 nas-auth：发现文档没有 `end_session_endpoint`，`/logout` 也不接受回跳地址，下游想联动也无处可跳。

### 做法

- 发现文档加 `end_session_endpoint = {issuer}/logout`
- `/logout` 收 GET / POST，参数 `post_logout_redirect_uri`、`state`、`client_id`、`id_token_hint`（接受但不用）。清会话后，回跳地址校验通过就带上 `state` 跳回去，否则落到登录页（原行为）
- 回跳地址校验（`Services/EndSession`，防开放跳转）：只认绝对 http/https、不带 userinfo；scheme + host + port 必须等于某个**预置**客户端（`auto_registered = 0`）登记过的 redirect_uri 的来源；带 `client_id` 时只在该客户端里找。DCR 自助注册的客户端不算（任何人都能 DCR 注册 evil.example 的回调）

### 下游

| 应用 | 情况 |
|---|---|
| Immich | 自动读发现文档的 `end_session_endpoint`，退出时带 `id_token_hint` 跳过来（Immich `AuthService.getLogoutEndpoint`），不需配置 |
| 内部 ASP.NET Core 应用（OpenIdConnect handler） | 退出改为同时 `SignOut` OIDC scheme：ASP.NET 自动跳 end_session_endpoint，回跳 `/signout-callback-oidc` |
| Grafana | client `grafana`，aud `grafana-web`：generic OAuth，按 `preferred_username` 对上本地管理员账号、不自动注册；`GF_AUTH_SIGNOUT_REDIRECT_URL` 指 `/logout?client_id=grafana&post_logout_redirect_uri=…/login` |
| Gitea | < 1.27.1 按账号的 LoginType 决定是否走 RP-initiated logout；≥ 1.27.1 改按会话的登录方式判断，但拼退出地址仍用**账号的** `LoginSource` 找认证源，所以需要联动 RP-initiated logout 的账号，要把认证源设成本 IdP（密码登录不受影响：OAuth2 源的密码校验回落本地库）。退出地址形如 `/logout?client_id=gitea-web&post_logout_redirect_uri=https://git.example.com/` |

## 十六、个人中心 / 管理后台拆分、会话作废、审计入库（2026-09-29）

### 背景

Basecoat 改版（§5.4）上线后，反馈指出「管理 nas-auth 和管理自己的混在一起」。盘下来是结构问题加三处功能缺口：

1. 个人页和管理页共用一条菜单，只靠两个小标题区分；管理员登录后落在个人的「我的授权」
2. 管理员只能吊销自己的授权；要切断别人的 Claude / Grok 授权只能删人。别人的外部身份看不到、解不了绑
3. 登录 cookie 是 30 天滑动的自包含票据，服务端没有作废手段 —— 在别人电脑上忘了退出，只能等它过期（§十五 隐患的另一半）
4. 审计只在容器 stdout，后台看不到谁什么时候从哪登录；普通用户看不到自己开通了哪些应用

### 结构

两个空间，各一套菜单；管理员在侧边栏顶部切换（非管理员的 HTML 里不出现任何 `/admin` 链接）：

| 空间 | 菜单 | 内容 |
|---|---|---|
| 个人中心 `/account`（所有人） | 概览 | 用户名 / 邮箱 / 角色 / 登录方式 / 最近一次登录；我能用的应用（`user_resources`） |
| | 已授权应用 `/account/grants` | 原「我的授权」 |
| | 登录与安全 `/account/security` | 外部账号绑定、改密码（只对能用密码登录的人显示）、退出其他所有设备、最近登录（含失败） |
| 管理后台 `/admin`（仅 `is_admin`） | 概览 | 用户 / 待批 / 活跃授权 / 客户端 / 24 小时登录（失败标红）+ 最近事件 |
| | 用户 `/admin/users` | 列表 + 新建；编辑页：资料、资源授权、外部身份（可解绑）、已授权应用（可逐条 / 全部吊销）、登录与会话（最近登录 + 强制下线）、重置密码、删除 |
| | 待批申请 `/admin/approvals` | 不变 |
| | 应用与资源 `/admin/apps` | resources.json 资源（接入方式、开通用户数、活跃授权数）+ OAuth 客户端（活跃授权数；DCR 客户端可手动删，连带其 refresh token 与授权码；预置客户端不可删） |
| | 审计日志 `/admin/audit` | 按事件类型 / 用户 / 只看失败筛选，最近 300 条 |
| | 系统 `/admin/system` | 密码登录总闸、JWT 密钥轮换 |

- `/admin` 整组一个端点过滤器：非 `is_admin` 一律 404（规则同 §5.4，由组级过滤器实时查库执行，handler 不再各自判断）
- 管理员登录后没指定去处（默认 `/account`）时落到 `/admin`；指定了（如 OAuth 授权页）照旧
- 旧地址：`/account/bindings` → `/account/security`；`/account/users` / `users/edit` / `users/resources` / `approvals` / `clients` / `system` 对管理员 302 到 `/admin` 对应页（保留 query），对其他人仍 404。旧的管理区 POST 路由已删除

### 会话作废（session_version）

- `users.session_version`（默认 0）。登录时票据带 claim `nas_sv` = 当前版本；cookie 验证环节（`OnValidatePrincipal` → `Services/SessionValidator`）每个请求比对，对不上或用户已删就作废并清 cookie
- 版本 +1 的场景：个人「退出其他所有设备」、自助改密、强制改密完成、管理员重置密码、管理员强制下线。前三者随即给当前浏览器换发新票据，所以自己不掉线
- **升级兼容**：老票据没有 `nas_sv`，按 0 算，与所有人的初始版本一致 —— 部署后没人掉线（本地实测：升级前的 cookie 直接进了新后台）
- 只管 nas-auth 自己的登录会话。已发给应用的 access / refresh token 不受影响，要断开另外吊销（页面文案里都写明了）
- 代价：每个已登录请求多一次按主键查 `users`（SQLite，家用量级可忽略）

### 审计入库

- 新表 `audit_log(id, ts, event, success, user_id, client_id, ip, detail)`，`AuditLogger` 在原有 stdout 日志之外同步写入；写库失败只记警告，不影响请求
- 入库事件：`login` / `external_login` / `authorize` / `token` / `revoke` / `register` / `proxy.deny` / `account.<动作>`。**高频的 `proxy.fwd` 与 `introspect` 只打日志不入库**
- 保留 90 天，`TokenCleanupService` 每小时清理。detail 只放 k=v 形式的 client / resource / scope / reason 之类，绝不放 token（该约束不变）
- 账号操作没有显式 IP 的，从 `IHttpContextAccessor` 取当前请求 IP（经 ForwardedHeaders 后即真实访客 IP，§十四）

### 测试

`tests/.../AdminConsoleTests.cs`：会话版本（老票据兼容、+1 后旧票据全失效、删人即失效、老库补列）、审计的写入 / 筛选 / 清理、按用户全部吊销、DCR 客户端删除连带且不动预置、管理员落点；`TemplateContractTests` 补了非管理员看不到 `/admin`、两个空间菜单不混、代管吊销表单带目标 user_id。

## 十七、HTTP 层安全加固（2026-09-29）

### 背景

2026-09-29 安全 review 查出几处 HTTP 层的缺口，共同前提是：**如果 IdP 与其他应用（Gitea / Immich / Grafana 等）共用同一个可注册域、挂在兄弟子域上**，对浏览器来说这些子域与 auth 是 same-site，`SameSite=Lax` 挡不住它们发起的请求，也挡不住它们往 `.<domain>` 上种 cookie。任何一个兄弟子域被 XSS 或接管，就能借已登录用户的会话在 nas-auth 上做事。

1. 全站没有 antiforgery token：兄弟子域可以替已登录用户 `POST /authorize`（`use_session=1`，一键把授权码发给自己 DCR 注册的回调）、改密码、在 `/admin` 下建用户
2. `POST /login` 的 `return_url` 不校验：`/login?return_url=https://evil` 在真登录成功后把人送出站（开放跳转）；外部登录那条的校验漏了控制字符（浏览器会剥掉 TAB / CR / LF，`/\t/evil.com` 到地址栏就是 `//evil.com`）
3. 自绑定是 GET（见 §5.3 补注）
4. 没有任何安全响应头：consent 页能被 iframe 嵌入做点击劫持
5. `/login?notice=`、`/account?notice=` / `?error=` 原样回显任意文本：能在可信页面上印钓鱼文案

### 会话 cookie：`__Host-` 前缀

| 项 | 做法 |
|---|---|
| 名字 | `__Host-nas-auth-session`（主会话）、`__Host-nas-auth-external`（IdP 回调临时 cookie）。原名 `nas-auth-session` / `nas-auth-external` |
| 属性 | `Secure`（`SecurePolicy = Always`）、`Path=/`、不带 `Domain`、`HttpOnly`、`SameSite=Lax`。`__Host-` 前缀由浏览器强制前三条，兄弟子域没法种同名 cookie 顶替会话（cookie tossing） |
| 未登录跳转 | cookie handler 的 `ReturnUrlParameter` 改成 `return_url`（默认是 `ReturnUrl`，与 `/login` 读的对不上，深链登录后会丢） |
| 语言 cookie | `nas_auth_lang` 在 https 请求下带 `Secure` |

- ⚠️ **改名那次部署所有人掉线一次**（旧名不再被读取），之后正常。DataProtection 密钥不变（§十四），与 cookie 名无关
- ⚠️ **纯 HTTP 入口再也拿不到会话**：`Secure` cookie 只在 https 下回传。经反向代理的 https 入口不受影响；如果有人直连容器的 http 端口（例如 `http://<host>:<port>`），登录后 cookie 不回传，表现为登录成功又被踢回登录页
- 本地开发：Chrome / Firefox 把 `http://localhost` 当安全上下文，照常可用；Safari 不接受，本地调试用 Chrome / Firefox

### 跨源写拦截（CSRF）：`Services/CrossOriginGuard`

不逐个表单加 antiforgery token，而是一个中间件（排在 `UseForwardedHeaders` 之后）按浏览器自带的来源头统一判：

- 对象：POST / PUT / PATCH / DELETE。**默认全拦、按清单豁免**（以后新加的 cookie 端点不用记着登记）
- 豁免：`/token` `/revoke` `/introspect` `/register` `/userinfo`（客户端凭证 / Bearer，不认 cookie）、`/proxy/*`（MCP 流量）、`/logout`（RP-Initiated Logout 就是跨站表单 POST，§十五；登出型 CSRF 无害）。`/signin/*`（IdP 回调）**不豁免**：Google / MicrosoftAccount handler 现在都是 GET 回调，哪天改 `form_post` 再按精确路径加回来
- 判定顺序：
  1. 有 `Sec-Fetch-Site`：只认 `same-origin` / `none`（`same-site` 也拒 —— 兄弟子域正是要挡的对象）
  2. 否则有 `Origin`：只认请求自己的来源（`scheme://host[:port]`，经 ForwardedHeaders 还原）或 `Auth:Issuer` 的来源；`Origin: null` 拒绝
  3. 否则有 `Referer`：来源不是本站 / Issuer 就拒（解析不了也拒）
  4. 三个头都没有：放行（curl、服务端客户端）
- 拒绝：403 纯文本 + `nas-auth.csrf` 警告日志（method / path / 原因 / IP）。**不进审计表**，免得被人伪造请求头刷库

### 安全响应头：`Services/SecurityHeaders`

排在管线最前面（静态文件、403、429、重定向都带上）；`/proxy/*` 整段跳过（那是 YARP 流式转发的上游 MCP 响应）。

| 头 | 值 / 说明 |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`。页面交互已全部改为 `data-*` + `theme.js` 事件委托，没有内联脚本（`NoInlineScriptTests` 兜底）。**不加 `form-action`**：Chrome 会把它套到表单提交后的 302 上，consent 之后跳回客户端 `redirect_uri` 那一跳会被拦，OAuth 流程直接断 |
| `X-Frame-Options` | `DENY`（与 `frame-ancestors 'none'` 一起防点击劫持） |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `same-origin`，**不是 `no-referrer`**：按 Fetch 规范，页面策略为 no-referrer 时浏览器给同源表单 POST 发 `Origin: null`，没有 `Sec-Fetch-Site` 的旧浏览器（Safari < 16.4）会被上面的跨源拦截误拒。对外站同样一个字节的 referrer 都不发 |
| `Cache-Control` | 命中端点的响应（页面、重定向、`/token` 的 JSON，RFC 6749 §5.1）：`no-store` + `Pragma: no-cache`；`/.well-known/*`（发现文档、JWKS）：`public, max-age=300`，轮换密钥后 RP 最多 5 分钟看到新 JWKS（previous 本来就并存一段）；wwwroot 静态文件不加，继续按哈希 URL 缓存 |
| HSTS | 不发：TLS 在前置反向代理 / CDN 终结，HSTS 由那一层决定 |

- ⚠️ **CDN 侧（例如 Cloudflare）**：Rocket Loader、Web Analytics / Zaraz 这类「自动往 HTML 里注入脚本」的功能会被 `script-src 'self'` 拦掉（浏览器控制台报 CSP 违规；Rocket Loader 还会把页面自己的脚本改写成它的加载器，导致 `theme.js` 不执行）。auth 子域上保持关闭；要开就得同步放宽 CSP

### 回跳地址校验：`Services/ReturnUrl`

- `IsLocalUrl` 照抄 ASP.NET Core `UrlHelper.IsLocalUrl`：只放行 `/x` 与 `~/x`，拒绝空串、绝对 URL、`//x`、`/\x`、**任何位置**的控制字符；比框架多一条：只收可打印 ASCII（0x20–0x7E）—— 非 ASCII（中文、U+2028 等）进 `Location` 头时 Kestrel 抛异常，而 `POST /login` 那时已经写了会话 cookie，用户看到的是登录成功后的 500
- `SafeLocal(url, fallback = "/account")` 用在所有用户可控的回跳点：`GET /login`（隐藏字段不回显外站地址）、`POST /login`、`LandingFor`、`/external/{provider}/start`、`/external/complete`。带 query 的站内地址（consent 的 `/authorize?...`）照旧往返
- `/logout` 的 `post_logout_redirect_uri` 仍按 §十五 的预置客户端来源校验，不走这里

### 自绑定：POST + `prompt=select_account`

见 §5.3 补注。`/account/security` 的两个绑定按钮改成小表单；challenge 时 `AuthenticationProperties.SetParameter("prompt", "select_account")`，Google / MicrosoftAccount handler 都从 Parameters 取它拼进授权 URL。登录（`/start`）不强制选账号（§十四「不做」那条仍成立）。

### 页面提示文案防伪造

- `/login?notice=` 只认固定 key：目前只有 `signed_out`（`/logout` 落到登录页时带），文案按当前语言渲染；未知 key 什么都不显示
- `/account/*`、`/admin/*` 的 `notice` / `error` / `rotated`（`DashboardSupport.RedirectTo` → `Render` / `ReadFlash`）：文案里有动态部分（「已吊销 N 个」「已创建用户 X」），用不了 key 表，改为 **DataProtection 加密签名**的 query 值 —— purpose 绑定当前登录用户、10 分钟过期，密钥就是会话 cookie 那套（`dp-keys/`）。明文、被篡改、过期、换了用户的一律不显示

### 测试

- `HttpSecurityTests`：`ReturnUrl` 正反例（含 `/\t/evil.com`、非 ASCII、U+2028）、跨源拦截判定矩阵、安全头中间件
- `HttpPipelineTests`：`WebApplicationFactory<Program>` 起真实管线（临时目录 SQLite、`resources.example.json`、假的外部 provider 凭证），覆盖真实端点上的 403 矩阵与豁免、`POST /login` 带外站 / 非 ASCII `return_url` 落回站内、深链 `return_url`、`/login` notice 只认 key、后台 flash 防伪造、安全头（`/login` 有、`/proxy` 没有、`/.well-known` 可缓存）、`__Host-` cookie 属性、绑定仅 POST 且带 `prompt=select_account`；与 RS256（§7.2）合并后补了：RS256 模式下 `POST /admin/rotate-jwt-key` 经加密 flash 回显说明、真实 `/authorize` + `/token` 拿到的 RS256 access token 能用 `/userinfo`、id_token 被拒
