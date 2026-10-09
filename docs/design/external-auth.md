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

> 2026-09-30 增补 **`admin_only`**：`resources.json` 条目可标 `"admin_only": true`，只能授给 `is_admin` 用户。
> 针对「资源服务拿管理员的一把固定凭据访问上游、不区分来访者」的资源（gitea-mcp 用管理员 PAT、ezBookkeeping proxy 用管理员账本 token、
> obsidian-mcp 直读管理员 vault）：授给别人 = 把管理员的数据交出去，而原先审批页把它们和 Immich 这类「各进各的账号」的资源并排列着，一勾就授出去了。
> 生效点：审批页不列（审批建的都是非管理员）；用户编辑页对非管理员置灰、服务端写入时丢弃；`/authorize` 与 refresh 对非管理员一律跳过该资源（库里残留的旧授权行也挡）。

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
- ~~账号关联：开启 `ENABLE_AUTO_REGISTRATION=false`（沿用 Gitea 现有本地账号，首次 OIDC 登录时用"关联已有账号"输一次密码完成 link）~~（原设计；现行做法见 §7.5）
- 认证源可用 CLI 配置免去 UI 手点：`docker exec gitea gitea admin auth add-oauth --name nas-auth --provider openidConnect --key gitea-web --secret <secret> --auto-discover-url https://auth.example.com/.well-known/openid-configuration`

### 7.4 密码 / PAT 保持

- Gitea 本地密码不删：git over HTTP、API、紧急 web 登录全部照旧
- gitea-mcp 的 admin PAT 链路不受任何影响
- 效果 = web 登录多一个 "Sign in with nas-auth" 按钮，其余一切不变

### 7.5 账号由 nas-auth 统一管：自动注册 + 「登着就关联」陷阱（2026-09-30）

**目标**：Gitea 账号不再手工建。nas-auth 里批准 / 新建用户并授 `gitea-web`，这个人第一次用 nas-auth 登录 Gitea 时自动建号。

**Gitea 侧配置**（`app.ini` `[oauth2_client]`，或 compose 里 `GITEA__oauth2_client__*`）：

| 项 | 值 | 为什么 |
|---|---|---|
| `ENABLE_AUTO_REGISTRATION` | `true` | 首登自动建号。**`[service] DISABLE_REGISTRATION=true` 挡不住它**（1.27.3 `routers/web/auth/oauth.go` 只判 `!AllowOnlyInternalRegistration && EnableAutoRegistration`），注册页照样关着 |
| `USERNAME` | `preferred_username` | Gitea 用户名 = nas-auth `user_id`（`preferred_username` 与 `sub` 同值），**建了改不了**，审批时起名要想清楚 |
| `ACCOUNT_LINKING` | `disabled` | 用户名 / 邮箱撞上已有账号时直接报错，不按名字或邮箱自动关联（`auto` 会把新身份挂到同名 / 同邮箱的已有账号上） |

自动建出来的账号 `login_type=OAuth2`、`login_source`=本 IdP、`login_name=sub`，天然满足 §十五 退出联动的前提，不用再手工 PATCH 认证源。前提：id_token / userinfo 里要有 `email`（外部身份审批建的用户都有；纯本地用户要在后台填 `users.email`）。

**陷阱（2026-09-30 实测复现）：浏览器里 Gitea 已登录时再走一次 OIDC，新身份会被永久关联到当前登录的账号。**
Gitea 回调里找不到对应用户时，先判 `ctx.Doer != nil` → `LinkAccountToUser(当前用户, 新身份)` → 303 到 `/user/settings/security`，这一支排在自动注册之前，且 `/user/oauth2/{provider}` 两个路由都不要求未登录（这是「设置 → 安全 → 关联账号」用的同一条路）。
复现：Gitea 登着管理员账号，另一个 nas-auth 用户（Gitea 里还没号）走一次登录 → `external_login_user` 多出 `(新 sub → 管理员账号)`，此后这个人每次登录 Gitea 都进管理员账号。
「必须先在 Gitea 建号再授权」就是在绕这个坑：建了号，Gitea 先按 `login_name=sub` 命中本人，走不到关联分支。

**修法**：反代在「发起登录」那一跳（`GET /user/oauth2/<认证源名>`，不含 `/callback`）去掉请求的 `Cookie` 头。Gitea 只能新开匿名会话存 OAuth `state` 并下发新会话 cookie，浏览器里旧的登录会话 cookie 被覆盖，回调时 `ctx.Doer` 为空，走不到关联分支。
代价：Gitea「设置 → 安全」里的关联外部账号失效——账号全由 nas-auth 管后本来就不该再用。「记住我」cookie 只在 `/user/login` 页触发自动登录（`performAutoLogin`），不影响回调。

**盘点**：外链表里每个 OIDC 账号应只有自己的 `sub`：
`select u.name, e.external_id from external_login_user e join user u on u.id = e.user_id where e.external_id <> u.login_name;` 应为空。

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

> **2026-09-30 推翻上一条**：串号不在 nas-auth 这一层，在 IdP 那一层。不带 `prompt` 时 Google / 微软会静默选浏览器里当前登着的账号——实测授权页「或换个账号 → 通过 Google 继续」直接登回了原来那个号，想换的号根本选不到；
> 共用电脑上前一个人退出应用（§十五 联动退出 nas-auth）后，下一个人点「通过 Google 继续」照样被静默登成前一个人。所以 `/external/{provider}/start` 现在一律带 `prompt=select_account`，每次登录多点一下选账号。

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
  - 2026-09-30 起改为**开自动注册**（账号由本 IdP 统一管，同 Gitea §7.5）：准入由审批 + `user_resources` 把关，Immich 自身没有自助注册、密码登录关着；新人首登按 `email` / `name` 建号，所以没有外部身份的纯密码用户必须先填 `users.email`。已有 Immich 账号仍按邮箱关联。

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

## 十八、预绑定邮箱、只走外部登录的用户、user_id 不复用（2026-10-02）

### 背景

账号改由本 IdP 统一管、下游应用首登自动建号（§7.5）之后，暴露三个问题：

1. **想给某人先开好账号、等他以后自己来登**（家人暂时没空操作）：外部身份只能等他登录一次、进待批，管理员再批。管理员得在他登录的那一刻在线。
2. **后台新建用户一律「首次登录必须改密」**，而 `/authorize` 遇到 `must_change_password` 直接拒。只用 Google / 微软的人没有密码可改，建出来就永远登不进下游应用。
3. **user_id 就是下发给应用的 `sub` / `preferred_username`**，Gitea（`login_name`）、Grafana（`user_auth.auth_id`）、Immich（`oauthId`）、ezBookkeeping（`external_username`）都按它认账号。删掉一个人后再建同名用户，新人会直接进旧人在各应用里的账号。

### 做法

| 项 | 做法 |
|---|---|
| 预绑定邮箱 | `external_invites(email PK 小写, user_id, created_at, created_by)`。管理员在用户编辑页「外部身份」卡片登记，或新建用户时填「预绑定 Google 邮箱」。外部登录回调时，身份**首见或仍在待批**、且 `ExternalClaims.IsEmailVerified` 为真、邮箱命中登记 → `BindActive` 绑到登记的用户并建会话（审计 reason `invite_redeemed`），预绑定用 `DELETE … RETURNING` 原子取出即删（一次性，并发登录不会用两次）。已 active（属于谁已定）/ rejected（管理员已表态）的身份不走这条 |
| 什么算「邮箱已验证」 | 判据是**登录服务商能不能证明他拥有这个邮箱**，与域名无关。**Google**：handler 用 `ClaimActions.MapJsonKey("email_verified", "email_verified")` 把 userinfo 的标记映射成 claim（Google 账号可用任意邮箱注册，但要收验证码才标 verified）。**微软**：只接个人账号（`/consumers/` 端点写死；个人账号注册时验证登录邮箱，微软对消费者租户的邮箱视为已验证）。Graph `/me` 没有标记，ASP.NET 的 Email claim 取 `mail ?? userPrincipalName`，另把 `userPrincipalName`（登录名）映射成 `ms_upn`，要求**登录名就是 Email claim**才算已验证（`mail` 与登录名不同、或登录名是手机号的不算）。工作 / 学校账号的 email 可被租户管理员随意设置（2023 nOAuth），它们走不进 `/consumers/`；**以后若改成 `/common/`，这里必须重审**。（同日先做过一版「只认微软自有域名」，用户指出 Google 也能用任意邮箱注册、真正的判据是服务商是否担保，改成现在这样） |
| 只走外部登录的新建用户 | 新建时不勾「允许密码登录」：不要求临时密码，存 `PasswordHasher.UnusableHash()`（随机 32 字节，明文不落任何人之手），`must_change_password = 0`。勾了照旧要临时密码、首次登录改密（**2026-10-04 起改密可选**：新建与重置密码表单各有「首次登录必须改密」开关，默认不勾，管理员设的密码就是正式密码——给家人开的账号不会去改密，强制只添麻烦；不许密码登录的用户该开关无效） |
| user_id 不复用 | `deleted_user_ids(user_id PK COLLATE NOCASE)`：`UserRepository.Delete` 默认登记；后台新建、审批新建都先查 `IsRetiredId`，大小写不敏感。审批失败回滚刚建的空用户时传 `retireId: false`（那个 id 从没对外用过）。本节上线前删掉的 id（2026-09-30 ~ 10-02 的 devtest 系列测试号）没有登记，下游账号都已手工删掉 |
| 删用户 | 连带删其预绑定（同 identities / user_resources） |

### 测试

`PreBoundEmailTests`：已验证邮箱命中 → 直接绑定且预绑定被消耗；未验证 → 待批且预绑定保留；微软永不算已验证；`email_verified` 的 `True` / `true` / `false` / 缺失；先进了待批、后登记预绑定 → 再登录即绑定；rejected 不被预绑定救回；别人的 active 身份不会被挪走；同一邮箱只能登记一次、只能用一次；登记的用户已删 → 回落待批；删过的 id 大小写不敏感地不可复用、审批也拒；审批回滚不占用 id。`HttpPipelineTests` 走真实管线：后台新建纯外部登录用户（不填临时密码、带预绑定邮箱）→ 不强制改密、编辑页能看到预绑定；删除后同名（大小写不同）重建被拒，预绑定随之清掉。

## 十九、昵称与头像（2026-10-02）

### 背景

`name` 原先直接取外部账号的名字，用户没法改；没有头像。用户 id（`sub` / `preferred_username`）是各应用认人的依据，不能改，所以昵称要与它分开。

### 做法

| 项 | 做法 |
|---|---|
| 数据 | `users.display_name`（昵称）、`users.avatar`（头像文件名）；`external_identities.avatar` = 该外部账号最近一次登录时缓存的头像 |
| 下发 | `name` = 昵称 → 第一条 active 外部身份的名字 → user_id；`picture` = `<issuer>/avatars/<文件名>`（userinfo 与 id_token 都带，discovery 的 `claims_supported` 加了 `picture`） |
| 头像存储 | auth.db 同目录 `avatars/`，文件名 = 内容 SHA-256 前 32 位 + 扩展名（内容变地址就变，可长期缓存、天然去重）。只收 PNG / JPEG / WebP，**按文件头判断**，≤ 2 MB；SVG（能带脚本）、GIF 不收。`GET /avatars/{file}` 不要求登录（各应用服务端要拉），`Cache-Control: public, max-age=31536000, immutable`、`nosniff`、`CSP: default-src 'none'; sandbox`，文件名不合规（防路径穿越）一律 404。孤儿文件不清理（量小） |
| 从外部账号取 | Google / 微软 handler 的 `OnCreatingTicket` 里下载对方头像（Google 用 userinfo 的 `picture`，96px 换成 256px；微软用这次登录的 access token 取 Graph `/me/photos/240x240/$value`，没设照片 404 当没有），文件名作为 claim 随外部登录 cookie 带到 `/external/complete`（cookie 有大小上限，不带图片本身）。下载 5 秒超时、任何失败只记日志，不挡登录 |
| 补空 | 每次外部登录都刷新该外部账号的名字 / 头像快照；用户昵称 / 头像为空时用它补（`FillProfileIfEmpty`，只填空的、不覆盖）。首次绑定、自绑定、审批通过（用申请时缓存的快照）都会补 |
| 手动 | 个人中心「昵称与头像」：改昵称、传 / 去头像、「用已绑定账号的头像 / 名字」（取最近一次登录时的快照）；管理后台用户页可替人改（昵称随「基本信息」保存，头像单独上传） |
| 老库回填 | 一次性（settings 标志位）：昵称取第一条 active 外部身份的名字，与升级前下发的 `name` 一致；**没有外部身份的留空**（下发时回落 user_id）——首版填了 user_id，挡住了预建用户首次绑定时取外部账号名，同日改掉 |

### 各应用跟不跟（2026-10-02 实查源码，只靠登录时下发、nas-auth 不持有任何应用的管理员权限）

| 应用 | 昵称 | 头像 |
|---|---|---|
| Grafana 11.2 | 每次登录按 `name` 更新 | 不支持 OAuth 头像 |
| Open WebUI 0.11.4 | `OAUTH_UPDATE_NAME_ON_LOGIN=true` 每次登录更新 | `OAUTH_UPDATE_PICTURE_ON_LOGIN=true` 每次登录更新 |
| Gitea 1.27.3 | OIDC 建号不设全名，同步不了 | `[oauth2_client] UPDATE_AVATAR=true` 每次登录服务端拉 `picture`；**拉取受 `[security] ALLOWED_HOST_LIST` 防 SSRF 白名单管**，默认 `external` 会拒内网解析的 IdP 地址，要加上 IdP 主机名 |
| Immich 3.1 | 只在建号时取 | 只在用户还没有头像时取一次 |
| ezBookkeeping（fork） | 只在建号时取 | 不读 |

### 测试

`ProfileTests`：文件头识别只认位图、存储按内容寻址且拒非图片 / 超大、`PathFor` 拒路径穿越与非存储名、昵称回落顺序与 picture 地址、补空不覆盖用户设过的、快照 null 不冲掉旧值、老库回填只取外部账号名且只跑一次。`HttpPipelineTests`：改昵称 → 传头像 → `/avatars` 的类型与缓存 / 沙箱头 → 个人中心页显示 → 拒 SVG → 真实 `/authorize` + `/token` 拿到的 token 调 `/userinfo` 带新昵称与 `picture`、id_token 也带。

## 二十、客户端认证加 `client_secret_basic`（2026-10-04）

### 背景

`/token` 原先只收表单里的 `client_id` + `client_secret`（`client_secret_post`）。OIDC 规范的默认写法是把它们放在 `Authorization: Basic` 头里（`client_secret_basic`），不少应用只会这一种或默认用它（要接的 Homepage 基于 NextAuth，默认就是 basic）。逐个应用去试哪种能用不划算。

这是**应用后端向本 IdP 证明「我是哪个客户端」**，与用户密码无关：secret 是随机长串，单独拿到也换不出 token，还得有用户刚登录产生的一次性授权码。同一个 secret 现在放表单里就能用，所以加这个写法不增加攻击面。

### 做法

| 项 | 做法 |
|---|---|
| 读取 | `Services/ClientCredentials.cs` 的 `ClientCredentialsReader.Read`：有 `Authorization: Basic` 头就从头里取，否则读表单；别的 scheme（Bearer 等）不理。`/token`（授权码、刷新）、`/revoke`、`/introspect` 四条路径共用 |
| 两种都收 | 带 secret 的客户端不管登记的是 `client_secret_post` 还是 `client_secret_basic`，两种写法都通过——secret 是同一个，按登记区分没有安全收益，还会让换写法的应用白白失败 |
| 表单编码 | RFC 6749 §2.3.1 要求 id 和 secret 先做表单编码再 base64（Go 的 oauth2、openid-client 都这么做），但也有客户端直接塞原文。两种读法都当候选，任一命中即通过；比较仍是定长时间 |
| 一次一种 | 头和表单同时带 secret → `400 invalid_request`；表单里重复 `client_id` 且与头一致放行，不一致同样 400 |
| 失败响应 | 用 Basic 头来认证而失败（含坏 base64、没有冒号、非 UTF-8）→ `401 invalid_client` 并带 `WWW-Authenticate: Basic`（RFC 6749 §5.2）；表单写法失败不带 |
| 公开客户端 | 不变，仍只靠 PKCE；`client_id` 放头里（secret 留空）也认 |
| 宣告 | 两份发现文档的 `token_endpoint_auth_methods_supported` = `client_secret_post`、`client_secret_basic`、`none`（post 仍排第一，对按顺序挑的老客户端行为不变） |
| DCR / 预置 | `/register` 与 `clients.preset.json` 的 `token_endpoint_auth_method` 可写 `client_secret_basic`，同样发 secret |
| 顺序 | 认证失败发生在消费授权码之前：先用错写法试一次（Go 的自动探测就是先 basic 后 post）不会把码烧掉 |

### 风险

发现文档宣告 basic 之后，会按宣告自动选方式的客户端可能从 post 换成 basic。两种都实现了，理论上无感；上线后仍要把已接的应用逐个重新登录一遍确认。

### 测试

`ClientCredentialsTests`：表单 / Basic 头 / 别的 scheme 忽略、scheme 大小写、表单编码与原文两种读法、secret 含冒号、公开客户端空 secret、各种坏头、头与表单同带、两处 `client_id` 不一致。`HttpPipelineTests`：预置 confidential 客户端只用 Basic 头走完换码 → 刷新 → 内省 → 吊销；错 secret / 坏 base64 得 401 且带 `WWW-Authenticate`，头与表单同带、`client_id` 不一致得 400，这些失败之后同一个授权码仍可用正确的 Basic 换到 token；发现文档宣告与 DCR 注册 `client_secret_basic`。

## 二十一、按客户端附加的固定 claim、`email_verified`（2026-10-05）

### 背景

要接的 Dozzle v11.2.0 两种 OIDC 接法都过不了：`oidc` 模式要从 id_token 或 userinfo 里读到角色（`dozzle_roles` / `roles` 等），一个都没有就拒绝登录；`simple` 模式把缺失的 `email_verified` 当 false，同样拒绝。本 IdP 原先只下发 `sub` / `preferred_username` / `email` / `name` / `picture`，没有角色、没有组、没有 `email_verified`。以后要接的应用里还有要 `groups` 的。

### A：按客户端附加固定 claim

| 项 | 做法 |
|---|---|
| 配置 | `clients.preset.json` 的客户端条目里写 `"extra_claims": { "dozzle_roles": ["all"], "tenant": "home" }`。值只能是字符串或字符串数组（各 ≤ 256 字符，数组 ≤ 64 项，一个客户端 ≤ 16 个） |
| 下发 | 对这个客户端签发的 id_token 带上；`/userinfo` 按 access token 里的 `client_id` 找到客户端后也带上。access token 本身不带（那是给资源服务器看的） |
| 数组形状 | 数组一律写成 JSON 数组，只有一项也是数组（多个同名 Claim 只有一项时默认会被序列化成字符串，要 `groups` 是数组的应用会认不出） |
| 保留名 | 协议字段（`iss` `sub` `aud` `exp` `nbf` `iat` `jti` `nonce` `auth_time` `acr` `amr` `azp` `at_hash` `c_hash` `s_hash` `sid` `typ` `cnf` `scope` `client_id` `resource`）和本 IdP 自己下发的身份字段（`email` `email_verified` `name` `preferred_username` `picture`）不许配，大小写不敏感。**撞名或值的形状不对 → 启动即失败**，与 `clients.preset.json` 的其他错误一致，不带着半套配置跑 |
| 存储 | `clients.extra_claims`（JSON 文本），启动时随预置 upsert；从配置里删掉这个字段，下次启动即清空。读库时再过滤一次保留名、`/userinfo` 用 `TryAdd`，手改库也覆盖不了身份字段。DCR 客户端没有这个字段 |
| 局限 | 同一客户端所有用户拿到相同的值，**分不了人**。能不能进这个应用仍由 `user_resources` 把关；这里只解决「应用非要某个 claim 才放行」。以后要按用户区分，在条目里另加一层（如 `extra_claims_by_user`）叠在这上面，不改现有格式 |
| 后台 | 「应用与资源」的客户端列表在名字下标出带了哪些附加字段 |

### B：`email_verified`

id_token 和 `/userinfo` 里只要有 `email` 就带 `email_verified: true`（JSON 布尔）；没有邮箱时这个字段不出现。发现文档 `claims_supported` 同步加上。

**含义是「管理员为这个邮箱担保」，不是「发过验证邮件」。** `email` 的取值是 `users.email`（只有管理员能在后台填，用户自己改不了），为空才回落到已绑定外部身份的邮箱（那个身份要么经管理员审批，要么经预绑定邮箱且服务商证明过归属，§十八）。本 IdP 从不发验证邮件。下游应用如果把它当成「用户本人确认过这个邮箱」，在这套部署里等价于「管理员确认过」。

### 对已接应用的影响（2026-10-05，按线上版本读源码）

字段从缺失变成 `true`，六个应用行为都不变——它们的 OIDC 客户端代码都不读这个字段：

| 应用 | 依据 |
|---|---|
| Gitea 1.27.3 | goth 的 OIDC provider 只定义了常量没使用；找人只按 `sub`；`ACCOUNT_LINKING=disabled` 下不按邮箱关联 |
| Immich 3.1.0 | `auth.service.ts` 的回调全程不看它；按邮箱关联已有账号这件事本来就是无条件的（§十四），改动前后一样 |
| Grafana 11.2.0 | generic OAuth 的用户结构里没有它（只有 Google / GitLab 专用 connector 读）；按邮箱找人只看 `oauth_allow_insecure_email_lookup`（未开） |
| Open WebUI 0.11.4 | 合并只看 `OAUTH_MERGE_ACCOUNTS_BY_EMAIL`（线上 false） |
| ezBookkeeping（fork） | OIDC claims 结构只有用户名、名字、邮箱；按 username 认人 |
| Home Assistant hass-oidc-auth 1.2.1 | 只取 `name` / `preferred_username` / `groups`，按 `sub` 找人 |

没核实的：Gitea 认证源里的 `RequiredClaimName`、Immich 的 `roleClaim` 等自定义项存在各自数据库里，没读；只有把它们配成 `email_verified` 才会受影响。

### 测试

`ExtraClaimsTests`：字符串与字符串数组往返、空配置、保留名（含大小写不同）全拒、数字 / 布尔 / 对象 / 嵌套数组 / 空串 / 坏名字全拒、读库时过滤保留名、id_token 里单项数组仍是数组、`email_verified` 是布尔且只在有邮箱时出现。`HttpPipelineTests`：示例预置的 `gitea-web` 走真实流程，id_token 与 userinfo 都带附加字段和 `email_verified`，清掉邮箱后 userinfo 不再带 `email_verified`，发现文档宣告，后台列表标出附加字段。

## 二十二、forward-auth：给自己不带登录的站点挡门（2026-10-09）

### 背景

本 IdP 原先只能当 OIDC 登录中心：应用自己得会 OIDC 才接得上。静态页面、没有账号体系的小工具接不了，要么放内网，要么在反向代理上挂一个 Basic 认证。目标是让反向代理（Caddy `forward_auth` / nginx `auth_request`）每个请求先来问一句「这个人能不能进」，登录、准入、按人授权全部复用现有的。

替代方案是在每类站点前面加一个 oauth2-proxy 之类的容器，不改本服务。没选它：每多一类站点多一个容器和一份客户端登记，而这里要的只是「登录了且被授权」这一个判断。

### 核心取舍：会话放哪

主会话 cookie 是 `__Host-` 前缀（§十七），只在本服务的域名上，被保护的站点收不到。三种办法：

| | A. 每个站点一张 host-only cookie（采用） | B. 父域上一张 forward-auth 专用 cookie | C. 主会话 cookie 改成父域 |
|---|---|---|---|
| 做法 | 没会话时跳到本服务，查过授权后带一次性票据跳回站点的保留路径，在站点域名上种 `__Host-` cookie | 登录后在 `.example.com` 上种一张只给 forward-auth 用的 cookie | 所有子域共用登录 cookie |
| 兄弟子域能拿到什么 | 拿不到 cookie。但能让访客的浏览器带着 cookie 向站点发请求，verify 另按来源头挡（见下文「别的来源借浏览器发来的请求」） | 这张 cookie，可以重放去进所有被保护的站 | 整个登录会话 |
| 一张 cookie 泄漏的范围 | 一个站 | 该用户被授权的所有站 | 全部，含后台 |
| 代价 | 每站首次访问多两跳；站点要让出 `/.nas-auth/*` | 不能用 `__Host-`，兄弟子域能种假 cookie | 推翻 §十七 |

§十七 的前提是「同一主域下的兄弟子域不可信」，B 和 C 都在往回退，所以选 A。

### 流程

```
浏览器 → docs.example.com/page（没有站点 cookie）
  反向代理 → GET /forward-auth/verify?aud=docs-site（带访客的 Cookie、原方法、原路径）
  ← 302 到 https://auth.example.com/forward-auth/start?aud=docs-site&state=…
     + Set-Cookie: __Host-nas-auth-fa-state（种在 docs.example.com 上）
浏览器 → auth.example.com/forward-auth/start
  没登录 → 现有登录页（return_url 指回这里），登录后原样回来
  已登录 → admin_only + user_resources 检查
     不过 → 403 页，带「换个账号」
     过   → 302 到 https://docs.example.com/.nas-auth/callback?ticket=…&state=…
浏览器 → docs.example.com/.nas-auth/callback（反向代理把 /.nas-auth/* 原样转给本服务）
  ← Set-Cookie: __Host-nas-auth-fa，302 回 /page
之后每个请求：verify 回 200，反向代理放行
```

已登录时不出「以 xx 身份授权」确认页：这里没有 token 交给第三方，站点 cookie 只在本服务与访客浏览器之间流转。

### 端点

| 端点 | 落在哪个域名 | 行为 |
|---|---|---|
| `GET /forward-auth/verify?aud=…` | 反向代理内部调用 | 站点 cookie 有效且授权还在 → `200`，带 `X-Auth-User` / `X-Auth-Email`；cookie 有效但请求是别的来源借浏览器发来的 → `403`；没有有效会话时页面导航 → `302` 去 start，其它请求 → `401`；`aud` 不存在或不是 forward-auth 资源 → `404` |
| `GET /forward-auth/start?aud=…&state=…` | 本服务 | 要求已登录。授权通过 → `302` 带票据回站点；不通过 → `403` 页；state 过期或对不上 → `302` 回站点首页重新来 |
| `GET /.nas-auth/callback?ticket=…&state=…` | 被保护的站点 | 校验通过 → 种站点 cookie，`302` 回原地址；否则 `400`，一张不引用任何外部资源的说明页加「重试」链接 |
| `GET /.nas-auth/logout` | 被保护的站点 | 清站点 cookie，`302` 到本服务的 `/logout`，退出后回站点 |

- **「页面导航」的判据**：原方法是 GET，且 `Sec-Fetch-Mode: navigate`；没有这个头的老浏览器退回看 `Accept` 里有没有 `text/html`。脚本的 fetch、图片、表单 POST 一律 `401`：跨域跳转对它们没有意义，还会把登录页的 HTML 当成接口响应喂给脚本。
- **回调失败不自动重试**：浏览器禁了 cookie 这类必然失败的情况，自动跳回去就是无限重定向。
- **被撤了授权的人**在 verify 这里和没登录一样走跳转，到 start 那边看带样式的 403 页。verify 的响应落在站点的域名上，那里引用不了本服务的样式。

### 「这是哪个站」只认反向代理写死的 `aud`

verify 不读 `X-Forwarded-Host`。反向代理若信任它上游的代理（CDN、隧道），访客自带的 `X-Forwarded-Host` 会被原样传下来（Caddy 2.11.4 配 `trusted_proxies` 时实测如此）。按这个头认站点的话，被授权进 A 站的人拿着 A 站的 cookie 去访问 B 站，把自己说成 A 站就过了。所以 `aud` 由运维写在反向代理配置的 verify 地址里，站点 cookie 里也记着 `aud`，两边对不上就不放。

回调和退出按 `Host` 头找站点：反向代理按它路由，访客改不了。票据同样绑 `aud`，A 站的票据拿到 B 站的回调上不认。

站点 cookie 里记 `aud` 另有一层用处：两个站都进得去的人，A 站的 cookie 泄漏后不能拿去开 B 站。这一点实时授权检查挡不住（他确实有 B 站的权限）。

### 别的来源借浏览器发来的请求

站点 cookie 有效还不够。被保护的站点与其它应用通常挂在同一主域的兄弟子域上，对浏览器来说是 same-site，cookie 的 `SameSite` 挡不住它们（`Strict` 也挡不住）。任何一个兄弟子域被 XSS 或被接管，就能让访客的浏览器带着站点 cookie 发请求：用 `<script src>` 读走 JS 形式的数据，或者向站点里的小工具发写请求。对手与 §十七 的跨源写拦截是同一类，那里保护的是本服务自己的表单，这里保护的是站点。

`ForwardAuthService.IsCrossOriginRide`，用的是反向代理原样转来的访客请求头（浏览器不允许页面脚本伪造 `Sec-Fetch-*`）：

| `Sec-Fetch-Site` | 处理 |
|---|---|
| `same-origin` / `none` | 站点自己的页面、地址栏、书签：放 |
| `same-site` / `cross-site` / 其它取值 | 只放顶层页面导航（GET + `Sec-Fetch-Mode: navigate` + `Sec-Fetch-Dest: document`，即从别处点链接进来）。被嵌进 iframe、子资源、fetch、表单 POST、WebSocket 一律 `403` |
| 没有这个头（老浏览器、非浏览器） | GET / HEAD 无从判断，放；写方法看 `Origin`，有且不是站点自己的来源就 `403` |

只在 cookie 有效时才判：没有会话的请求照旧是 `302` / `401`。副作用：别的子域的页面不能再直接引用被保护站点上的图片、脚本；需要的话把资源放到不设门的地方。

### 三种加密载荷

`Services/ForwardAuthService`。都用 DataProtection（密钥就是会话 cookie 那一套，数据卷里的 `dp-keys/`，重启不丢），各用各的 purpose，互相冒充解不开；过期时间写在载荷里。

| 载荷 | 内容 | 寿命 | 用途 |
|---|---|---|---|
| state | aud、原本要去的路径、随机数 | 1 小时 | verify 签发，经 start 原样带到回调。随机数同时种成站点上的 `__Host-nas-auth-fa-state` cookie，回调时两边要一致（定长时间比较）。别人把自己的回调链接发来点，对不上，种不上会话 |
| ticket | aud、用户、会话版本、发起登录的那份 state 的随机数、一次性 id | 60 秒 | start 签发，回调消费。只能用一次，而且**一经出示就作废**，不等后面的检查通过（用过的 id 记在内存里；重启丢了也只是让重启前 60 秒内的票据能再用一次，重放还得过随机数那一关） |
| session | aud、用户、会话版本 | 按资源配，默认 12 小时 | 站点 cookie `__Host-nas-auth-fa` 的内容 |

- 原本要去的路径来自反向代理的 `X-Forwarded-Uri`，只有是干净的站内路径才记（判据同 `ReturnUrl`，另外不回到 `/.nas-auth/` 下面、不超过 2000 字符），否则回首页。回跳目标不从 query 里收。
- 回调时**票据、state、浏览器里的 cookie 三处的随机数要一致**。cookie 对不上：发起这次登录的不是这个浏览器。票据对不上：票据不是为这份 state 签的，挡的是「拿到别人的 state，配上自己的票据发给对方点」，那样对方会以攻击者的身份登进站点。
- 票据一经出示就作废的原因：`/forward-auth/start` 是普通的 GET，别人能诱导已登录的人带着「别人的 state」去换票据。回调在随机数那一步失败，这时票据留在地址栏和访问日志里，不作废就还能在攻击者自己的浏览器里用 60 秒。
- 消费票据时用同一个时刻再判一次过期。否则读票据和消费之间跨过到期那一秒时，清理会先把「已用」记录删掉，同一张票据能再用一次。
- 同一个浏览器并排开几个标签页时共用一个随机数；回调成功后不清 state cookie，让它自己过期。否则先完成的标签页会把后完成的顶掉。
- 站点 cookie 是 `SameSite=Lax`。`Strict` 的 cookie 在「外站链接点进来 → 一串跳转」里全程不回传，登录完又被当成没登录。

### 站点 cookie 的寿命

签发后固定，不随访问续期：反向代理在放行时不会把本服务的 `Set-Cookie` 传给浏览器，没法原地续。到期后的下一次页面访问走一遍上面的跳转，主会话（30 天滑动）还在就静默换一张新的。

关系类似 access token 与 refresh token：站点 cookie 短，主会话长；能续期的东西只在本服务的域名上，站点 cookie 被偷了续不了。

寿命只影响这些情况，其余都是实时查库：

- 在别人电脑上用过两个被保护的站，在其中一个点了退出：另一个站的 cookie 还在那台电脑上，能用到过期
- 站点 cookie 被偷：能用到过期
- 主会话自然过期：站点最多再多活一个寿命

页面开着超过寿命时，页面里的脚本请求会拿到 `401`，刷新页面即恢复。

### 授权

`resources.json` 里一个站一条，带 `forward_auth`：

```json
{ "aud": "docs-site", "resource_url": "https://docs.example.com", "display_name": "Family docs", "forward_auth": {} }
```

- `resource_url` 必须是站点的来源（不带路径）；回跳地址、回调地址都由它拼。两个站点不能指向同一个来源，`aud` 不能重复，不能与 `proxy` 同配。这些在启动时校验，不合格直接启动失败。
- `scopes` 可以不写，默认补一条 `access`，只是为了复用后台按 scope 勾选的授权模型。
- `forward_auth.session_hours`：站点 cookie 寿命，1 到 720，默认 12。
- `admin_only` 照常生效。
- 判据与 `/authorize` 的用户级检查（§5.5）相同：`admin_only` 通过，且 `user_resources` 里有这一行。
- **每次 verify 都实时查**用户还在不在、会话版本对不对（§十六）、授权行还在不在。撤销授权、强制下线、改密、删用户立即生效，不等 cookie 过期。代价是每个请求两到三次主键查询。
- 这类资源**不参与 OAuth**：`ResourceCatalog.FindByUrl` 不返回它们，而那是 `/authorize`、`/token`（换码与刷新）认 `resource` 的唯一入口，所以哪条路径都签不出它的 token，包括把一个原有的 OAuth 资源原地改成 `forward_auth` 之后还留在别人手里的 refresh token。发现文档的 `scopes_supported` 不含它的 scope；DCR 客户端按 scope 反推资源（§十三）时拉不到它。站点条目也不会遮住挂在同一来源下面的 OAuth 资源。

审计：start 那一步记 `forward_auth` 事件（放行或拒绝各一条，约每 `session_hours` 一次）。逐请求的 verify 不记，量级同 `proxy.fwd`。

### 身份头

verify 放行时总是返回 `X-Auth-User`（user_id）和 `X-Auth-Email`（没有邮箱时是空串），含非 ASCII 字符的值做百分号编码。总是返回，是为了反向代理配了透传时，访客自带的同名头一定被盖掉。

要不要传给上游由反向代理决定，**建议默认不传**：上游一旦信任这个头，它就不能被反向代理以外的任何人直接访问到，否则谁都能自己写一个头进去。静态站用不着身份。

### 退出、过期、本服务不可用

| 场景 | 表现 |
|---|---|
| 在站点上访问 `/.nas-auth/logout` | 清本站 cookie，再退出主会话（不退的话下一次访问就静默登回来），然后回到站点，落在登录页 |
| 退出之后，其它被保护的站 | cookie 留到各自到期。与已接的 OIDC 应用一致：退出一个，其它应用自己的会话不受影响 |
| 强制下线、退出其他设备、改密、撤销授权、删用户 | 所有站点立即失效 |
| 本服务挂了或在重启 | 反向代理拿不到 2xx，站点一律不可访问，不会放行。重启后已有的站点 cookie 继续有效 |

`/logout` 的回跳白名单（§十五）加上了 forward-auth 站点的来源：它们没有客户端条目，按 `resources.json` 认，且只在请求没带 `client_id` 时算数。

### 对反向代理的要求

Caddy 示例（2.11.4 实测）：

```
# 用法：import protect <aud>
(protect) {
	# 回调、退出：原样交给 nas-auth，不过 forward_auth（这时还没有站点 cookie）
	@nasauth path /.nas-auth/*
	handle @nasauth {
		reverse_proxy nas-auth:8080
	}
	@gated not path /.nas-auth/*
	forward_auth @gated nas-auth:8080 {
		uri /forward-auth/verify?aud={args[0]}
	}
	# 不透传身份头时，访客自带的同名头也删掉
	request_header @gated -X-Auth-*
}

docs.example.com {
	import protect docs-site
	reverse_proxy docs:80 {
		# 登录后才看得到的内容不能进 CDN / 共享缓存
		header_down Cache-Control "private, no-cache"
	}
}

auth.example.com {
	# verify 只给反向代理内部调用
	@verify path /forward-auth/verify
	respond @verify 404
	reverse_proxy nas-auth:8080
}
```

1. **verify 地址里的 `aud` 写死**，一个站点一个，不要从请求里取。
2. **`/.nas-auth/*` 原样转给本服务**，并且不过 forward-auth。被保护的站点自己不能再用这个路径前缀。
3. **登录后才看得到的响应必须带 `Cache-Control: private`（或 `no-store`）**。前面有 CDN 时，CDN 默认按扩展名缓存静态文件，不看请求里有没有 cookie：不标 `private`，登录的人取过一次的文件就会被边缘节点存下来发给所有人。本服务自己的跳转、401、403 已经是 `no-store`；上游的响应归反向代理管，示例里用 `header_down` 统一盖成 `private, no-cache`（带内容哈希的文件可以单独放宽成 `private, max-age=…`）。
4. **不透传身份头时，删掉访客自带的 `X-Auth-*`**。要透传就把 `request_header` 那行换成 forward_auth 块里的 `copy_headers X-Auth-User X-Auth-Email`；实测访客自带的同名头会被盖掉，值为空时也一样。
5. **不要把 verify 暴露在本服务的公开域名上**。直接打它泄漏不了内容（只有状态码），但没有理由留着。
6. forward-auth 的子请求要带上访客的 `Cookie`、`Sec-Fetch-*`、`Origin`、`Accept`，以及原方法（`X-Forwarded-Method`）和原路径（`X-Forwarded-Uri`）。Caddy 的 `forward_auth` 默认把访客的请求头原样带上并补后两个。
7. 站点 cookie 会随请求一起到上游。上游不完全可信时（它拿到 cookie 也只能用来访问它自己），可以在反向代理里把 `__Host-nas-auth-fa*` 从 `Cookie` 头里剥掉。

### 没做的

- **退出一个站点、其它站点立即跟着失效**：需要服务端的会话表（主会话 cookie 现在是自包含票据），会改到主登录路径。现在靠站点 cookie 的寿命兜底。
- **按路径授权**：一个站点一个 `aud`，进得去就全能看。
- **verify 结果缓存**：每个请求都查库，家用量级没有压力。

### 测试

- `ForwardAuthServiceTests`：三种载荷往返、各自的过期时间（拨时钟）、互相冒充解不开、篡改 / 换密钥 / 垃圾输入、票据只能用一次且过期边界上不能重放、随机数比较、回跳路径清洗、页面导航判定矩阵、别的来源借浏览器的判定矩阵、身份头编码、`resources.json` 的默认值与各种非法写法启动即失败、按 Host 找站点、`FindByUrl` 不认站点也不被站点遮住、不进 `scopes_supported` 与 scope 反推、`/logout` 回跳白名单。
- `ForwardAuthPipelineTests`：走真实管线，测试扮演反向代理。完整流程（被拦 → 登录 → start → 回调 → 放行，含各 cookie 的属性）；已登录时静默通过；非页面导航回 401；未知 `aud` 不放行；没授权 → 403，授权后通过，撤销立即失效；`admin_only` 站点对非管理员即使有授权行也拒；会话版本 +1、删用户后站点会话立即失效；A 站的票据 / cookie 拿到 B 站不认（含两个站都有权限的人），自带 `X-Forwarded-Host` 也没用；别的浏览器捡到回调链接用不了，且票据随之作废；别人的 state 配自己的票据、诱导受害者换票据两种拼法都种不上会话；兄弟子域借 cookie 的子资源 / fetch / iframe / 表单 POST 被拒，顶层导航放行；伪造或串站的 state 回站点重来；并排标签页；回调失败页不引用外部资源；站点退出的三跳；不参与 OAuth；后台标出接入方式。
- 做过变异检查：把 verify 的 aud 比对、授权检查、会话版本比对、来源检查，回调的票据 aud、两处随机数比对，票据一次性、消费时判过期，`FindByUrl` 的排除，逐个临时拿掉，对应用例都变红。
- 另用真的 Caddy 2.11.4 加本地实例端到端走过一遍（登录流程、缓存头改写、身份头清理与透传、兄弟子域请求被拒、verify 在公开域名上被挡、退出），并在浏览器里实际点过。
- 上线前做过一次独立的安全复查，没有发现认证或授权绕过；它指出的来源检查缺口、票据未绑定随机数、过期边界竞态、`/token` 路径未排除站点，都已按上文修掉。
