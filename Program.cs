using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.RateLimiting;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Endpoints;
using NasAuth.Services;

var builder = WebApplication.CreateBuilder(args);

// ---------- 配置 ----------
var authOptions = new AuthOptions();
builder.Configuration.GetSection(AuthOptions.SectionName).Bind(authOptions);
builder.Services.AddSingleton(authOptions);

var jwtOptions = new JwtOptions();
builder.Configuration.GetSection(JwtOptions.SectionName).Bind(jwtOptions);
builder.Services.AddSingleton(jwtOptions);

if (string.IsNullOrWhiteSpace(authOptions.Issuer))
    throw new InvalidOperationException("Auth:Issuer 未配置");

// ---------- 容器内监听 0.0.0.0:8080（Production 走环境变量 ASPNETCORE_URLS 也行） ----------
if (builder.Environment.IsProduction())
{
    builder.WebHost.UseUrls("http://0.0.0.0:8080");
}

// ---------- 数据层 ----------
builder.Services.AddSingleton<AuthDb>();
builder.Services.AddScoped<ClientRepository>();
builder.Services.AddScoped<AuthCodeRepository>();
builder.Services.AddScoped<RefreshTokenRepository>();
builder.Services.AddScoped<UserRepository>();
builder.Services.AddScoped<SettingsRepository>();
builder.Services.AddScoped<ExternalIdentityRepository>();
builder.Services.AddScoped<UserResourceRepository>();
builder.Services.AddScoped<ExternalInviteRepository>();
builder.Services.AddSingleton<ProfileService>();
// 取外部头像用：短超时，拿不到就算了，不能拖慢登录
builder.Services.AddHttpClient(ProfileService.HttpClientName, c =>
{
    c.Timeout = TimeSpan.FromSeconds(5);
    c.DefaultRequestHeaders.UserAgent.ParseAdd("nas-auth");
});
builder.Services.AddSingleton<AuditRepository>(); // AuditLogger 是单例，它的仓储也得是

// ---------- 服务 ----------
builder.Services.AddSingleton<ResourceCatalog>();
builder.Services.AddSingleton<JwtIssuer>();
builder.Services.AddSingleton<OidcKeyService>();
builder.Services.AddSingleton<JwtValidator>();
builder.Services.AddSingleton<AuditLogger>();
builder.Services.AddHostedService<TokenCleanupService>();
builder.Services.AddHttpContextAccessor();

// ---------- /proxy/{aud}/* 反代 ----------
// IHttpForwarder 是 YARP 的"单请求转发"原语，比 ReverseProxy 全家桶轻量。
// 这里只用它做："验完 JWT → 替换 Bearer → 流式转发"。
builder.Services.AddHttpForwarder();
// 给 forwarder 用的长连接 HttpClient。SocketsHttpHandler 默认参数即可，
// 一个进程一份共享实例，避免每次请求新建 socket。
builder.Services.AddSingleton(_ => new HttpMessageInvoker(new SocketsHttpHandler
{
    AllowAutoRedirect = false,
    UseProxy = false,
    UseCookies = false,
    AutomaticDecompression = System.Net.DecompressionMethods.None,
    EnableMultipleHttp2Connections = true,
    PooledConnectionLifetime = TimeSpan.FromMinutes(5),
}));

// ---------- 认证（cookie session + 外部 IdP）----------
// 外部 IdP 凭证只从环境变量读（外部认证设计 §六）；没配的 provider 不注册 handler，
// 登录页也不渲染按钮 —— 密码登录是永久兜底，外部登录纯增量。
var externalProviders = ExternalProviderOptions.FromEnvironment();
builder.Services.AddSingleton(externalProviders);

var authBuilder = builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        // __Host- 前缀（2026-09-29 安全修复）：浏览器强制 Secure + Path=/ + 不带 Domain，
        // 兄弟子域就没法往 .<domain> 上种同名 cookie 顶替会话（cookie tossing）。
        // ⚠️ 改名那次部署会让所有人掉线一次（旧名 nas-auth-session 不再被读取），之后正常。
        // 本地 http://localhost 开发不受影响：Chrome / Firefox 把 localhost 当安全上下文，接受 Secure / __Host- cookie。
        options.Cookie.Name = "__Host-nas-auth-session";
        options.Cookie.Path = "/";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // __Host- 要求；生产 HTTPS 由前置反向代理终结
        // 未登录访问受保护页时跳 /login?return_url=…（默认参数名是 ReturnUrl，与 /login 读的对不上，深链会丢）
        options.ReturnUrlParameter = "return_url";
        // 30 天滑动续期：活跃用户 SSO 会话不掉，下游 RP（Gitea / Immich 等）
        // 重新 authorize 时静默放行，不用重输密码
        options.ExpireTimeSpan = TimeSpan.FromDays(30);
        options.SlidingExpiration = true;
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        // 会话版本比对（external-auth.md §十六）：退出其他设备 / 改密 / 强制下线后旧 cookie 立即失效
        options.Events.OnValidatePrincipal = SessionValidator.ValidateAsync;
    })
    // 承接 IdP 回调结果的临时 cookie：/signin/{provider} handler 写入，
    // /external/complete 读出并立即注销。与主会话分离，pending/rejected 绝不污染主会话。
    .AddCookie(ExternalLoginEndpoints.ExternalScheme, options =>
    {
        options.Cookie.Name = "__Host-nas-auth-external"; // 同上，防兄弟子域种 cookie
        options.Cookie.Path = "/";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(10);
        options.SlidingExpiration = false;
    });

if (externalProviders.GoogleEnabled)
{
    authBuilder.AddGoogle(options =>
    {
        options.ClientId = externalProviders.GoogleClientId;
        options.ClientSecret = externalProviders.GoogleClientSecret;
        options.CallbackPath = "/signin/google"; // 与 Google Console 注册的回调一致（设计 §六）
        options.SignInScheme = ExternalLoginEndpoints.ExternalScheme;
        // state + correlation cookie CSRF 防护是 RemoteAuthenticationHandler 默认行为，
        // 这里不关闭任何校验；默认 scope 已含 openid email profile
        options.Events.OnRemoteFailure = ExternalLoginEndpoints.HandleRemoteFailure;
        // userinfo 里的 email_verified 默认不进 claim；预绑定邮箱（§十八）只认验证过的邮箱
        options.ClaimActions.MapJsonKey(ExternalClaims.EmailVerifiedClaimType, "email_verified");
        // §十九：顺手把 Google 头像存一份（picture 地址默认 96px，换成 256px）
        options.Events.OnCreatingTicket = async ctx =>
        {
            if (!ctx.User.TryGetProperty("picture", out var pic) || pic.GetString() is not { Length: > 0 } url) return;
            url = System.Text.RegularExpressions.Regex.Replace(url, @"=s\d+(-c)?$", "=s256-c");
            await ExternalLoginEndpoints.AttachAvatarAsync(ctx, url, bearerToken: null);
        };
    });
}
if (externalProviders.MicrosoftEnabled)
{
    authBuilder.AddMicrosoftAccount(options =>
    {
        options.ClientId = externalProviders.MicrosoftClientId;
        options.ClientSecret = externalProviders.MicrosoftClientSecret;
        options.CallbackPath = "/signin/microsoft";
        options.SignInScheme = ExternalLoginEndpoints.ExternalScheme;
        // Azure 应用注册的 audience 是 "Personal Microsoft accounts only"（Consumer）。
        // 默认 /common/ 端点对 Consumer-only 应用直接报 invalid_request
        // （"userAudience should be configured with 'All' to use /common/"），必须改走 /consumers/。
        options.AuthorizationEndpoint = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
        options.TokenEndpoint = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
        options.Events.OnRemoteFailure = ExternalLoginEndpoints.HandleRemoteFailure;
        // 登录名单独留一份：预绑定邮箱（§十八）要求登录名就是下发的邮箱（Email claim 可能取的是 mail）。
        // ⚠️ 上面写死 /consumers/ 也是预绑定安全的前提：工作 / 学校账号的 email 可被租户管理员随意设置（nOAuth）
        options.ClaimActions.MapJsonKey(ExternalClaims.MicrosoftUpnClaimType, "userPrincipalName");
        // §十九：微软头像在 Graph 上，要用这次登录拿到的 access token 取；没设照片时 404，当作没有
        options.Events.OnCreatingTicket = ctx => ExternalLoginEndpoints.AttachAvatarAsync(
            ctx, "https://graph.microsoft.com/v1.0/me/photos/240x240/$value", ctx.AccessToken);
    });
}
builder.Services.AddAuthorization();
builder.Services.AddScoped<ExternalSignInService>();
builder.Services.AddScoped<ApprovalService>();
builder.Services.AddScoped<PasswordLoginGate>();
builder.Services.AddScoped<PasswordSignIn>();

// ---------- 速率限制（in-memory token bucket）----------
// /authorize / /login / /token 每 IP 每分钟 5 次。
// 注意：成功也计数（实现复杂度），单容器场景容忍这层近似。
// 原始设想是"失败 5 次/分钟"，更严格的"成功不计"需要在 endpoint 内部手动 release，
// 这里采用 5/min 总体上限 → 暴力枚举密码场景下达到等价效果。
builder.Services.AddRateLimiter(opts =>
{
    opts.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    opts.AddPolicy("auth-sensitive", ctx =>
    {
        var key = RateLimitKeys.ClientKey(ctx); // IPv4 整址、IPv6 按 /64
        return RateLimitPartition.GetTokenBucketLimiter(key, _ => new TokenBucketRateLimiterOptions
        {
            TokenLimit = 5,
            TokensPerPeriod = 5,
            ReplenishmentPeriod = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true,
        });
    });
    // /register（匿名 DCR）：每来源每小时 10 次 + 全局 200 次封顶，定义在 RegistrationEndpoints
    RegistrationEndpoints.AddDcrRateLimits(opts);
});

// ---------- 反向代理头（服务部署在反向代理后面）----------
builder.Services.Configure<Microsoft.AspNetCore.Builder.ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor |
        Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto;
    // 信任私网段里的代理，逐跳剥 X-Forwarded-For，取第一个公网地址当访客 IP（2026-09-29，external-auth.md §十四）。
    // 典型链路：访客 → CDN / 隧道（追加访客真实 IP）→ 私网里的一到多层反向代理（各自再追加上一跳地址）→ 本服务。
    // 原先默认 ForwardLimit=1 只剥最后一跳，拿到的是上一层代理的私网地址 ——
    // 所有外网访客共用一个 auth-sensitive 限速桶（攻击者能顺手把正常用户挡在外面），审计日志也记不到真实 IP。
    // 伪造 XFF 无效：外网请求的 XFF 最右端的公网段一定是边缘代理追加的真实地址，从右往左碰到它就停。
    // 私网直连（带着自己伪造的 XFF）会被信任 —— 与反向代理本身的信任边界一致。
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
    foreach (var cidr in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7" })
        options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(cidr));
    options.ForwardLimit = null;
});

// ---------- 会话 cookie 加密密钥持久化（2026-09-29）----------
// 不配的话 ASP.NET 把密钥放容器内 /app/.aspnet/DataProtection-Keys，每次 CI 部署重建容器密钥就丢，
// 30 天滑动的 SSO 会话全员作废（日志里有官方警告）。落到数据卷里 auth.db 同目录的 dp-keys/。
// ⚠️ 不要 SetApplicationName：会改变 purpose 鉴别串（默认是内容根 /app/），已发出去的 cookie 全部解不开。
{
    var dbPath = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(authOptions.Database).DataSource;
    var dataDir = Path.GetDirectoryName(Path.GetFullPath(dbPath)) ?? AppContext.BaseDirectory;
    builder.Services.AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDir, "dp-keys")));
}

var app = builder.Build();

// app.css / theme.js 的内容哈希，拼在页面引用的 URL 上（部署后浏览器不会拿旧样式配新 HTML）
NasAuth.Pages.Ui.InitAssets(app.Environment.WebRootPath);

// ---------- 启动期 bootstrap（任何失败 → fast fail）----------
using (var scope = app.Services.CreateScope())
{
    var sp = scope.ServiceProvider;
    var bootLogger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("nas-auth.bootstrap");

    var db = sp.GetRequiredService<AuthDb>();
    db.EnsureCreated();
    bootLogger.LogInformation("SQLite EnsureCreated 完成：{Database}", authOptions.Database);

    // 加载 resources.json（构造期校验，依赖 ILogger 注入）
    _ = sp.GetRequiredService<ResourceCatalog>();

    // 预置 client
    PresetClientLoader.Load(authOptions, sp.GetRequiredService<ClientRepository>(), bootLogger);
    PresetClientLoader.WarnAudCollisions(sp.GetRequiredService<ClientRepository>(), sp.GetRequiredService<ResourceCatalog>(), bootLogger);

    // admin 引导
    AdminBootstrapper.EnsureAdmin(authOptions, sp.GetRequiredService<UserRepository>(), bootLogger);

    // user_resources 一次性 seed（升级后行为不变：既有用户拿到全部 aud 的全量 scope）
    UserResourceSeeder.SeedIfNeeded(
        sp.GetRequiredService<ResourceCatalog>(),
        sp.GetRequiredService<UserRepository>(),
        sp.GetRequiredService<UserResourceRepository>(),
        sp.GetRequiredService<SettingsRepository>(),
        bootLogger);

    // 校验 Jwt 配置（构造 JwtIssuer 即触发 JwtOptions.Validate；RS256 时顺带加载 / 生成 RSA 钥）
    _ = sp.GetRequiredService<JwtIssuer>();
    bootLogger.LogInformation(
        "Jwt Issuer 配置 OK，AccessToken={Alg} {AccessDays}d RefreshToken={RefreshDays}d，遗留 HS256 验签={LegacyHs} 截止={NotAfter}",
        jwtOptions.NormalizedAlgorithm, jwtOptions.AccessTokenLifetimeDays, jwtOptions.RefreshTokenLifetimeDays,
        jwtOptions.HasHs256Keys, jwtOptions.UsesRs256 ? jwtOptions.LegacyHs256NotAfterUtc?.ToString("o") ?? "-" : "n/a");
    if (jwtOptions.UsesRs256 && jwtOptions.LegacyHs256NotAfterUtc < DateTimeOffset.UtcNow)
        bootLogger.LogWarning("Jwt:LegacyHs256NotAfter 已过，遗留 HS256 token 一律拒绝；可以去掉 Jwt:SigningKey:* 与 Jwt:LegacyHs256NotAfter");
}

// ---------- 中间件流水线 ----------
app.UseForwardedHeaders();

// 安全响应头（CSP / X-Frame-Options / nosniff / Referrer-Policy / 端点响应 no-store），/proxy/* 不动。
// 排在静态文件和所有端点之前，403 / 429 / 重定向也都带上。
app.Use(SecurityHeaders.InvokeAsync);

// 跨源写请求拦截（CSRF）：同一可注册域下的兄弟子域对 SameSite=Lax 来说是 same-site，挡不住，靠来源头判。
// 要在 UseForwardedHeaders 之后（比对本站来源需要还原后的 scheme）。
{
    var issuerOrigin = CrossOriginGuard.IssuerOrigin(authOptions);
    var csrfLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("nas-auth.csrf");
    app.Use((ctx, next) => CrossOriginGuard.InvokeAsync(ctx, next, issuerOrigin, csrfLogger));
}

// i18n 语言协商：?lang= 显式切换（写 cookie），否则 cookie，否则 Accept-Language。
// 存 AsyncLocal（NasAuth.Pages.I18n），SSR 模板内直接 I18n.T() 取词。
app.Use(async (ctx, next) =>
{
    var q = ctx.Request.Query["lang"].ToString();
    string lang;
    if (q is "zh" or "en")
    {
        lang = q;
        ctx.Response.Cookies.Append(NasAuth.Pages.I18n.CookieName, q, new CookieOptions
        {
            MaxAge = TimeSpan.FromDays(365),
            Path = "/",
            SameSite = SameSiteMode.Lax,
            Secure = ctx.Request.IsHttps, // UseForwardedHeaders 已还原 scheme
        });
    }
    else
    {
        var cookie = ctx.Request.Cookies[NasAuth.Pages.I18n.CookieName];
        lang = cookie is "zh" or "en"
            ? cookie
            : (ctx.Request.Headers.AcceptLanguage.ToString()
                   .Contains("zh", StringComparison.OrdinalIgnoreCase) ? "zh" : "en");
    }
    NasAuth.Pages.I18n.Lang = lang;
    await next();
});
// wwwroot 静态资源：favicon、app.css / theme.js、vendor/basecoat-1.0.2（页面样式，本地托管不走 CDN）。
// 排在认证与强制改密拦截之前，改密页自己的样式请求不会被重定向。
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

// 强制改密拦截：已登录 cookie session 且 users.must_change_password=1 时，
// 把所有受保护路径重定向到 /account/force-change-password。
// 命中放行白名单：force-change-password 页本身、/logout、discovery、favicon、healthz。
app.Use(async (ctx, next) =>
{
    if (ctx.User?.Identity?.IsAuthenticated == true)
    {
        var path = ctx.Request.Path.Value ?? "";
        var allow =
            path.StartsWith("/account/force-change-password", StringComparison.OrdinalIgnoreCase) ||
            path.Equals("/logout", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("/.well-known/", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("/favicon", StringComparison.OrdinalIgnoreCase) ||
            path.Equals("/healthz", StringComparison.OrdinalIgnoreCase);
        if (!allow)
        {
            var users = ctx.RequestServices.GetRequiredService<NasAuth.Data.Repositories.UserRepository>();
            var uid = ctx.User.Identity.Name;
            if (!string.IsNullOrEmpty(uid))
            {
                var u = users.GetById(uid);
                if (u != null && u.must_change_password != 0)
                {
                    ctx.Response.Redirect("/account/force-change-password");
                    return;
                }
            }
        }
    }
    await next();
});

// ---------- 端点 ----------
app.MapDiscoveryEndpoints();
app.MapOidcEndpoints();
app.MapRegistrationEndpoints();
app.MapAuthorizationEndpoints();
app.MapTokenEndpoints();
app.MapAccountEndpoints();
app.MapAdminEndpoints();
app.MapExternalLoginEndpoints();
app.MapProfileEndpoints();
app.MapProxyEndpoints();

// 简单 health check
app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));
app.MapGet("/", () => Results.Redirect("/login"));

app.Run();

/// <summary>
/// 这一行让 WebApplicationFactory 等测试基础设施能拿到 Program 类型（partial 占位）。
/// </summary>
public partial class Program { }
