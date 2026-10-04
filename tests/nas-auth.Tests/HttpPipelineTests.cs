using System.Net;
using System.Net.Http.Json;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using NasAuth.Data.Repositories;
using NasAuth.Endpoints;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// 起真实 Program（WebApplicationFactory + TestServer）的 Development 实例：临时目录里的 SQLite、
/// 仓库里的 resources.example.json、Development 配置里的管理员 admin / devpassword。
/// 外部 provider 与代理 bearer 用假凭证经环境变量注入（Program 启动时直接读 env，不走 IConfiguration）。
/// </summary>
public sealed class NasAuthAppFactory : WebApplicationFactory<Program>
{
    public const string AdminUser = "admin";
    public const string AdminPassword = "devpassword"; // appsettings.Development.json 里的开发口令

    private readonly string _dataDir =
        Path.Combine(Path.GetTempPath(), "nas-auth-it-" + Guid.NewGuid().ToString("N"));

    static NasAuthAppFactory()
    {
        // 进程级环境变量：只设假值、不回收（多个测试类共用同一组，值一致）
        Environment.SetEnvironmentVariable("EZBK_MCP_TOKEN", "it-dummy-bearer");
        Environment.SetEnvironmentVariable("GOOGLE_CLIENT_ID", "it-google-id");
        Environment.SetEnvironmentVariable("GOOGLE_CLIENT_SECRET", "it-google-secret");
        Environment.SetEnvironmentVariable("MS_CLIENT_ID", "it-ms-id");
        Environment.SetEnvironmentVariable("MS_CLIENT_SECRET", "it-ms-secret");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Directory.CreateDirectory(_dataDir);
        var root = RepoRoot();
        builder.UseEnvironment("Development");
        builder.UseSetting("Auth:Database", $"Data Source={Path.Combine(_dataDir, "auth.db")}");
        builder.UseSetting("Auth:ResourcesPath", Path.Combine(root, "resources.example.json"));
        builder.UseSetting("Auth:ClientsPresetPath", Path.Combine(root, "clients.preset.example.json"));
        builder.ConfigureServices(s => s.AddSingleton<IStartupFilter, DistinctClientIpFilter>());
    }

    /// <summary>
    /// 配了外部 provider 后防锁死兜底失效，密码登录改按用户开关（allow_password_login 默认 0）；
    /// 启动后给管理员打开，集成测试才能走密码登录拿会话。
    /// </summary>
    protected override IHost CreateHost(IHostBuilder builder)
    {
        var host = base.CreateHost(builder);
        using var scope = host.Services.CreateScope();
        scope.ServiceProvider.GetRequiredService<UserRepository>().UpdateProfile(AdminUser, email: null, allowPasswordLogin: true);
        return host;
    }

    /// <summary>默认走 https://localhost：__Host- cookie 带 Secure，http 下 CookieContainer 不回传。</summary>
    public HttpClient Client(string baseAddress = "https://localhost") =>
        CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(baseAddress),
            AllowAutoRedirect = false,
        });

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dataDir, recursive: true); } catch { /* ignore */ }
    }

    internal static string RepoRoot()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "nas-auth.csproj"))) return d.FullName;
        throw new InvalidOperationException("找不到 nas-auth.csproj");
    }

    /// <summary>
    /// 每个请求换一个来源 IP：/login /authorize /token 的 auth-sensitive 限速按 IP 5 次/分钟，
    /// TestServer 的 RemoteIpAddress 是 null（全部挤进同一个桶），不拆开的话测试之间互相 429。
    /// </summary>
    private sealed class DistinctClientIpFilter : IStartupFilter
    {
        private static int _n;

        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((ctx, nxt) =>
            {
                ctx.Connection.RemoteIpAddress = new IPAddress(BitConverter.GetBytes(0x0B000000 + Interlocked.Increment(ref _n)).Reverse().ToArray());
                return nxt(ctx);
            });
            next(app);
        };
    }
}

/// <summary>2026-09-29 安全修复的集成测试：走完整中间件管线（转发头 → 安全头 → CSRF → 认证 → 端点）。</summary>
public class HttpPipelineTests : IClassFixture<NasAuthAppFactory>
{
    private readonly NasAuthAppFactory _app;

    public HttpPipelineTests(NasAuthAppFactory app) => _app = app;

    private static FormUrlEncodedContent Form(params (string K, string V)[] kv) =>
        new(kv.Select(p => new KeyValuePair<string, string>(p.K, p.V)));

    private static HttpRequestMessage Post(string path, HttpContent? body = null,
        string? secFetchSite = null, string? origin = null, string? referer = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, path) { Content = body ?? Form() };
        if (secFetchSite is not null) req.Headers.TryAddWithoutValidation("Sec-Fetch-Site", secFetchSite);
        if (origin is not null) req.Headers.TryAddWithoutValidation("Origin", origin);
        if (referer is not null) req.Headers.TryAddWithoutValidation("Referer", referer);
        return req;
    }

    private Task<HttpResponseMessage> Login(HttpClient c, string returnUrl) =>
        c.PostAsync("/login", Form(("username", NasAuthAppFactory.AdminUser),
            ("password", NasAuthAppFactory.AdminPassword), ("return_url", returnUrl)));

    // ---------- CSRF ----------

    public static IEnumerable<object?[]> CrossOriginCases() => new[]
    {
        new object?[] { "same-site", null, null },                            // 兄弟子域
        new object?[] { "cross-site", "https://evil.example", null },
        new object?[] { null, "https://git.example.com", null },         // 无 Sec-Fetch-Site，看 Origin
        new object?[] { null, "null", null },
        new object?[] { null, null, "https://git.example.com/some/page" }, // 只剩 Referer
    };

    [Theory]
    [MemberData(nameof(CrossOriginCases))]
    public async Task Csrf_CrossOriginWrites_Rejected(string? site, string? origin, string? referer)
    {
        var c = _app.Client();
        foreach (var path in new[] { "/login", "/authorize", "/account/change-password", "/admin/users/create", "/external/google/bind" })
        {
            var r = await c.SendAsync(Post(path, secFetchSite: site, origin: origin, referer: referer));
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        }
    }

    [Fact]
    public async Task Csrf_SameOriginWrites_PassToEndpoint()
    {
        var c = _app.Client();
        // 没会话：放行到认证层，被踢去登录（302），而不是 403
        foreach (var r in new[]
                 {
                     await c.SendAsync(Post("/account/change-password", secFetchSite: "same-origin")),
                     await c.SendAsync(Post("/account/change-password", origin: "https://localhost")),
                     await c.SendAsync(Post("/account/change-password", origin: "https://auth.example.com")), // Auth:Issuer
                     await c.SendAsync(Post("/account/change-password", referer: "https://localhost/account/security")),
                     await c.SendAsync(Post("/account/change-password")), // 无任何浏览器头（curl）
                 })
            Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
    }

    [Fact]
    public async Task Csrf_ExemptEndpoints_AcceptCrossSite()
    {
        var c = _app.Client();
        var logout = await c.SendAsync(Post("/logout", secFetchSite: "cross-site", origin: "https://photo.example"));
        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        var token = await c.SendAsync(Post("/token", Form(("grant_type", "nope")), secFetchSite: "cross-site", origin: "https://evil.example"));
        Assert.Equal(HttpStatusCode.BadRequest, token.StatusCode);
        // /signin/* 不再豁免：IdP 回调是 GET
        var signin = await c.SendAsync(Post("/signin/google", secFetchSite: "cross-site"));
        Assert.Equal(HttpStatusCode.Forbidden, signin.StatusCode);
    }

    // ---------- 开放跳转 ----------

    [Theory]
    [InlineData("https://evil.example/")]
    [InlineData("//evil.example")]
    [InlineData("/\t/evil.example")]
    [InlineData("/account/中文")]
    [InlineData("/account\u2028")]
    public async Task Login_OffsiteOrNonAscii_ReturnUrl_LandsLocally(string returnUrl)
    {
        var r = await Login(_app.Client(), returnUrl);
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode); // 非 ASCII 原先在这里 500
        Assert.Equal("/admin", r.Headers.Location!.OriginalString); // admin 是管理员，默认去处 → /admin
    }

    [Fact]
    public async Task Login_LocalReturnUrl_KeepsQuery()
    {
        var r = await Login(_app.Client(), "/authorize?client_id=x&state=y");
        Assert.Equal("/authorize?client_id=x&state=y", r.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task DeepLink_RoundTripsThroughReturnUrlParameter()
    {
        var c = _app.Client();
        var r = await c.GetAsync("/account/security");
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Contains("/login?return_url=%2Faccount%2Fsecurity", r.Headers.Location!.ToString());

        var page = await (await c.GetAsync("/login?return_url=%2Faccount%2Fsecurity")).Content.ReadAsStringAsync();
        Assert.Contains("name='return_url' value='/account/security'", page);
        var evil = await (await c.GetAsync("/login?return_url=https%3A%2F%2Fevil.example")).Content.ReadAsStringAsync();
        Assert.Contains("name='return_url' value='/account'", evil);
    }

    [Fact]
    public async Task LoginNotice_OnlyKnownKeys()
    {
        var c = _app.Client();
        var logout = await c.GetAsync("/logout");
        Assert.Equal("/login?notice=signed_out", logout.Headers.Location!.OriginalString);
        Assert.Contains("Signed out", await (await c.GetAsync("/login?notice=signed_out")).Content.ReadAsStringAsync());
        var phish = await (await c.GetAsync("/login?notice=Call%20support%20at%20evil")).Content.ReadAsStringAsync();
        Assert.DoesNotContain("Call support", phish);
    }

    [Fact]
    public async Task DashboardFlash_OnlyServerIssued()
    {
        var c = _app.Client();
        Assert.Equal(HttpStatusCode.Redirect, (await Login(c, "/account")).StatusCode);

        // 明文 ?notice= / ?error= 不再回显
        var forged = await (await c.GetAsync("/account?notice=Call%20support%20at%20evil&error=Phish%20text")).Content.ReadAsStringAsync();
        Assert.DoesNotContain("Call support", forged);
        Assert.DoesNotContain("Phish text", forged);

        // 服务端自己发的提示照常显示（mode=clear = 回到默认状态，不影响其他测试）
        var r = await c.SendAsync(Post("/admin/password-login", Form(("mode", "clear")), secFetchSite: "same-origin"));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        var loc = r.Headers.Location!.OriginalString;
        Assert.StartsWith("/admin/system?notice=", loc);
        Assert.DoesNotContain("override", loc, StringComparison.OrdinalIgnoreCase); // 密文，不是明文
        Assert.Contains("Runtime override cleared", await (await c.GetAsync(loc)).Content.ReadAsStringAsync());

        // 篡改一个字节 → 不显示
        var tampered = loc[..^3] + (loc[^3] == 'A' ? 'B' : 'A') + loc[^2..];
        Assert.DoesNotContain("Runtime override cleared", await (await c.GetAsync(tampered)).Content.ReadAsStringAsync());

        // 别的会话（未登录）拿到同一链接也解不开：先被踢去登录
        Assert.Equal(HttpStatusCode.Redirect, (await _app.Client().GetAsync(loc)).StatusCode);
    }

    // ---------- 安全头 ----------

    [Fact]
    public async Task Headers_OnLoginPage()
    {
        var r = await _app.Client().GetAsync("/login");
        Assert.Contains("frame-ancestors 'none'", r.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("DENY", r.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("nosniff", r.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("same-origin", r.Headers.GetValues("Referrer-Policy").Single());
        Assert.True(r.Headers.CacheControl!.NoStore);
    }

    [Fact]
    public async Task Headers_WellKnown_Cacheable()
    {
        var r = await _app.Client().GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.False(r.Headers.CacheControl!.NoStore);
        Assert.True(r.Headers.CacheControl.Public);
        Assert.Equal(TimeSpan.FromSeconds(300), r.Headers.CacheControl.MaxAge);
    }

    [Fact]
    public async Task Headers_Proxy_Untouched()
    {
        var r = await _app.Client().GetAsync("/proxy/ezbookkeeping/.well-known/oauth-protected-resource");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.False(r.Headers.Contains("Content-Security-Policy"));
        Assert.False(r.Headers.Contains("X-Frame-Options"));
        Assert.Null(r.Headers.CacheControl);
    }

    [Fact]
    public async Task Headers_StaticFile_NoNoStore()
    {
        var r = await _app.Client().GetAsync("/app.css");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.False(r.Headers.CacheControl?.NoStore ?? false);
    }

    // ---------- cookie ----------

    [Fact]
    public async Task SessionCookie_HostPrefixed_Secure()
    {
        var r = await Login(_app.Client(), "/account");
        var cookie = r.Headers.GetValues("Set-Cookie").Single(v => v.StartsWith("__Host-nas-auth-session="));
        var attrs = cookie.ToLowerInvariant();
        Assert.Contains("; secure", attrs);
        Assert.Contains("; path=/", attrs);
        Assert.Contains("; httponly", attrs);
        Assert.Contains("; samesite=lax", attrs);
        Assert.DoesNotContain("domain=", attrs);
    }

    [Fact]
    public void ExternalCookie_HostPrefixed_Secure()
    {
        var o = _app.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(ExternalLoginEndpoints.ExternalScheme);
        Assert.Equal("__Host-nas-auth-external", o.Cookie.Name);
        Assert.Equal(CookieSecurePolicy.Always, o.Cookie.SecurePolicy);
        Assert.Equal("/", o.Cookie.Path);
        Assert.Null(o.Cookie.Domain);
    }

    [Fact]
    public async Task LangCookie_SecureOnlyOverHttps()
    {
        var https = await _app.Client().GetAsync("/login?lang=zh");
        Assert.Contains("; secure", https.Headers.GetValues("Set-Cookie").Single(v => v.StartsWith("nas_auth_lang=")).ToLowerInvariant());
        var http = await _app.Client("http://localhost").GetAsync("/login?lang=zh");
        Assert.DoesNotContain("; secure", http.Headers.GetValues("Set-Cookie").Single(v => v.StartsWith("nas_auth_lang=")).ToLowerInvariant());
    }

    // ---------- 自绑定 ----------

    [Fact]
    public async Task Bind_IsPostOnly_AndForcesAccountPicker()
    {
        var c = _app.Client();
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await c.GetAsync("/external/google/bind")).StatusCode);

        // 没会话：去登录
        var anon = await c.SendAsync(Post("/external/google/bind", secFetchSite: "same-origin"));
        Assert.Equal(HttpStatusCode.Redirect, anon.StatusCode);
        Assert.StartsWith("/login?return_url=", anon.Headers.Location!.OriginalString);

        // 有会话：跳 IdP，且带 prompt=select_account
        Assert.Equal(HttpStatusCode.Redirect, (await Login(c, "/account")).StatusCode);
        foreach (var (provider, host) in new[] { ("google", "accounts.google.com"), ("microsoft", "login.microsoftonline.com") })
        {
            var r = await c.SendAsync(Post($"/external/{provider}/bind", secFetchSite: "same-origin"));
            Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
            var loc = r.Headers.Location!;
            Assert.Equal(host, loc.Host);
            Assert.Contains("prompt=select_account", loc.Query);
        }
    }
    // ---------- 换个账号（2026-09-30）----------

    [Fact]
    public async Task ExternalStart_AlwaysForcesAccountPicker()
    {
        var c = _app.Client();
        foreach (var provider in new[] { "google", "microsoft" })
        {
            // 普通登录入口也弹选择器：否则 IdP 静默选回浏览器里当前那个账号（共用电脑串号）
            var plain = await c.GetAsync($"/external/{provider}/start?return_url=%2Faccount");
            Assert.Equal(HttpStatusCode.Redirect, plain.StatusCode);
            Assert.Contains("prompt=select_account", plain.Headers.Location!.Query);

            var picker = await c.GetAsync($"/external/{provider}/start?return_url=%2Faccount&select_account=1");
            Assert.Equal(HttpStatusCode.Redirect, picker.StatusCode);
            Assert.Contains("prompt=select_account", picker.Headers.Location!.Query);
        }
    }

    // ---------- RS256（与 sec/rs256 合并后补）----------

    [Fact]
    public async Task RotateJwtKey_Rs256_ExplainsViaProtectedFlash()
    {
        var c = _app.Client();
        Assert.Equal(HttpStatusCode.Redirect, (await Login(c, "/account")).StatusCode);

        var r = await c.SendAsync(Post("/admin/rotate-jwt-key", secFetchSite: "same-origin"));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        var loc = r.Headers.Location!.OriginalString;
        Assert.StartsWith("/admin/system?error=", loc);
        Assert.DoesNotContain("RS256", loc); // 提示走加密签名的 flash，不是明文 query

        var page = await (await c.GetAsync(loc)).Content.ReadAsStringAsync();
        Assert.Contains("Access tokens are signed with RS256; no HS256 key was generated.", page);
        Assert.Contains("oidc_rs256_previous.pem", page); // RSA 轮换步骤卡片

        // RS256 模式下不该生成 HS256 待生效密钥
        using var scope = _app.Services.CreateScope();
        Assert.Null(scope.ServiceProvider.GetRequiredService<SettingsRepository>().Get("jwt.signing_key.pending_current"));
    }

    [Fact]
    public async Task Rs256AccessToken_FromRealFlow_WorksAtUserinfo_IdTokenRejected()
    {
        // 预置的 confidential 客户端 gitea-web（client_secret_post、default_resource = Gitea SSO 资源）
        const string clientId = "gitea-web";
        using var preset = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(NasAuthAppFactory.RepoRoot(), "clients.preset.example.json")));
        var gitea = preset.RootElement.EnumerateArray().Single(e => e.GetProperty("client_id").GetString() == clientId);
        var secret = gitea.GetProperty("client_secret").GetString()!;
        var redirectUri = gitea.GetProperty("redirect_uris")[0].GetString()!;

        var c = _app.Client();
        Assert.Equal(HttpStatusCode.Redirect, (await Login(c, "/account")).StatusCode);

        // consent 页「以 admin 授权」那个表单（use_session=1），同源提交
        var auth = await c.SendAsync(Post("/authorize", Form(
            ("response_type", "code"), ("client_id", clientId), ("redirect_uri", redirectUri),
            ("scope", "openid email profile"), ("state", "st-1"), ("nonce", "n-1"), ("use_session", "1")),
            secFetchSite: "same-origin"));
        Assert.Equal(HttpStatusCode.Redirect, auth.StatusCode);
        var cb = auth.Headers.Location!;
        Assert.StartsWith(redirectUri + "?code=", cb.OriginalString);
        var code = System.Web.HttpUtility.ParseQueryString(cb.Query)["code"]!;

        // /token 是服务端到服务端：不带任何浏览器头
        var tok = await _app.Client().PostAsync("/token", Form(
            ("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirectUri),
            ("client_id", clientId), ("client_secret", secret)));
        var body = await tok.Content.ReadAsStringAsync();
        Assert.True(tok.StatusCode == HttpStatusCode.OK, body);
        Assert.True(tok.Headers.CacheControl!.NoStore); // RFC 6749 §5.1
        using var json = JsonDocument.Parse(body);
        var accessToken = json.RootElement.GetProperty("access_token").GetString()!;
        var idToken = json.RootElement.GetProperty("id_token").GetString()!;

        using (var header = JsonDocument.Parse(Base64UrlDecode(accessToken.Split('.')[0])))
        {
            Assert.Equal("RS256", header.RootElement.GetProperty("alg").GetString());
            Assert.Equal("at+jwt", header.RootElement.GetProperty("typ").GetString());
        }

        async Task<HttpResponseMessage> UserInfo(string bearer)
        {
            var req = new HttpRequestMessage(HttpMethod.Get, "/userinfo");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            return await _app.Client().SendAsync(req);
        }

        var ok = await UserInfo(accessToken);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        using (var info = JsonDocument.Parse(await ok.Content.ReadAsStringAsync()))
            Assert.Equal(NasAuthAppFactory.AdminUser, info.RootElement.GetProperty("sub").GetString());

        // id_token 同样是 RS256 签的，但不是 access token，/userinfo 必须拒
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserInfo(idToken)).StatusCode);
    }

    [Fact]
    public async Task AdminOnlyResource_DeniedForNonAdmin_EvenWithGrantRow()
    {
        // resources.example.json 里 ezbookkeeping 标了 admin_only；给普通用户硬塞一条授权行（模拟标记之前授出去的）
        const string bob = "bob-admin-only", pwd = "bob-password-123";
        using (var scope = _app.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserRepository>();
            users.Create(bob, bob, NasAuth.Services.PasswordHasher.Hash(pwd), mustChangePassword: false);
            users.UpdateProfile(bob, email: null, allowPasswordLogin: true);
            scope.ServiceProvider.GetRequiredService<UserResourceRepository>()
                .Upsert(bob, "ezbookkeeping", "read:ezbookkeeping write:ezbookkeeping");
        }

        Task<HttpResponseMessage> Authorize(string user, string password) =>
            _app.Client().SendAsync(Post("/authorize", Form(
                ("response_type", "code"), ("client_id", "ezbookkeeping-mcp"),
                ("redirect_uri", "https://book.example.com/oauth/callback"),
                ("resource", "https://auth.example.com/proxy/ezbookkeeping"),
                ("scope", "read:ezbookkeeping"), ("state", "st"),
                ("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"), ("code_challenge_method", "S256"),
                ("username", user), ("password", password)),
                secFetchSite: "same-origin"));

        Assert.Equal(HttpStatusCode.Forbidden, (await Authorize(bob, pwd)).StatusCode);
        // 管理员（启动 seed 了全量授权）照常拿到 code
        var ok = await Authorize(NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword);
        Assert.Equal(HttpStatusCode.Redirect, ok.StatusCode);
        Assert.StartsWith("https://book.example.com/oauth/callback?code=", ok.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task AdminCreate_ExternalOnlyUser_NoForcedPasswordChange_PreBoundEmail_IdNotReusable()
    {
        var c = _app.Client();
        Assert.Equal(HttpStatusCode.Redirect, (await Login(c, "/admin/users")).StatusCode);

        // 不勾「允许密码登录」、不填临时密码，顺带登记预绑定邮箱
        var create = await c.SendAsync(Post("/admin/users/create", Form(
            ("username", "googleonly"), ("email", "g@example.com"), ("invite_email", "G@Example.com")),
            secFetchSite: "same-origin"));
        Assert.Equal(HttpStatusCode.Redirect, create.StatusCode);
        Assert.StartsWith("/admin/users/edit", create.Headers.Location!.OriginalString);

        using (var scope = _app.Services.CreateScope())
        {
            var u = scope.ServiceProvider.GetRequiredService<UserRepository>().GetById("googleonly")!;
            Assert.Equal(0, u.must_change_password);     // 否则 /authorize 永远拒他
            Assert.Equal(0, u.allow_password_login);
            var invite = Assert.Single(scope.ServiceProvider.GetRequiredService<ExternalInviteRepository>().ListByUser("googleonly"));
            Assert.Equal("g@example.com", invite.email);
        }

        // 编辑页能看到预绑定邮箱
        var edit = await c.GetStringAsync("/admin/users/edit?user=googleonly");
        Assert.Contains("g@example.com", edit);
        Assert.Contains("/admin/users/invites/delete", edit);

        // 删人 → 同名（大小写不同也算）不许再建
        Assert.Equal(HttpStatusCode.Redirect, (await c.SendAsync(Post("/admin/users/delete",
            Form(("user_id", "googleonly")), secFetchSite: "same-origin"))).StatusCode);
        var again = await c.SendAsync(Post("/admin/users/create", Form(("username", "GoogleOnly")),
            secFetchSite: "same-origin"));
        Assert.Equal(HttpStatusCode.Redirect, again.StatusCode);
        using (var scope = _app.Services.CreateScope())
        {
            Assert.Null(scope.ServiceProvider.GetRequiredService<UserRepository>().GetById("GoogleOnly"));
            Assert.Empty(scope.ServiceProvider.GetRequiredService<ExternalInviteRepository>().ListByUser("googleonly"));
        }
    }

    // ---------- client_secret_basic ----------

    private static AuthenticationHeaderValue BasicAuth(string id, string secret) =>
        new("Basic", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(
            $"{Uri.EscapeDataString(id)}:{Uri.EscapeDataString(secret)}")));

    private static HttpRequestMessage TokenRequest(string path, AuthenticationHeaderValue? auth, params (string K, string V)[] kv)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, path) { Content = Form(kv) };
        req.Headers.Authorization = auth;
        return req;
    }

    /// <summary>预置 confidential 客户端 gitea-web 走一遍 /authorize，拿一个授权码。</summary>
    private async Task<(string ClientId, string Secret, string RedirectUri, string Code)> GiteaAuthCode()
    {
        const string clientId = "gitea-web";
        using var preset = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(NasAuthAppFactory.RepoRoot(), "clients.preset.example.json")));
        var gitea = preset.RootElement.EnumerateArray().Single(e => e.GetProperty("client_id").GetString() == clientId);
        var redirectUri = gitea.GetProperty("redirect_uris")[0].GetString()!;

        var c = _app.Client();
        Assert.Equal(HttpStatusCode.Redirect, (await Login(c, "/account")).StatusCode);
        var auth = await c.SendAsync(Post("/authorize", Form(
            ("response_type", "code"), ("client_id", clientId), ("redirect_uri", redirectUri),
            ("scope", "openid email profile"), ("state", "st-basic"), ("use_session", "1")), secFetchSite: "same-origin"));
        Assert.Equal(HttpStatusCode.Redirect, auth.StatusCode);
        var code = System.Web.HttpUtility.ParseQueryString(auth.Headers.Location!.Query)["code"]!;
        return (clientId, gitea.GetProperty("client_secret").GetString()!, redirectUri, code);
    }

    [Fact]
    public async Task ClientSecretBasic_WorksOnTokenRefreshIntrospectRevoke()
    {
        var (clientId, secret, redirectUri, code) = await GiteaAuthCode();
        var basic = BasicAuth(clientId, secret);

        // 换 token：认证材料只在头里，表单不带 client_id / client_secret
        var tok = await _app.Client().SendAsync(TokenRequest("/token", basic,
            ("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirectUri)));
        var body = await tok.Content.ReadAsStringAsync();
        Assert.True(tok.StatusCode == HttpStatusCode.OK, body);
        using var json = JsonDocument.Parse(body);
        Assert.False(string.IsNullOrEmpty(json.RootElement.GetProperty("id_token").GetString()));
        var refresh = json.RootElement.GetProperty("refresh_token").GetString()!;

        // 刷新
        var ref2 = await _app.Client().SendAsync(TokenRequest("/token", basic,
            ("grant_type", "refresh_token"), ("refresh_token", refresh)));
        var refBody = await ref2.Content.ReadAsStringAsync();
        Assert.True(ref2.StatusCode == HttpStatusCode.OK, refBody);
        using var refJson = JsonDocument.Parse(refBody);
        var refresh2 = refJson.RootElement.GetProperty("refresh_token").GetString()!;

        // 内省 / 吊销
        var intro = await _app.Client().SendAsync(TokenRequest("/introspect", basic, ("token", refresh2)));
        using (var introJson = JsonDocument.Parse(await intro.Content.ReadAsStringAsync()))
            Assert.True(introJson.RootElement.GetProperty("active").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await _app.Client().SendAsync(TokenRequest("/revoke", basic, ("token", refresh2)))).StatusCode);
        var intro2 = await _app.Client().SendAsync(TokenRequest("/introspect", basic, ("token", refresh2)));
        using (var introJson = JsonDocument.Parse(await intro2.Content.ReadAsStringAsync()))
            Assert.False(introJson.RootElement.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task ClientSecretBasic_BadCredentials_AreRejected_WithoutBurningTheCode()
    {
        var (clientId, secret, redirectUri, code) = await GiteaAuthCode();
        (string, string)[] grant = { ("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirectUri) };

        // 错 secret → 401，且因为对方用的是 Basic 头，要带 WWW-Authenticate（RFC 6749 §5.2）
        var wrong = await _app.Client().SendAsync(TokenRequest("/token", BasicAuth(clientId, "not-the-secret"), grant));
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.StartsWith("Basic", wrong.Headers.WwwAuthenticate.Single().ToString());

        // 坏 base64 → 同样 401 + WWW-Authenticate
        var bad = TokenRequest("/token", null, grant);
        bad.Headers.TryAddWithoutValidation("Authorization", "Basic !!!not-base64!!!");
        var badResp = await _app.Client().SendAsync(bad);
        Assert.Equal(HttpStatusCode.Unauthorized, badResp.StatusCode);
        Assert.NotEmpty(badResp.Headers.WwwAuthenticate);

        // 头和表单都带 secret → 400 invalid_request（一次请求只许一种认证方式）
        var both = await _app.Client().SendAsync(TokenRequest("/token", BasicAuth(clientId, secret),
            grant.Append(("client_id", clientId)).Append(("client_secret", secret)).ToArray()));
        Assert.Equal(HttpStatusCode.BadRequest, both.StatusCode);
        Assert.Contains("invalid_request", await both.Content.ReadAsStringAsync());

        // 表单 client_id 与头里的不一致 → 400
        var mismatch = await _app.Client().SendAsync(TokenRequest("/token", BasicAuth(clientId, secret),
            grant.Append(("client_id", "immich")).ToArray()));
        Assert.Equal(HttpStatusCode.BadRequest, mismatch.StatusCode);

        // 表单写法（client_secret_post）错 secret：401，不带 WWW-Authenticate
        var postWrong = await _app.Client().SendAsync(TokenRequest("/token", null,
            grant.Append(("client_id", clientId)).Append(("client_secret", "nope")).ToArray()));
        Assert.Equal(HttpStatusCode.Unauthorized, postWrong.StatusCode);
        Assert.Empty(postWrong.Headers.WwwAuthenticate);

        // 以上失败都发生在消费授权码之前：正确的 Basic 仍然能换到 token；表单里重复一遍相同的 client_id 是允许的
        var ok = await _app.Client().SendAsync(TokenRequest("/token", BasicAuth(clientId, secret),
            grant.Append(("client_id", clientId)).ToArray()));
        Assert.True(ok.StatusCode == HttpStatusCode.OK, await ok.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ClientSecretBasic_IsAdvertised_AndRegistrable()
    {
        foreach (var doc in new[] { "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server" })
        {
            using var meta = JsonDocument.Parse(await _app.Client().GetStringAsync(doc));
            var methods = meta.RootElement.GetProperty("token_endpoint_auth_methods_supported")
                .EnumerateArray().Select(e => e.GetString()).ToArray();
            Assert.Equal(new[] { "client_secret_post", "client_secret_basic", "none" }, methods);
        }

        var reg = await _app.Client().PostAsJsonAsync("/register", new
        {
            client_name = "basic-client",
            redirect_uris = new[] { "https://app.example.com/callback" },
            token_endpoint_auth_method = "client_secret_basic",
        });
        var regBody = await reg.Content.ReadAsStringAsync();
        Assert.True(reg.StatusCode == HttpStatusCode.Created, regBody);
        using var regJson = JsonDocument.Parse(regBody);
        Assert.Equal("client_secret_basic", regJson.RootElement.GetProperty("token_endpoint_auth_method").GetString());
        Assert.False(string.IsNullOrEmpty(regJson.RootElement.GetProperty("client_secret").GetString()));
    }

    [Fact]
    public async Task AdminCreateAndReset_ForcedPasswordChange_IsOptIn()
    {
        var c = _app.Client();
        Assert.Equal(HttpStatusCode.Redirect, (await Login(c, "/admin/users")).StatusCode);

        long MustChange(string id)
        {
            using var scope = _app.Services.CreateScope();
            return scope.ServiceProvider.GetRequiredService<UserRepository>().GetById(id)!.must_change_password;
        }

        // 默认：管理员设的密码就是正式密码，不强制改
        var page = await c.GetStringAsync("/admin/users");
        Assert.Contains("name='must_change_password'", page);
        Assert.Equal(HttpStatusCode.Redirect, (await c.SendAsync(Post("/admin/users/create", Form(
            ("username", "family1"), ("temp_password", "family-password"), ("allow_password_login", "1")),
            secFetchSite: "same-origin"))).StatusCode);
        Assert.Equal(0, MustChange("family1"));

        // 勾了才强制
        Assert.Equal(HttpStatusCode.Redirect, (await c.SendAsync(Post("/admin/users/create", Form(
            ("username", "strict1"), ("temp_password", "strict-password"), ("allow_password_login", "1"),
            ("must_change_password", "1")), secFetchSite: "same-origin"))).StatusCode);
        Assert.Equal(1, MustChange("strict1"));

        // 不许密码登录的用户：勾了也不置（没有可改的密码，置了 /authorize 永远拒他）
        Assert.Equal(HttpStatusCode.Redirect, (await c.SendAsync(Post("/admin/users/create", Form(
            ("username", "extonly1"), ("must_change_password", "1")), secFetchSite: "same-origin"))).StatusCode);
        Assert.Equal(0, MustChange("extonly1"));

        // 重置密码同理：默认清掉标志，勾了才置
        Assert.Contains("name='must_change_password'", await c.GetStringAsync("/admin/users/edit?user=strict1"));
        Assert.Equal(HttpStatusCode.Redirect, (await c.SendAsync(Post("/admin/users/reset-password", Form(
            ("user_id", "strict1"), ("temp_password", "another-password")), secFetchSite: "same-origin"))).StatusCode);
        Assert.Equal(0, MustChange("strict1"));
        Assert.Equal(HttpStatusCode.Redirect, (await c.SendAsync(Post("/admin/users/reset-password", Form(
            ("user_id", "family1"), ("temp_password", "another-password"), ("must_change_password", "1")),
            secFetchSite: "same-origin"))).StatusCode);
        Assert.Equal(1, MustChange("family1"));
    }

    [Fact]
    public async Task Profile_NicknameAndAvatar_UploadedServedAndSentToApps()
    {
        var c = _app.Client();
        Assert.Equal(HttpStatusCode.Redirect, (await Login(c, "/account")).StatusCode);

        // 改昵称
        Assert.Equal(HttpStatusCode.Redirect, (await c.SendAsync(Post("/account/profile",
            Form(("display_name", "管理员小陶")), secFetchSite: "same-origin"))).StatusCode);

        // 传头像（1x1 PNG）
        var png = Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==");
        var upload = new MultipartFormDataContent { { new ByteArrayContent(png), "avatar", "me.png" } };
        Assert.Equal(HttpStatusCode.Redirect, (await c.SendAsync(Post("/account/avatar", upload, secFetchSite: "same-origin"))).StatusCode);

        string file;
        using (var scope = _app.Services.CreateScope())
        {
            var me = scope.ServiceProvider.GetRequiredService<UserRepository>().GetById(NasAuthAppFactory.AdminUser)!;
            Assert.Equal("管理员小陶", me.display_name);
            file = me.avatar!;
        }

        // 公开头像：不用登录、长期缓存、沙箱 CSP
        var img = await _app.Client().GetAsync($"/avatars/{file}");
        Assert.Equal(HttpStatusCode.OK, img.StatusCode);
        Assert.Equal("image/png", img.Content.Headers.ContentType!.MediaType);
        Assert.Contains("immutable", img.Headers.CacheControl!.ToString());
        Assert.Contains("sandbox", img.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal(HttpStatusCode.NotFound, (await _app.Client().GetAsync("/avatars/..%2Fauth.db")).StatusCode);

        // 个人中心页显示新昵称和头像
        var page = await c.GetStringAsync("/account");
        Assert.Contains("管理员小陶", page);
        Assert.Contains($"/avatars/{file}", page);

        // 拒非图片
        var svg = new MultipartFormDataContent { { new ByteArrayContent("<svg xmlns='http://www.w3.org/2000/svg'/>"u8.ToArray()), "avatar", "x.png" } };
        await c.SendAsync(Post("/account/avatar", svg, secFetchSite: "same-origin"));
        using (var scope = _app.Services.CreateScope())
            Assert.Equal(file, scope.ServiceProvider.GetRequiredService<UserRepository>().GetById(NasAuthAppFactory.AdminUser)!.avatar);

        // 下发：真实 /authorize + /token 拿到的 access token 去 /userinfo，带新昵称与 picture
        const string clientId = "gitea-web";
        using var preset = JsonDocument.Parse(File.ReadAllText(Path.Combine(NasAuthAppFactory.RepoRoot(), "clients.preset.example.json")));
        var gitea = preset.RootElement.EnumerateArray().Single(e => e.GetProperty("client_id").GetString() == clientId);
        var redirectUri = gitea.GetProperty("redirect_uris")[0].GetString()!;
        var auth = await c.SendAsync(Post("/authorize", Form(
            ("response_type", "code"), ("client_id", clientId), ("redirect_uri", redirectUri),
            ("scope", "openid email profile"), ("state", "st-p"), ("use_session", "1")), secFetchSite: "same-origin"));
        var code = System.Web.HttpUtility.ParseQueryString(auth.Headers.Location!.Query)["code"]!;
        var tok = await _app.Client().PostAsync("/token", Form(("grant_type", "authorization_code"), ("code", code),
            ("redirect_uri", redirectUri), ("client_id", clientId), ("client_secret", gitea.GetProperty("client_secret").GetString()!)));
        using var tj = JsonDocument.Parse(await tok.Content.ReadAsStringAsync());
        var req = new HttpRequestMessage(HttpMethod.Get, "/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tj.RootElement.GetProperty("access_token").GetString());
        using var info = JsonDocument.Parse(await (await _app.Client().SendAsync(req)).Content.ReadAsStringAsync());
        Assert.Equal("管理员小陶", info.RootElement.GetProperty("name").GetString());
        Assert.EndsWith($"/avatars/{file}", info.RootElement.GetProperty("picture").GetString());
        Assert.Equal(NasAuthAppFactory.AdminUser, info.RootElement.GetProperty("preferred_username").GetString());

        // id_token 也带
        var idPayload = Base64UrlDecode(tj.RootElement.GetProperty("id_token").GetString()!.Split('.')[1]);
        Assert.Contains("\"picture\"", idPayload);
    }

    private static string Base64UrlDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        return Encoding.UTF8.GetString(Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=')));
    }
}
