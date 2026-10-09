using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>external-auth.md §二十二：forward-auth 的载荷、纯判定与资源登记校验。</summary>
public class ForwardAuthServiceTests : IDisposable
{
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private readonly Clock _clock = new();
    private readonly ForwardAuthService _fa;
    private readonly string _tmpDir;

    public ForwardAuthServiceTests()
    {
        _fa = new ForwardAuthService(new EphemeralDataProtectionProvider(), _clock);
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    // ---------- 三种载荷 ----------

    [Fact]
    public void Payloads_RoundTrip()
    {
        Assert.True(_fa.TryReadState(_fa.CreateState("docs", "/a?b=1", "n1"), out var st));
        Assert.Equal(("docs", "/a?b=1", "n1"), (st!.Aud, st.ReturnPath, st.Nonce));

        Assert.True(_fa.TryReadTicket(_fa.CreateTicket("docs", "alice", 3, "n1"), out var t));
        Assert.Equal(("docs", "alice", 3L, "n1"), (t!.Aud, t.UserId, t.SessionVersion, t.Nonce));

        Assert.True(_fa.TryReadSession(_fa.CreateSession("docs", "alice", 3, TimeSpan.FromHours(12)), out var s));
        Assert.Equal(("docs", "alice", 3L), (s!.Aud, s.UserId, s.SessionVersion));
    }

    [Fact]
    public void Payloads_ExpireOnTheirOwnClock()
    {
        var state = _fa.CreateState("docs", "/", "n");
        var ticket = _fa.CreateTicket("docs", "alice", 0, "n");
        var session = _fa.CreateSession("docs", "alice", 0, TimeSpan.FromHours(12));

        _clock.Now += TimeSpan.FromSeconds(59);
        Assert.True(_fa.TryReadTicket(ticket, out _));
        _clock.Now += TimeSpan.FromSeconds(2); // 票据 60 秒
        Assert.False(_fa.TryReadTicket(ticket, out _));
        Assert.True(_fa.TryReadState(state, out _));

        _clock.Now += TimeSpan.FromHours(1); // state 1 小时
        Assert.False(_fa.TryReadState(state, out _));
        Assert.True(_fa.TryReadSession(session, out _));

        _clock.Now += TimeSpan.FromHours(11); // 站点 cookie 按资源配的寿命
        Assert.False(_fa.TryReadSession(session, out _));
    }

    [Fact]
    public void Payloads_CannotStandInForEachOther()
    {
        // 票据是会经过浏览器地址栏的：拿它当站点 cookie 用必须解不开
        var ticket = _fa.CreateTicket("docs", "alice", 0, "n");
        var state = _fa.CreateState("docs", "/", "n");
        var session = _fa.CreateSession("docs", "alice", 0, TimeSpan.FromHours(1));

        Assert.False(_fa.TryReadSession(ticket, out _));
        Assert.False(_fa.TryReadSession(state, out _));
        Assert.False(_fa.TryReadTicket(session, out _));
        Assert.False(_fa.TryReadTicket(state, out _));
        Assert.False(_fa.TryReadState(ticket, out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-base64-!!")]
    [InlineData("AAAA")]
    public void Payloads_GarbageRejected(string? raw)
    {
        Assert.False(_fa.TryReadSession(raw, out _));
        Assert.False(_fa.TryReadTicket(raw, out _));
        Assert.False(_fa.TryReadState(raw, out _));
    }

    [Fact]
    public void Payloads_TamperedOrForeignKeyRejected()
    {
        var session = _fa.CreateSession("docs", "alice", 0, TimeSpan.FromHours(1));
        var flipped = session[..^2] + (session[^2] == 'A' ? 'B' : 'A') + session[^1];
        Assert.False(_fa.TryReadSession(flipped, out _));
        Assert.False(_fa.TryReadSession(new string('A', 5000), out _)); // 超长的不解

        var other = new ForwardAuthService(new EphemeralDataProtectionProvider(), _clock);
        Assert.False(other.TryReadSession(session, out _));
    }

    [Fact]
    public void Ticket_SingleUse()
    {
        Assert.True(_fa.TryReadTicket(_fa.CreateTicket("docs", "alice", 0, "n"), out var a));
        Assert.True(_fa.TryReadTicket(_fa.CreateTicket("docs", "alice", 0, "n"), out var b));
        Assert.NotEqual(a!.Id, b!.Id);

        Assert.True(_fa.TryConsume(a));
        Assert.False(_fa.TryConsume(a));
        Assert.True(_fa.TryConsume(b)); // 各算各的

        // 过期的记录被清掉后也不会让旧票据复活：票据自己已经过期读不出来了
        _clock.Now += TimeSpan.FromMinutes(5);
        Assert.True(_fa.TryReadTicket(_fa.CreateTicket("docs", "alice", 0, "n"), out var c));
        Assert.True(_fa.TryConsume(c!));
    }

    [Fact]
    public void Ticket_ExpiredBetweenReadAndConsume_CannotBeReplayed()
    {
        // 读票据与消费之间跨过到期那一秒：清理会把「已用」记录删掉，消费时必须自己再判一次过期
        Assert.True(_fa.TryReadTicket(_fa.CreateTicket("docs", "alice", 0, "n"), out var t));
        Assert.True(_fa.TryConsume(t!));
        _clock.Now += ForwardAuthService.TicketLifetime; // 正好到期：记录被清理
        Assert.False(_fa.TryConsume(t!));
        Assert.False(_fa.TryConsume(t!));
    }

    [Fact]
    public void Nonce_FixedTimeCompare()
    {
        var n = ForwardAuthService.NewNonce();
        Assert.NotEqual(n, ForwardAuthService.NewNonce());
        Assert.True(ForwardAuthService.NonceMatches(n, n));
        Assert.False(ForwardAuthService.NonceMatches(null, n));
        Assert.False(ForwardAuthService.NonceMatches("", n));
        Assert.False(ForwardAuthService.NonceMatches(n + "x", n));
    }

    // ---------- 纯判定 ----------

    [Theory]
    [InlineData("/", "/")]
    [InlineData("/layout.html?x=1&y=%E4%B8%AD", "/layout.html?x=1&y=%E4%B8%AD")]
    [InlineData("", "/")]
    [InlineData(null, "/")]
    [InlineData("//evil.example/x", "/")]
    [InlineData("/\\evil.example", "/")]
    [InlineData("/\t/evil.example", "/")]
    [InlineData("https://evil.example/", "/")]
    [InlineData("~/x", "/")]
    [InlineData("/页面", "/")]
    [InlineData("/.nas-auth/callback?ticket=x", "/")] // 不回到回调自己
    [InlineData("/.NAS-AUTH/logout", "/")]
    [InlineData("/.nas-auth", "/")]
    [InlineData("/.nas-authx/ok", "/.nas-authx/ok")]
    public void SafeReturnPath_OnlyCleanSitePaths(string? input, string expected) =>
        Assert.Equal(expected, ForwardAuthService.SafeReturnPath(input));

    [Fact]
    public void SafeReturnPath_TooLongFallsBack() =>
        Assert.Equal("/", ForwardAuthService.SafeReturnPath("/" + new string('a', 3000)));

    [Theory]
    [InlineData("GET", "navigate", "*/*", true)]
    [InlineData("GET", "NAVIGATE", null, true)]
    [InlineData("GET", "cors", "text/html", false)]      // fetch：有 Sec-Fetch-Mode 就按它判
    [InlineData("GET", "no-cors", "image/*", false)]     // <img>
    [InlineData("GET", null, "text/html,application/xhtml+xml", true)] // 老浏览器
    [InlineData("GET", null, "application/json", false)]
    [InlineData("GET", null, null, false)]               // curl
    [InlineData("POST", "navigate", "text/html", false)] // 表单提交跳走会丢 body，回 401
    [InlineData("", "navigate", null, true)]             // 反向代理没带原方法：当 GET
    public void IsPageNavigation_Matrix(string? method, string? mode, string? accept, bool expected) =>
        Assert.Equal(expected, ForwardAuthService.IsPageNavigation(method, mode, accept));

    private const string Site = "https://docs.example.com";

    [Theory]
    // 站点自己的页面、地址栏 / 书签
    [InlineData("GET", "same-origin", "cors", "empty", null, false)]
    [InlineData("POST", "same-origin", "cors", "empty", Site, false)]
    [InlineData("GET", "none", "navigate", "document", null, false)]
    [InlineData("GET", "SAME-ORIGIN", "no-cors", "image", null, false)]
    // 从别处点链接进来（兄弟子域的导航页、外站）：顶层页面导航，放
    [InlineData("GET", "same-site", "navigate", "document", null, false)]
    [InlineData("GET", "cross-site", "navigate", "document", null, false)]
    [InlineData("", "same-site", "navigate", "document", null, false)] // 反向代理没带原方法：当 GET
    // 兄弟子域 / 外站借浏览器发的其它一切：拒
    [InlineData("GET", "same-site", "no-cors", "script", null, true)]   // <script src> 读 JS 形式的数据
    [InlineData("GET", "same-site", "cors", "empty", "https://evil.example.com", true)] // fetch
    [InlineData("GET", "same-site", "no-cors", "image", null, true)]
    [InlineData("GET", "same-site", "navigate", "iframe", null, true)]  // 被嵌进别人的页面
    [InlineData("GET", "same-site", "websocket", "websocket", "https://evil.example.com", true)]
    [InlineData("POST", "same-site", "navigate", "document", "https://evil.example.com", true)] // 表单 CSRF
    [InlineData("POST", "cross-site", "cors", "empty", "https://evil.example", true)]
    [InlineData("GET", "same-site", null, null, null, true)]
    [InlineData("GET", "weird-value", "navigate", "document", null, false)] // 不认识的取值按「不是自己人」算，但顶层导航仍放
    [InlineData("GET", "weird-value", "cors", "empty", null, true)]
    // 没有 Sec-Fetch-Site 的老浏览器 / 非浏览器：GET 放，写方法看 Origin
    [InlineData("GET", null, null, null, null, false)]
    [InlineData("GET", null, null, null, "https://evil.example.com", false)]
    [InlineData("HEAD", null, null, null, "https://evil.example.com", false)]
    [InlineData("POST", null, null, null, null, false)]               // curl
    [InlineData("POST", null, null, null, Site, false)]
    [InlineData("POST", null, null, null, "https://DOCS.example.com:443", false)]
    [InlineData("POST", null, null, null, "https://evil.example.com", true)]
    [InlineData("DELETE", null, null, null, "http://docs.example.com", true)] // scheme 不同
    [InlineData("POST", null, null, null, "null", true)]
    public void IsCrossOriginRide_Matrix(string? method, string? site, string? mode, string? dest, string? origin, bool expected) =>
        Assert.Equal(expected, ForwardAuthService.IsCrossOriginRide(method, site, mode, dest, origin, Site));

    [Theory]
    [InlineData("alice", "alice")]
    [InlineData("a b@example.com", "a b@example.com")]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("小明", "%E5%B0%8F%E6%98%8E")]
    [InlineData("a\r\nX-Evil: 1", "a%0D%0AX-Evil%3A%201")]
    public void HeaderValue_AsciiOrPercentEncoded(string? input, string expected) =>
        Assert.Equal(expected, ForwardAuthService.HeaderValue(input));

    // ---------- resources.json 校验 ----------

    private ResourceCatalog Load(string json)
    {
        var path = Path.Combine(_tmpDir, $"resources-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, json);
        return new ResourceCatalog(new AuthOptions { ResourcesPath = path }, NullLogger<ResourceCatalog>.Instance);
    }

    private const string TwoSites = """
        [
          { "aud": "gitea-web", "resource_url": "https://git.example.com", "scopes": ["openid", "access"] },
          { "aud": "docs", "resource_url": "https://docs.example.com", "display_name": "Docs", "forward_auth": {} },
          { "aud": "ops", "resource_url": "https://Ops.example.com:8443/", "admin_only": true,
            "forward_auth": { "session_hours": 2 } }
        ]
        """;

    [Fact]
    public void Catalog_ForwardAuthDefaultsAndLookup()
    {
        var cat = Load(TwoSites);

        var docs = cat.FindForwardAuth("docs");
        Assert.NotNull(docs);
        Assert.Equal(new[] { ResourceCatalog.ForwardAuthScope }, docs!.Scopes); // 没写 scopes 补一条
        Assert.Equal(ForwardAuthConfig.DefaultSessionHours, docs.ForwardAuth!.SessionHours);
        Assert.Equal("https://docs.example.com", ResourceCatalog.SiteOrigin(docs));

        var ops = cat.FindForwardAuth("ops");
        Assert.Equal(2, ops!.ForwardAuth!.SessionHours);
        Assert.Equal("https://ops.example.com:8443", ResourceCatalog.SiteOrigin(ops));
        Assert.False(ops.AllowsUser(isAdmin: false));

        // 普通资源、不存在的、空的都不算 forward-auth 站点
        Assert.Null(cat.FindForwardAuth("gitea-web"));
        Assert.Null(cat.FindForwardAuth("nope"));
        Assert.Null(cat.FindForwardAuth(""));
        Assert.Null(cat.FindForwardAuth(null));

        Assert.Equal(new[] { "https://docs.example.com", "https://ops.example.com:8443" }, cat.ForwardAuthOrigins());
    }

    [Theory]
    [InlineData("docs.example.com", "docs")]
    [InlineData("DOCS.example.com", "docs")]
    [InlineData("docs.example.com:443", "docs")]
    [InlineData("docs.example.com:8443", null)]
    [InlineData("ops.example.com:8443", "ops")]
    [InlineData("ops.example.com", null)]          // 站点登记了非默认端口，不带端口的 Host 不算
    [InlineData("git.example.com", null)]          // 普通资源
    [InlineData("evil-docs.example.com", null)]
    [InlineData("", null)]
    public void Catalog_FindByHost(string host, string? expectedAud) =>
        Assert.Equal(expectedAud, Load(TwoSites).FindForwardAuthByHost(new HostString(host))?.Aud);

    [Fact]
    public void Catalog_ForwardAuthStaysOutOfOAuth()
    {
        var cat = Load(TwoSites);
        // 站点的 "access" 不进发现文档；gitea-web 自己也有一个同名 scope，照常在
        Assert.Equal(new[] { "openid", "access" }, cat.AllScopes());
        // DCR 客户端按 scope 反推资源时拉不到站点
        Assert.Equal(new[] { "gitea-web" }, cat.ResourcesForScopes(new[] { "access" }).Select(r => r.Aud));
    }

    [Fact]
    public void Catalog_FindByUrl_NeverReturnsForwardAuthSites()
    {
        // FindByUrl 是 /authorize、/token（换码与刷新）认 resource 的唯一入口
        var cat = Load("""
            [
              { "aud": "docs", "resource_url": "https://apps.example.com", "forward_auth": {} },
              { "aud": "mcp", "resource_url": "https://apps.example.com/tools", "scopes": ["read:mcp"] }
            ]
            """);
        Assert.Null(cat.FindByUrl("https://apps.example.com"));
        Assert.Null(cat.FindByUrl("https://apps.example.com/"));
        Assert.Null(cat.FindByUrl("https://apps.example.com/anything"));
        // 站点条目排在前面，也不遮住挂在同一来源下面的 OAuth 资源（含带 /mcp 子路径的写法）
        Assert.Equal("mcp", cat.FindByUrl("https://apps.example.com/tools")?.Aud);
        Assert.Equal("mcp", cat.FindByUrl("https://apps.example.com/tools/mcp")?.Aud);
        Assert.Equal("docs", cat.FindForwardAuth("docs")?.Aud);
    }

    [Theory]
    [InlineData("""[{ "aud": "s", "resource_url": "https://s.example.com/app", "forward_auth": {} }]""", "不带路径")]
    [InlineData("""[{ "aud": "s", "resource_url": "https://s.example.com/?a=1", "forward_auth": {} }]""", "不带路径")]
    [InlineData("""[{ "aud": "s", "resource_url": "https://u:p@s.example.com", "forward_auth": {} }]""", "不带路径")]
    [InlineData("""[{ "aud": "s", "resource_url": "ftp://s.example.com", "forward_auth": {} }]""", "不带路径")]
    [InlineData("""[{ "aud": "s", "resource_url": "s.example.com", "forward_auth": {} }]""", "不带路径")]
    [InlineData("""[{ "aud": "s", "resource_url": "https://s.example.com", "forward_auth": { "session_hours": 0 } }]""", "session_hours")]
    [InlineData("""[{ "aud": "s", "resource_url": "https://s.example.com", "forward_auth": { "session_hours": 721 } }]""", "session_hours")]
    [InlineData("""
        [{ "aud": "a", "resource_url": "https://s.example.com", "forward_auth": {} },
         { "aud": "b", "resource_url": "https://S.example.com/", "forward_auth": {} }]
        """, "同一个来源")]
    [InlineData("""
        [{ "aud": "a", "resource_url": "https://a.example.com", "scopes": ["x"] },
         { "aud": "a", "resource_url": "https://b.example.com", "forward_auth": {} }]
        """, "aud 重复")]
    [InlineData("""
        [{ "aud": "s", "resource_url": "https://s.example.com", "forward_auth": {},
           "proxy": { "upstream": "http://up:1", "bearer_env": "X" } }]
        """, "不能同时配")]
    public void Catalog_BadForwardAuthEntry_FailsStartup(string json, string expectedMessagePart)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Load(json));
        Assert.Contains(expectedMessagePart, ex.Message);
    }

    // ---------- /logout 回跳白名单 ----------

    [Fact]
    public void EndSession_SiteOriginsOnlyCountWithoutClientId()
    {
        var db = new AuthDb(new AuthOptions { Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}" });
        db.EnsureCreated();
        var clients = new ClientRepository(db);
        clients.Insert("immich", "h", "Immich", new[] { "https://photos.example.com/auth/login" },
            "client_secret_post", autoRegistered: false);
        var sites = new[] { "https://docs.example.com" };

        Assert.Equal("https://docs.example.com/",
            EndSession.ResolveRedirect("https://docs.example.com/", null, null, clients, sites));
        Assert.Equal("https://docs.example.com/x?state=s1",
            EndSession.ResolveRedirect("https://docs.example.com/x", null, "s1", clients, sites));
        // 带了 client_id 就只认那个客户端登记的来源
        Assert.Null(EndSession.ResolveRedirect("https://docs.example.com/", "immich", null, clients, sites));
        // 别的来源照旧不放
        Assert.Null(EndSession.ResolveRedirect("https://docs.example.com.evil.example/", null, null, clients, sites));
        Assert.Null(EndSession.ResolveRedirect("http://docs.example.com/", null, null, clients, sites));
        // 没传站点清单 = 原行为
        Assert.Null(EndSession.ResolveRedirect("https://docs.example.com/", null, null, clients));
    }
}

/// <summary>
/// forward-auth 走真实管线。反向代理的角色由测试扮演：把「访客对站点的请求」换成对
/// <c>/forward-auth/verify?aud=…</c> 的 GET，带上原方法 / 原路径和访客的 cookie。
/// 一个 HttpClient = 一个浏览器（cookie 按域名分开存），站点与本服务是两个域名。
/// </summary>
public class ForwardAuthPipelineTests : IClassFixture<NasAuthAppFactory>
{
    private const string Auth = "https://auth.example.com"; // = Auth:Issuer
    private const string Docs = "https://docs.example.com"; // resources.example.json: docs-site
    private const string Ops = "https://ops.example.com";   // resources.example.json: ops-dashboard（admin_only）

    private readonly NasAuthAppFactory _app;

    public ForwardAuthPipelineTests(NasAuthAppFactory app) => _app = app;

    private HttpClient Browser() => _app.Client(Auth);

    private static FormUrlEncodedContent Form(params (string K, string V)[] kv) =>
        new(kv.Select(p => new KeyValuePair<string, string>(p.K, p.V)));

    private static HttpRequestMessage Verify(string site, string aud, string uri = "/", string? mode = "navigate",
        string method = "GET", string? cookie = null, string? forwardedHost = null,
        params (string K, string V)[] headers)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{site}/forward-auth/verify?aud={aud}");
        req.Headers.TryAddWithoutValidation("X-Forwarded-Method", method);
        req.Headers.TryAddWithoutValidation("X-Forwarded-Uri", uri);
        if (mode is not null) req.Headers.TryAddWithoutValidation("Sec-Fetch-Mode", mode);
        if (cookie is not null) req.Headers.TryAddWithoutValidation("Cookie", cookie);
        if (forwardedHost is not null) req.Headers.TryAddWithoutValidation("X-Forwarded-Host", forwardedHost);
        foreach (var (k, v) in headers) req.Headers.TryAddWithoutValidation(k, v);
        return req;
    }

    private static Task<HttpResponseMessage> SignIn(HttpClient c, string user, string password, string returnUrl = "/account") =>
        c.PostAsync($"{Auth}/login", Form(("username", user), ("password", password), ("return_url", returnUrl)));

    private void CreateUser(string id, string password, params string[] grantedAuds)
    {
        using var scope = _app.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserRepository>();
        users.Create(id, id, PasswordHasher.Hash(password), mustChangePassword: false,
            email: $"{id}@example.com", allowPasswordLogin: true);
        var grants = scope.ServiceProvider.GetRequiredService<UserResourceRepository>();
        foreach (var aud in grantedAuds) grants.Upsert(id, aud, ResourceCatalog.ForwardAuthScope);
    }

    private T WithScope<T>(Func<IServiceProvider, T> f)
    {
        using var scope = _app.Services.CreateScope();
        return f(scope.ServiceProvider);
    }

    private static string SetCookieValue(HttpResponseMessage r, string name) =>
        r.Headers.GetValues("Set-Cookie").Single(v => v.StartsWith(name + "=", StringComparison.Ordinal))
            .Split(';')[0][(name.Length + 1)..];

    /// <summary>已登录的浏览器走完「被拦 → start → 回调」，返回回调的响应（成功时是 302 回原地址并种下站点 cookie）。</summary>
    private static async Task<HttpResponseMessage> PassGate(HttpClient browser, string site, string aud, string uri = "/")
    {
        var blocked = await browser.SendAsync(Verify(site, aud, uri));
        Assert.Equal(HttpStatusCode.Redirect, blocked.StatusCode);
        var start = await browser.GetAsync(blocked.Headers.Location);
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        Assert.StartsWith($"{site}/.nas-auth/callback?ticket=", start.Headers.Location!.OriginalString);
        return await browser.GetAsync(start.Headers.Location);
    }

    // ---------- 主流程 ----------

    [Fact]
    public async Task FullFlow_Blocked_SignIn_Callback_ThenAllowed()
    {
        var browser = Browser();

        // 1. 没有站点 cookie：页面导航被送去本服务，同时在站点域名上种一张临时的 state cookie
        var blocked = await browser.SendAsync(Verify(Docs, "docs-site", "/layout.html?room=1"));
        Assert.Equal(HttpStatusCode.Redirect, blocked.StatusCode);
        var startUrl = blocked.Headers.Location!.OriginalString;
        Assert.StartsWith($"{Auth}/forward-auth/start?aud=docs-site&state=", startUrl);
        Assert.Contains("no-store", blocked.Headers.CacheControl!.ToString());
        var stateCookie = blocked.Headers.GetValues("Set-Cookie").Single(v => v.StartsWith("__Host-nas-auth-fa-state=", StringComparison.Ordinal));
        foreach (var attr in new[] { "secure", "httponly", "samesite=lax", "path=/" })
            Assert.Contains(attr, stateCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("domain=", stateCookie, StringComparison.OrdinalIgnoreCase);

        // 2. 本服务上没登录：去登录页，return_url 是 start 的完整地址
        var needLogin = await browser.GetAsync(startUrl);
        Assert.Equal(HttpStatusCode.Redirect, needLogin.StatusCode);
        var loginUrl = needLogin.Headers.Location!.OriginalString;
        Assert.Contains("/login?return_url=", loginUrl);
        var startPath = startUrl[Auth.Length..];
        Assert.Contains(Uri.EscapeDataString(startPath), loginUrl);

        // 3. 登录后原样回到 start，start 带一次性票据跳回站点的回调
        var signedIn = await SignIn(browser, NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword, startPath);
        Assert.Equal(HttpStatusCode.Redirect, signedIn.StatusCode);
        Assert.Equal(startPath, signedIn.Headers.Location!.OriginalString);
        var start = await browser.GetAsync(startUrl);
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        var callbackUrl = start.Headers.Location!.OriginalString;
        Assert.StartsWith($"{Docs}/.nas-auth/callback?ticket=", callbackUrl);

        // 4. 回调：种站点 cookie，回到最初要去的地址
        var callback = await browser.GetAsync(callbackUrl);
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("/layout.html?room=1", callback.Headers.Location!.OriginalString);
        var siteCookie = callback.Headers.GetValues("Set-Cookie").Single(v => v.StartsWith("__Host-nas-auth-fa=", StringComparison.Ordinal));
        foreach (var attr in new[] { "secure", "httponly", "samesite=lax", "path=/", "max-age=43200" })
            Assert.Contains(attr, siteCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("domain=", siteCookie, StringComparison.OrdinalIgnoreCase);

        // 5. 之后反向代理每次来问都放行，并拿到身份头
        var allowed = await browser.SendAsync(Verify(Docs, "docs-site", "/layout.html?room=1"));
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        Assert.Equal(NasAuthAppFactory.AdminUser, allowed.Headers.GetValues("X-Auth-User").Single());
        Assert.True(allowed.Headers.Contains("X-Auth-Email")); // 没邮箱也回（空串），好盖掉访客自带的
        // 页面里的 fetch、图片也放行
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(Verify(Docs, "docs-site", "/api", mode: "cors"))).StatusCode);

        // 6. 票据只能用一次：同一个回调地址再打一遍不行（state cookie 还在，挡住它的是票据）
        var replay = await browser.GetAsync(callbackUrl);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.False(replay.Headers.Contains("Set-Cookie"));

        // 审计里有这次放行
        var row = _app.Services.GetRequiredService<AuditRepository>()
            .Query(events: new[] { "forward_auth" }, userId: NasAuthAppFactory.AdminUser).First();
        Assert.Equal(1, row.success);
        Assert.Contains("resource=docs-site", row.detail);
    }

    [Fact]
    public async Task AlreadySignedIn_PassesSilently_NoConsentPage()
    {
        var browser = Browser();
        await SignIn(browser, NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword);
        var callback = await PassGate(browser, Docs, "docs-site", "/deep/link");
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("/deep/link", callback.Headers.Location!.OriginalString);
    }

    [Theory]
    [InlineData("cors", "GET")]      // 页面里的 fetch
    [InlineData("no-cors", "GET")]   // 图片 / 脚本
    [InlineData("navigate", "POST")] // 表单提交
    public async Task NotAPageNavigation_Gets401_NotARedirect(string mode, string method)
    {
        var r = await Browser().SendAsync(Verify(Docs, "docs-site", "/api/data", mode, method));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.False(r.Headers.Contains("Set-Cookie"));
    }

    [Theory]
    [InlineData("nope")]
    [InlineData("gitea-web")] // 存在，但不是 forward-auth 站点
    [InlineData("")]
    public async Task UnknownAud_FailsClosed(string aud)
    {
        var browser = Browser();
        await SignIn(browser, NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword);
        Assert.Equal(HttpStatusCode.NotFound, (await browser.SendAsync(Verify(Docs, aud))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await browser.GetAsync($"{Auth}/forward-auth/start?aud={aud}&state=x")).StatusCode);
    }

    // ---------- 授权 ----------

    [Fact]
    public async Task UserWithoutGrant_Denied_UntilGranted_AndRevocationIsImmediate()
    {
        const string bob = "bob-fa-grant", pwd = "bob-password-123";
        CreateUser(bob, pwd);
        var browser = Browser();
        await SignIn(browser, bob, pwd);

        // 登录了但没被授权：停在本服务的 403 页，不发票据
        var blocked = await browser.SendAsync(Verify(Docs, "docs-site"));
        var startUrl = blocked.Headers.Location!;
        var denied = await browser.GetAsync(startUrl);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        var html = await denied.Content.ReadAsStringAsync();
        Assert.Contains(bob, html);
        Assert.Contains("Family docs", html);
        // 「换个账号」：退出本服务后回到站点
        Assert.Contains("/logout?post_logout_redirect_uri=" + Uri.EscapeDataString(Docs + "/"), html);
        var audit = _app.Services.GetRequiredService<AuditRepository>();
        Assert.Equal(0, audit.Query(events: new[] { "forward_auth" }, userId: bob).First().success);

        // 管理员勾上之后同一个地址就通了
        WithScope(sp => { sp.GetRequiredService<UserResourceRepository>().Upsert(bob, "docs-site", "access"); return 0; });
        var start = await browser.GetAsync(startUrl);
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync(start.Headers.Location)).StatusCode);
        var ok = await browser.SendAsync(Verify(Docs, "docs-site"));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal(bob, ok.Headers.GetValues("X-Auth-User").Single());
        Assert.Equal($"{bob}@example.com", ok.Headers.GetValues("X-Auth-Email").Single());

        // 撤销授权：站点 cookie 还没到期也立刻不放
        WithScope(sp => { sp.GetRequiredService<UserResourceRepository>().Delete(bob, "docs-site"); return 0; });
        Assert.Equal(HttpStatusCode.Redirect, (await browser.SendAsync(Verify(Docs, "docs-site"))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.SendAsync(Verify(Docs, "docs-site", mode: "cors"))).StatusCode);

        // 再授回来，原来那张 cookie 接着用
        WithScope(sp => { sp.GetRequiredService<UserResourceRepository>().Upsert(bob, "docs-site", "access"); return 0; });
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(Verify(Docs, "docs-site"))).StatusCode);
    }

    [Fact]
    public async Task AdminOnlySite_DeniedForNonAdmin_EvenWithGrantRow()
    {
        const string carol = "carol-fa-adminonly", pwd = "carol-password-123";
        CreateUser(carol, pwd, "ops-dashboard"); // 硬塞一条授权行
        var browser = Browser();
        await SignIn(browser, carol, pwd);

        var blocked = await browser.SendAsync(Verify(Ops, "ops-dashboard"));
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.GetAsync(blocked.Headers.Location)).StatusCode);

        // 管理员进得去，cookie 寿命按这个资源配的 1 小时
        var admin = Browser();
        await SignIn(admin, NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword);
        var callback = await PassGate(admin, Ops, "ops-dashboard");
        Assert.Contains("max-age=3600", string.Join(';', callback.Headers.GetValues("Set-Cookie")), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ForcedSignOutOrDeletedUser_KillsSiteSession()
    {
        const string dave = "dave-fa-revoke", pwd = "dave-password-123";
        CreateUser(dave, pwd, "docs-site");
        var browser = Browser();
        await SignIn(browser, dave, pwd);
        await PassGate(browser, Docs, "docs-site");
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(Verify(Docs, "docs-site"))).StatusCode);

        // 强制下线 / 改密 / 退出其他设备 = 会话版本 +1
        WithScope(sp => sp.GetRequiredService<UserRepository>().BumpSessionVersion(dave));
        Assert.Equal(HttpStatusCode.Redirect, (await browser.SendAsync(Verify(Docs, "docs-site"))).StatusCode);

        // 重新登录后拿到新的站点 cookie；删掉用户后同样立刻失效
        await SignIn(browser, dave, pwd);
        await PassGate(browser, Docs, "docs-site");
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(Verify(Docs, "docs-site"))).StatusCode);
        WithScope(sp => { sp.GetRequiredService<UserRepository>().Delete(dave); return 0; });
        Assert.Equal(HttpStatusCode.Redirect, (await browser.SendAsync(Verify(Docs, "docs-site"))).StatusCode);
    }

    // ---------- 站点之间互不通用 ----------

    [Fact]
    public async Task SiteCookieAndTicket_AreBoundToTheirSite()
    {
        const string erin = "erin-fa-cross", pwd = "erin-password-123";
        CreateUser(erin, pwd, "docs-site"); // 只有 docs，没有 ops
        var browser = Browser();
        await SignIn(browser, erin, pwd);

        var blocked = await browser.SendAsync(Verify(Docs, "docs-site"));
        var start = await browser.GetAsync(blocked.Headers.Location);
        var docsCallbackUrl = start.Headers.Location!.OriginalString;

        // docs 的票据拿到 ops 的回调上：不认，也不种 cookie
        var wrongSite = await browser.GetAsync(docsCallbackUrl.Replace(Docs, Ops));
        Assert.Equal(HttpStatusCode.BadRequest, wrongSite.StatusCode);
        Assert.False(wrongSite.Headers.Contains("Set-Cookie"));
        // 回调只存在于登记过的站点域名上
        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync(docsCallbackUrl.Replace(Docs, Auth))).StatusCode);

        // 正主照常完成，拿到 docs 的站点 cookie（上面两次拿错地方的尝试没有把票据废掉）
        var callback = await browser.GetAsync(docsCallbackUrl);
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);

        // 另一个浏览器事后捡到这个回调链接：票据用过了，也没有发起时种下的 state cookie
        var thief = await Browser().GetAsync(docsCallbackUrl);
        Assert.Equal(HttpStatusCode.BadRequest, thief.StatusCode);
        Assert.False(thief.Headers.Contains("Set-Cookie"));
        var docsCookie = "__Host-nas-auth-fa=" + SetCookieValue(callback, "__Host-nas-auth-fa");

        // 把 docs 的 cookie 带到 ops 去：反向代理问的是 aud=ops-dashboard，不放
        var onOps = await Browser().SendAsync(Verify(Ops, "ops-dashboard", cookie: docsCookie));
        Assert.Equal(HttpStatusCode.Redirect, onOps.StatusCode);
        // 自带 X-Forwarded-Host 冒充 docs 也没用：站点只认反向代理写死的 aud
        var spoofed = await Browser().SendAsync(Verify(Ops, "ops-dashboard", cookie: docsCookie, forwardedHost: "docs.example.com"));
        Assert.Equal(HttpStatusCode.Redirect, spoofed.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await Browser().SendAsync(Verify(Ops, "ops-dashboard", mode: "cors", cookie: docsCookie))).StatusCode);

        // 主会话 cookie 的名字换成站点 cookie 的名字也混不过去（purpose 不同，解不开）
        var junk = await Browser().SendAsync(Verify(Docs, "docs-site", cookie: "__Host-nas-auth-fa=" + new string('A', 200)));
        Assert.Equal(HttpStatusCode.Redirect, junk.StatusCode);
    }

    [Fact]
    public async Task StolenSiteCookie_OnlyOpensItsOwnSite_EvenIfTheUserMayEnterBoth()
    {
        // 管理员两个站都进得去。docs 的站点 cookie 泄漏了：拿它去 ops 不行 ——
        // 实时授权检查挡不住这种情况（这个人确实有 ops 的权限），靠的是 cookie 里记着它属于哪个站
        var admin = Browser();
        await SignIn(admin, NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword);
        var docsCookie = "__Host-nas-auth-fa=" + SetCookieValue(await PassGate(admin, Docs, "docs-site"), "__Host-nas-auth-fa");
        var opsCookie = "__Host-nas-auth-fa=" + SetCookieValue(await PassGate(admin, Ops, "ops-dashboard"), "__Host-nas-auth-fa");

        Assert.Equal(HttpStatusCode.OK, (await Browser().SendAsync(Verify(Docs, "docs-site", cookie: docsCookie))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Browser().SendAsync(Verify(Ops, "ops-dashboard", cookie: opsCookie))).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await Browser().SendAsync(Verify(Ops, "ops-dashboard", cookie: docsCookie))).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await Browser().SendAsync(Verify(Docs, "docs-site", cookie: opsCookie))).StatusCode);
    }

    [Fact]
    public async Task CallbackLinkSnatchedFirst_IsUselessToTheThief_AndBurnsTheTicket()
    {
        var browser = Browser();
        await SignIn(browser, NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword);
        var blocked = await browser.SendAsync(Verify(Docs, "docs-site", "/wanted"));
        var start = await browser.GetAsync(blocked.Headers.Location);
        var callbackUrl = start.Headers.Location!.OriginalString;

        // 抢在正主之前用：没有那个浏览器的 state cookie，种不上会话
        var thief = await Browser().GetAsync(callbackUrl);
        Assert.Equal(HttpStatusCode.BadRequest, thief.StatusCode);
        Assert.False(thief.Headers.Contains("Set-Cookie"));

        // 票据一经出示就作废：正主这次也用不了，停在重试页……
        var owner = await browser.GetAsync(callbackUrl);
        Assert.Equal(HttpStatusCode.BadRequest, owner.StatusCode);
        // ……点重试重新走一遍就好（本服务上还登着）
        var retry = await PassGate(browser, Docs, "docs-site", "/wanted");
        Assert.Equal("/wanted", retry.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task TicketIssuedForSomeoneElsesState_CannotLogTheVictimInAsTheAttacker()
    {
        const string mallory = "mallory-fa-csrf", pwd = "mallory-password-123";
        CreateUser(mallory, pwd, "docs-site");

        // 受害者的浏览器被拦了一次，它的 state 泄漏给了攻击者（它的 state cookie 还在自己浏览器里）
        var victim = Browser();
        var victimBlocked = await victim.SendAsync(Verify(Docs, "docs-site"));
        var victimState = victimBlocked.Headers.Location!.OriginalString.Split("state=")[1];

        // 攻击者用自己的账号、自己的 state 换到一张自己的票据
        var attacker = Browser();
        await SignIn(attacker, mallory, pwd);
        var attackerBlocked = await attacker.SendAsync(Verify(Docs, "docs-site"));
        var attackerStart = await attacker.GetAsync(attackerBlocked.Headers.Location);
        var attackerTicket = attackerStart.Headers.Location!.OriginalString.Split("ticket=")[1].Split("&state=")[0];

        // 把「自己的票据 + 受害者的 state」拼成回调链接发给受害者点：state 与受害者的 cookie 对得上，但票据不是为它签的
        var forged = await victim.GetAsync($"{Docs}/.nas-auth/callback?ticket={attackerTicket}&state={victimState}");
        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
        Assert.False(forged.Headers.Contains("Set-Cookie"));
        Assert.Equal(HttpStatusCode.Redirect, (await victim.SendAsync(Verify(Docs, "docs-site"))).StatusCode);

        // 反过来：诱导已登录的受害者带着攻击者的 state 去换票据 —— 回调落在受害者浏览器里失败，票据随即作废
        var signedInVictim = Browser();
        await SignIn(signedInVictim, NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword);
        var attackerState = attackerBlocked.Headers.Location!.OriginalString.Split("state=")[1];
        var lured = await signedInVictim.GetAsync($"{Auth}/forward-auth/start?aud=docs-site&state={attackerState}");
        var luredCallback = lured.Headers.Location!.OriginalString;
        Assert.Equal(HttpStatusCode.BadRequest, (await signedInVictim.GetAsync(luredCallback)).StatusCode);
        // 攻击者事后从日志 / 地址栏拿到这个链接，在自己的浏览器里（state cookie 对得上）也换不到受害者的会话
        var stolen = await attacker.GetAsync(luredCallback);
        Assert.Equal(HttpStatusCode.BadRequest, stolen.StatusCode);
        Assert.False(stolen.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task SiblingOriginRidingTheSiteCookie_IsRefused()
    {
        var browser = Browser();
        await SignIn(browser, NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword);
        await PassGate(browser, Docs, "docs-site");

        async Task<HttpStatusCode> Ask(string method, params (string K, string V)[] headers) =>
            (await browser.SendAsync(Verify(Docs, "docs-site", "/data.js", mode: null, method: method, headers: headers))).StatusCode;

        // 站点自己的页面发的、地址栏输的：放
        Assert.Equal(HttpStatusCode.OK, await Ask("GET", ("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "cors"), ("Sec-Fetch-Dest", "empty")));
        Assert.Equal(HttpStatusCode.OK, await Ask("POST", ("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "cors"), ("Sec-Fetch-Dest", "empty")));
        Assert.Equal(HttpStatusCode.OK, await Ask("GET", ("Sec-Fetch-Site", "none"), ("Sec-Fetch-Mode", "navigate"), ("Sec-Fetch-Dest", "document")));
        // 从兄弟子域的导航页、外站点链接进来：放
        Assert.Equal(HttpStatusCode.OK, await Ask("GET", ("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Mode", "navigate"), ("Sec-Fetch-Dest", "document")));
        Assert.Equal(HttpStatusCode.OK, await Ask("GET", ("Sec-Fetch-Site", "cross-site"), ("Sec-Fetch-Mode", "navigate"), ("Sec-Fetch-Dest", "document")));

        // 兄弟子域的页面借这个浏览器的 cookie：<script src>、fetch、iframe、表单 POST 都不放
        Assert.Equal(HttpStatusCode.Forbidden, await Ask("GET", ("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Mode", "no-cors"), ("Sec-Fetch-Dest", "script")));
        Assert.Equal(HttpStatusCode.Forbidden, await Ask("GET", ("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Mode", "cors"), ("Sec-Fetch-Dest", "empty")));
        Assert.Equal(HttpStatusCode.Forbidden, await Ask("GET", ("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Mode", "navigate"), ("Sec-Fetch-Dest", "iframe")));
        Assert.Equal(HttpStatusCode.Forbidden, await Ask("POST", ("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Mode", "navigate"), ("Sec-Fetch-Dest", "document")));
        // 没有 Sec-Fetch-Site 的老浏览器：写请求按 Origin 判
        Assert.Equal(HttpStatusCode.Forbidden, await Ask("POST", ("Origin", "https://git.example.com")));
        Assert.Equal(HttpStatusCode.OK, await Ask("POST", ("Origin", Docs)));

        // 被拒的响应不带身份头
        var refused = await browser.SendAsync(Verify(Docs, "docs-site", "/data.js", mode: "no-cors",
            headers: new[] { ("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Dest", "script") }));
        Assert.False(refused.Headers.Contains("X-Auth-User"));
        // 没有站点 cookie 时这条规则不参与：照旧是「没登录」
        Assert.Equal(HttpStatusCode.Unauthorized, (await Browser().SendAsync(Verify(Docs, "docs-site", "/data.js", mode: "no-cors",
            headers: new[] { ("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Dest", "script") }))).StatusCode);
    }

    [Fact]
    public async Task ExpiredOrForgedState_RestartsFromTheSite()
    {
        var browser = Browser();
        await SignIn(browser, NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword);
        var r = await browser.GetAsync($"{Auth}/forward-auth/start?aud=docs-site&state=forged");
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal(Docs + "/", r.Headers.Location!.OriginalString);

        // docs 的 state 拿去换 ops 的票据：不认，回 ops 首页重新来
        var blocked = await browser.SendAsync(Verify(Docs, "docs-site"));
        var docsState = blocked.Headers.Location!.OriginalString.Split("state=")[1];
        var mixed = await browser.GetAsync($"{Auth}/forward-auth/start?aud=ops-dashboard&state={docsState}");
        Assert.Equal(Ops + "/", mixed.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task ParallelTabs_ShareOneStateCookie()
    {
        var browser = Browser();
        await SignIn(browser, NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword);

        // 两个标签页先后被拦，各拿到一份 state，共用一个随机数；谁先完成回调都不影响另一个
        var tab1 = await browser.SendAsync(Verify(Docs, "docs-site", "/one"));
        var tab2 = await browser.SendAsync(Verify(Docs, "docs-site", "/two"));
        Assert.Equal(SetCookieValue(tab1, "__Host-nas-auth-fa-state"), SetCookieValue(tab2, "__Host-nas-auth-fa-state"));

        var start2 = await browser.GetAsync(tab2.Headers.Location);
        var start1 = await browser.GetAsync(tab1.Headers.Location);
        var cb1 = await browser.GetAsync(start1.Headers.Location);
        Assert.Equal("/one", cb1.Headers.Location!.OriginalString);
        var cb2 = await browser.GetAsync(start2.Headers.Location);
        Assert.Equal("/two", cb2.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(Verify(Docs, "docs-site", "/two"))).StatusCode);
    }

    // ---------- 回调失败页、退出 ----------

    [Fact]
    public async Task CallbackFailure_IsSelfContainedPage_WithRetryLink()
    {
        var r = await Browser().GetAsync($"{Docs}/.nas-auth/callback?ticket=x&state=y");
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains("no-store", r.Headers.CacheControl!.ToString());
        var html = await r.Content.ReadAsStringAsync();
        // 这一页显示在站点的域名上：不能引用本服务的样式 / 脚本（那边没有，还会被站点自己的 forward-auth 拦）
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<link", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("src=", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("href=\"/\"", html);
    }

    [Fact]
    public async Task SiteLogout_ClearsSiteCookie_ThenEndsSsoSession_ThenReturnsToSite()
    {
        var browser = Browser();
        await SignIn(browser, NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword);
        await PassGate(browser, Docs, "docs-site");
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(Verify(Docs, "docs-site"))).StatusCode);

        var siteLogout = await browser.GetAsync($"{Docs}/.nas-auth/logout");
        Assert.Equal(HttpStatusCode.Redirect, siteLogout.StatusCode);
        var ssoLogout = siteLogout.Headers.Location!.OriginalString;
        Assert.Equal($"{Auth}/logout?post_logout_redirect_uri={Uri.EscapeDataString(Docs + "/")}", ssoLogout);
        Assert.Contains("__Host-nas-auth-fa=;", string.Join('\n', siteLogout.Headers.GetValues("Set-Cookie")));

        // 本服务退出后回到站点（来源在 resources.json 里登记过）
        var back = await browser.GetAsync(ssoLogout);
        Assert.Equal(Docs + "/", back.Headers.Location!.OriginalString);

        // 站点没 cookie 了、本服务也没会话了：再访问要重新登录
        var blocked = await browser.SendAsync(Verify(Docs, "docs-site"));
        Assert.Equal(HttpStatusCode.Redirect, blocked.StatusCode);
        var needLogin = await browser.GetAsync(blocked.Headers.Location);
        Assert.Contains("/login?return_url=", needLogin.Headers.Location!.OriginalString);

        // 退出端点只在登记过的站点域名上；别的来源不能借 /logout 跳走
        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync($"{Auth}/.nas-auth/logout")).StatusCode);
        var evil = await browser.GetAsync($"{Auth}/logout?post_logout_redirect_uri={Uri.EscapeDataString("https://evil.example/")}");
        Assert.StartsWith("/login", evil.Headers.Location!.OriginalString);
    }

    // ---------- 不参与 OAuth ----------

    [Fact]
    public async Task ForwardAuthSites_AreNotOAuthResources()
    {
        var c = Browser();
        foreach (var doc in new[] { "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration" })
        {
            using var json = JsonDocument.Parse(await c.GetStringAsync(Auth + doc));
            var scopes = json.RootElement.GetProperty("scopes_supported").EnumerateArray().Select(e => e.GetString()).ToList();
            Assert.DoesNotContain(ResourceCatalog.ForwardAuthScope, scopes);
        }

        // 预置客户端显式点名站点当 resource：不在白名单
        var r = await c.GetAsync($"{Auth}/authorize?response_type=code&client_id=gitea-web" +
                                 $"&redirect_uri={Uri.EscapeDataString("https://git.example.com/user/oauth2/nas-auth/callback")}" +
                                 $"&resource={Uri.EscapeDataString(Docs)}&scope=access&state=s");
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains("resource not in allowlist", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task AdminAppsPage_LabelsForwardAuthSites()
    {
        var browser = Browser();
        await SignIn(browser, NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword);
        var html = await browser.GetStringAsync($"{Auth}/admin/apps");
        Assert.Contains("Family docs", html);
        Assert.Contains("Forward-auth", html);
    }
}
