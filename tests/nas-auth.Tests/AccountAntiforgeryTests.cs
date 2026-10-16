using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// /account、/admin、/external/{provider}/bind 写请求的 antiforgery token（external-auth.md §二十三）。
/// 走真实管线：CrossOriginGuard 放行的同源请求，没带令牌照样 403；表单隐藏字段与 X-CSRF-TOKEN 头两种带法都认；
/// 登录与协议端点不受影响。
/// </summary>
public class AccountAntiforgeryTests : IClassFixture<NasAuthAppFactory>
{
    private readonly NasAuthAppFactory _app;

    public AccountAntiforgeryTests(NasAuthAppFactory app) => _app = app;

    private static FormUrlEncodedContent Form(params (string K, string V)[] kv) =>
        new(kv.Select(p => new KeyValuePair<string, string>(p.K, p.V)));

    /// <summary>默认扮演本站页面发的请求（Sec-Fetch-Site: same-origin），CrossOriginGuard 放行，只剩令牌这一关。</summary>
    private static HttpRequestMessage Post(string path, HttpContent? body = null, string? token = null,
        string secFetchSite = "same-origin")
    {
        var req = new HttpRequestMessage(HttpMethod.Post, path) { Content = body ?? Form() };
        req.Headers.TryAddWithoutValidation("Sec-Fetch-Site", secFetchSite);
        if (token is not null) req.Headers.TryAddWithoutValidation(AntiforgeryGuard.HeaderName, token);
        return req;
    }

    private async Task<HttpClient> LoggedIn(string user = NasAuthAppFactory.AdminUser, string password = NasAuthAppFactory.AdminPassword)
    {
        var c = _app.Client();
        var r = await c.PostAsync("/login", Form(("username", user), ("password", password), ("return_url", "/account")));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        return c;
    }

    private string DisplayName(string userId = NasAuthAppFactory.AdminUser)
    {
        using var scope = _app.Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<UserRepository>().GetById(userId)!.display_name ?? "";
    }

    /// <summary>页面里 action=<paramref name="action"/> 那个表单的隐藏令牌字段。</summary>
    private static string FormToken(string html, string action)
    {
        var m = Regex.Match(html,
            $"<form[^>]*action='{Regex.Escape(action)}'[^>]*><input type='hidden' name='{AntiforgeryGuard.FormFieldName}' value='([^']+)'>");
        Assert.True(m.Success, $"{action} 表单里没有令牌字段");
        return WebUtility.HtmlDecode(m.Groups[1].Value);
    }

    // ---------- 没带令牌：拒 ----------

    [Theory]
    [InlineData("/account/profile")]
    [InlineData("/account/revoke")]
    [InlineData("/account/sessions/revoke-others")]
    [InlineData("/account/change-password")]
    [InlineData("/account/bindings/unbind")]
    [InlineData("/account/avatar/remove")]
    [InlineData("/admin/users/create")]
    [InlineData("/admin/password-login")]
    [InlineData("/admin/users/avatar/remove")]
    [InlineData("/external/google/bind")]
    public async Task NoToken_SameOrigin_Rejected(string path)
    {
        var c = await LoggedIn();
        await c.GetAsync("/account"); // 浏览器里已经有 antiforgery cookie，只是请求里没带令牌
        var r = await c.SendAsync(Post(path, Form(("display_name", "should-not-stick"))));
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        Assert.Contains("CSRF token", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task NoToken_NothingChanges()
    {
        var c = await LoggedIn();
        var before = DisplayName();
        await c.GetAsync("/account");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await c.SendAsync(Post("/account/profile", Form(("display_name", "csrf-forged"))))).StatusCode);
        Assert.Equal(before, DisplayName());
    }

    [Fact]
    public async Task GarbageToken_Rejected()
    {
        var c = await LoggedIn();
        await c.GetAsync("/account");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await c.SendAsync(Post("/account/profile", Form(("display_name", "x")), token: "CfDJ8garbage"))).StatusCode);
    }

    // ---------- 带对令牌：放 ----------

    [Fact]
    public async Task FormField_FromRenderedPage_Accepted()
    {
        var c = await LoggedIn();
        var html = await c.GetStringAsync("/account");
        var token = FormToken(html, "/account/profile");
        var r = await c.SendAsync(Post("/account/profile",
            Form(("display_name", "表单带令牌"), (AntiforgeryGuard.FormFieldName, token))));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("表单带令牌", DisplayName());
    }

    [Fact]
    public async Task Header_LikeFetch_Accepted()
    {
        var c = await LoggedIn();
        var token = await HttpPipelineTests.CsrfToken(c);
        var r = await c.SendAsync(Post("/account/profile", Form(("display_name", "头带令牌")), token: token));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("头带令牌", DisplayName());

        // 没有表单体的 fetch（例如 JSON）也认头
        var json = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");
        Assert.Equal(HttpStatusCode.Redirect, (await c.SendAsync(Post("/account/avatar/remove", json, token: token))).StatusCode);
    }

    [Fact]
    public async Task Multipart_FormField_Accepted()
    {
        var c = await LoggedIn();
        var token = FormToken(await c.GetStringAsync("/account"), "/account/avatar");
        var png = Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==");
        var upload = new MultipartFormDataContent
        {
            { new ByteArrayContent(png), "avatar", "me.png" },
            { new StringContent(token), AntiforgeryGuard.FormFieldName },
        };
        var r = await c.SendAsync(Post("/account/avatar", upload));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.DoesNotContain("error=", r.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task AdminPage_FormToken_Accepted()
    {
        var c = await LoggedIn();
        var token = FormToken(await c.GetStringAsync("/admin/system"), "/admin/password-login");
        var r = await c.SendAsync(Post("/admin/password-login", Form(("mode", "clear"), (AntiforgeryGuard.FormFieldName, token))));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.StartsWith("/admin/system?notice=", r.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task ForceChangePassword_PageCarriesToken()
    {
        using (var scope = _app.Services.CreateScope())
            scope.ServiceProvider.GetRequiredService<UserRepository>().Create("csrf-forced", "csrf-forced",
                PasswordHasher.Hash("temp-password-1"), mustChangePassword: true, allowPasswordLogin: true);
        var c = await LoggedIn("csrf-forced", "temp-password-1");

        var html = await c.GetStringAsync("/account/force-change-password");
        var token = FormToken(html, "/account/force-change-password");
        var form = (string? t) => Form(("new_password", "brand-new-pass"), ("confirm_password", "brand-new-pass"),
            (AntiforgeryGuard.FormFieldName, t ?? ""));
        Assert.Equal(HttpStatusCode.Forbidden, (await c.SendAsync(Post("/account/force-change-password", form(null)))).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await c.SendAsync(Post("/account/force-change-password", form(token)))).StatusCode);
    }

    // ---------- 换个来源 / 换个会话：拒 ----------

    [Theory]
    [InlineData("same-site")]   // 兄弟子域
    [InlineData("cross-site")]
    public async Task ValidToken_FromOtherOrigin_StillRejected(string site)
    {
        var c = await LoggedIn();
        var token = await HttpPipelineTests.CsrfToken(c);
        var r = await c.SendAsync(Post("/account/profile", Form(("display_name", "x")), token: token, secFetchSite: site));
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
    }

    [Fact]
    public async Task TokenFromAnotherSession_Rejected()
    {
        // 攻击者自己登录拿到的令牌，配不上受害者浏览器里的 antiforgery cookie
        var attacker = await LoggedIn();
        var stolen = await HttpPipelineTests.CsrfToken(attacker);
        var victim = await LoggedIn();
        await victim.GetAsync("/account");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await victim.SendAsync(Post("/account/profile", Form(("display_name", "x")), token: stolen))).StatusCode);
    }

    [Fact]
    public async Task TokenOfAnotherUser_Rejected()
    {
        // 令牌绑定用户：别的用户（例如攻击者自己的号）的 antiforgery cookie + 令牌整套搬进管理员会话也不认
        using (var scope = _app.Services.CreateScope())
            scope.ServiceProvider.GetRequiredService<UserRepository>().Create("csrf-other", "csrf-other",
                PasswordHasher.Hash("other-password-1"), mustChangePassword: false, allowPasswordLogin: true);

        var raw = _app.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = false,
        });
        async Task<string> SessionOf(string user, string password)
        {
            var r = await raw.PostAsync("/login", Form(("username", user), ("password", password), ("return_url", "/account")));
            return CookiePair(r, "__Host-nas-auth-session");
        }
        var otherSession = await SessionOf("csrf-other", "other-password-1");
        var page = new HttpRequestMessage(HttpMethod.Get, "/account");
        page.Headers.Add("Cookie", otherSession);
        var pageResp = await raw.SendAsync(page);
        var otherAf = CookiePair(pageResp, AntiforgeryGuard.CookieName);
        var otherToken = WebUtility.HtmlDecode(Regex.Match(await pageResp.Content.ReadAsStringAsync(),
            "<meta name='csrf-token' content='([^']+)'>").Groups[1].Value);

        // 对照：other 自己用这套是放行的
        var own = Post("/account/profile", Form(("display_name", "other-ok")), token: otherToken);
        own.Headers.Add("Cookie", $"{otherSession}; {otherAf}");
        Assert.Equal(HttpStatusCode.Redirect, (await raw.SendAsync(own)).StatusCode);

        var adminSession = await SessionOf(NasAuthAppFactory.AdminUser, NasAuthAppFactory.AdminPassword);
        var forged = Post("/account/profile", Form(("display_name", "x")), token: otherToken);
        forged.Headers.Add("Cookie", $"{adminSession}; {otherAf}");
        Assert.Equal(HttpStatusCode.Forbidden, (await raw.SendAsync(forged)).StatusCode);
    }

    private static string CookiePair(HttpResponseMessage r, string name) =>
        r.Headers.GetValues("Set-Cookie").Single(v => v.StartsWith(name + "=")).Split(';')[0];

    [Fact]
    public async Task Anonymous_Bind_StillGoesToLogin()
    {
        var r = await _app.Client().SendAsync(Post("/external/google/bind"));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.StartsWith("/login?return_url=", r.Headers.Location!.OriginalString);
    }

    // ---------- 不误伤 ----------

    [Fact]
    public async Task LoginAndProtocolEndpoints_NeedNoToken()
    {
        // /login 不要令牌（LoggedIn 本身就是证明）；协议端点不认 cookie，也不要
        var c = await LoggedIn();
        Assert.Equal(HttpStatusCode.BadRequest, (await c.SendAsync(Post("/token", Form(("grant_type", "nope"))))).StatusCode);
        Assert.NotEqual(HttpStatusCode.Forbidden, (await c.SendAsync(Post("/revoke", Form(("token", "x"))))).StatusCode);
        Assert.NotEqual(HttpStatusCode.Forbidden, (await c.SendAsync(Post("/introspect", Form(("token", "x"))))).StatusCode);
        Assert.NotEqual(HttpStatusCode.Forbidden, (await c.SendAsync(Post("/authorize", Form(("client_id", "nope"))))).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await c.SendAsync(Post("/logout"))).StatusCode);
    }

    [Fact]
    public void EveryAccountAndAdminWrite_RequiresToken_ProtocolEndpointsDoNot()
    {
        var endpoints = _app.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>()
            .Select(e => (Route: "/" + e.RoutePattern.RawText!.TrimStart('/'),
                Methods: e.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods ?? Array.Empty<string>(),
                Protected: e.Metadata.GetMetadata<AntiforgeryGuard.RequiresTokenMetadata>() is not null))
            .ToList();

        var writes = endpoints.Where(e => e.Methods.Any(CrossOriginGuard.IsStateChanging)).ToList();
        var mustProtect = writes.Where(e =>
            e.Route.StartsWith("/account/", StringComparison.OrdinalIgnoreCase) ||
            e.Route.StartsWith("/admin/", StringComparison.OrdinalIgnoreCase) ||
            e.Route.Equals("/external/{provider}/bind", StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.NotEmpty(mustProtect);
        Assert.All(mustProtect, e => Assert.True(e.Protected, $"{e.Route} 没挂 RequireCsrfToken"));

        foreach (var route in new[] { "/login", "/logout", "/authorize", "/token", "/revoke", "/introspect", "/register", "/userinfo" })
            Assert.All(endpoints.Where(e => e.Route.Equals(route, StringComparison.OrdinalIgnoreCase)),
                e => Assert.False(e.Protected, $"{route} 不该要令牌"));
        Assert.All(endpoints.Where(e => e.Route.StartsWith("/proxy", StringComparison.OrdinalIgnoreCase) ||
                                        e.Route.StartsWith("/forward-auth", StringComparison.OrdinalIgnoreCase) ||
                                        e.Route.StartsWith("/.nas-auth", StringComparison.OrdinalIgnoreCase)),
            e => Assert.False(e.Protected, $"{e.Route} 不该要令牌"));
    }

    [Fact]
    public async Task LoginAndConsentPages_HaveNoToken()
    {
        var login = await _app.Client().GetStringAsync("/login");
        Assert.DoesNotContain(AntiforgeryGuard.FormFieldName, login);
        Assert.DoesNotContain("csrf-token", login);
    }

    // ---------- cookie 与注入 ----------

    [Fact]
    public async Task AntiforgeryCookie_HostPrefixed_Strict()
    {
        var c = await LoggedIn();
        var r = await c.GetAsync("/account");
        var cookie = r.Headers.GetValues("Set-Cookie").Single(v => v.StartsWith(AntiforgeryGuard.CookieName + "=")).ToLowerInvariant();
        Assert.Contains("; secure", cookie);
        Assert.Contains("; path=/", cookie);
        Assert.Contains("; httponly", cookie);
        Assert.Contains("; samesite=strict", cookie);
        Assert.DoesNotContain("domain=", cookie);
        Assert.Equal("DENY", r.Headers.GetValues("X-Frame-Options").Single()); // 没被 antiforgery 改成 SAMEORIGIN
    }

    [Fact]
    public async Task EveryPostFormOnDashboardPages_CarriesToken()
    {
        var c = await LoggedIn();
        foreach (var page in new[] { "/account", "/account/security", "/account/grants", "/admin", "/admin/users",
                     $"/admin/users/edit?user={NasAuthAppFactory.AdminUser}", "/admin/approvals", "/admin/apps", "/admin/system" })
        {
            var html = await c.GetStringAsync(page);
            var forms = Regex.Matches(html, @"<form\b[^>]*\bmethod='post'[^>]*>(.{0,200})", RegexOptions.Singleline);
            Assert.All(forms, f => Assert.StartsWith($"<input type='hidden' name='{AntiforgeryGuard.FormFieldName}'", f.Groups[1].Value));
            Assert.Contains("<meta name='csrf-token'", html);
        }
    }

    [Fact]
    public void Inject_OnlyPostForms()
    {
        var html = "<html><head><title>x</title></head><body>" +
                   "<form method='post' action='/a'><button></button></form>" +
                   "<form method=\"POST\" action='/b' data-confirm='a &gt; b'></form>" +
                   "<form method='get' action='/c'></form></body></html>";
        var outHtml = AntiforgeryGuard.Inject(html, "tok<'>");
        var hidden = $"<input type='hidden' name='{AntiforgeryGuard.FormFieldName}' value='tok&lt;&#39;&gt;'>";
        Assert.Contains("<form method='post' action='/a'>" + hidden, outHtml);
        Assert.Contains("data-confirm='a &gt; b'>" + hidden, outHtml);
        Assert.DoesNotContain("action='/c'>" + hidden, outHtml);
        Assert.Contains("<meta name='csrf-token' content='tok&lt;&#39;&gt;'></head>", outHtml);
    }
}
