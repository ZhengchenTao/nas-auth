using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Endpoints;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>2026-09-29 安全修复：开放跳转（return_url）的站内地址校验。</summary>
public class ReturnUrlTests
{
    [Theory]
    [InlineData("/account")]
    [InlineData("/")]
    [InlineData("/authorize?client_id=x&state=y")]
    [InlineData("/authorize?client_id=x&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&state=y")]
    [InlineData("/a\\b")] // 第二位之后的反斜杠与 ASP.NET 一致放行（浏览器里是站内 /a/b）
    [InlineData("~/account")]
    public void Local_Allowed(string url) => Assert.True(ReturnUrl.IsLocalUrl(url));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("//evil.example.com")]
    [InlineData("/\\evil.example.com")]
    [InlineData("/\t/evil.example.com")] // 浏览器剥掉 TAB 后是 //evil.example.com
    [InlineData("/\r\n/evil.example.com")]
    [InlineData("/account\u0000")]
    [InlineData("https://evil.example.com/")]
    [InlineData("http:evil.example.com")]
    [InlineData("javascript:alert(1)")]
    [InlineData("evil.example.com")]
    [InlineData("~//evil.example.com")]
    [InlineData("~/\\evil.example.com")]
    [InlineData("~")]
    [InlineData(" /account")]
    [InlineData("/account/中文")]      // 非 ASCII 进 Location 头 Kestrel 会抛异常
    [InlineData("/account\u2028")]
    [InlineData("/account\u00a0")]
    [InlineData("/account\u007f")]
    [InlineData("~/中文")]
    public void OffSite_Rejected(string? url) => Assert.False(ReturnUrl.IsLocalUrl(url));

    [Fact]
    public void SafeLocal_KeepsQuery_FallsBack_StripsTilde()
    {
        Assert.Equal("/authorize?client_id=x&state=y", ReturnUrl.SafeLocal("/authorize?client_id=x&state=y"));
        Assert.Equal("/account", ReturnUrl.SafeLocal("https://evil.example.com"));
        Assert.Equal("/account", ReturnUrl.SafeLocal("/\t/evil.example.com"));
        Assert.Equal("/account", ReturnUrl.SafeLocal(null));
        Assert.Equal("/login", ReturnUrl.SafeLocal("//evil", fallback: "/login"));
        Assert.Equal("/account/security", ReturnUrl.SafeLocal("~/account/security"));
    }

    [Fact]
    public void LandingFor_NeverLeavesSite()
    {
        var admin = new UserRow("a", "a", "h", 0, 0, 1, 0, null, 1, 0, null, 0);
        var user = admin with { is_admin = 0 };
        // 站外地址回落默认去处：管理员 → /admin，普通用户 → /account
        Assert.Equal("/admin", DashboardSupport.LandingFor("https://evil.example.com", admin));
        Assert.Equal("/account", DashboardSupport.LandingFor("//evil.example.com", user));
        Assert.Equal("/account", DashboardSupport.LandingFor("javascript:alert(1)", user));
        Assert.Equal("/account", DashboardSupport.LandingFor(null, user));
        Assert.Equal("/authorize?client_id=x&state=y", DashboardSupport.LandingFor("/authorize?client_id=x&state=y", user));
    }
}

/// <summary>2026-09-29 安全修复：跨源写请求拦截（CSRF）的放行 / 拒绝矩阵。</summary>
public class CrossOriginGuardTests
{
    private const string Self = "https://auth.example.com";
    private const string Issuer = "https://auth.example.com";

    private static string? C(string method, string path, string? site, string? origin,
        string self = Self, string? issuer = Issuer) =>
        CrossOriginGuard.Check(method, new PathString(path), site, origin, self, issuer);

    [Theory]
    [InlineData("/login")]
    [InlineData("/authorize")]
    [InlineData("/account/change-password")]
    [InlineData("/account/sessions/revoke-others")]
    [InlineData("/admin/users/create")]
    [InlineData("/admin/rotate-jwt-key")]
    [InlineData("/external/google/start")]
    public void ProtectedPaths_SameOriginAllowed_CrossSiteRejected(string path)
    {
        Assert.Null(C("POST", path, "same-origin", Self));
        Assert.Null(C("POST", path, "none", null));
        // 兄弟子域（Gitea / Immich …）对 Lax cookie 来说是 same-site，照样要挡
        Assert.NotNull(C("POST", path, "same-site", "https://git.example.com"));
        Assert.NotNull(C("POST", path, "cross-site", "https://evil.example"));
    }

    [Theory]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    [InlineData("DELETE")]
    [InlineData("post")]
    public void AllStateChangingMethods_Checked(string method) =>
        Assert.NotNull(C(method, "/admin/users/delete", "cross-site", null));

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    public void SafeMethods_NeverChecked(string method) =>
        Assert.Null(C(method, "/authorize", "cross-site", "https://evil.example"));

    [Theory]
    [InlineData("/token")]
    [InlineData("/revoke")]
    [InlineData("/introspect")]
    [InlineData("/register")]
    [InlineData("/userinfo")]
    [InlineData("/proxy/mcp/sse")]
    [InlineData("/logout")] // RP-Initiated Logout 是跨站表单 POST
    public void ExemptPaths_CrossSiteAllowed(string path) =>
        Assert.Null(C("POST", path, "cross-site", "https://evil.example"));

    [Fact]
    public void ExemptMatch_IsSegmentAware()
    {
        // /account/revoke 不是 /revoke；/logoutx 也不是 /logout
        Assert.NotNull(C("POST", "/account/revoke", "cross-site", null));
        Assert.NotNull(C("POST", "/logoutx", "cross-site", null));
    }

    [Fact]
    public void OriginFallback_WhenNoSecFetchSite()
    {
        Assert.Null(C("POST", "/login", null, "https://auth.example.com"));
        Assert.Null(C("POST", "/login", null, "https://AUTH.example.com:443")); // 默认端口 / 大小写不敏感
        Assert.NotNull(C("POST", "/login", null, "https://git.example.com"));
        Assert.NotNull(C("POST", "/login", null, "http://auth.example.com")); // scheme 不同
        Assert.NotNull(C("POST", "/login", null, "https://auth.example.com:8443"));
        Assert.NotNull(C("POST", "/login", null, "null"));
        Assert.NotNull(C("POST", "/login", null, "garbage"));
    }

    [Fact]
    public void OriginFallback_IssuerOriginAlsoAccepted()
    {
        // 容器内看到的 Host 与对外 Issuer 不一致时（反代改写 Host），Issuer 的来源也算本站
        Assert.Null(C("POST", "/login", null, "https://auth.example.com", self: "http://nas-auth:8080"));
        Assert.NotNull(C("POST", "/login", null, "https://evil.example", self: "http://nas-auth:8080"));
        Assert.Null(C("POST", "/login", null, "http://localhost:5000", self: "http://localhost:5000", issuer: null));
    }

    [Fact]
    public void SecFetchSite_TakesPrecedenceOverOrigin()
    {
        Assert.NotNull(C("POST", "/login", "same-site", Self)); // 头互相矛盾时以 Sec-Fetch-Site 为准
        Assert.Null(C("POST", "/login", "same-origin", "null"));
    }

    [Fact]
    public void SignInCallbacks_NotExempt() =>
        Assert.NotNull(C("POST", "/signin/microsoft", "cross-site", null));

    [Fact]
    public void RefererFallback_WhenNoSecFetchSiteNorOrigin()
    {
        string? R(string referer) =>
            CrossOriginGuard.Check("POST", new PathString("/login"), null, null, Self, Issuer, referer);
        Assert.Null(R("https://auth.example.com/login?return_url=%2Faccount"));
        Assert.NotNull(R("https://git.example.com/"));
        Assert.NotNull(R("http://auth.example.com/login"));
        Assert.NotNull(R("not a url"));
        // Origin 在场时以 Origin 为准，不再看 Referer
        Assert.Null(CrossOriginGuard.Check("POST", new PathString("/login"), null, Self, Self, Issuer, "https://git.example.com/"));
    }

    [Fact]
    public void NoBrowserHeaders_Allowed() => Assert.Null(C("POST", "/admin/users/create", null, null));

    [Fact]
    public void IssuerOrigin_FromConfig()
    {
        Assert.Equal("https://auth.example.com", CrossOriginGuard.IssuerOrigin(new AuthOptions { Issuer = "https://auth.example.com/" }));
        Assert.Null(CrossOriginGuard.IssuerOrigin(new AuthOptions { Issuer = "" }));
    }

    [Fact]
    public async Task Middleware_Rejects403_WithoutCallingNext()
    {
        var ctx = NewContext("POST", "/account/change-password");
        ctx.Request.Headers["Sec-Fetch-Site"] = "same-site";
        var called = false;
        await CrossOriginGuard.InvokeAsync(ctx, _ => { called = true; return Task.CompletedTask; }, Issuer, NullLogger.Instance);
        Assert.False(called);
        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task Middleware_UsesRequestOwnOrigin()
    {
        var ctx = NewContext("POST", "/login");
        ctx.Request.Headers.Origin = "https://auth.example.com";
        var called = false;
        await CrossOriginGuard.InvokeAsync(ctx, _ => { called = true; return Task.CompletedTask; }, null, NullLogger.Instance);
        Assert.True(called);
    }

    private static DefaultHttpContext NewContext(string method, string path)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Path = path;
        ctx.Request.Scheme = "https";
        ctx.Request.Host = new HostString("auth.example.com");
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }
}

/// <summary>2026-09-29 安全修复：通用安全响应头。</summary>
public class SecurityHeadersTests
{
    private static async Task<HttpResponse> Run(string path, bool endpoint)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = path;
        if (endpoint) ctx.SetEndpoint(new Endpoint(_ => Task.CompletedTask, EndpointMetadataCollection.Empty, "test"));
        await SecurityHeaders.InvokeAsync(ctx, _ => Task.CompletedTask);
        return ctx.Response;
    }

    [Fact]
    public async Task Page_GetsAllHeaders_AndNoStore()
    {
        var r = await Run("/login", endpoint: true);
        var csp = r.Headers.ContentSecurityPolicy.ToString();
        Assert.Contains("script-src 'self'", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.Contains("object-src 'none'", csp);
        Assert.DoesNotContain("form-action", csp); // 会拦 consent 后跳回 redirect_uri 的 302
        Assert.DoesNotContain("unsafe-eval", csp);
        Assert.Equal("DENY", r.Headers.XFrameOptions.ToString());
        Assert.Equal("nosniff", r.Headers.XContentTypeOptions.ToString());
        Assert.Equal("same-origin", r.Headers["Referrer-Policy"].ToString());
        Assert.Equal("no-store", r.Headers.CacheControl.ToString());
        Assert.Equal("no-cache", r.Headers.Pragma.ToString());
        Assert.False(r.Headers.ContainsKey("Strict-Transport-Security"));
    }

    [Fact]
    public async Task WellKnown_PublicCache()
    {
        var r = await Run("/.well-known/jwks.json", endpoint: true);
        Assert.Equal("public, max-age=300", r.Headers.CacheControl.ToString());
        Assert.False(r.Headers.ContainsKey("Pragma"));
    }

    [Fact]
    public async Task Token_NoStore()
    {
        var r = await Run("/token", endpoint: true);
        Assert.Equal("no-store", r.Headers.CacheControl.ToString());
    }

    [Fact]
    public async Task StaticFile_KeepsCaching_ButGetsSecurityHeaders()
    {
        var r = await Run("/app.css", endpoint: false);
        Assert.False(r.Headers.ContainsKey("Cache-Control"));
        Assert.Equal("nosniff", r.Headers.XContentTypeOptions.ToString());
    }

    [Theory]
    [InlineData("/proxy/mcp/sse")]
    [InlineData("/proxy/mcp/.well-known/oauth-protected-resource")]
    public async Task Proxy_Untouched(string path)
    {
        var r = await Run(path, endpoint: true);
        Assert.False(r.Headers.ContainsKey("Content-Security-Policy"));
        Assert.False(r.Headers.ContainsKey("X-Frame-Options"));
        Assert.False(r.Headers.ContainsKey("Cache-Control"));
    }
}
