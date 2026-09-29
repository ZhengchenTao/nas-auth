using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Endpoints;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// POST /register（RFC 7591）加固（2026-09-29）：client_name 清洗与长度、redirect_uris 形态规则、
/// 运维白名单（Auth:Dcr:AllowedRedirectHosts / AllowedCustomSchemes，/register 与 DCR 客户端的 /authorize 两处都判）、
/// 启动器 scheme 黑名单、非 ASCII 拒绝、按来源（IPv6 /64）限速 + 全局封顶。
/// 纯规则测 RedirectUriPolicy；端点行为起一个只挂 /register + /authorize 的 Kestrel（127.0.0.1 随机端口）真打 HTTP。
/// </summary>
public class RedirectUriPolicyTests
{
    private static readonly DcrOptions Open = new();
    /// <summary>典型配置：只放行常见 MCP 客户端的回调主机与 cursor scheme。</summary>
    private static readonly DcrOptions Prod = new()
    {
        AllowedRedirectHosts = new[] { "claude.ai", "claude.com", "chatgpt.com", "grok.com", "www.cursor.com" },
        AllowedCustomSchemes = new[] { "cursor" },
    };

    [Theory]
    [InlineData("https://claude.ai/api/mcp/auth_callback")]
    [InlineData("https://chatgpt.com/connector_platform_oauth_redirect?x=1")]
    [InlineData("http://localhost:33418/callback")]
    [InlineData("http://localhost/callback")]
    [InlineData("http://127.0.0.1:6274/oauth/callback")]
    [InlineData("http://[::1]:8080/cb")]
    [InlineData("app.immich:///oauth-callback")]
    [InlineData("cursor://anysphere.cursor-retrieval/oauth/user-nas/callback")]
    [InlineData("cursor://anysphere.cursor-mcp/oauth/callback")]
    [InlineData("com.example.app:/oauth2redirect")]
    [InlineData("https://claude.ai/cb?next=%2Fhome")]
    public void Valid_Accepted(string uri) => Assert.Null(RedirectUriPolicy.Validate(uri, Open));

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("JavaScript:alert(1)")]
    [InlineData("data:text/html,<script>alert(1)</script>")]
    [InlineData("vbscript:msgbox(1)")]
    [InlineData("file:///etc/passwd")]
    [InlineData("about:blank")]
    [InlineData("blob:https://claude.ai/uuid")]
    [InlineData("ftp://example.com/cb")]
    [InlineData("ws://example.com/cb")]
    [InlineData("wss://example.com/cb")]
    [InlineData("http://example.com/cb")]              // 非环回 http
    [InlineData("http://192.0.2.5/cb")]
    [InlineData("http://localhost.evil.com/cb")]
    [InlineData("https://claude.ai/cb#frag")]          // RFC 6749 §3.1.2：不许 fragment
    [InlineData("https://user:pass@claude.ai/cb")]     // userinfo
    [InlineData("https://claude.ai@evil.com/cb")]
    [InlineData("cursor://x@anysphere/cb")]
    [InlineData("/relative/cb")]
    [InlineData("claude.ai/cb")]
    [InlineData("https:///nohost")]
    [InlineData(" https://claude.ai/cb")]
    [InlineData("https://claude.ai/c b")]
    [InlineData("https://claude.ai/cb\n")]
    [InlineData("https://claude.ai\\@evil.com/cb")]    // 反斜杠
    [InlineData("1app://cb")]
    [InlineData("")]
    public void Invalid_Rejected(string uri) => Assert.NotNull(RedirectUriPolicy.Validate(uri, Open));

    /// <summary>浏览器 / 系统启动器 scheme：把后面的内容当 URL 打开，等于把授权码交给任意网站。不看配置一律拒。</summary>
    [Theory]
    [InlineData("microsoft-edge:https://evil.com/?")]
    [InlineData("microsoft-edge-holographic:https://evil.com/")]
    [InlineData("x-safari-https://evil.com/?")]
    [InlineData("googlechrome://evil.com/")]
    [InlineData("googlechromes://evil.com/")]
    [InlineData("firefox:evil.com")]
    [InlineData("opera://evil.com/")]
    [InlineData("brave://evil.com/")]
    [InlineData("ms-word:ofe|u|https://evil.com/a?x=")]
    [InlineData("ms-excel:ofe|u|evil.com")]
    [InlineData("ms-settings:privacy")]
    [InlineData("search-ms:query=x&crumb=location:\\\\evil.com\\s")]
    [InlineData("search:query=x")]
    [InlineData("web+mcp://evil.com/")]
    [InlineData("intent://evil.com/#Intent;scheme=https;end")]
    [InlineData("shell:startup")]
    [InlineData("vscode-webview://x/")]
    [InlineData("myapp:https://evil.com/")]              // 自定义 scheme 内嵌 URL
    [InlineData("myapp://cb?u=https%3A%2F%2Fevil.com")]
    [InlineData("myapp://host/HTTP://evil.com")]
    public void LauncherSchemes_AlwaysRejected(string uri)
    {
        Assert.NotNull(RedirectUriPolicy.Validate(uri, Open));
        Assert.NotNull(RedirectUriPolicy.Validate(uri, Prod));
    }

    /// <summary>非 ASCII 一律拒：consent 页显示的 punycode 与浏览器 UTS46 映射后的实际去向可能不同。</summary>
    [Theory]
    [InlineData("https://claude.ai\u2024evil.com/cb")]   // ONE DOT LEADER，浏览器映射成 "."
    [InlineData("https://cl\u0430ude.ai/cb")]           // 西里尔 а
    [InlineData("https://claude.ai/\u56DE\u8C03")]      // 路径里未编码的中文也不收
    [InlineData("cursor://anysphere\u3002cursor-mcp/cb")]
    public void NonAscii_Rejected(string uri)
    {
        Assert.NotNull(RedirectUriPolicy.Validate(uri, Open));
        Assert.NotNull(RedirectUriPolicy.Validate(uri, Prod));
    }

    [Fact]
    public void TooLong_Rejected()
    {
        var ok = "https://claude.ai/" + new string('a', RedirectUriPolicy.MaxRedirectUriLength - "https://claude.ai/".Length);
        Assert.Null(RedirectUriPolicy.Validate(ok, Open));
        Assert.NotNull(RedirectUriPolicy.Validate(ok + "a", Open));
    }

    [Fact]
    public void List_CountLimits()
    {
        Assert.NotNull(RedirectUriPolicy.ValidateList(null, Open));
        Assert.NotNull(RedirectUriPolicy.ValidateList(Array.Empty<string>(), Open));
        var ten = Enumerable.Range(0, 10).Select(i => $"https://claude.ai/cb{i}").ToArray();
        Assert.Null(RedirectUriPolicy.ValidateList(ten, Open));
        Assert.NotNull(RedirectUriPolicy.ValidateList(ten.Append("https://claude.ai/cb10").ToArray(), Open));
        Assert.NotNull(RedirectUriPolicy.ValidateList(new string?[] { "https://claude.ai/cb", null }, Open));
    }

    [Fact]
    public void HostAllowlist_ExactAndSubdomain()
    {
        var dcr = new DcrOptions { AllowedRedirectHosts = new[] { "claude.ai", ".example.com" } };
        Assert.Null(RedirectUriPolicy.Validate("https://claude.ai/cb", dcr));
        Assert.Null(RedirectUriPolicy.Validate("https://CLAUDE.ai/cb", dcr));
        Assert.Null(RedirectUriPolicy.Validate("https://a.example.com/cb", dcr));
        Assert.Null(RedirectUriPolicy.Validate("https://a.b.example.com/cb", dcr));
        Assert.NotNull(RedirectUriPolicy.Validate("https://example.com/cb", dcr));      // "." 条目不含顶级本身
        Assert.NotNull(RedirectUriPolicy.Validate("https://www.claude.ai/cb", dcr));    // 无 "." 的条目只精确匹配
        Assert.NotNull(RedirectUriPolicy.Validate("https://claude.ai.evil.com/cb", dcr));
        Assert.NotNull(RedirectUriPolicy.Validate("https://evilexample.com/cb", dcr));
        // 环回 http 始终放行
        Assert.Null(RedirectUriPolicy.Validate("http://localhost:1234/cb", dcr));
        // 白名单模式下两张表同时生效：只配了主机、没配 scheme → 私有 scheme 一个都不许
        Assert.NotNull(RedirectUriPolicy.Validate("app.immich:///oauth-callback", dcr));
    }

    [Fact]
    public void SchemeAllowlist_ProdConfig()
    {
        Assert.Null(RedirectUriPolicy.Validate("cursor://anysphere.cursor-mcp/oauth/callback", Prod));
        Assert.Null(RedirectUriPolicy.Validate("CURSOR://anysphere.cursor-mcp/oauth/callback", Prod));
        Assert.Null(RedirectUriPolicy.Validate("https://www.cursor.com/cb", Prod));
        Assert.Null(RedirectUriPolicy.Validate("http://127.0.0.1:6274/cb", Prod));
        Assert.NotNull(RedirectUriPolicy.Validate("app.immich:///oauth-callback", Prod));
        Assert.NotNull(RedirectUriPolicy.Validate("https://evil.com/cb", Prod));

        // 只配了 scheme、没配主机 → https 一个都不许
        var schemesOnly = new DcrOptions { AllowedCustomSchemes = new[] { "cursor" } };
        Assert.NotNull(RedirectUriPolicy.Validate("https://claude.ai/cb", schemesOnly));
        Assert.Null(RedirectUriPolicy.Validate("cursor://anysphere.cursor-mcp/oauth/callback", schemesOnly));
    }

    [Theory]
    [InlineData("  Claude  ", "Claude")]
    [InlineData("Claude\r\nAdmin", "Claude Admin")]
    [InlineData("Cla\u200Bude", "Claude")]                   // 零宽空格
    [InlineData("\u202Eedualc", "edualc")]                   // RTL override
    [InlineData("a\u0000b\u0007c", "abc")]
    [InlineData("A   B\tC", "A B C")]
    [InlineData("中文 名字", "中文 名字")]
    [InlineData("\u0001\u200B ", null)]
    [InlineData(null, null)]
    public void ClientName_Sanitized(string? input, string? expected) =>
        Assert.Equal(expected, RedirectUriPolicy.SanitizeClientName(input));

    [Fact]
    public void RateLimitPartition_TenPerSource()
    {
        var a = new DefaultHttpContext(); a.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.7");
        var b = new DefaultHttpContext(); b.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.8");
        var pa = RegistrationEndpoints.DcrRateLimitPartition(a);
        var pb = RegistrationEndpoints.DcrRateLimitPartition(b);
        Assert.NotEqual(pa.PartitionKey, pb.PartitionKey);
        using var limiter = pa.Factory(pa.PartitionKey);
        for (var i = 0; i < 10; i++) Assert.True(limiter.AttemptAcquire().IsAcquired);
        Assert.False(limiter.AttemptAcquire().IsAcquired);
    }

    [Theory]
    [InlineData("203.0.113.7", "203.0.113.7")]
    [InlineData("::ffff:203.0.113.7", "203.0.113.7")]                 // IPv4 映射按 IPv4
    [InlineData("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64")]
    [InlineData("2001:db8:1:2::1", "2001:db8:1:2::/64")]
    [InlineData("2001:db8:1:3::1", "2001:db8:1:3::/64")]
    public void ClientKey_Ipv6By64(string ip, string key) =>
        Assert.Equal(key, RateLimitKeys.ClientKey(IPAddress.Parse(ip)));

    [Fact]
    public void ClientKey_SameIpv6Prefix_SharesDcrBucket()
    {
        var a = new DefaultHttpContext(); a.Connection.RemoteIpAddress = IPAddress.Parse("2001:db8::1");
        var b = new DefaultHttpContext(); b.Connection.RemoteIpAddress = IPAddress.Parse("2001:db8::ffff:1234");
        Assert.Equal(RegistrationEndpoints.DcrRateLimitPartition(a).PartitionKey, RegistrationEndpoints.DcrRateLimitPartition(b).PartitionKey);
        Assert.Equal("unknown", RateLimitKeys.ClientKey(new DefaultHttpContext()));
    }

    [Fact]
    public void GlobalLimiter_CapsOnlyDcrEndpoint()
    {
        using var global = RegistrationEndpoints.CreateGlobalLimiter();
        HttpContext Ctx(string? policy, string ip)
        {
            var c = new DefaultHttpContext();
            c.Connection.RemoteIpAddress = IPAddress.Parse(ip);
            var metadata = policy is null ? new EndpointMetadataCollection() : new EndpointMetadataCollection(new EnableRateLimitingAttribute(policy));
            c.SetEndpoint(new Endpoint(_ => Task.CompletedTask, metadata, "test"));
            return c;
        }
        // 来源各不相同也共用一个全局窗口
        for (var i = 0; i < RegistrationEndpoints.GlobalRegistrationsPerHour; i++)
            Assert.True(global.AttemptAcquire(Ctx(RegistrationEndpoints.RateLimitPolicy, $"198.51.{i / 250}.{i % 250 + 1}")).IsAcquired);
        Assert.False(global.AttemptAcquire(Ctx(RegistrationEndpoints.RateLimitPolicy, "192.0.2.1")).IsAcquired);
        // 其他端点不受影响
        Assert.True(global.AttemptAcquire(Ctx("auth-sensitive", "192.0.2.1")).IsAcquired);
        Assert.True(global.AttemptAcquire(Ctx(null, "192.0.2.1")).IsAcquired);
    }
}

/// <summary>端点行为：每个用例一个独立 Kestrel（限速桶、库都不串）。</summary>
public class DcrEndpointTests : IAsyncLifetime
{
    private readonly string _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-dcr-" + Guid.NewGuid().ToString("N"));
    private readonly AuthOptions _options = new();
    private WebApplication? _app;
    private HttpClient _http = null!;

    private const string Resources = """
        [ {"aud": "obsidian", "resource_url": "https://obsidian-mcp.example.com",
           "display_name": "Obsidian", "scopes": ["read:obsidian"]} ]
        """;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_tmpDir);
        var resourcesPath = Path.Combine(_tmpDir, "resources.json");
        await File.WriteAllTextAsync(resourcesPath, Resources);
        _options.Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}";
        _options.ResourcesPath = resourcesPath;
        _options.Dcr.AllowedRedirectHosts = new[] { "claude.ai" };
        _options.Dcr.AllowedCustomSchemes = new[] { "app.immich" };

        NasAuth.Pages.I18n.Lang = "en";
        var b = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development" });
        b.WebHost.UseUrls("http://127.0.0.1:0");
        b.Logging.ClearProviders();
        b.Services.AddSingleton(_options);
        b.Services.AddSingleton<AuthDb>();
        b.Services.AddScoped<ClientRepository>();
        b.Services.AddScoped<SettingsRepository>();
        b.Services.AddSingleton<AuditRepository>();
        b.Services.AddSingleton<AuditLogger>();
        b.Services.AddSingleton<ResourceCatalog>();
        b.Services.AddSingleton(new ExternalProviderOptions());
        b.Services.AddScoped<PasswordLoginGate>();
        b.Services.AddHttpContextAccessor();
        // POST /authorize 的依赖。本测试只走到错误重渲染，不签发令牌：JwtIssuer 给一个未初始化的空壳，
        // 不依赖它的构造参数（签名方式在别的分支上改），真被调用会 NRE 暴露出来
        b.Services.AddScoped<UserRepository>();
        b.Services.AddScoped<UserResourceRepository>();
        b.Services.AddScoped<AuthCodeRepository>();
        b.Services.AddScoped<PasswordSignIn>();
        b.Services.AddSingleton(_ => (JwtIssuer)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(JwtIssuer)));
        b.Services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            RegistrationEndpoints.AddDcrRateLimits(o);
            o.AddPolicy("auth-sensitive", RegistrationEndpoints.DcrRateLimitPartition);
        });
        _app = b.Build();
        _app.Services.GetRequiredService<AuthDb>().EnsureCreated();
        _app.UseRateLimiter();
        _app.MapRegistrationEndpoints();
        _app.MapAuthorizationEndpoints();
        await _app.StartAsync();
        _http = new HttpClient { BaseAddress = new Uri(_app.Urls.First()) };
    }

    public async Task DisposeAsync()
    {
        _http.Dispose();
        if (_app != null) await _app.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    private async Task<(HttpStatusCode Status, JsonElement Body)> Register(object body)
    {
        var resp = await _http.PostAsJsonAsync("/register", body);
        var text = await resp.Content.ReadAsStringAsync();
        return (resp.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone());
    }

    [Fact]
    public async Task Register_Valid_Returns201_WithSanitizedName()
    {
        var (status, body) = await Register(new
        {
            client_name = "  Claude\u200B\r\n",
            redirect_uris = new[] { "https://claude.ai/api/mcp/auth_callback", "http://localhost:3000/cb", "app.immich:///oauth-callback" },
        });
        Assert.Equal(HttpStatusCode.Created, status);
        Assert.Equal("Claude", body.GetProperty("client_name").GetString());
        var id = body.GetProperty("client_id").GetString()!;
        using var scope = _app!.Services.CreateScope();
        Assert.Equal("Claude", scope.ServiceProvider.GetRequiredService<ClientRepository>().GetById(id)!.client_name);
    }

    [Fact]
    public async Task Register_NameTooLong_InvalidClientMetadata()
    {
        var (status, body) = await Register(new { client_name = new string('a', 101), redirect_uris = new[] { "https://claude.ai/cb" } });
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_client_metadata", body.GetProperty("error").GetString());

        // 恰好 100 可以；清洗掉的字符不计长度
        (status, _) = await Register(new { client_name = new string('a', 100) + "\u200B\u200B", redirect_uris = new[] { "https://claude.ai/cb" } });
        Assert.Equal(HttpStatusCode.Created, status);
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("https://claude.ai/cb#x")]
    [InlineData("http://evil.example/cb")]
    [InlineData("https://evil.example/cb")] // 不在白名单
    [InlineData("microsoft-edge:https://evil.com/?")]  // 启动器 scheme
    [InlineData("cursor://anysphere.cursor-mcp/oauth/callback")] // 私有 scheme 不在白名单
    [InlineData("https://claude.ai\u2024evil.com/cb")] // 非 ASCII 主机
    public async Task Register_BadRedirect_InvalidRedirectUri(string uri)
    {
        var (status, body) = await Register(new { client_name = "x", redirect_uris = new[] { "https://claude.ai/cb", uri } });
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_redirect_uri", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Register_TooManyRedirects_Rejected()
    {
        var uris = Enumerable.Range(0, 11).Select(i => $"https://claude.ai/cb{i}").ToArray();
        var (status, body) = await Register(new { client_name = "x", redirect_uris = uris });
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_redirect_uri", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Register_RateLimited_After10PerIp()
    {
        for (var i = 0; i < 10; i++)
        {
            // 失败的请求也计数（刷垃圾请求同样受限）
            var (s, _) = await Register(new { client_name = "x", redirect_uris = i % 2 == 0 ? new[] { "https://claude.ai/cb" } : new[] { "javascript:x" } });
            Assert.NotEqual(HttpStatusCode.TooManyRequests, s);
        }
        var (status, _) = await Register(new { client_name = "x", redirect_uris = new[] { "https://claude.ai/cb" } });
        Assert.Equal(HttpStatusCode.TooManyRequests, status);
    }

    private string AuthorizeUrl(string clientId, string redirectUri) =>
        "/authorize?response_type=code&client_id=" + Uri.EscapeDataString(clientId) +
        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
        "&resource=" + Uri.EscapeDataString("https://obsidian-mcp.example.com") +
        "&scope=read:obsidian&code_challenge=abc&code_challenge_method=S256&state=s";

    private void InsertClient(string id, string redirectUri, bool dcr, string name = "Claude")
    {
        using var scope = _app!.Services.CreateScope();
        scope.ServiceProvider.GetRequiredService<ClientRepository>()
            .Insert(id, null, name, new[] { redirectUri }, "none", autoRegistered: dcr);
    }

    [Fact]
    public async Task Authorize_DcrClientOutsideAllowlist_Rejected_PresetUnaffected()
    {
        // 白名单配上之前注册的 DCR 客户端：回调主机不在白名单 → /authorize 直接拒
        InsertClient("c_old", "https://evil.example/cb", dcr: true);
        var resp = await _http.GetAsync(AuthorizeUrl("c_old", "https://evil.example/cb"));
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Contains("not allowed for dynamically registered clients", await resp.Content.ReadAsStringAsync());

        // 形态本身就不合规的旧 DCR 客户端（非环回 http）同样拒
        InsertClient("c_http", "http://evil.example/cb", dcr: true);
        resp = await _http.GetAsync(AuthorizeUrl("c_http", "http://evil.example/cb"));
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);

        // 预置客户端由运维手写，不受白名单约束
        InsertClient("preset", "https://evil.example/cb", dcr: false);
        resp = await _http.GetAsync(AuthorizeUrl("preset", "https://evil.example/cb"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Contains("<strong>evil.example</strong>", html);
        Assert.DoesNotContain("Unverified app", html);
    }

    [Fact]
    public async Task Authorize_DcrClientInAllowlist_ConsentShowsTargetAndWarning()
    {
        InsertClient("c_ok", "https://claude.ai/api/mcp/auth_callback", dcr: true);
        var resp = await _http.GetAsync(AuthorizeUrl("c_ok", "https://claude.ai/api/mcp/auth_callback"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Contains("you will be sent to <strong>claude.ai</strong>", html);
        Assert.Contains("Unverified app", html);
    }

    [Fact]
    public async Task AuthorizePost_ErrorRerender_KeepsWarningAndTarget()
    {
        // use_session=1 但没有会话 → 401 重渲染 consent 页：未核实提示与去向不能在错误分支上丢掉
        InsertClient("c_post", "https://claude.ai/api/mcp/auth_callback", dcr: true);
        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = "c_post",
            ["redirect_uri"] = "https://claude.ai/api/mcp/auth_callback",
            ["resource"] = "https://obsidian-mcp.example.com",
            ["scope"] = "read:obsidian",
            ["code_challenge"] = "abc",
            ["code_challenge_method"] = "S256",
            ["state"] = "s",
            ["use_session"] = "1",
        });
        var resp = await _http.PostAsync("/authorize", form);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Contains("Your session has expired", html);
        Assert.Contains("you will be sent to <strong>claude.ai</strong>", html);
        Assert.Contains("Unverified app", html);
    }

    [Fact]
    public async Task Authorize_LegacyNameWithBidiControls_SanitizedOnConsent()
    {
        // 清洗规则上线前注册的名字（RTL override / 零宽字符）在页面上也按清洗后显示
        InsertClient("c_legacy", "https://claude.ai/cb", dcr: true, name: "\u202EClaude\u200B Admin");
        var html = await (await _http.GetAsync(AuthorizeUrl("c_legacy", "https://claude.ai/cb"))).Content.ReadAsStringAsync();
        Assert.Contains("<strong>Claude Admin</strong> wants to access", html);
        // 必须按序号比较：默认的区域性比较会忽略这类格式字符，恒报「找到」
        Assert.DoesNotContain("\u202E", html, StringComparison.Ordinal);
        Assert.DoesNotContain("\u200B", html, StringComparison.Ordinal);
    }
}
