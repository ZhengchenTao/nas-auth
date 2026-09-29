using System.Net;
using NasAuth.Pages;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// consent 页防钓鱼（2026-09-29）：DCR 客户端的 client_name 是自报的，谁都能叫 "Claude"。
/// 页面必须同时显示授权码的去向（redirect_uri 的主机 / 本机 / 私有 scheme），
/// 对自助注册的客户端再加一条「名字未核实」提示。
/// </summary>
public class ConsentPageTests
{
    private static readonly Dictionary<string, string?> Hidden = new() { ["client_id"] = "c1" };

    private static string Render(string clientName, string? redirectUri, bool dcr, string lang = "en")
    {
        I18n.Lang = lang;
        return HtmlTemplates.Authorize(clientName, "Obsidian", new[] { "read:x" }, Hidden, null,
            redirectUri: redirectUri, selfRegistered: dcr);
    }

    [Fact]
    public void Https_ShowsHostOnly()
    {
        var html = Render("Claude", "https://claude.ai/api/mcp/auth_callback?x=1", dcr: false);
        Assert.Contains("you will be sent to <strong>claude.ai</strong>", html);
        Assert.DoesNotContain("auth_callback", html); // 只显示主机，路径 / query 不上页面
        Assert.DoesNotContain("Unverified app", html);
    }

    [Fact]
    public void Https_NonDefaultPort_Shown()
    {
        var html = Render("App", "https://app.example.com:8443/cb", dcr: false);
        Assert.Contains("<strong>app.example.com:8443</strong>", html);
    }

    [Fact]
    public void Https_IdnHost_ShownAsPunycode()
    {
        // 同形字域名（西里尔 а）显示成 xn-- 形式，不让它在页面上冒充 claude.ai
        var html = Render("Claude", "https://cl\u0430ude.ai/cb", dcr: true);
        Assert.Contains("<strong>xn--", html);
        Assert.DoesNotContain("cl\u0430ude.ai", html);
    }

    [Theory]
    [InlineData("http://localhost:33418/callback", "localhost:33418")]
    [InlineData("http://127.0.0.1:6274/oauth/callback", "127.0.0.1:6274")]
    [InlineData("http://[::1]:8080/cb", "[::1]:8080")]
    public void Loopback_SaysLocalApp(string uri, string shown)
    {
        var html = Render("Cursor", uri, dcr: true);
        Assert.Contains($"an app running on this computer (<strong>{shown}</strong>)", html);
    }

    [Fact]
    public void NonLoopbackHttp_ShowsScheme()
    {
        // 预置客户端可能是局域网 http：显示 http:// 前缀提示未加密
        var html = Render("Gitea", "http://192.0.2.5:3000/user/oauth2/nas/callback", dcr: false);
        Assert.Contains("<strong>http://192.0.2.5:3000</strong>", html);
    }

    [Fact]
    public void CustomScheme_ShowsScheme()
    {
        var html = Render("Immich", "app.immich:///oauth-callback", dcr: true);
        Assert.Contains("the app that opens <strong>app.immich:</strong> links", html);
    }

    [Fact]
    public void Dcr_ShowsUnverifiedWarning_WithEscapedName()
    {
        var name = "Claude <img src=x>";
        var html = Render(name, "https://evil.example/cb", dcr: true);
        Assert.Contains("Unverified app", html);
        Assert.Contains($"The name <strong>{WebUtility.HtmlEncode(name)}</strong> was supplied by the app itself", html);
        Assert.DoesNotContain("<img src=x>", html);
        Assert.Contains("<strong>evil.example</strong>", html);
    }

    [Fact]
    public void Zh_Strings()
    {
        var html = Render("Claude", "https://claude.ai/cb", dcr: true, lang: "zh");
        Assert.Contains("授权后将跳转到 <strong>claude.ai</strong>", html);
        Assert.Contains("未核实的应用", html);
        Assert.Contains("只有在你本人刚刚发起连接这个应用时才继续", html);
        I18n.Lang = "en";
    }

    [Fact]
    public void UnparseableUri_StillShownEscaped()
    {
        var html = Render("X", "not a uri <b>", dcr: true);
        Assert.Contains("<strong>not a uri &lt;b&gt;</strong>", html);
    }

    [Fact]
    public void NoRedirectUri_NoTargetLine()
    {
        Assert.DoesNotContain("consent-target", Render("X", null, dcr: false));
    }
}
