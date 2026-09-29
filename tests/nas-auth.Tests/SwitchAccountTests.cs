using NasAuth.Pages;
using Xunit;

namespace NasAuth.Tests;

/// <summary>等待批准 / 被拒 / IdP 失败页上的「换个账号」出口（2026-09-30：选错 Google 账号后卡在等待页）。</summary>
public class SwitchAccountTests
{
    [Fact]
    public void Pending_OffersAccountPicker_AndBackToAuthorize()
    {
        var ret = "/authorize?client_id=open-webui&state=s1";
        var html = HtmlTemplates.ExternalPending("google", "someone@example.com",
            new SwitchAccountOptions(ret, GoogleEnabled: true, MicrosoftEnabled: true, PasswordEnabled: true));

        var encoded = Uri.EscapeDataString(ret);
        Assert.Contains($"/external/google/start?return_url={encoded}&amp;select_account=1", html);
        Assert.Contains($"/external/microsoft/start?return_url={encoded}&amp;select_account=1", html);
        // 回原授权页（那里有密码登录），不是泛泛的 /login
        Assert.Contains("href='/authorize?client_id=open-webui&amp;state=s1'", html);
    }

    [Fact]
    public void NonAuthorizeReturn_GoesBackViaLogin_AndHidesDisabledProviders()
    {
        var html = HtmlTemplates.ExternalError("Access denied", "nope",
            new SwitchAccountOptions("/account", GoogleEnabled: true, MicrosoftEnabled: false, PasswordEnabled: false));

        Assert.Contains("/external/google/start?return_url=%2Faccount&amp;select_account=1", html);
        Assert.DoesNotContain("/external/microsoft/start", html);
        Assert.Contains("href='/login?return_url=%2Faccount'", html);
    }

    [Fact]
    public void WithoutOptions_KeepsPlainBackLink()
    {
        var html = HtmlTemplates.ExternalError("x", "y");
        Assert.Contains("href='/login'", html);
        Assert.DoesNotContain("select_account", html);
    }
}
