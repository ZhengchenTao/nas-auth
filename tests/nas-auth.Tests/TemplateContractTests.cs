using NasAuth.Pages;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// 页面改版不许动的表单契约：字段名、隐藏字段、外部登录跳转地址、三种授权入口的出现条件。
/// 2026-09-29 换 Basecoat 时补的护栏 —— 这些名字由 AuthorizationEndpoints / AccountEndpoints 读取，
/// 改了模板不改端点（或反之）编译照样过，只有真走一遍 OAuth 才会炸。
/// </summary>
public class TemplateContractTests
{
    private static readonly Dictionary<string, string?> Hidden = new()
    {
        ["response_type"] = "code",
        ["client_id"] = "c1",
        ["redirect_uri"] = "https://app.example/cb",
        ["resource"] = "https://res.example",
        ["scope"] = "read:x",
        ["state"] = "st",
        ["code_challenge"] = "cc",
        ["code_challenge_method"] = "S256",
        ["nonce"] = "n1",
    };

    private static string Authorize(string? session, bool providers, bool password, string? error = null) =>
        HtmlTemplates.Authorize("Claude", "Obsidian", new[] { "read:x" }, Hidden, error,
            returnUrl: "/authorize?client_id=c1", sessionUser: session,
            googleEnabled: providers, microsoftEnabled: providers, passwordEnabled: password);

    private static int Count(string html, string needle)
    {
        var n = 0;
        for (var i = html.IndexOf(needle, StringComparison.Ordinal); i >= 0; i = html.IndexOf(needle, i + 1, StringComparison.Ordinal)) n++;
        return n;
    }

    [Fact]
    public void Authorize_AllEntries_KeepFieldNamesAndHiddenFields()
    {
        var html = Authorize(session: "admin", providers: true, password: true);

        // 一键授权表单 + 密码表单，各带一整套隐藏字段
        foreach (var k in Hidden.Keys)
            Assert.Equal(2, Count(html, $"name='{k}'"));
        Assert.Contains("name='use_session' value='1'", html);
        Assert.Contains("name='username'", html);
        Assert.Contains("name='password'", html);
        Assert.Equal(2, Count(html, "action='/authorize'"));

        var ret = Uri.EscapeDataString("/authorize?client_id=c1");
        Assert.Contains($"href='/external/google/start?return_url={ret}'", html);
        Assert.Contains($"href='/external/microsoft/start?return_url={ret}'", html);

        // 有会话 / 外部按钮时密码表单折叠
        Assert.Contains("<details class='password-login'>", html);
    }

    [Fact]
    public void Authorize_NoSessionNoProviders_PasswordFormNotFolded()
    {
        var html = Authorize(session: null, providers: false, password: true);
        Assert.DoesNotContain("use_session", html);
        Assert.DoesNotContain("/external/", html);
        Assert.DoesNotContain("<details", html);
        Assert.Contains("name='password'", html);
    }

    [Fact]
    public void Authorize_PasswordDisabled_NoPasswordForm_ErrorKeepsFoldOpen()
    {
        Assert.DoesNotContain("name='password'", Authorize(session: "admin", providers: true, password: false));
        Assert.Contains("<details class='password-login' open>", Authorize(session: null, providers: true, password: true, error: "bad"));
    }

    [Fact]
    public void Login_KeepsFieldNames()
    {
        var html = HtmlTemplates.Login("/account/users", null, null, googleEnabled: true, microsoftEnabled: false);
        Assert.Contains("action='/login'", html);
        Assert.Contains("name='return_url' value='/account/users'", html);
        Assert.Contains("name='username'", html);
        Assert.Contains("name='password'", html);
        Assert.Contains($"href='/external/google/start?return_url={Uri.EscapeDataString("/account/users")}'", html);
        Assert.DoesNotContain("/external/microsoft/", html);
    }

    [Fact]
    public void Pages_UseLocalAssetsOnly()
    {
        // 登录页在 OAuth 链路上，不许依赖外部 CDN
        foreach (var html in new[]
                 {
                     Authorize(session: "admin", providers: true, password: true),
                     DashboardTemplates.Shell(DashboardSpace.Admin, "overview", "admin", true, 1, "Overview", ""),
                 })
        {
            Assert.Contains($"{Ui.BasecoatDir}/basecoat.cdn.min.css", html);
            Assert.DoesNotContain("src=\"http", html);
            Assert.DoesNotContain("href=\"http", html);
        }
    }

    [Fact]
    public void Shell_NonAdmin_HasNoAdminEntry_EvenIfAdminSpaceRequested()
    {
        foreach (var space in new[] { DashboardSpace.Personal, DashboardSpace.Admin })
        {
            var html = DashboardTemplates.Shell(space, "overview", "bob", isAdmin: false, pendingCount: 3, "Overview", "");
            Assert.DoesNotContain("/admin", html);
            Assert.DoesNotContain("space-switch", html);
            Assert.Contains("href='/account/security'", html);
        }
    }

    [Fact]
    public void Shell_Admin_SeparatesPersonalAndAdminMenus()
    {
        var personal = DashboardTemplates.Shell(DashboardSpace.Personal, "overview", "admin", isAdmin: true, pendingCount: 2, "Overview", "");
        Assert.Contains("space-switch", personal);
        Assert.Contains("href='/account/grants'", personal);
        Assert.DoesNotContain("href='/admin/users'", personal); // 个人空间不混入管理菜单

        var admin = DashboardTemplates.Shell(DashboardSpace.Admin, "users", "admin", isAdmin: true, pendingCount: 2, "Users", "");
        Assert.Contains("href='/admin/users' aria-current='page'", admin);
        Assert.DoesNotContain("href='/account/grants'", admin);
    }

    [Fact]
    public void AdminGrantRevoke_CarriesTargetUser()
    {
        var user = new UserAdminView("bob", "bob", false, false, false, "2026-09-29 20:00");
        var grants = new[] { new AccountAuthorizationView("c1", "Claude", "https://res.example", "Res", new[] { "read:x" }, "-") };
        var html = DashboardTemplates.UserEditSection(new UserDetailView(user, Array.Empty<UserResourceEditView>(),
            Array.Empty<BindingView>(), grants, Array.Empty<AuditView>()));
        Assert.Contains("action='/admin/users/revoke'", html);
        Assert.Contains("name='user_id' value='bob'", html);
        Assert.Contains("action='/admin/users/force-logout'", html);
        Assert.Contains("action='/admin/users/revoke-all'", html);
    }
}
