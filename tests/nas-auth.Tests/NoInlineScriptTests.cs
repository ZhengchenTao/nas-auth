using System.Net;
using System.Text.RegularExpressions;
using NasAuth.Pages;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// 2026-09-29 安全整改：页面里不许有内联 on*= 事件、内联 &lt;script&gt;、javascript: 链接。
/// 起因：管理后台删 DCR 客户端的 onsubmit="return confirm('…{client_name}…')" —— HtmlEncode 把 ' 编成 &amp;#39;，
/// 浏览器先解码属性再执行 JS，匿名 POST /register 注册一个恶意 client_name 就能在管理员浏览器里跑脚本（存储型 XSS）。
/// 现在交互全走 data-* + theme.js 事件委托，页面要能在 CSP script-src 'self' 下工作。
/// 这里把所有页面用恶意输入渲染一遍，按标签逐个检查属性。
/// </summary>
public class NoInlineScriptTests
{
    // 不含空格：模板里有按空格拆分的字段（resource_url、审计 detail），带空格会让骨架比对因拆分而不同
    private const string Hostile =
        "x');fetch('/admin/users/delete',{method:'POST'})//\"onmouseover=\"alert(1)\"<script>alert(1)</script>" +
        "<a/href='javascript:alert(1)'>x</a><base/href=//evil.example/><meta/http-equiv=refresh/content='0;url=//evil.example'>" +
        "<img/src=x/onerror=alert(1)><iframe/src=//evil.example>";

    private const string Benign = "benign";

    private static readonly Regex TagRe = new(@"<([a-zA-Z][a-zA-Z0-9-]*)((?:[^>'""]|'[^']*'|""[^""]*"")*)>", RegexOptions.Compiled);
    private static readonly Regex AttrRe = new(@"([^\s=/>'""]+)(?:\s*=\s*('[^']*'|""[^""]*""|[^\s'"">]+))?", RegexOptions.Compiled);

    private static IEnumerable<(string Tag, string Name, string? Value)> Attributes(string html)
    {
        foreach (Match t in TagRe.Matches(html))
        {
            var tag = t.Groups[1].Value.ToLowerInvariant();
            foreach (Match a in AttrRe.Matches(t.Groups[2].Value))
            {
                var raw = a.Groups[2].Success ? a.Groups[2].Value : null;
                if (raw is { Length: >= 2 } && (raw[0] == '\'' || raw[0] == '"')) raw = raw[1..^1];
                yield return (tag, a.Groups[1].Value.ToLowerInvariant(), raw is null ? null : WebUtility.HtmlDecode(raw));
            }
        }
    }

    /// <summary>通用断言：无内联事件、script 只能外链且无内容、URL 类属性不是 javascript:、恶意原文不出现。</summary>
    private static void AssertNoInlineScript(string html)
    {
        foreach (var (tag, name, value) in Attributes(html))
        {
            Assert.False(Regex.IsMatch(name, "^on[a-z]+$"), $"<{tag}> 带内联事件属性 {name}");
            if (name is "href" or "src" or "action" or "formaction" && value != null)
                Assert.False(value.TrimStart().StartsWith("javascript:", StringComparison.OrdinalIgnoreCase), $"<{tag} {name}> 是 javascript: URL");
        }
        foreach (Match t in TagRe.Matches(html))
        {
            if (!t.Groups[1].Value.Equals("script", StringComparison.OrdinalIgnoreCase)) continue;
            Assert.Contains("src=", t.Groups[2].Value);
            var close = html.IndexOf("</script>", t.Index + t.Length, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(t.Index + t.Length, close); // 外链 script 标签体为空
        }
        Assert.DoesNotContain(Hostile, html);
        Assert.DoesNotContain("<script>alert", html);
    }

    private static IEnumerable<string> AllPages(string x = Hostile)
    {
        var self = new UserAdminView("admin", "admin", true, false, true, "2026-09-29 20:00", "admin@example.com", true);
        var victim = new UserAdminView("bob", x, false, false, false, "2026-09-29 20:00", x, true, x);
        var grants = new[] { new AccountAuthorizationView("c_1", x, "https://res.example", x, new[] { x }, x) };
        var bindings = new[] { new BindingView("google", x, x, x, x) };
        var logins = new[] { new AuditView(x, "external_login", false, x, x, x, "method=google reason=" + x) };
        var resources = new[] { new UserResourceEditView("obsidian", x, new[] { "read:x" }, new[] { "read:x" }) };
        var pending = new[] { new PendingApprovalView("google", x, x, x, x) };
        var clients = new[]
        {
            new ClientAdminView("c_1", x, true, "none", new[] { x }, x, x, 1),
            new ClientAdminView("gitea-web", "Gitea", false, "client_secret_post", new[] { "https://git.example/cb" }, "-", "-"),
        };
        var catalog = new[] { new ResourceAdminView("obsidian", x, x, new[] { x }, false, 1, 1) };
        var hidden = new Dictionary<string, string?> { ["client_id"] = x, ["redirect_uri"] = x, ["state"] = x };

        var sections = string.Concat(
            DashboardTemplates.PersonalOverviewSection(new ProfileView(self, bindings, true,
                new[] { new ProfileAppView(x, "obsidian", new[] { x }) }, 1, logins[0])),
            DashboardTemplates.GrantsSection(grants),
            DashboardTemplates.SecuritySection(bindings, true, true, true, logins),
            DashboardTemplates.AdminOverviewSection(new AdminStats(1, 1, 1, 1, 1, 1, 1, 1), logins),
            DashboardTemplates.UsersSection(new[] { self, victim }),
            DashboardTemplates.UserEditSection(new UserDetailView(victim, resources, bindings, grants, logins)),
            DashboardTemplates.ApprovalsSection(pending, pending, new[] { self, victim }, resources),
            DashboardTemplates.AppsSection(catalog, clients),
            DashboardTemplates.AuditSection(new AuditFilter("login", x, true), logins),
            DashboardTemplates.SystemSection(x, true, false, true, true),
            // RS256 分支加的签名密钥卡片：RS256（RSA 轮换步骤）与 HS256（生成按钮）两种都要扫到
            DashboardTemplates.SystemSection(x, true, false, null, false,
                jwt: new JwtKeyView(Rs256: true, LegacyHs256Keys: true, AccessTokenLifetimeDays: 30, LegacyHs256NotAfter: x)),
            DashboardTemplates.SystemSection(x, true, false, null, false,
                jwt: new JwtKeyView(Rs256: true, LegacyHs256Keys: false, AccessTokenLifetimeDays: 30)),
            DashboardTemplates.SystemSection(x, true, false, false, false,
                jwt: new JwtKeyView(Rs256: false, LegacyHs256Keys: true, AccessTokenLifetimeDays: 30, LegacyHs256NotAfter: x)));

        foreach (var space in new[] { DashboardSpace.Personal, DashboardSpace.Admin })
            yield return DashboardTemplates.Shell(space, "overview", x, true, 3, "Overview", sections, notice: x, error: x);

        foreach (var (uri, dcr) in new[] { ("https://claude.ai/api/mcp/auth_callback", true), ("app.immich:///oauth-callback", false), (x, true) })
            yield return HtmlTemplates.Authorize(x, x, new[] { x }, hidden, x,
                returnUrl: x, sessionUser: x, googleEnabled: true, microsoftEnabled: true,
                redirectUri: uri, selfRegistered: dcr);
        yield return HtmlTemplates.Login(x, x, x, googleEnabled: true, microsoftEnabled: true);
        yield return HtmlTemplates.ExternalPending(x, x);
        yield return HtmlTemplates.ExternalBindResult(x, x, x);
        yield return HtmlTemplates.ExternalError(x, x);
        yield return HtmlTemplates.ForceChangePassword(x, x);
        yield return HtmlTemplates.SimpleMessage(x, x, isError: true);
    }

    [Theory]
    [InlineData("en")]
    [InlineData("zh")]
    public void AllPages_HaveNoInlineHandlersOrScripts(string lang)
    {
        I18n.Lang = lang;
        foreach (var html in AllPages()) AssertNoInlineScript(html);
    }

    /// <summary>
    /// 标签 / 属性骨架：恶意输入与普通输入渲染出的「标签名 + 属性名」序列必须完全一致。
    /// 上面的检查只认识 on*= / script / javascript:，这条兜住其余注入（&lt;base&gt;、&lt;meta refresh&gt;、&lt;img&gt;、&lt;iframe&gt;…）：
    /// 只要用户输入能多造出一个标签或属性，骨架就会不同。
    /// </summary>
    [Theory]
    [InlineData("en")]
    [InlineData("zh")]
    public void AllPages_HostileInput_SameTagSkeletonAsBenign(string lang)
    {
        I18n.Lang = lang;
        var hostile = AllPages(Hostile).ToList();
        var benign = AllPages(Benign).ToList();
        Assert.Equal(benign.Count, hostile.Count);
        for (var i = 0; i < benign.Count; i++)
        {
            var sb = Skeleton(benign[i]);
            var sh = Skeleton(hostile[i]);
            Assert.True(sb.SequenceEqual(sh), $"第 {i} 个页面骨架不同，多出：{string.Join(" | ", sh.Except(sb).Take(5))}");
        }
    }

    private static List<string> Skeleton(string html)
    {
        var list = new List<string>();
        foreach (Match t in TagRe.Matches(html))
            list.Add(t.Groups[1].Value.ToLowerInvariant() + "[" +
                     string.Join(',', AttrRe.Matches(t.Groups[2].Value).Select(a => a.Groups[1].Value.ToLowerInvariant())) + "]");
        return list;
    }

    [Fact]
    public void Skeleton_DetectsInjectedTag()
    {
        Assert.NotEqual(Skeleton("<p>benign</p>"), Skeleton("<p><base href=//evil>benign</p>"));
        Assert.Equal(Skeleton("<p>benign</p>"), Skeleton($"<p>{WebUtility.HtmlEncode(Hostile)}</p>"));
    }

    [Fact]
    public void Scanner_CatchesTheOldPattern()
    {
        // 自检：扫描器确实能抓到整改前的写法，免得上面的用例因为正则写歪而恒真
        var old = "<form method='post' onsubmit=\"return confirm('x');\"><button>ok</button></form>";
        Assert.Throws<Xunit.Sdk.FalseException>(() => AssertNoInlineScript(old));
        Assert.ThrowsAny<Exception>(() => AssertNoInlineScript("<p>a</p><script>alert(1)</script>"));
        Assert.ThrowsAny<Exception>(() => AssertNoInlineScript("<a href=' javascript:alert(1)'>x</a>"));
    }

    [Fact]
    public void AdminApps_HostileClientName_OnlyInDataConfirm_HtmlEncoded()
    {
        I18n.Lang = "en";
        var html = DashboardTemplates.AppsSection(Array.Empty<ResourceAdminView>(),
            new[] { new ClientAdminView("c_1", Hostile, true, "none", new[] { "https://claude.ai/cb" }, "-", "-") });

        AssertNoInlineScript(html);
        var expected = I18n.T("Delete client {0}? Its grants are revoked; the app must register again.", Hostile);
        Assert.Contains($"data-confirm='{WebUtility.HtmlEncode(expected)}'", html);

        // 浏览器解码属性后拿到的就是原始纯文本（theme.js 用 getAttribute 取，交给 confirm 当字符串显示）
        var confirm = Attributes(html).Single(a => a.Name == "data-confirm");
        Assert.Equal("form", confirm.Tag);
        Assert.Equal(expected, confirm.Value);
    }

    [Fact]
    public void UserEdit_ConfirmsUseDataAttributes()
    {
        I18n.Lang = "en";
        var u = new UserAdminView("bob", "bob", false, false, false, "-");
        var html = DashboardTemplates.UserEditSection(new UserDetailView(u, Array.Empty<UserResourceEditView>(),
            new[] { new BindingView("google", "sub", null, null, "-") },
            new[] { new AccountAuthorizationView("c1", "Claude", "https://res.example", "Res", new[] { "read:x" }, "-") },
            Array.Empty<AuditView>()));
        AssertNoInlineScript(html);
        var confirms = Attributes(html).Where(a => a.Name == "data-confirm").Select(a => a.Value).ToList();
        Assert.Contains("Unbind this external account?", confirms);
        Assert.Contains("Revoke all grants of bob?", confirms);
        Assert.Contains("Sign bob out on all devices?", confirms);
        Assert.Contains("Delete user bob? All of their refresh tokens will be revoked.", confirms);
    }

    [Fact]
    public void Shell_LangAndSidebar_UseDataAttributes_ThemeJsLoaded()
    {
        I18n.Lang = "en";
        var html = DashboardTemplates.Shell(DashboardSpace.Admin, "overview", "admin", true, 0, "Overview", "");
        Assert.Contains("data-lang=\"zh\"", html);
        Assert.Contains("data-sidebar-toggle", html);
        Assert.Contains("<script src=\"/theme.js?v=", html);
        Assert.Contains("data-lang='zh'", HtmlTemplates.LangSwitcher());
    }
}
