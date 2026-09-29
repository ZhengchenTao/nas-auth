using System.Net;
using System.Security.Cryptography;

namespace NasAuth.Pages;

/// <summary>
/// 页面公共件：静态资源引用、图标、提示条。
/// 样式是 Basecoat 1.0.2（shadcn/ui 的纯 CSS 版，MIT），整包放在 wwwroot/vendor/ 下，
/// 不走 CDN —— 登录页在 OAuth 重定向链路上，CDN 挂了或被墙就登录不了。
/// </summary>
public static class Ui
{
    public const string BasecoatDir = "/vendor/basecoat-1.0.2";

    /// <summary>app.css + theme.js 的内容哈希，拼在 URL 上做缓存失效（vendor 目录名自带版本号，不用拼）。</summary>
    public static string AssetVersion { get; private set; } = "0";

    public static void InitAssets(string? webRootPath)
    {
        if (string.IsNullOrEmpty(webRootPath)) return;
        using var sha = SHA256.Create();
        foreach (var name in new[] { "app.css", "theme.js" })
        {
            var path = Path.Combine(webRootPath, name);
            if (!File.Exists(path)) continue;
            var bytes = File.ReadAllBytes(path);
            sha.TransformBlock(bytes, 0, bytes.Length, null, 0);
        }
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        AssetVersion = Convert.ToHexString(sha.Hash!)[..8].ToLowerInvariant();
    }

    /// <summary>head 公共片段。theme.js 同步加载（要在首帧前定下亮 / 暗色）。</summary>
    public static string HeadAssets() =>
        $@"<meta name=""color-scheme"" content=""light dark"">
  <link rel=""icon"" type=""image/png"" href=""/favicon.png"">
  <link rel=""stylesheet"" href=""{BasecoatDir}/basecoat.cdn.min.css"">
  <link rel=""stylesheet"" href=""/app.css?v={AssetVersion}"">
  <script src=""/theme.js?v={AssetVersion}""></script>";

    /// <summary>提示条。html 由调用方负责转义（部分文案本身带 &lt;code&gt;）。</summary>
    public static string Alert(string html, bool error) => error
        ? $"<div class='alert' data-variant='destructive' role='alert'>{IconAlert}<section>{html}</section></div>"
        : $"<div class='alert' role='status'>{IconCheck}<section>{html}</section></div>";

    public static string Esc(string? s) => WebUtility.HtmlEncode(s ?? "");

    /// <summary>
    /// 客户端名的显示形式：渲染时再按注册时的规则清洗一遍（控制 / 格式字符、多余空白），
    /// 这条规则上线前注册进来的名字（RTL override、零宽字符）也不能在页面上伪装。结果仍需 Esc。
    /// </summary>
    public static string ClientDisplayName(string? name) =>
        NasAuth.Services.RedirectUriPolicy.SanitizeClientName(name) ?? "(unnamed)";

    // ---- 图标：内联 SVG（线框图标仿 Lucide 画法，品牌图标用官方配色）----

    private static string Line(string d, int size = 16) =>
        $"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' " +
        $"stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>{d}</svg>";

    public static readonly string IconLogo = Line("<path d='M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z'/><path d='M9 12l2 2 4-4'/>", 24);
    public static readonly string IconCheck = Line("<circle cx='12' cy='12' r='10'/><path d='m9 12 2 2 4-4'/>");
    public static readonly string IconAlert = Line("<circle cx='12' cy='12' r='10'/><path d='M12 8v4M12 16h.01'/>");
    public static readonly string IconMenu = Line("<path d='M4 6h16M4 12h16M4 18h16'/>");
    public static readonly string IconBack = Line("<path d='m15 18-6-6 6-6'/>");
    public static readonly string IconExternal = Line("<path d='M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6'/>");

    public static readonly string IconGoogle =
        "<svg width='16' height='16' viewBox='0 0 48 48' aria-hidden='true'>" +
        "<path fill='#FFC107' d='M43.6 20.1H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 8 3l5.7-5.7C34 6.1 29.3 4 24 4 13 4 4 13 4 24s9 20 20 20 20-9 20-20c0-1.3-.1-2.6-.4-3.9z'/>" +
        "<path fill='#FF3D00' d='m6.3 14.7 6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 8 3l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z'/>" +
        "<path fill='#4CAF50' d='M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2A11.9 11.9 0 0 1 24 36c-5.2 0-9.6-3.3-11.3-7.9l-6.5 5C9.5 39.6 16.2 44 24 44z'/>" +
        "<path fill='#1976D2' d='M43.6 20.1H42V20H24v8h11.3a12 12 0 0 1-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.6-.4-3.9z'/></svg>";

    public static readonly string IconMicrosoft =
        "<svg width='16' height='16' viewBox='0 0 21 21' aria-hidden='true'>" +
        "<path fill='#f25022' d='M1 1h9v9H1z'/><path fill='#00a4ef' d='M1 11h9v9H1z'/>" +
        "<path fill='#7fba00' d='M11 1h9v9h-9z'/><path fill='#ffb900' d='M11 11h9v9h-9z'/></svg>";

    public static string ProviderIcon(string provider) => provider switch
    {
        "google" => IconGoogle,
        "microsoft" => IconMicrosoft,
        _ => "",
    };

    /// <summary>后台侧边栏菜单图标，key 与 DashboardTemplates 的 PersonalMenu / AdminMenu 对应。</summary>
    public static string NavIcon(string key) => key switch
    {
        "overview" => Line("<rect x='3' y='3' width='7' height='9' rx='1'/><rect x='14' y='3' width='7' height='5' rx='1'/><rect x='14' y='12' width='7' height='9' rx='1'/><rect x='3' y='16' width='7' height='5' rx='1'/>"),
        "security" => Line("<rect x='4' y='11' width='16' height='10' rx='2'/><path d='M8 11V7a4 4 0 0 1 8 0v4'/>"),
        "apps" => Line("<path d='m12 3 9 5-9 5-9-5z'/><path d='m3 13 9 5 9-5'/>"),
        "audit" => Line("<path d='M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z'/><path d='M14 3v6h6M8 13h8M8 17h5'/>"),
        "grants" => Line("<circle cx='8' cy='15' r='4'/><path d='M10.8 12.2 20 3M16 7l3 3M14 9l2 2'/>"),
        "bindings" => Line("<path d='M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1'/><path d='M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1'/>"),
        "users" => Line("<circle cx='9' cy='7' r='4'/><path d='M3 21v-2a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v2M16 3.1a4 4 0 0 1 0 7.8M21 21v-2a4 4 0 0 0-3-3.9'/>"),
        "approvals" => Line("<circle cx='9' cy='7' r='4'/><path d='M3 21v-2a4 4 0 0 1 4-4h4M16 19l2 2 4-4'/>"),
        "clients" => Line("<rect x='3' y='3' width='7' height='7' rx='1'/><rect x='14' y='3' width='7' height='7' rx='1'/><rect x='3' y='14' width='7' height='7' rx='1'/><rect x='14' y='14' width='7' height='7' rx='1'/>"),
        "system" => Line("<circle cx='12' cy='12' r='3'/><path d='M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1'/>"),
        _ => "",
    };
}
