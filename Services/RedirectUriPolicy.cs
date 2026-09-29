using System.Text;
using System.Text.RegularExpressions;
using NasAuth.Config;

namespace NasAuth.Services;

/// <summary>
/// DCR（RFC 7591）客户端的元数据规则：redirect_uri 形态 + 运维白名单，client_name 清洗。
/// /register 注册时整套校验；/authorize 对 auto_registered=1 的客户端每次再校验一遍 ——
/// 规则收紧 / 白名单改动之前注册进来的 DCR 客户端，不符合的立刻用不了（重新注册同样过不去）。
/// 预置客户端（clients.preset.json）由运维手写，不走这里。
/// </summary>
public static partial class RedirectUriPolicy
{
    public const int MaxRedirectUris = 10;
    public const int MaxRedirectUriLength = 2000;
    public const int MaxClientNameLength = 100;

    /// <summary>RFC 3986 scheme 语法（比较前已转小写）。</summary>
    [GeneratedRegex("^[a-z][a-z0-9+.-]*$")]
    private static partial Regex SchemeRegex();

    /// <summary>
    /// 私有 scheme 里始终拒绝的（不看配置）：能在浏览器里执行 / 读本地 / 非 TLS 的，
    /// 以及「浏览器 / 系统启动器」—— 它们把 scheme 后面的内容当 URL 打开（microsoft-edge:https://evil/?code=…），
    /// 等于绕过主机白名单把授权码交给任意网站（2026-09-29 review 实测可注册）。
    /// ⚠️ 黑名单不可能列全（每装一个应用就多一个 scheme），真正的控制是 Auth:Dcr:AllowedCustomSchemes 白名单；
    /// 这里只兜住已知的高危项，给没配白名单的部署一层底线。
    /// http 不在这里：它单独按「仅环回地址」判。
    /// </summary>
    private static readonly HashSet<string> ForbiddenSchemes = new(StringComparer.Ordinal)
    {
        "javascript", "data", "vbscript", "file", "about", "blob", "ftp", "ws", "wss", "view-source", "jar",
        // 浏览器启动器
        "microsoft-edge", "microsoft-edge-holographic", "googlechrome", "googlechromes", "firefox", "firefox-private",
        "opera", "brave", "vivaldi", "chrome", "chrome-extension", "edge", "moz-extension", "safari-extension",
        // 系统 / shell 启动器
        "search", "search-ms", "intent", "shell", "vscode-webview", "res", "mk", "its", "hcp", "help",
        "smb", "nfs", "afp", "webdav", "telnet", "ssh", "ldap", "gopher",
    };

    /// <summary>按前缀拒绝的 scheme 族：Safari 的 x-safari-https、Office 的 ms-word / ms-excel、系统的 ms-settings、web+ 协议处理器等。</summary>
    private static readonly string[] ForbiddenSchemePrefixes =
    {
        "x-safari-", "ms-", "microsoft-", "web+", "firefox-", "opera-",
    };

    private static readonly HashSet<string> LoopbackHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost", "127.0.0.1", "[::1]",
    };

    /// <summary>环回主机：localhost / 127.0.0.1 / [::1]（任意端口）。host 取 <see cref="Uri.Host"/>，IPv6 带方括号。</summary>
    public static bool IsLoopbackHost(string host) => LoopbackHosts.Contains(host);

    /// <summary>
    /// 运维白名单模式：AllowedRedirectHosts / AllowedCustomSchemes 任一非空即进入，
    /// 此后两张表同时生效（另一张为空 = 那一类一个都不许）。都空 = 不限（默认，只剩形态规则 + 黑名单）。
    /// </summary>
    public static bool AllowlistMode(DcrOptions dcr) =>
        dcr.AllowedRedirectHosts.Length > 0 || dcr.AllowedCustomSchemes.Length > 0;

    /// <summary>
    /// 校验整组 redirect_uris（/register 用）。返回 null = 通过；否则是给客户端看的 error_description。
    /// </summary>
    public static string? ValidateList(IReadOnlyList<string?>? uris, DcrOptions dcr)
    {
        if (uris is null || uris.Count == 0) return "redirect_uris is required";
        if (uris.Count > MaxRedirectUris) return $"at most {MaxRedirectUris} redirect_uris are allowed";
        for (var i = 0; i < uris.Count; i++)
        {
            var err = Validate(uris[i], dcr);
            if (err != null) return $"redirect_uris[{i}]: {err}";
        }
        return null;
    }

    /// <summary>
    /// 单条 redirect_uri：形态规则（RFC 6749 §3.1.2 + RFC 8252 私有 scheme）+ 黑名单 + 运维白名单。
    /// 返回 null = 通过。错误文案不回显 URI 本身（最长 2000 字符，也可能带诱导内容）。
    /// </summary>
    public static string? Validate(string? uri, DcrOptions dcr)
    {
        if (string.IsNullOrEmpty(uri)) return "empty redirect_uri";
        if (uri.Length > MaxRedirectUriLength) return $"redirect_uri longer than {MaxRedirectUriLength} characters";
        // 空白 / 控制字符一律不收：Uri.TryCreate 会悄悄 trim 首尾空白，注册值与比对值就对不上了。
        // 非 ASCII 一律不收：IDN 主机在 consent 页显示的 punycode 与浏览器按 UTS46 映射后真正去的地址可能不一致
        // （claude.ai[U+2024]evil.com 显示成 xn--…，浏览器却去 claude.ai.evil.com）；正常 DCR 客户端不用 IDN，路径里的非 ASCII 应已百分号编码
        foreach (var ch in uri)
        {
            if (ch <= 0x20 || ch == 0x7f) return "redirect_uri must not contain whitespace or control characters";
            if (ch > 0x7e) return "redirect_uri must be ASCII (percent-encode other characters; IDN hosts are not accepted)";
        }
        if (uri.Contains('#')) return "redirect_uri must not contain a fragment";
        // 反斜杠：浏览器对 http(s) 当 / 处理、对 Windows 启动器是 UNC 路径，各方解读不一致，一律不收
        if (uri.Contains('\\')) return "redirect_uri must not contain a backslash";

        // 先按原文取 scheme：Linux 上 Uri.TryCreate 会把 "/path" 当成 file:// 绝对 URI
        var colon = uri.IndexOf(':');
        if (colon <= 0) return "redirect_uri must be an absolute URI";
        var scheme = uri[..colon].ToLowerInvariant();
        if (!SchemeRegex().IsMatch(scheme)) return "redirect_uri has an invalid scheme";
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed)) return "redirect_uri must be an absolute URI";
        if (!string.IsNullOrEmpty(parsed.UserInfo) || AuthorityHasUserInfo(uri, colon))
            return "redirect_uri must not contain user info";

        var allowlist = AllowlistMode(dcr);
        switch (scheme)
        {
            case "https":
                if (string.IsNullOrEmpty(parsed.Host)) return "https redirect_uri must have a host";
                if (allowlist && !HostAllowed(parsed.Host, dcr.AllowedRedirectHosts)) return "redirect_uri host is not in the allowed list";
                return null;
            case "http":
                return IsLoopbackHost(parsed.Host) ? null
                    : "http redirect_uri is only allowed for loopback hosts (localhost, 127.0.0.1, [::1])";
            default:
                // 私有 scheme（app.immich:///oauth-callback、cursor://…）：移动端 / 桌面应用回调
                if (ForbiddenSchemes.Contains(scheme) || ForbiddenSchemePrefixes.Any(p => scheme.StartsWith(p, StringComparison.Ordinal)))
                    return $"redirect_uri scheme '{scheme}' is not allowed";
                // scheme 后面再嵌一个 URL（x:https://evil/、x://a/?u=http%3A//evil）的，多半是启动器转发，一律不收（UNC 路径已被上面的反斜杠规则拦掉）；
                // 正常回调（cursor://anysphere.cursor-mcp/oauth/callback、app.immich:///oauth-callback）不会带这些
                var rest = uri[(colon + 1)..];
                if (rest.Contains("http:", StringComparison.OrdinalIgnoreCase) || rest.Contains("https:", StringComparison.OrdinalIgnoreCase) ||
                    rest.Contains("http%3a", StringComparison.OrdinalIgnoreCase) || rest.Contains("https%3a", StringComparison.OrdinalIgnoreCase))
                    return "custom-scheme redirect_uri must not embed another URL";
                if (allowlist && !dcr.AllowedCustomSchemes.Any(s => string.Equals(s?.Trim(), scheme, StringComparison.OrdinalIgnoreCase)))
                    return $"redirect_uri scheme '{scheme}' is not in the allowed list";
                return null;
        }
    }

    /// <summary>
    /// 主机白名单匹配（Auth:Dcr:AllowedRedirectHosts）。是否启用白名单由调用方按 <see cref="AllowlistMode"/> 决定，这里空表 = 一个都不匹配。
    /// 条目精确匹配（忽略大小写）；以 "." 开头的条目只匹配其子域（".example.com" 匹配 a.example.com，不匹配 example.com 本身）。
    /// 只对 https 用：环回 http 始终放行，私有 scheme 走 AllowedCustomSchemes。
    /// </summary>
    public static bool HostAllowed(string host, IReadOnlyList<string> allowedHosts)
    {
        foreach (var raw in allowedHosts)
        {
            var entry = raw?.Trim();
            if (string.IsNullOrEmpty(entry)) continue;
            if (entry.StartsWith('.'))
            {
                if (host.Length > entry.Length && host.EndsWith(entry, StringComparison.OrdinalIgnoreCase)) return true;
            }
            else if (string.Equals(host, entry, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>
    /// 原文里 authority 段有没有 "@"。System.Uri 对未知 scheme 不一定拆 UserInfo，这里按原文兜一层：
    /// "scheme://" 之后、第一个 / ? 之前出现 @ 即视为带 userinfo。
    /// </summary>
    private static bool AuthorityHasUserInfo(string uri, int colon)
    {
        if (uri.Length < colon + 3 || uri[colon + 1] != '/' || uri[colon + 2] != '/') return false;
        var start = colon + 3;
        var end = uri.IndexOfAny(new[] { '/', '?' }, start);
        var authority = end < 0 ? uri[start..] : uri[start..end];
        return authority.Contains('@');
    }

    /// <summary>
    /// client_name 清洗：去掉控制字符与格式字符（含 RTL override、零宽字符这类能在 consent 页上伪装名字的），
    /// 连续空白压成一个空格，首尾 trim。空 → null（调用方兜底 "(unnamed)"）。
    /// 长度判断在清洗之后做，超长由调用方拒绝（invalid_client_metadata），不截断。
    /// </summary>
    public static string? SanitizeClientName(string? name)
    {
        if (string.IsNullOrEmpty(name)) return null;
        var sb = new StringBuilder(name.Length);
        var pendingSpace = false;
        foreach (var ch in name)
        {
            var cat = char.GetUnicodeCategory(ch);
            if (char.IsWhiteSpace(ch) || cat is System.Globalization.UnicodeCategory.LineSeparator
                                            or System.Globalization.UnicodeCategory.ParagraphSeparator)
            {
                pendingSpace = sb.Length > 0;
                continue;
            }
            if (cat is System.Globalization.UnicodeCategory.Control or System.Globalization.UnicodeCategory.Format)
                continue;
            if (pendingSpace) { sb.Append(' '); pendingSpace = false; }
            sb.Append(ch);
        }
        return sb.Length == 0 ? null : sb.ToString();
    }
}
