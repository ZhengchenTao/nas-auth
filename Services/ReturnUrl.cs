using System.Diagnostics.CodeAnalysis;

namespace NasAuth.Services;

/// <summary>
/// 用户可控的回跳目标（return_url 等）统一过这里，防开放跳转（2026-09-29 安全修复）。
/// <para>
/// 判据照抄 ASP.NET Core 的 <c>UrlHelper.IsLocalUrl</c>（SharedUrlHelper）：只放行 "/x" 与 "~/x"；
/// 拒绝空串、绝对 URL、协议相对 "//x"、"/\x"，以及<b>任何位置</b>的控制字符 ——
/// 浏览器解析 URL 时会先剥掉 TAB / CR / LF，"/\t/evil.com" 到了地址栏就是 "//evil.com"。
/// 第二位之后的反斜杠放行（与框架一致："/a\b" 在浏览器里是站内的 "/a/b"）。
/// </para>
/// <para>
/// 比框架多一条：只收可打印 ASCII（0x20–0x7E）。非 ASCII（中文、U+2028 等）进 Location 头时
/// Kestrel 直接抛异常 —— POST /login 那时已经 SignInCookie，用户看到的是登录成功后的 500。
/// 正常的站内回跳（/authorize?… 由 QueryString 原样拼回）本来就是百分号编码过的纯 ASCII。
/// </para>
/// </summary>
public static class ReturnUrl
{
    public const string DefaultTarget = "/account";

    public static bool IsLocalUrl([NotNullWhen(true)] string? url)
    {
        if (string.IsNullOrEmpty(url)) return false;

        // "/" 或 "/foo"，但不能是 "//" 或 "/\"
        if (url[0] == '/')
        {
            if (url.Length == 1) return true;
            if (url[1] != '/' && url[1] != '\\') return !HasInvalidCharacter(url.AsSpan(1));
            return false;
        }

        // "~/" 或 "~/foo"，但不能是 "~//" 或 "~/\"
        if (url[0] == '~' && url.Length > 1 && url[1] == '/')
        {
            if (url.Length == 2) return true;
            if (url[2] != '/' && url[2] != '\\') return !HasInvalidCharacter(url.AsSpan(2));
            return false;
        }

        return false;
    }

    /// <summary>
    /// 合法站内地址原样返回（带 query 的 "/authorize?..." 照旧往返），否则回落到 <paramref name="fallback"/>。
    /// "~/x" 折成 "/x"：本服务没有 PathBase，直接把 "~" 写进 Location 浏览器会按相对路径解析成 "/当前目录/~/x"。
    /// </summary>
    public static string SafeLocal(string? url, string fallback = DefaultTarget)
    {
        if (!IsLocalUrl(url)) return fallback;
        return url[0] == '~' ? url[1..] : url;
    }

    /// <summary>控制字符（框架原有判据）或可打印 ASCII 之外的任何字符。</summary>
    private static bool HasInvalidCharacter(ReadOnlySpan<char> s)
    {
        foreach (var c in s)
            if (c < 0x20 || c > 0x7E) return true;
        return false;
    }
}
