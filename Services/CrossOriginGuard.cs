using NasAuth.Config;

namespace NasAuth.Services;

/// <summary>
/// 跨源写请求拦截（CSRF，2026-09-29 安全修复）。全站没有 antiforgery token，这里按浏览器自带的来源头统一挡。
/// <para>
/// 为什么 SameSite=Lax 不够：如果 IdP 与其他应用（Gitea / Immich / Grafana 等）共用同一个可注册域、挂在兄弟子域上，
/// 对浏览器来说它们与 auth.* 是 same-site，Lax cookie 照带。任何一个子域被 XSS / 被接管，
/// 就能替已登录用户 POST /authorize（use_session=1，一键把授权码发给自己 DCR 注册的客户端）、
/// 改密码、在 /admin 下建用户。
/// </para>
/// <para>
/// 判据：写方法（POST / PUT / PATCH / DELETE）且不在豁免清单里时 ——
/// 有 <c>Sec-Fetch-Site</c> 只认 <c>same-origin</c> / <c>none</c>；否则有 <c>Origin</c> 只认本站来源
/// （请求自己的 scheme://host[:port]，经 UseForwardedHeaders 还原）或 <c>Auth:Issuer</c> 的来源，
/// <c>Origin: null</c> 拒绝；两个头都没有时再看 <c>Referer</c>：有且不是本站来源就拒（很老的浏览器 / 某些扩展剥掉了 Origin），
/// 三个头都没有放行（curl / 服务端客户端）。
/// </para>
/// <para>
/// 默认全拦、按清单豁免，而不是按清单保护：以后新加的 cookie 端点不用记着登记。
/// 豁免的都是机器接口或本来就该跨站的：/token /revoke /introspect /register /userinfo（Bearer / 客户端凭证，
/// 不认 cookie）、/proxy/*（MCP 流量）、/logout（RP-Initiated Logout 就是跨站表单 POST，登出型 CSRF 无害）。
/// /signin/*（IdP 回调）不豁免：Google / MicrosoftAccount handler 现在都是 GET 回调（response_mode=query），
/// 哪天改成 form_post 再按精确路径加回来。
/// </para>
/// </summary>
public static class CrossOriginGuard
{
    private static readonly string[] ExemptPrefixes =
    {
        "/token", "/revoke", "/introspect", "/register", "/userinfo", "/proxy", "/logout",
    };

    public static bool IsStateChanging(string method) =>
        HttpMethods.IsPost(method) || HttpMethods.IsPut(method) ||
        HttpMethods.IsPatch(method) || HttpMethods.IsDelete(method);

    public static bool IsExempt(PathString path) =>
        ExemptPrefixes.Any(p => path.StartsWithSegments(p, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// 纯判定（便于单测）：返回 null = 放行；否则返回拒绝原因（进日志）。
    /// <paramref name="requestOrigin"/> 是本次请求自己的来源，<paramref name="issuerOrigin"/> 是 Auth:Issuer 的来源（可空）。
    /// </summary>
    public static string? Check(string method, PathString path, string? secFetchSite, string? origin,
        string requestOrigin, string? issuerOrigin, string? referer = null)
    {
        if (!IsStateChanging(method) || IsExempt(path)) return null;

        if (!string.IsNullOrEmpty(secFetchSite))
        {
            return secFetchSite.Equals("same-origin", StringComparison.OrdinalIgnoreCase) ||
                   secFetchSite.Equals("none", StringComparison.OrdinalIgnoreCase)
                ? null
                : $"sec-fetch-site={secFetchSite}";
        }

        if (!string.IsNullOrEmpty(origin))
        {
            if (origin == "null") return "origin=null";
            return IsSelf(origin, requestOrigin, issuerOrigin) ? null : $"origin={origin}";
        }

        // Referer 带 path，SameOrigin 只比 scheme / host / port；解析不了的也按跨源处理
        if (!string.IsNullOrEmpty(referer))
            return IsSelf(referer, requestOrigin, issuerOrigin) ? null : "referer-cross-origin";

        return null;
    }

    private static bool IsSelf(string url, string requestOrigin, string? issuerOrigin) =>
        SameOrigin(url, requestOrigin) || (issuerOrigin is not null && SameOrigin(url, issuerOrigin));

    /// <summary>scheme + host（不分大小写）+ port（省略时按默认端口）都相等才算同源。</summary>
    public static bool SameOrigin(string a, string b) =>
        Uri.TryCreate(a, UriKind.Absolute, out var ua) &&
        Uri.TryCreate(b, UriKind.Absolute, out var ub) &&
        string.Equals(ua.Scheme, ub.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(ua.Host, ub.Host, StringComparison.OrdinalIgnoreCase) &&
        ua.Port == ub.Port;

    /// <summary>Auth:Issuer 的 scheme://host[:port]；没配或不是绝对 URL 返回 null。</summary>
    public static string? IssuerOrigin(AuthOptions options) =>
        Uri.TryCreate(options.Issuer, UriKind.Absolute, out var u) ? u.GetLeftPart(UriPartial.Authority) : null;

    /// <summary>中间件本体：取头 → <see cref="Check"/> → 拒绝时 403 + 警告日志（不入审计表，免得被刷库）。</summary>
    public static Task InvokeAsync(HttpContext ctx, RequestDelegate next, string? issuerOrigin, ILogger logger)
    {
        var req = ctx.Request;
        var reason = Check(req.Method, req.Path,
            req.Headers["Sec-Fetch-Site"].ToString(),
            req.Headers.Origin.ToString(),
            $"{req.Scheme}://{req.Host.Value}",
            issuerOrigin,
            req.Headers.Referer.ToString());
        if (reason is null) return next(ctx);

        logger.LogWarning("跨源写请求已拦截 method={Method} path={Path} reason={Reason} ip={Ip}",
            req.Method, req.Path.Value, reason, ctx.Connection.RemoteIpAddress?.ToString() ?? "-");
        ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
        ctx.Response.ContentType = "text/plain; charset=utf-8";
        return ctx.Response.WriteAsync("403 Forbidden: cross-origin request blocked. Reload the page and try again.");
    }
}
