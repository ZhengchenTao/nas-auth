using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Antiforgery;

namespace NasAuth.Services;

/// <summary>
/// 个人中心 / 管理后台写请求的 antiforgery token（external-auth.md §二十三，2026-10-16）。
/// <para>
/// 与 <see cref="CrossOriginGuard"/> 叠加，不替代它：那一层按浏览器自带的来源头判，挡的是兄弟子域
/// （对 SameSite 来说是 same-site，cookie 照带）借访客浏览器发来的写请求；这一层要求请求里带一个只有本站页面拿得到的令牌，
/// 来源头被剥掉（老浏览器、扩展、中间代理）或判据哪天出漏洞时还挡得住。
/// </para>
/// <para>
/// 只管 <c>/account/*</c>、<c>/admin/*</c> 与 <c>/external/{provider}/bind</c>：这些都是本服务自己的页面发的表单。
/// 登录（<c>/login</c>）、OAuth / OIDC 协议端点（<c>/authorize</c>、<c>/token</c>、<c>/revoke</c>、<c>/introspect</c>、
/// <c>/register</c>、<c>/userinfo</c>、<c>/logout</c>）、<c>/proxy/*</c>、forward-auth 不加：它们要么不认 cookie，
/// 要么本来就该接受别的应用发起的请求。
/// </para>
/// <para>
/// 用框架自带的 <see cref="IAntiforgery"/>：令牌绑定到当前用户（NameIdentifier），cookie 用 <c>__Host-</c> 前缀，
/// 兄弟子域种不了也读不到。表单由服务端渲染时自动插入隐藏字段（<see cref="Protect"/>）；
/// 脚本 fetch 带 <see cref="HeaderName"/> 头，值取页面 <c>&lt;meta name="csrf-token"&gt;</c>（theme.js 自动加）。
/// </para>
/// </summary>
public static class AntiforgeryGuard
{
    public const string CookieName = "__Host-nas-auth-csrf";
    public const string FormFieldName = "__RequestVerificationToken";
    public const string HeaderName = "X-CSRF-TOKEN";
    public const string MetaName = "csrf-token";

    public static void Configure(AntiforgeryOptions o)
    {
        o.Cookie.Name = CookieName;
        o.Cookie.Path = "/";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Strict;
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always; // __Host- 要求，同会话 cookie
        o.FormFieldName = FormFieldName;
        o.HeaderName = HeaderName;
        // X-Frame-Options 由 SecurityHeaders 统一给 DENY，别让 antiforgery 补一个 SAMEORIGIN
        o.SuppressXFrameOptionsHeader = true;
    }

    /// <summary>端点元数据：标明这个端点要求 antiforgery token（测试按它检查有没有漏挂）。</summary>
    public sealed class RequiresTokenMetadata
    {
        public static readonly RequiresTokenMetadata Instance = new();
        private RequiresTokenMetadata() { }
    }

    /// <summary>给端点 / 路由组挂上校验。挂在门禁过滤器（未登录 → 登录页、非管理员 → 404）之后，那些照旧先生效。</summary>
    public static TBuilder RequireCsrfToken<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder
    {
        builder.WithMetadata(RequiresTokenMetadata.Instance);
        builder.AddEndpointFilter(FilterAsync);
        return builder;
    }

    private static async ValueTask<object?> FilterAsync(EndpointFilterInvocationContext ic, EndpointFilterDelegate next)
    {
        var ctx = ic.HttpContext;
        if (!CrossOriginGuard.IsStateChanging(ctx.Request.Method)) return await next(ic);
        // 没有会话的请求不借任何人的身份，交给端点自己处理（/external/{provider}/bind 送去登录）；
        // /account、/admin 有 RequireAuthorization，走不到这里
        if (ctx.User.Identity?.IsAuthenticated != true) return await next(ic);

        try
        {
            await ctx.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(ctx);
        }
        catch (AntiforgeryValidationException ex)
        {
            ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("nas-auth.csrf")
                .LogWarning("缺少或无效的 antiforgery token method={Method} path={Path} user={User} reason={Reason} ip={Ip}",
                    ctx.Request.Method, ctx.Request.Path.Value, ctx.User.Identity?.Name ?? "-", ex.Message,
                    ctx.Connection.RemoteIpAddress?.ToString() ?? "-");
            return Results.Text("403 Forbidden: missing or invalid CSRF token. Reload the page and try again.",
                "text/plain; charset=utf-8", statusCode: StatusCodes.Status403Forbidden);
        }
        return await next(ic);
    }

    // 只处理本服务模板产出的 HTML：属性值都经过 HtmlEncode，不会出现裸的 '>'
    private static readonly Regex PostFormTag = new(
        @"<form\b[^>]*\bmethod\s*=\s*['""]?post\b[^>]*>", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>签发令牌（顺带种 cookie），插进页面里每个 POST 表单和 &lt;head&gt;。</summary>
    public static string Protect(HttpContext ctx, string html)
    {
        var tokens = ctx.RequestServices.GetRequiredService<IAntiforgery>().GetAndStoreTokens(ctx);
        return Inject(html, tokens.RequestToken!);
    }

    /// <summary>纯函数（便于单测）：每个 method=post 的 &lt;form&gt; 后插隐藏字段，&lt;/head&gt; 前插 meta。</summary>
    public static string Inject(string html, string requestToken)
    {
        var enc = WebUtility.HtmlEncode(requestToken);
        var hidden = $"<input type='hidden' name='{FormFieldName}' value='{enc}'>";
        html = PostFormTag.Replace(html, m => m.Value + hidden);
        var head = html.IndexOf("</head>", StringComparison.OrdinalIgnoreCase);
        return head < 0 ? html : html.Insert(head, $"<meta name='{MetaName}' content='{enc}'>");
    }
}
