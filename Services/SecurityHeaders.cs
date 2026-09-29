namespace NasAuth.Services;

/// <summary>
/// 通用安全响应头（2026-09-29 安全修复）。在 next() 之前写好，端点要覆盖可以再改。
/// <list type="bullet">
/// <item><c>/proxy/*</c> 整段跳过：那是 YARP 流式转发的上游 MCP 响应，头归上游管。</item>
/// <item>CSP 不带 <c>form-action</c>：Chrome 会把它套到表单提交后的 302 上，consent POST /authorize
/// 跳回客户端 redirect_uri 那一跳会被拦，OAuth 流程直接断。<c>frame-ancestors 'none'</c> 防 consent 页被嵌进 iframe 点击劫持。</item>
/// <item>Referrer-Policy 用 <c>same-origin</c> 而不是 <c>no-referrer</c>：按 Fetch 规范，文档策略为 no-referrer 时
/// 浏览器给同源表单 POST 发的是 <c>Origin: null</c>，没有 Sec-Fetch-Site 的旧浏览器（Safari &lt; 16.4）会被
/// <see cref="CrossOriginGuard"/> 当成跨源拒掉。same-origin 对外同样一个字节的 referrer 都不发。</item>
/// <item><c>Cache-Control: no-store</c> 只给命中端点的响应（页面 / 重定向 / /token 的 JSON，RFC 6749 §5.1）；
/// wwwroot 静态文件不命中端点，继续按哈希 URL 缓存。<c>/.well-known/*</c>（发现文档、JWKS）是公开元数据，
/// 给 <c>public, max-age=300</c> 让 RP 能缓存；轮换签名密钥后最多 5 分钟 RP 才看到新 JWKS，旧 key 本来就会并存一段。
/// 不发 HSTS：TLS 在前置反向代理 / CDN 终结，HSTS 由那一层决定。</item>
/// </list>
/// </summary>
public static class SecurityHeaders
{
    public const string ContentSecurityPolicy =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
        "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

    public static Task InvokeAsync(HttpContext ctx, RequestDelegate next)
    {
        if (ctx.Request.Path.StartsWithSegments("/proxy", StringComparison.OrdinalIgnoreCase))
            return next(ctx);

        var h = ctx.Response.Headers;
        h.ContentSecurityPolicy = ContentSecurityPolicy;
        h.XFrameOptions = "DENY";
        h.XContentTypeOptions = "nosniff";
        h["Referrer-Policy"] = "same-origin";

        // 路由在 WebApplication 里隐式排在所有自定义中间件之前，这里已经能拿到命中的端点
        if (ctx.Request.Path.StartsWithSegments("/.well-known", StringComparison.OrdinalIgnoreCase))
        {
            h.CacheControl = "public, max-age=300";
        }
        else if (ctx.GetEndpoint() is not null)
        {
            h.CacheControl = "no-store";
            h.Pragma = "no-cache";
        }
        return next(ctx);
    }
}
