using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using NasAuth.Services;
using Yarp.ReverseProxy.Forwarder;

namespace NasAuth.Endpoints;

/// <summary>
/// /proxy/{aud}/{**path} —— 换 token 的反代翻译层。
/// 流程：
///   1. 读 Authorization: Bearer &lt;jwt&gt;
///   2. JwtValidator 验签（RS256 at+jwt 走 current / previous RSA 公钥；过渡期 HS256 走 Current / Previous）
///   3. aud claim 必须等于 URL 里的 {aud}
///   4. 查 ResourceCatalog 拿 ProxyConfig
///   5. 用环境变量里的上游 token 替换 Authorization
///   6. IHttpForwarder 流式反代到 upstream
/// scope 暂不细化（只校验 aud）。
/// </summary>
public static class ProxyEndpoints
{
    public static void MapProxyEndpoints(this IEndpointRouteBuilder app)
    {
        // RFC 9728 Protected Resource Metadata
        // 必须挂在 proxy 总路由之前，避免被 {**path} 兜底吃掉。
        // Claude.ai MCP discovery 流程：
        //   1. POST /proxy/{aud}/mcp → 401 (WWW-Authenticate 指明 resource_metadata)
        //   2. GET <resource_metadata URL> → 拿到 authorization_servers
        //   3. 走 OAuth，/authorize 携带 resource=<resource identifier>
        app.MapGet("/proxy/{aud}/.well-known/oauth-protected-resource",
            (string aud, ResourceCatalog catalog, NasAuth.Config.AuthOptions auth) =>
        {
            var r = catalog.FindByAud(aud);
            if (r is null || r.Proxy is null) return Results.NotFound();
            return Results.Ok(new
            {
                resource = r.ResourceUrl,
                authorization_servers = new[] { auth.Issuer.TrimEnd('/') },
                scopes_supported = r.Scopes,
                bearer_methods_supported = new[] { "header" },
            });
        });

        // 涵盖 MCP 常用动词：GET（SSE 流）、POST（JSON-RPC）、OPTIONS（CORS preflight）。
        // 其他动词 ezBookkeeping MCP 用不到，但留全套避免奇异客户端撞 405。
        var methods = new[] { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD" };

        app.MapMethods("/proxy/{aud}/{**path}", methods, HandleAsync);
    }

    /// <summary>
    /// 401 时往响应里塞 WWW-Authenticate，按 MCP spec §authorization + RFC 9728 §5.1。
    /// resource_metadata 指向上面的 PRM 端点。
    /// </summary>
    private static void SetWwwAuthenticate(HttpContext ctx, string aud, string error)
    {
        var prmUrl = $"{ctx.Request.Scheme}://{ctx.Request.Host}/proxy/{aud}/.well-known/oauth-protected-resource";
        ctx.Response.Headers["WWW-Authenticate"] =
            $"Bearer error=\"{error}\", resource_metadata=\"{prmUrl}\"";
    }

    private static async Task<IResult> HandleAsync(
        HttpContext ctx,
        string aud,
        ResourceCatalog catalog,
        JwtValidator jwtValidator,
        IHttpForwarder forwarder,
        HttpMessageInvoker httpClient,
        AuditLogger audit,
        ILoggerFactory loggerFactory)
    {
        var logger = loggerFactory.CreateLogger("nas-auth.proxy");

        // ---- 1. 取 Bearer ----
        var authHeader = ctx.Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(authHeader) ||
            !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            SetWwwAuthenticate(ctx, aud, "invalid_token");
            return Results.Unauthorized();
        }
        var token = authHeader["Bearer ".Length..].Trim();
        if (string.IsNullOrEmpty(token))
        {
            SetWwwAuthenticate(ctx, aud, "invalid_token");
            return Results.Unauthorized();
        }

        // ---- 2. 验签 ----
        var principal = jwtValidator.TryValidate(token, out var validated);
        if (principal is null || validated is not JwtSecurityToken jwt)
        {
            audit.ProxyDenied(aud, userId: null, clientId: null, ctx.RemoteIp(), "jwt_invalid");
            SetWwwAuthenticate(ctx, aud, "invalid_token");
            return Results.Unauthorized();
        }

        // ---- 3. aud 匹配 ----
        // JwtValidator 没开 ValidateAudience，这里手动比对：URL 里的 {aud} 必须在 JWT 的 aud 集合里。
        // 否则可以用 aud=X 的 token 去调 /proxy/Y/*，违反资源隔离。
        // 用 Contains 而非 FirstOrDefault：DCR 客户端（如 Grok）不发 resource 时签的是多 aud
        // token（aud 为数组），URL 里的 {aud} 只要落在数组内即放行，见 docs/design/external-auth.md §十三。
        // 用 JwtSecurityToken.Audiences 比 principal.FindFirst("aud") 可靠（数组 aud 是多条 claim）。
        // sub / client_id 直接按原名取：JwtValidator 不做 inbound claim map。
        var sub = principal.FindFirst("sub")?.Value;
        var clientId = principal.FindFirst("client_id")?.Value;
        if (!jwt.Audiences.Contains(aud, StringComparer.Ordinal))
        {
            audit.ProxyDenied(aud, sub, clientId, ctx.RemoteIp(), $"aud_mismatch:{string.Join(',', jwt.Audiences)}");
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        // ---- 4. 查 ResourceCatalog ----
        var resource = catalog.FindByAud(aud);
        if (resource is null)
        {
            // 不应发生（aud 已经在 token 里，签发时一定查过 catalog），但兜底。
            return Results.NotFound();
        }
        if (resource.Proxy is null)
        {
            // aud 是真的，但这个资源没配 proxy 模式（典型：obsidian / gitea，客户端应直连）。
            return Results.StatusCode(StatusCodes.Status404NotFound);
        }

        // ---- 5. 取上游 token ----
        // 启动期 ResourceCatalog 已校验 bearer_env 非空，这里再取一次防止运行时被改空。
        var upstreamToken = Environment.GetEnvironmentVariable(resource.Proxy.BearerEnv);
        if (string.IsNullOrWhiteSpace(upstreamToken))
        {
            logger.LogError("proxy {Aud} bearer_env={Env} 运行时为空", aud, resource.Proxy.BearerEnv);
            return Results.Problem(
                title: "proxy upstream token not configured",
                statusCode: StatusCodes.Status500InternalServerError);
        }

        // ---- 6. YARP 反代 ----
        // upstream 是 host root（ResourceCatalog 校验过 path=='/' 或空）。
        // 入站路径 /proxy/{aud}/{**path} 中的 /proxy/{aud} 前缀由 transformer 剥掉，
        // {**path} 直接透传到上游 —— 客户端 connector URL 里的 path（如 /mcp）就是 MCP 端点。
        var stripPrefix = $"/proxy/{aud}";
        var transformer = new BearerSwapTransformer(upstreamToken, stripPrefix);
        var requestConfig = new ForwarderRequestConfig
        {
            ActivityTimeout = TimeSpan.FromMinutes(5), // MCP SSE 长连接
        };

        var error = await forwarder.SendAsync(ctx, resource.Proxy.Upstream.TrimEnd('/'), httpClient, requestConfig, transformer);
        if (error != ForwarderError.None)
        {
            var ex = ctx.GetForwarderErrorFeature()?.Exception;
            logger.LogWarning(ex, "proxy {Aud} forward error: {Error}", aud, error);
            // SendAsync 在出错时已写过 status code，不要再覆盖。
            // 返回 EmptyResult 让 ASP.NET 把已写入的响应原样返回。
        }

        audit.ProxyForward(aud, sub, clientId, ctx.RemoteIp(),
            ctx.Request.Method, ctx.Response.StatusCode);

        return Results.Empty;
    }

    /// <summary>
    /// 改写转发请求：
    ///  - 重写 RequestUri：剥掉入站 /proxy/{aud} 前缀，剩余 path 拼到 upstream 后面
    ///    （否则 YARP 默认 transformer 会把完整入站 path 拼上去，导致 /mcp/proxy/{aud}/mcp 这种笑话）
    ///  - 把入站 Authorization（nas-auth JWT）替换成上游 Bearer
    ///  - 去掉 Cookie（避免上游误把 cookie 当会话来源）
    ///  - Host header 设回 null 让 HttpClient 用 RequestUri 的 host
    /// </summary>
    private class BearerSwapTransformer : HttpTransformer
    {
        private readonly string _upstreamBearer;
        private readonly string _stripPrefix;

        public BearerSwapTransformer(string upstreamBearer, string stripPrefix)
        {
            _upstreamBearer = upstreamBearer;
            _stripPrefix = stripPrefix;
        }

        public override async ValueTask TransformRequestAsync(
            HttpContext httpContext,
            HttpRequestMessage proxyRequest,
            string destinationPrefix,
            CancellationToken cancellationToken)
        {
            // base 会基于 destinationPrefix + 入站 path 算出 RequestUri；我们之后整体覆盖。
            await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix, cancellationToken);

            var incomingPath = httpContext.Request.Path.Value ?? "";
            var subPath = incomingPath.StartsWith(_stripPrefix, StringComparison.Ordinal)
                ? incomingPath.Substring(_stripPrefix.Length)
                : incomingPath;
            if (string.IsNullOrEmpty(subPath)) subPath = "/";
            var qs = httpContext.Request.QueryString.Value ?? "";
            proxyRequest.RequestUri = new Uri($"{destinationPrefix.TrimEnd('/')}{subPath}{qs}");

            proxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _upstreamBearer);
            proxyRequest.Headers.Remove("Cookie");

            // 把 Host header 设回 null 让 HttpClient 从 RequestUri 计算，避免回到入站域名
            proxyRequest.Headers.Host = null;
        }
    }
}
