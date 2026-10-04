using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using NasAuth.Config;
using NasAuth.Data.Repositories;
using NasAuth.Services;

namespace NasAuth.Endpoints;

public static class RegistrationEndpoints
{
    /// <summary>RFC 7591 DCR。public client（PKCE）默认不发 secret。</summary>
    public class RegisterRequest
    {
        [JsonPropertyName("client_name")] public string? ClientName { get; set; }
        [JsonPropertyName("redirect_uris")] public List<string>? RedirectUris { get; set; }
        [JsonPropertyName("token_endpoint_auth_method")] public string? TokenEndpointAuthMethod { get; set; }
        [JsonPropertyName("grant_types")] public List<string>? GrantTypes { get; set; }
        [JsonPropertyName("response_types")] public List<string>? ResponseTypes { get; set; }
        [JsonPropertyName("scope")] public string? Scope { get; set; }
    }

    /// <summary>/register 的限速策略名：每 IP（IPv6 按 /64）每小时 10 次，另有全局每小时 200 次封顶。</summary>
    public const string RateLimitPolicy = "dcr";

    /// <summary>全局封顶：所有来源合计每小时最多注册这么多次（固定窗口）。</summary>
    public const int GlobalRegistrationsPerHour = 200;

    /// <summary>
    /// 限速分区：按来源（<see cref="RateLimitKeys.ClientKey(HttpContext)"/>）的 token bucket，每小时回满 10 个。
    /// /register 不需要登录，不限的话任何人都能刷出无数个客户端（admin 后台被垃圾名字淹没、clients 表无限长）。
    /// 正常 MCP 客户端一次连接只注册一次，10/h 足够。
    /// </summary>
    public static RateLimitPartition<string> DcrRateLimitPartition(HttpContext ctx) =>
        RateLimitPartition.GetTokenBucketLimiter(RateLimitKeys.ClientKey(ctx), _ => new TokenBucketRateLimiterOptions
        {
            TokenLimit = 10,
            TokensPerPeriod = 10,
            ReplenishmentPeriod = TimeSpan.FromHours(1),
            QueueLimit = 0,
            AutoReplenishment = true,
        });

    /// <summary>
    /// 全局限速器：只对挂了 "dcr" 策略的端点（/register）计数，全体来源共用一个固定窗口，
    /// 防分布式来源（大量 IP / IPv6 段）绕过按来源的桶。其余端点 NoLimiter。
    /// </summary>
    public static PartitionedRateLimiter<HttpContext> CreateGlobalLimiter() =>
        PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
            ctx.GetEndpoint()?.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName == RateLimitPolicy
                ? RateLimitPartition.GetFixedWindowLimiter("dcr-global", _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = GlobalRegistrationsPerHour,
                    Window = TimeSpan.FromHours(1),
                    QueueLimit = 0,
                    AutoReplenishment = true,
                })
                : RateLimitPartition.GetNoLimiter("other"));

    /// <summary>
    /// 注册 /register 的两层限速（Program.cs 的 AddRateLimiter 里调一次）：按来源的 "dcr" 策略 + 全局封顶。
    /// 已有 GlobalLimiter 时与之串联，不覆盖。
    /// </summary>
    public static void AddDcrRateLimits(RateLimiterOptions opts)
    {
        opts.AddPolicy(RateLimitPolicy, DcrRateLimitPartition);
        var global = CreateGlobalLimiter();
        opts.GlobalLimiter = opts.GlobalLimiter is null ? global : PartitionedRateLimiter.CreateChained(opts.GlobalLimiter, global);
    }

    public static void MapRegistrationEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/register", async (HttpContext ctx, ClientRepository clients,
            AuditLogger audit, AuthOptions options) =>
        {
            RegisterRequest? req;
            try
            {
                req = await ctx.Request.ReadFromJsonAsync<RegisterRequest>();
            }
            catch
            {
                return Results.BadRequest(new { error = "invalid_client_metadata", error_description = "could not parse JSON" });
            }
            if (req is null)
                return Results.BadRequest(new { error = "invalid_client_metadata" });

            // client_name 先清洗（控制 / 格式字符、多余空白），审计里也只记清洗后的值；
            // 超长拒绝而不截断：截断后的名字在 consent 页上可能恰好拼成误导性的文字
            var clientName = RedirectUriPolicy.SanitizeClientName(req.ClientName);
            if (clientName is { Length: > RedirectUriPolicy.MaxClientNameLength })
            {
                audit.Register(false, clientName[..RedirectUriPolicy.MaxClientNameLength], ctx.RemoteIp(), "client_name_too_long");
                return Results.BadRequest(new
                {
                    error = "invalid_client_metadata",
                    error_description = $"client_name must be at most {RedirectUriPolicy.MaxClientNameLength} characters",
                });
            }
            clientName ??= "(unnamed)";

            // redirect_uris：1–10 条，每条 ≤ 2000 字符、绝对 URI、无 fragment、无 userinfo；
            // https（白名单模式下受 AllowedRedirectHosts 约束）、http 仅环回、私有 scheme（排除启动器类，白名单模式下受 AllowedCustomSchemes 约束）
            var uriError = RedirectUriPolicy.ValidateList(req.RedirectUris, options.Dcr);
            if (uriError != null)
            {
                audit.Register(false, clientName, ctx.RemoteIp(), "bad_redirect_uri");
                return Results.BadRequest(new { error = "invalid_redirect_uri", error_description = uriError });
            }
            var redirectUris = req.RedirectUris!;

            var authMethod = string.IsNullOrEmpty(req.TokenEndpointAuthMethod) ? "none" : req.TokenEndpointAuthMethod!;
            // 带 secret 的两种写法（post / basic）在 /token 上都收，登记哪一种只是客户端自己的偏好
            if (authMethod != "none" && authMethod != "client_secret_post" && authMethod != "client_secret_basic")
            {
                audit.Register(false, clientName, ctx.RemoteIp(), "unsupported_auth_method");
                return Results.BadRequest(new { error = "invalid_client_metadata", error_description = "unsupported token_endpoint_auth_method" });
            }

            var clientId = "c_" + GenerateRandomToken(16);
            string? clientSecret = null;
            string? secretHash = null;
            if (authMethod != "none")
            {
                clientSecret = GenerateRandomToken(32);
                Span<byte> h = stackalloc byte[32];
                SHA256.TryHashData(Encoding.UTF8.GetBytes(clientSecret), h, out _);
                secretHash = Convert.ToHexString(h);
            }

            clients.Insert(clientId, secretHash, clientName, redirectUris, authMethod, autoRegistered: true);

            audit.Register(true, clientName, ctx.RemoteIp());

            // RFC 7591 §3.2.1 推荐字段
            var resp = new Dictionary<string, object?>
            {
                ["client_id"] = clientId,
                ["client_id_issued_at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["client_name"] = clientName,
                ["redirect_uris"] = redirectUris,
                ["token_endpoint_auth_method"] = authMethod,
                ["grant_types"] = req.GrantTypes ?? new() { "authorization_code", "refresh_token" },
                ["response_types"] = req.ResponseTypes ?? new() { "code" },
            };
            if (clientSecret is not null) resp["client_secret"] = clientSecret;
            return Results.Json(resp, statusCode: StatusCodes.Status201Created);
        }).RequireRateLimiting(RateLimitPolicy);
    }

    public static string GenerateRandomToken(int byteLen)
    {
        Span<byte> raw = stackalloc byte[64];
        if (byteLen > 64) raw = new byte[byteLen];
        var slice = raw.Slice(0, byteLen);
        RandomNumberGenerator.Fill(slice);
        return PkceVerifier.Base64UrlEncode(slice);
    }
}

internal static class HttpContextExtensions
{
    public static string? RemoteIp(this HttpContext ctx)
        => ctx.Connection.RemoteIpAddress?.ToString();
}
