using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using NasAuth.Config;
using NasAuth.Data.Repositories;
using NasAuth.Services;

namespace NasAuth.Endpoints;

/// <summary>
/// 最小 OIDC（外部认证设计 §七）：discovery / JWKS / userinfo。
/// 服务对象是外部 RP（Gitea web SSO），与现有 MCP OAuth（RFC 8414 discovery）并存。
/// id_token 签发在 /token（scope 含 openid 时附带），见 TokenEndpoints。
/// </summary>
public static class OidcEndpoints
{
    public static void MapOidcEndpoints(this IEndpointRouteBuilder app)
    {
        // OIDC Discovery（go-oidc 要求；与 oauth-authorization-server 并存）
        app.MapGet("/.well-known/openid-configuration",
            (AuthOptions auth, ResourceCatalog catalog) =>
        {
            var issuer = auth.Issuer.TrimEnd('/');
            return Results.Ok(new
            {
                issuer,
                authorization_endpoint = $"{issuer}/authorize",
                token_endpoint = $"{issuer}/token",
                userinfo_endpoint = $"{issuer}/userinfo",
                // RP-Initiated Logout（§十五）：Immich 会自动读这个字段，退出时带 id_token_hint 跳过来
                end_session_endpoint = $"{issuer}/logout",
                jwks_uri = $"{issuer}/.well-known/jwks.json",
                response_types_supported = new[] { "code" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { "RS256" },
                grant_types_supported = new[] { "authorization_code", "refresh_token" },
                code_challenge_methods_supported = new[] { "S256" },
                scopes_supported = new[] { "openid", "email", "profile" }
                    .Concat(catalog.AllScopes()).Distinct().ToArray(),
                token_endpoint_auth_methods_supported = new[] { "client_secret_post", "none" },
                claims_supported = new[] { "sub", "email", "name", "preferred_username", "iss", "aud", "iat", "exp" },
            });
        });

        app.MapGet("/.well-known/jwks.json", (OidcKeyService keys) => Results.Ok(keys.BuildJwks()));

        // UserInfo（OIDC Core §5.3）：Bearer = nas-auth 自己签的 access token（RS256 at+jwt，或过渡期 HS256）。
        // Gitea 拿到 token response 后会带 access_token 来取 claims。
        app.MapGet("/userinfo", HandleUserInfo);
        app.MapPost("/userinfo", HandleUserInfo);
    }

    private static IResult HandleUserInfo(HttpContext ctx,
        JwtValidator validator,
        UserRepository users,
        ExternalIdentityRepository identities)
    {
        var auth = ctx.Request.Headers.Authorization.ToString();
        if (!auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return Unauthorized(ctx);

        var principal = validator.TryValidate(auth["Bearer ".Length..].Trim(), out _);
        // JwtValidator 不做 inbound claim map，sub 就叫 sub
        var userId = principal?.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(userId) || users.GetById(userId) is null)
            return Unauthorized(ctx);

        var (email, name) = ResolveProfile(identities, users, userId);
        return Results.Ok(new
        {
            sub = userId,
            preferred_username = userId,
            email,
            name,
        });
    }

    /// <summary>
    /// email：优先用户自己的 <c>users.email</c>（管理员在后台设，external-auth.md §十四）；
    /// 没设才退回第一条 active 外部身份的邮箱（google 优先于 microsoft，按 provider 字典序）。
    /// <para>为什么要自己的邮箱：下游（如 Immich）按 email 把 OIDC 身份关联到它自己的账号。
    /// 一个用户可能同时绑了 Google 和 Microsoft 两个外部账号，退回逻辑只会下发其中一个的邮箱 ——
    /// 它未必是该用户在下游应用里的账号邮箱，甚至可能恰好是下游另一个账号的邮箱，于是关联到错误的账号。
    /// 纯本地密码用户没有外部身份，不设就没有 email 可发。</para>
    /// name：第一条 active 外部身份的 display_name，没有就是 user_id。
    /// </summary>
    public static (string? Email, string? Name) ResolveProfile(
        ExternalIdentityRepository identities, UserRepository users, string userId)
    {
        var first = identities.ListByUser(userId)
            .FirstOrDefault(r => r.status == "active" && !string.IsNullOrEmpty(r.email));
        var own = users.GetById(userId)?.email;
        return (string.IsNullOrEmpty(own) ? first?.email : own, first?.display_name ?? userId);
    }

    private static IResult Unauthorized(HttpContext ctx)
    {
        ctx.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
        return Results.Unauthorized();
    }
}
