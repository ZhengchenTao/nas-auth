using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using NasAuth.Config;
using NasAuth.Services;

namespace NasAuth.Endpoints;

public static class DiscoveryEndpoints
{
    public static void MapDiscoveryEndpoints(this IEndpointRouteBuilder app)
    {
        // RFC 8414
        app.MapGet("/.well-known/oauth-authorization-server",
            (AuthOptions auth, ResourceCatalog catalog) =>
        {
            // RFC 8414 §2: issuer 必须是不带路径 / 不带尾斜杠的 issuer identifier。
            // 端点字段也用同一份去尾斜杠的根，确保 issuer 与下游 MCP（obsidian-mcp /
            // gitea-mcp）的 ValidIssuer（如 "https://auth.example.com"）完全一致。
            var issuer = auth.Issuer.TrimEnd('/');
            return Results.Ok(new
            {
                issuer = issuer,
                authorization_endpoint = $"{issuer}/authorize",
                token_endpoint = $"{issuer}/token",
                registration_endpoint = $"{issuer}/register",
                revocation_endpoint = $"{issuer}/revoke",
                introspection_endpoint = $"{issuer}/introspect",
                // RS256 access token 的验签公钥（RFC 8414 §2）；与 openid-configuration 指向同一份 JWKS
                jwks_uri = $"{issuer}/.well-known/jwks.json",
                response_types_supported = new[] { "code" },
                grant_types_supported = new[] { "authorization_code", "refresh_token" },
                code_challenge_methods_supported = new[] { "S256" },
                scopes_supported = catalog.AllScopes(),
                token_endpoint_auth_methods_supported = new[] { "client_secret_post", "client_secret_basic", "none" },
            });
        });
    }
}
