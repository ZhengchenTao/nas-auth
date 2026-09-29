using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Services;

namespace NasAuth.Endpoints;

public static class TokenEndpoints
{
    /// <summary>
    /// RFC 7662 §2.2 的 JWT 响应体。直接读 token 原始 claims：
    /// 原先用 principal.Claims.ToDictionary，多 aud token（DCR 回退签的数组 aud，§十三）有重复 "aud" 键直接抛异常 500；
    /// aud 与 JWT 同形：单个为字符串，多个为数组。
    /// </summary>
    public static object JwtIntrospection(JwtSecurityToken jwt)
    {
        string? Get(string type) => jwt.Claims.FirstOrDefault(c => c.Type == type)?.Value;
        long? GetLong(string type) => long.TryParse(Get(type), out var v) ? v : null;

        var auds = jwt.Audiences.ToArray();
        return new
        {
            active = true,
            sub = Get("sub"),
            aud = auds.Length switch { 0 => null, 1 => (object)auds[0], _ => auds },
            iss = jwt.Issuer,
            scope = Get("scope"),
            resource = Get("resource"),
            client_id = Get("client_id"),
            exp = GetLong("exp"),
            iat = GetLong("iat"),
            token_type = "Bearer",
        };
    }

    public static void MapTokenEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/token", async (HttpContext ctx,
            ClientRepository clients,
            AuthCodeRepository authCodes,
            RefreshTokenRepository refreshTokens,
            ExternalIdentityRepository identities,
            UserRepository users,
            ResourceCatalog catalog,
            JwtIssuer issuer,
            OidcKeyService oidcKeys,
            AuditLogger audit,
            UserResourceRepository userResources) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var grantType = form["grant_type"].ToString();

            if (grantType == "authorization_code")
                return await HandleAuthCode(ctx, form, clients, authCodes, refreshTokens, identities, users, catalog, issuer, oidcKeys, audit);
            if (grantType == "refresh_token")
                return await HandleRefresh(ctx, form, clients, refreshTokens, catalog, issuer, audit, userResources);

            audit.Token(false, grantType, form["client_id"]!, null, null, ctx.RemoteIp(), "unsupported_grant_type");
            return Results.BadRequest(new { error = "unsupported_grant_type" });
        }).RequireRateLimiting("auth-sensitive");

        app.MapPost("/revoke", async (HttpContext ctx,
            ClientRepository clients,
            RefreshTokenRepository refreshTokens,
            AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var token = form["token"].ToString();
            var clientId = form["client_id"].ToString();
            var clientSecret = form["client_secret"].ToString();

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(token))
            {
                audit.Revoke(false, clientId, ctx.RemoteIp(), "missing_params");
                return Results.BadRequest(new { error = "invalid_request" });
            }

            if (!TryAuthenticateClient(clients, clientId, clientSecret, out var client))
            {
                audit.Revoke(false, clientId, ctx.RemoteIp(), "client_auth_failed");
                return Results.Json(new { error = "invalid_client" }, statusCode: 401);
            }

            // RFC 7009：不区分 access vs refresh token，处理 refresh token；access token 是 JWT，到期自动失效。
            var hash = JwtIssuer.HashRefreshToken(token);
            var row = refreshTokens.GetByHash(hash);
            if (row is not null && row.client_id == client!.client_id)
                refreshTokens.Revoke(hash);

            audit.Revoke(true, client!.client_id, ctx.RemoteIp());
            // RFC 7009 §2.2：无论 token 是否存在都返回 200
            return Results.Ok();
        });

        app.MapPost("/introspect", async (HttpContext ctx,
            ClientRepository clients,
            RefreshTokenRepository refreshTokens,
            JwtValidator validator,
            AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var token = form["token"].ToString();
            var clientId = form["client_id"].ToString();
            var clientSecret = form["client_secret"].ToString();

            if (!TryAuthenticateClient(clients, clientId, clientSecret, out var client))
            {
                audit.Introspect(false, clientId, ctx.RemoteIp());
                return Results.Json(new { error = "invalid_client" }, statusCode: 401);
            }

            if (string.IsNullOrEmpty(token))
            {
                audit.Introspect(false, client!.client_id, ctx.RemoteIp());
                return Results.Ok(new { active = false });
            }

            // 先按 JWT 验
            var principal = validator.TryValidate(token, out var validated);
            if (principal is not null && validated is JwtSecurityToken jwt)
            {
                audit.Introspect(true, client!.client_id, ctx.RemoteIp());
                return Results.Ok(JwtIntrospection(jwt));
            }

            // 再按 refresh token 试（不透明字符串）
            var hash = JwtIssuer.HashRefreshToken(token);
            var row = refreshTokens.GetByHash(hash);
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (row is not null && row.revoked == 0 && row.expires_at > now)
            {
                audit.Introspect(true, client!.client_id, ctx.RemoteIp());
                return Results.Ok(new
                {
                    active = true,
                    sub = row.user_id,
                    aud = "",
                    scope = row.scope,
                    resource = row.resource,
                    client_id = row.client_id,
                    exp = row.expires_at,
                    token_type = "refresh_token",
                });
            }

            audit.Introspect(false, client!.client_id, ctx.RemoteIp());
            return Results.Ok(new { active = false });
        });
    }

    private static async Task<IResult> HandleAuthCode(HttpContext ctx,
        IFormCollection form,
        ClientRepository clients,
        AuthCodeRepository authCodes,
        RefreshTokenRepository refreshTokens,
        ExternalIdentityRepository identities,
        UserRepository users,
        ResourceCatalog catalog,
        JwtIssuer issuer,
        OidcKeyService oidcKeys,
        AuditLogger audit)
    {
        var code = form["code"].ToString();
        var clientId = form["client_id"].ToString();
        var clientSecret = form["client_secret"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var verifier = form["code_verifier"].ToString();

        // verifier 在这里不强制：code 没带 challenge（confidential 客户端跳过 PKCE）时
        // 自然不需要；带了 challenge 的 code 在下面验 PKCE 时缺 verifier 一样会失败。
        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(clientId) ||
            string.IsNullOrEmpty(redirectUri))
        {
            audit.Token(false, "authorization_code", clientId, null, null, ctx.RemoteIp(), "missing_params");
            return Results.BadRequest(new { error = "invalid_request" });
        }

        if (!TryAuthenticateClient(clients, clientId, clientSecret, out var client))
        {
            audit.Token(false, "authorization_code", clientId, null, null, ctx.RemoteIp(), "client_auth_failed");
            return Results.Json(new { error = "invalid_client" }, statusCode: 401);
        }

        // 原子消费 → 一次性
        var row = authCodes.ConsumeAtomic(code);
        if (row is null)
        {
            audit.Token(false, "authorization_code", client!.client_id, null, null, ctx.RemoteIp(), "code_not_consumable");
            return Results.BadRequest(new { error = "invalid_grant", error_description = "authorization code does not exist / expired / already used" });
        }
        if (row.client_id != client!.client_id)
        {
            audit.Token(false, "authorization_code", client.client_id, row.user_id, row.resource, ctx.RemoteIp(), "client_id_mismatch");
            return Results.BadRequest(new { error = "invalid_grant", error_description = "client_id mismatch" });
        }
        if (row.redirect_uri != redirectUri)
        {
            audit.Token(false, "authorization_code", client.client_id, row.user_id, row.resource, ctx.RemoteIp(), "redirect_uri_mismatch");
            return Results.BadRequest(new { error = "invalid_grant", error_description = "redirect_uri mismatch" });
        }
        if (!string.IsNullOrEmpty(row.code_challenge))
        {
            if (string.IsNullOrEmpty(verifier) || !PkceVerifier.VerifyS256(verifier, row.code_challenge))
            {
                audit.Token(false, "authorization_code", client.client_id, row.user_id, row.resource, ctx.RemoteIp(), "pkce_failed");
                return Results.BadRequest(new { error = "invalid_grant", error_description = "PKCE verification failed" });
            }
        }
        else if (client.token_endpoint_auth_method == "none")
        {
            // 不该发生：/authorize 对 public client 强制 PKCE。防御历史脏数据。
            audit.Token(false, "authorization_code", client.client_id, row.user_id, row.resource, ctx.RemoteIp(), "no_pkce_public_client");
            return Results.BadRequest(new { error = "invalid_grant" });
        }

        // row.resource 可能是空格拼接的多个 resource_url（DCR 客户端不发 resource 时反推的
        // 多资源，见 docs/design/external-auth.md §十三）；逐个还原成 aud。
        var auds = ResolveAuds(catalog, row.resource);
        if (auds.Count == 0)
        {
            audit.Token(false, "authorization_code", client.client_id, row.user_id, row.resource, ctx.RemoteIp(), "resource_disappeared");
            return Results.BadRequest(new { error = "invalid_grant", error_description = "resource is no longer available" });
        }

        var access = issuer.IssueAccessToken(row.user_id, client.client_id, auds, row.resource, row.scope);
        var (refreshPlain, refreshHash) = issuer.IssueRefreshToken();
        refreshTokens.Insert(new RefreshTokenRow(
            token_hash: refreshHash,
            client_id: client.client_id,
            resource: row.resource,
            scope: row.scope,
            user_id: row.user_id,
            expires_at: issuer.RefreshTokenExpiry().ToUnixTimeSeconds(),
            revoked: 0,
            created_at: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            last_used_at: null));

        clients.TouchLastUsed(client.client_id);
        audit.Token(true, "authorization_code", client.client_id, row.user_id, row.resource, ctx.RemoteIp());

        // OIDC：scope 含 openid → 附 RS256 id_token（aud=client_id，nonce 回显）。
        // 非 openid 流（MCP 客户端）响应形状不变，不掺 id_token 字段。
        if (row.scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains("openid"))
        {
            var (email, name) = OidcEndpoints.ResolveProfile(identities, users, row.user_id);
            return Results.Ok(new
            {
                access_token = access,
                token_type = "Bearer",
                expires_in = issuer.AccessTokenLifetimeSeconds(),
                refresh_token = refreshPlain,
                scope = row.scope,
                id_token = oidcKeys.IssueIdToken(row.user_id, client.client_id, email, name, row.nonce),
            });
        }

        return Results.Ok(new
        {
            access_token = access,
            token_type = "Bearer",
            expires_in = issuer.AccessTokenLifetimeSeconds(),
            refresh_token = refreshPlain,
            scope = row.scope,
        });
    }

    private static Task<IResult> HandleRefresh(HttpContext ctx,
        IFormCollection form,
        ClientRepository clients,
        RefreshTokenRepository refreshTokens,
        ResourceCatalog catalog,
        JwtIssuer issuer,
        AuditLogger audit,
        UserResourceRepository userResources)
    {
        var refresh = form["refresh_token"].ToString();
        var clientId = form["client_id"].ToString();
        var clientSecret = form["client_secret"].ToString();

        if (string.IsNullOrEmpty(refresh) || string.IsNullOrEmpty(clientId))
        {
            audit.Token(false, "refresh_token", clientId, null, null, ctx.RemoteIp(), "missing_params");
            return Task.FromResult(Results.BadRequest(new { error = "invalid_request" }));
        }

        if (!TryAuthenticateClient(clients, clientId, clientSecret, out var client))
        {
            audit.Token(false, "refresh_token", clientId, null, null, ctx.RemoteIp(), "client_auth_failed");
            return Task.FromResult(Results.Json(new { error = "invalid_client" }, statusCode: 401));
        }

        var hash = JwtIssuer.HashRefreshToken(refresh);
        var row = refreshTokens.GetByHash(hash);
        if (row is null || row.client_id != client!.client_id)
        {
            audit.Token(false, "refresh_token", client!.client_id, null, null, ctx.RemoteIp(), "unknown_token");
            return Task.FromResult(Results.BadRequest(new { error = "invalid_grant" }));
        }

        // rotation：原子作废旧 token
        if (!refreshTokens.RevokeIfActive(hash))
        {
            audit.Token(false, "refresh_token", client.client_id, row.user_id, row.resource, ctx.RemoteIp(), "token_already_revoked_or_expired");
            return Task.FromResult(Results.BadRequest(new { error = "invalid_grant", error_description = "refresh token is no longer valid" }));
        }

        // row.resource 可能是空格拼接的多资源（DCR 反推，见 docs/design/external-auth.md §十三）。
        var resourcesList = ResolveResources(catalog, row.resource);
        if (resourcesList.Count == 0)
        {
            audit.Token(false, "refresh_token", client.client_id, row.user_id, row.resource, ctx.RemoteIp(), "resource_disappeared");
            return Task.FromResult(Results.BadRequest(new { error = "invalid_grant" }));
        }

        // 用户级授权检查（设计 §5.5 / P4 的 refresh 路径）：admin 撤销资源授权后，
        // 下一次 refresh 立即被挡（上面 rotation 已作废旧 token，不会复活），
        // 否则长寿命 refresh token 会让撤销形同虚设。
        // 多资源：逐个查，撤销其一即 downscope，全撤才 access_denied。
        var rowScopes = row.scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var grantedResources = new List<NasAuth.Config.ResourceConfig>();
        var grantedScopes = new List<string>();
        foreach (var r in resourcesList)
        {
            var rScopes = rowScopes.Where(r.Scopes.Contains).ToArray();
            if (rScopes.Length == 0) continue;
            if (userResources.IsAllowed(row.user_id, r.Aud, rScopes))
            {
                grantedResources.Add(r);
                grantedScopes.AddRange(rScopes);
            }
        }
        if (grantedResources.Count == 0)
        {
            audit.Token(false, "refresh_token", client.client_id, row.user_id, row.resource, ctx.RemoteIp(), "access_denied");
            return Task.FromResult(Results.BadRequest(new { error = "invalid_grant", error_description = "user no longer has access to this resource" }));
        }

        var auds = grantedResources.Select(r => r.Aud).Distinct().ToList();
        var resourceOut = string.Join(' ', grantedResources.Select(r => r.ResourceUrl));
        var scopeOut = string.Join(' ', grantedScopes.Distinct());

        var access = issuer.IssueAccessToken(row.user_id, client.client_id, auds, resourceOut, scopeOut);
        var (refreshPlain, refreshHash) = issuer.IssueRefreshToken();
        refreshTokens.Insert(new RefreshTokenRow(
            token_hash: refreshHash,
            client_id: client.client_id,
            resource: resourceOut,
            scope: scopeOut,
            user_id: row.user_id,
            expires_at: issuer.RefreshTokenExpiry().ToUnixTimeSeconds(),
            revoked: 0,
            created_at: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            last_used_at: null));

        clients.TouchLastUsed(client.client_id);
        audit.Token(true, "refresh_token", client.client_id, row.user_id, resourceOut, ctx.RemoteIp());

        return Task.FromResult(Results.Ok(new
        {
            access_token = access,
            token_type = "Bearer",
            expires_in = issuer.AccessTokenLifetimeSeconds(),
            refresh_token = refreshPlain,
            scope = scopeOut,
        }));
    }

    /// <summary>
    /// 把 auth code / refresh token 里存的 resource 列（可能是空格拼接的多个 resource_url，
    /// DCR 反推多资源时）还原成 ResourceConfig 列表。catalog 里查不到的（资源被删）跳过。
    /// </summary>
    private static List<NasAuth.Config.ResourceConfig> ResolveResources(ResourceCatalog catalog, string resourceColumn)
    {
        var urls = resourceColumn.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var list = new List<NasAuth.Config.ResourceConfig>();
        foreach (var u in urls)
        {
            var r = catalog.FindByUrl(u);
            if (r is not null) list.Add(r);
        }
        return list;
    }

    /// <summary>ResolveResources 的 aud 投影（去重，保序）。</summary>
    private static List<string> ResolveAuds(ResourceCatalog catalog, string resourceColumn)
        => ResolveResources(catalog, resourceColumn).Select(r => r.Aud).Distinct().ToList();

    /// <summary>
    /// public client（PKCE）允许 client_id only；confidential 必须给 secret。
    /// introspect / revoke 要求 client 认证。
    /// </summary>
    private static bool TryAuthenticateClient(ClientRepository clients, string clientId,
        string? clientSecret, out ClientRow? client)
    {
        client = string.IsNullOrEmpty(clientId) ? null : clients.GetById(clientId);
        if (client is null) return false;

        if (client.token_endpoint_auth_method == "none")
        {
            return true; // public client，依赖 PKCE 防伪造
        }

        // client_secret_post
        if (string.IsNullOrEmpty(clientSecret) || string.IsNullOrEmpty(client.client_secret_hash))
            return false;

        Span<byte> h = stackalloc byte[32];
        SHA256.TryHashData(Encoding.UTF8.GetBytes(clientSecret), h, out _);
        var actual = Convert.ToHexString(h);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(actual),
            Encoding.ASCII.GetBytes(client.client_secret_hash));
    }
}
