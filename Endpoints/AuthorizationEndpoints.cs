using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Pages;
using NasAuth.Services;
using static NasAuth.Pages.I18n;

namespace NasAuth.Endpoints;

public static class AuthorizationEndpoints
{
    public static void MapAuthorizationEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/authorize", (HttpContext ctx,
            ClientRepository clients, ResourceCatalog catalog,
            ExternalProviderOptions providers, PasswordLoginGate passwordLogin, AuthOptions options) =>
        {
            var q = ctx.Request.Query;
            var err = ValidateAuthorizeParams(q, clients, catalog, options,
                out var client, out var resources, out var requestedScopes, out var redirectUri);
            if (err != null) return Results.BadRequest(new { error = "invalid_request", error_description = err });

            // 多资源时 scope 校验对全集（并集）做；反推路径下 requestedScopes 必 ⊆ 并集，
            // 显式单资源路径下保留原来的「scope 必须属于该资源」语义。
            var scopeUnion = resources.SelectMany(r => r.Scopes).ToHashSet(StringComparer.Ordinal);
            if (requestedScopes.Length == 0) requestedScopes = scopeUnion.ToArray();

            foreach (var s in requestedScopes)
                if (!scopeUnion.Contains(s))
                    return Results.BadRequest(new { error = "invalid_scope", error_description = $"scope {s} is not allowed for the requested resource(s)" });

            var resourceDisplay = string.Join(", ", resources.Select(r => r.DisplayName));
            var hidden = ExtractHiddenFields(q, requestedScopes);
            var html = HtmlTemplates.Authorize(
                client!.client_name,
                resourceDisplay,
                requestedScopes,
                hidden,
                error: null,
                // 外部登录回调后会带会话回到这个 URL，所以 return_url 必须含完整 query
                returnUrl: ctx.Request.Path + ctx.Request.QueryString,
                sessionUser: SessionUserId(ctx),
                googleEnabled: providers.GoogleEnabled,
                microsoftEnabled: providers.MicrosoftEnabled,
                passwordEnabled: passwordLogin.Enabled,
                redirectUri: redirectUri,
                selfRegistered: client!.auto_registered != 0);
            return Results.Content(html, "text/html; charset=utf-8");
        });

        app.MapPost("/authorize", async (HttpContext ctx,
            ClientRepository clients,
            UserRepository users,
            UserResourceRepository userResources,
            AuthCodeRepository authCodes,
            ResourceCatalog catalog,
            JwtIssuer issuer,
            AuditLogger audit,
            ExternalProviderOptions providers,
            PasswordLoginGate passwordLogin,
            PasswordSignIn passwordSignIn,
            AuthOptions options) =>
        {
            var form = await ctx.Request.ReadFormAsync();

            var err = ValidateAuthorizeParams(form, clients, catalog, options,
                out var client, out var resources, out var requestedScopes, out var redirectUri);
            if (err != null)
            {
                audit.Authorize(false, form["client_id"]!, null, form["resource"], form["scope"], ctx.RemoteIp(), err);
                return Results.BadRequest(new { error = "invalid_request", error_description = err });
            }

            var scopeUnion = resources.SelectMany(r => r.Scopes).ToHashSet(StringComparer.Ordinal);
            if (requestedScopes.Length == 0) requestedScopes = scopeUnion.ToArray();

            foreach (var s in requestedScopes)
                if (!scopeUnion.Contains(s))
                    return Results.BadRequest(new { error = "invalid_scope" });

            var resourceDisplay = string.Join(", ", resources.Select(r => r.DisplayName));
            // 授权成功前的错误审计用：候选资源 aud 逗号拼接（多资源反推时可能多条）
            var auditAud = string.Join(',', resources.Select(r => r.Aud));

            // 重渲染 consent 页的公共参数（错误分支共用）
            IResult RenderError(string message, int statusCode)
            {
                var hidden = ExtractHiddenFields(form, requestedScopes);
                var html = HtmlTemplates.Authorize(
                    client!.client_name, resourceDisplay, requestedScopes, hidden,
                    error: message,
                    returnUrl: BuildAuthorizeUrl(hidden),
                    sessionUser: SessionUserId(ctx),
                    googleEnabled: providers.GoogleEnabled,
                    microsoftEnabled: providers.MicrosoftEnabled,
                    passwordEnabled: passwordLogin.Enabled,
                    redirectUri: redirectUri,
                    selfRegistered: client!.auto_registered != 0);
                ctx.Response.StatusCode = statusCode;
                return Results.Content(html, "text/html; charset=utf-8");
            }

            UserRow? user;
            if (form["use_session"].ToString() == "1")
            {
                // 会话路径：外部登录（或此前的密码登录）已建立 cookie session，
                // consent 只确认授权，不再要密码。身份以会话内 user_id 实时查库为准。
                var sessionUid = SessionUserId(ctx);
                user = string.IsNullOrEmpty(sessionUid) ? null : users.GetById(sessionUid);
                if (user is null)
                {
                    audit.Authorize(false, client!.client_id, sessionUid, auditAud,
                        string.Join(' ', requestedScopes), ctx.RemoteIp(), "session_invalid");
                    return RenderError(T("Your session has expired. Please sign in again."),
                        StatusCodes.Status401Unauthorized);
                }
            }
            else
            {
                // §十 二期：密码登录停用 → consent 的密码分支同样关死
                if (!passwordLogin.Enabled)
                {
                    audit.Authorize(false, client!.client_id, null, auditAud,
                        string.Join(' ', requestedScopes), ctx.RemoteIp(), "password_login_disabled");
                    return RenderError(T("Password sign-in is disabled"),
                        StatusCodes.Status403Forbidden);
                }

                var username = form["username"].ToString();
                var password = form["password"].ToString();

                // §十四：总闸之后按用户判（允许密码登录？锁定中？），失败计数 / 锁定也在这里
                var result = passwordSignIn.Attempt(username, password);
                if (result.Status != PasswordSignInStatus.Ok)
                {
                    audit.Authorize(false, client!.client_id, username, auditAud,
                        string.Join(' ', requestedScopes), ctx.RemoteIp(), result.AuditReason);
                    return RenderError(AccountEndpoints.SignInErrorMessage(result.Status),
                        result.Status == PasswordSignInStatus.Locked
                            ? StatusCodes.Status429TooManyRequests
                            : StatusCodes.Status401Unauthorized);
                }
                user = result.User!;
            }

            // 首次登录 / admin 重置后必须先改密：不在 consent 页里处理改密流程
            // （consent 表单不带 cookie 也能 POST，改完不知道回哪），
            // 把人挤到正常 /login → 强制改密 → 再回来 consent。
            if (user.must_change_password != 0)
            {
                audit.Authorize(false, client!.client_id, user.user_id, auditAud,
                    string.Join(' ', requestedScopes), ctx.RemoteIp(), "must_change_password");
                return RenderError(T("This account must change its password first. Please go to /login, change your password, then return to this page to authorize."),
                    StatusCodes.Status403Forbidden);
            }

            // §5.5 用户级授权检查：逐资源查 user_resources（当前用户, aud）存在且
            // 该资源被请求的 scope ⊆ 授予 scopes。
            // 单资源（显式 resource）：未授权 → 403，语义同前。
            // 多资源（DCR 反推）：保留被授权的资源（downscope），全被丢弃才 403。
            // 在资源 allowlist 检查之后：资源合法 ≠ 这个用户被授权用它。
            var grantedResources = new List<NasAuth.Config.ResourceConfig>();
            var grantedScopes = new List<string>();
            foreach (var r in resources)
            {
                var rScopes = requestedScopes.Where(r.Scopes.Contains).ToArray();
                if (rScopes.Length == 0) continue; // 反推集合里这个资源没被请求到 scope
                if (!r.AllowsUser(user.is_admin != 0)) continue; // admin_only：非管理员即使有授权行也拒
                if (userResources.IsAllowed(user.user_id, r.Aud, rScopes))
                {
                    grantedResources.Add(r);
                    grantedScopes.AddRange(rScopes);
                }
            }
            if (grantedResources.Count == 0)
            {
                audit.Authorize(false, client!.client_id, user.user_id, auditAud,
                    string.Join(' ', requestedScopes), ctx.RemoteIp(), "access_denied_user_resource");
                return RenderError(T("Your account is not authorized for this resource (or the requested scopes exceed your grant). Ask an administrator to grant it under Users → Resources."),
                    StatusCodes.Status403Forbidden);
            }

            // 多资源时 resource 列存空格拼接的 resource_url，scope 存 downscope 后的并集；
            // /token 据此 split 还原、签多 aud token。
            var grantedResourceUrls = string.Join(' ', grantedResources.Select(r => r.ResourceUrl));
            var grantedScopeStr = string.Join(' ', grantedScopes.Distinct());
            var grantedAud = string.Join(',', grantedResources.Select(r => r.Aud));

            await SignInCookie(ctx, user.user_id);

            var code = RegistrationEndpoints.GenerateRandomToken(32);
            authCodes.Insert(new AuthCodeRow(
                code: code,
                client_id: client!.client_id,
                resource: grantedResourceUrls,
                scope: grantedScopeStr,
                redirect_uri: redirectUri!,
                // .ToString()：缺参时 StringValues→string 隐式转换给 null，会撞列上的 NOT NULL；
                // 空串=「没有 PKCE」（confidential client 跳过的合法形态）
                code_challenge: form["code_challenge"].ToString(),
                code_challenge_method: form["code_challenge_method"].ToString(),
                user_id: user.user_id,
                expires_at: issuer.AuthCodeExpiry().ToUnixTimeSeconds(),
                consumed: 0,
                created_at: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                // OIDC nonce：原样存下来，/token 签 id_token 时回显（防重放，Core §3.1.2.1）
                nonce: string.IsNullOrEmpty(form["nonce"].ToString()) ? null : form["nonce"].ToString()));

            audit.Authorize(true, client.client_id, user.user_id, grantedAud,
                grantedScopeStr, ctx.RemoteIp());

            var sep = redirectUri!.Contains('?') ? '&' : '?';
            var state = form["state"].ToString();
            var location = $"{redirectUri}{sep}code={Uri.EscapeDataString(code)}" +
                           (string.IsNullOrEmpty(state) ? "" : $"&state={Uri.EscapeDataString(state)}");
            return Results.Redirect(location);
        }).RequireRateLimiting("auth-sensitive");
    }

    /// <summary>
    /// 标准 OIDC scope。DCR 客户端（如 Grok）按 AS 元数据的 scopes_supported（= 全部资源 scope 并集）
    /// 一次性请求所有 scope，会把这三个 SSO scope 也带上 —— 它们只属于 gitea-web SSO 资源，
    /// 不是 MCP 资源 scope。多 aud 反推时剔除，避免把 SSO 资源拉进 MCP token 的 aud。
    /// </summary>
    private static readonly HashSet<string> OidcScopes =
        new(StringComparer.Ordinal) { "openid", "email", "profile" };

    /// <summary>
    /// 解析 + 校验 /authorize 参数。
    /// <para>
    /// <paramref name="resources"/> 是这次授权覆盖的资源集合：
    /// 正常情况（带 resource，或预置 client 的 default_resource）只有一条；
    /// DCR/auto-registered 的 public client 不发 resource 时（RFC 8707 非实现客户端，如 Grok），
    /// 退回到「按请求 scope 反推资源集合」—— 可能多条，/token 据此签多 aud token。
    /// 见 docs/design/external-auth.md §十三。
    /// </para>
    /// <paramref name="requestedScopes"/> 是生效 scope（多 aud 反推路径已剔除 OIDC scope）；
    /// 为空表示客户端没带 scope，调用方按资源默认 scope 兜底。
    /// </summary>
    private static string? ValidateAuthorizeParams(
        IEnumerable<KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues>> source,
        ClientRepository clients,
        ResourceCatalog catalog,
        AuthOptions options,
        out ClientRow? client,
        out List<NasAuth.Config.ResourceConfig> resources,
        out string[] requestedScopes,
        out string? redirectUri)
    {
        client = null; resources = new(); requestedScopes = Array.Empty<string>(); redirectUri = null;

        // 用 GroupBy + First 防御重复 key（IQueryCollection / IFormCollection 都允许同名多值；
        // ToDictionary 在键冲突时会 throw，这里取首个即可，OAuth 协议字段不应出现多值）。
        var dict = source
            .GroupBy(p => p.Key, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().Value.ToString(), StringComparer.Ordinal);
        string Get(string k) => dict.TryGetValue(k, out var v) ? v ?? "" : "";

        var responseType = Get("response_type");
        var clientId = Get("client_id");
        redirectUri = Get("redirect_uri");
        var resourceUrl = Get("resource");
        var codeChallenge = Get("code_challenge");
        var codeChallengeMethod = Get("code_challenge_method");
        var rawScopes = Get("scope")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (responseType != "code") return "response_type must be 'code'";
        if (string.IsNullOrEmpty(clientId)) return "client_id is required";
        if (string.IsNullOrEmpty(redirectUri)) return "redirect_uri is required";

        client = clients.GetById(clientId);
        if (client is null) return "unknown client_id";

        // PKCE：public client（auth method = none）强制；confidential client（如 Gitea
        // 的 gitea-web，client_secret_post）可不带 —— Gitea 的 goth OIDC 客户端不做 PKCE，
        // 伪造防护由 client_secret 承担（设计 §7.2"非 PKCE public"）。带了照样验。
        if (string.IsNullOrEmpty(codeChallenge))
        {
            if (client.token_endpoint_auth_method == "none")
                return "code_challenge is required (PKCE mandatory for public clients)";
        }
        else if (codeChallengeMethod != "S256")
        {
            return "code_challenge_method must be 'S256' (plain not supported)";
        }

        // resource：非 RFC 8707 客户端（Gitea OIDC）不发，回退到 client 预置的 default_resource
        if (string.IsNullOrEmpty(resourceUrl))
            resourceUrl = client.default_resource ?? "";

        // resourceUrl 仍为空 = 既没显式 resource 也没 default_resource。
        // 仅对 DCR/auto-registered client 走「按 scope 反推多资源」回退；其余照旧报错。
        var deriveFromScopes = string.IsNullOrEmpty(resourceUrl);
        if (deriveFromScopes)
        {
            if (client.auto_registered == 0) return "resource is required";
            // 剔除 OIDC scope 后才反推，避免把 gitea-web SSO 资源拉进来
            requestedScopes = rawScopes.Where(s => !OidcScopes.Contains(s)).ToArray();
            if (requestedScopes.Length == 0) return "resource is required";
        }
        else
        {
            requestedScopes = rawScopes;
        }

        var allowed = ClientRepository.ParseRedirectUris(client.redirect_uris);
        if (!allowed.Contains(redirectUri, StringComparer.Ordinal))
            return "redirect_uri does not match the registered value";

        // DCR 客户端每次授权都按当前规则 + 主机白名单（Auth:Dcr:AllowedRedirectHosts）再判一遍：
        // 收紧规则 / 配白名单之前注册进来的客户端，回调不合规的直接停用（重新注册同样过不去）
        if (client.auto_registered != 0 &&
            RedirectUriPolicy.Validate(redirectUri, options.Dcr) is { } policyErr)
            return $"redirect_uri is not allowed for dynamically registered clients: {policyErr}";

        if (deriveFromScopes)
        {
            resources = catalog.ResourcesForScopes(requestedScopes);
            // 反推不出任何资源 = 请求的全是未知 scope，回退到 resource 缺失的标准错误
            if (resources.Count == 0) return "resource is required";
        }
        else
        {
            var resource = catalog.FindByUrl(resourceUrl);
            if (resource is null) return $"resource not in allowlist: {resourceUrl}";
            resources.Add(resource);
        }

        return null;
    }

    private static IDictionary<string, string?> ExtractHiddenFields(
        IEnumerable<KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues>> source,
        string[] scopes)
    {
        string Pick(string k) => source.FirstOrDefault(p => p.Key == k).Value.ToString();
        return new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["response_type"] = "code",
            ["client_id"] = Pick("client_id"),
            ["redirect_uri"] = Pick("redirect_uri"),
            ["resource"] = Pick("resource"),
            ["scope"] = string.Join(' ', scopes),
            ["state"] = Pick("state"),
            ["code_challenge"] = Pick("code_challenge"),
            ["code_challenge_method"] = Pick("code_challenge_method"),
            ["nonce"] = Pick("nonce"),
        };
    }

    /// <summary>当前 cookie session 的 user_id；未登录返回 null。</summary>
    private static string? SessionUserId(HttpContext ctx) =>
        ctx.User?.Identity?.IsAuthenticated == true ? ctx.User.Identity.Name : null;

    /// <summary>
    /// 由 consent 页隐藏字段重建 GET /authorize URL，作外部登录的 return_url：
    /// IdP 回调建立会话后跳回来，consent 页此时渲染 "Authorize as ..." 一键按钮。
    /// </summary>
    private static string BuildAuthorizeUrl(IDictionary<string, string?> hiddenFields)
    {
        var query = string.Join('&', hiddenFields
            .Where(kv => !string.IsNullOrEmpty(kv.Value))
            .Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value!)}"));
        return string.IsNullOrEmpty(query) ? "/authorize" : "/authorize?" + query;
    }

    public static async Task SignInCookie(HttpContext ctx, string userId)
    {
        // 票据带上当前会话版本（§十六 SessionValidator）：版本被 +1 后这张 cookie 即作废
        var version = ctx.RequestServices.GetRequiredService<UserRepository>().GetById(userId)?.session_version ?? 0;
        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId),
            new Claim(ClaimTypes.Name, userId),
            new Claim(SessionValidator.ClaimType, version.ToString()),
        }, CookieAuthenticationDefaults.AuthenticationScheme);
        // IsPersistent：cookie 带 Expires 落盘，浏览器重启后 SSO 会话仍在
        await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties { IsPersistent = true });
    }
}
