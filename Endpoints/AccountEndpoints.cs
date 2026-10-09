using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using NasAuth.Config;
using NasAuth.Data.Repositories;
using NasAuth.Pages;
using NasAuth.Services;
using static NasAuth.Endpoints.DashboardSupport;
using static NasAuth.Pages.I18n;

namespace NasAuth.Endpoints;

/// <summary>
/// 登录 / 退出 + 个人中心（/account，所有登录用户）。管理后台在 <see cref="AdminEndpoints"/>（/admin）。
/// 2026-09-29 拆分（external-auth.md §十六）：原先个人页与管理页共用一条菜单、管理员落在个人页。
/// </summary>
public static class AccountEndpoints
{
    public static void MapAccountEndpoints(this IEndpointRouteBuilder app)
    {
        // ----- /login + /logout -----
        app.MapGet("/login", (HttpContext ctx, ExternalProviderOptions providers, PasswordLoginGate passwordLogin) =>
        {
            // 站外 / 畸形的 return_url 不回显进隐藏字段，直接换成 /account（POST 端还会再校验一次）
            var returnUrl = ReturnUrl.SafeLocal(ctx.Request.Query["return_url"].ToString());
            // notice 只认固定 key：原先原样回显任意文本，/login?notice=… 能在可信登录页上印钓鱼文案
            var notice = LoginNotice(ctx.Request.Query["notice"].ToString());
            return Results.Content(
                HtmlTemplates.Login(returnUrl, error: null,
                    notice: notice,
                    googleEnabled: providers.GoogleEnabled,
                    microsoftEnabled: providers.MicrosoftEnabled,
                    passwordEnabled: passwordLogin.Enabled),
                "text/html; charset=utf-8");
        });

        app.MapPost("/login", async (HttpContext ctx,
            PasswordSignIn passwordSignIn, AuditLogger audit, ExternalProviderOptions providers, PasswordLoginGate passwordLogin) =>
        {
            // §十 二期：密码登录总闸关 → endpoint 404（不暴露存在性，与管理区一致）
            if (!passwordLogin.Enabled) return Results.NotFound();

            var form = await ctx.Request.ReadFormAsync();
            var username = form["username"].ToString();
            var password = form["password"].ToString();
            // 防开放跳转：/login?return_url=https://evil 真登录成功后会被送出站，只认站内相对路径
            var returnUrl = ReturnUrl.SafeLocal(form["return_url"].ToString());

            // §十四：总闸之后按用户判（允许密码登录？锁定中？），失败计数 / 锁定也在这里
            var result = passwordSignIn.Attempt(username, password);
            if (result.Status != PasswordSignInStatus.Ok)
            {
                audit.Login(false, username, ctx.RemoteIp(), result.AuditReason);
                ctx.Response.StatusCode = result.Status == PasswordSignInStatus.Locked
                    ? StatusCodes.Status429TooManyRequests
                    : StatusCodes.Status401Unauthorized;
                return Results.Content(
                    HtmlTemplates.Login(returnUrl, error: SignInErrorMessage(result.Status), notice: null,
                        googleEnabled: providers.GoogleEnabled,
                        microsoftEnabled: providers.MicrosoftEnabled,
                        passwordEnabled: true),
                    "text/html; charset=utf-8");
            }
            var user = result.User!;

            await AuthorizationEndpoints.SignInCookie(ctx, user.user_id);
            audit.Login(true, username, ctx.RemoteIp());

            // 首次登录强制改密：标志位 1 → 不管 return_url 是啥，先去 force-change-password。
            // 改完密码后跳回 /account（不回原 return_url，避免新用户被一脚踢回 MCP 客户端
            // 还没建立信任关系就授权）。
            if (user.must_change_password != 0)
                return Results.Redirect("/account/force-change-password");

            return Results.Redirect(LandingFor(returnUrl, user));
        }).RequireRateLimiting("auth-sensitive");

        // 退出 = OIDC end_session_endpoint（§十五）。GET / POST 都收（RP-Initiated Logout 1.0 允许两种）。
        // 下游带 post_logout_redirect_uri（+ state）就在校验通过后跳回去，否则落到登录页（原行为）。
        // id_token_hint 接受但不用：回跳地址只按预置客户端的来源校验，不依赖它。
        app.MapMethods("/logout", new[] { "GET", "POST" }, async (HttpContext ctx, ClientRepository clients, ResourceCatalog catalog, AuditLogger audit) =>
        {
            var p = ctx.Request.HasFormContentType
                ? (await ctx.Request.ReadFormAsync()).ToDictionary(kv => kv.Key, kv => kv.Value.ToString())
                : ctx.Request.Query.ToDictionary(kv => kv.Key, kv => kv.Value.ToString());
            string? Get(string k) => p.TryGetValue(k, out var v) ? v : null;

            var sessionUser = ctx.User?.Identity?.IsAuthenticated == true ? ctx.User.Identity.Name : null;
            await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // forward-auth 站点（§二十二）的退出也回跳到这里登记的来源：它们没有客户端条目，按 resources.json 认
            var target = EndSession.ResolveRedirect(Get("post_logout_redirect_uri"), Get("client_id"), Get("state"), clients,
                catalog.ForwardAuthOrigins());
            if (!string.IsNullOrEmpty(sessionUser) || !string.IsNullOrEmpty(Get("post_logout_redirect_uri")))
                audit.AccountAction("logout", true, sessionUser ?? "-",
                    $"client={Get("client_id") ?? "-"} redirect={(target is null ? "login-page" : "post_logout_redirect_uri")} ip={ctx.RemoteIp()}");
            return Results.Redirect(target ?? "/login?notice=" + LoginNoticeSignedOut);
        });

        // ----- /account 个人中心（强制登录 cookie session）-----
        var account = app.MapGroup("/account").RequireAuthorization();

        // 概览：我是谁、怎么登录、能用哪些应用
        account.MapGet("", (HttpContext ctx,
            UserRepository users,
            ExternalIdentityRepository identities,
            UserResourceRepository userResources,
            RefreshTokenRepository refreshTokens,
            ResourceCatalog catalog,
            PasswordLoginGate passwordLogin,
            AuditRepository audit) =>
        {
            var (userId, me) = WhoAmI(ctx, users);
            if (me is null) return Results.Redirect("/login");

            var apps = userResources.ListByUser(userId)
                .Select(r => new ProfileAppView(
                    catalog.FindByAud(r.aud)?.DisplayName ?? r.aud, r.aud,
                    r.scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries)))
                .ToList();
            var grantCount = refreshTokens.ListActiveByUser(userId)
                .Select(r => (r.client_id, r.resource)).Distinct().Count();
            var lastLogin = audit.Query(events: LoginEvents, userId: userId, limit: 20)
                .FirstOrDefault(r => r.success != 0);
            var profile = new ProfileView(
                UserView(me, userId),
                BindingViews(userId, identities),
                PasswordAllowed: passwordLogin.AllowsUser(me),
                Apps: apps,
                GrantCount: grantCount,
                PreviousLogin: lastLogin is null ? null : AuditViews(new[] { lastLogin })[0]);

            return Render(ctx, users, identities, DashboardSpace.Personal, "overview", "Overview",
                DashboardTemplates.PersonalOverviewSection(profile));
        });

        // 已授权应用
        account.MapGet("/grants", (HttpContext ctx,
            RefreshTokenRepository refreshTokens, ClientRepository clients,
            UserRepository users, ExternalIdentityRepository identities, ResourceCatalog catalog) =>
        {
            var (userId, _) = WhoAmI(ctx, users);
            return Render(ctx, users, identities, DashboardSpace.Personal, "grants", "Authorized apps",
                DashboardTemplates.GrantsSection(GrantViews(userId, refreshTokens, clients, catalog)));
        });

        account.MapPost("/revoke", async (HttpContext ctx,
            RefreshTokenRepository refreshTokens,
            AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var clientId = form["client_id"].ToString();
            var resource = form["resource"].ToString();
            var userId = ctx.User.Identity?.Name ?? "";

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(resource))
                return RedirectTo("/account/grants", error: T("Missing parameters"));

            // resource 字段从隐藏 input 传上来，值是 ResourceUrl
            // （与 refresh_tokens 表的 resource 列同源），直接当作 URL 用 SQL 等值匹配即可。
            var n = refreshTokens.RevokeByClientResource(userId, clientId, resource);
            audit.AccountAction("revoke", true, userId, $"client={clientId} resource={resource} count={n}");
            return RedirectTo("/account/grants", notice: T("Revoked {0} refresh token(s)", n));
        });

        // 登录与安全：外部账号绑定、改密码、登录会话、最近登录
        account.MapGet("/security", (HttpContext ctx,
            UserRepository users,
            ExternalIdentityRepository identities,
            ExternalProviderOptions providers,
            PasswordLoginGate passwordLogin,
            AuditRepository audit) =>
        {
            var (userId, me) = WhoAmI(ctx, users);
            if (me is null) return Results.Redirect("/login");
            return Render(ctx, users, identities, DashboardSpace.Personal, "security", "Sign-in & security",
                DashboardTemplates.SecuritySection(BindingViews(userId, identities),
                    providers.GoogleEnabled, providers.MicrosoftEnabled,
                    passwordEnabled: passwordLogin.AllowsUser(me),
                    recentLogins: RecentLogins(userId, audit)));
        });

        account.MapPost("/bindings/unbind", async (HttpContext ctx,
            ExternalIdentityRepository identities, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var provider = form["provider"].ToString();
            var subject = form["subject"].ToString();
            var userId = ctx.User.Identity?.Name ?? "";

            // 只能解绑自己的身份
            var row = identities.Get(provider, subject);
            if (row is null || row.user_id != userId)
                return RedirectTo("/account/security", error: T("Binding not found"));

            identities.Delete(provider, subject);
            audit.AccountAction("unbind-external", true, userId, $"provider={provider} subject={subject}");
            return RedirectTo("/account/security", notice: T("Unbound {0} account", provider));
        });

        account.MapPost("/change-password", async (HttpContext ctx,
            UserRepository users, AuditLogger audit, PasswordLoginGate passwordLogin) =>
        {
            var (userId, me) = WhoAmI(ctx, users);
            // 不能用密码登录的账号（§十四）改密码没有意义，入口与页面卡片一起收掉
            if (me is null || !passwordLogin.AllowsUser(me)) return Results.NotFound();
            var form = await ctx.Request.ReadFormAsync();
            var current = form["current_password"].ToString();
            var newPwd = form["new_password"].ToString();

            if (!PasswordHasher.Verify(current, me.password_hash))
            {
                audit.AccountAction("change-password", false, userId, "bad_current");
                return RedirectTo("/account/security", error: T("Current password is incorrect"));
            }
            if (string.IsNullOrEmpty(newPwd) || newPwd.Length < 8)
            {
                audit.AccountAction("change-password", false, userId, "new_too_short");
                return RedirectTo("/account/security", error: T("New password must be at least 8 characters"));
            }

            users.UpdatePasswordHash(userId, PasswordHasher.Hash(newPwd));
            // 改密顺带让其他设备上的登录失效（§十六），当前浏览器换发新票据继续用
            users.BumpSessionVersion(userId);
            await AuthorizationEndpoints.SignInCookie(ctx, userId);
            audit.AccountAction("change-password", true, userId);
            return RedirectTo("/account/security", notice: T("Password updated; other devices have been signed out"));
        });

        // 退出其他设备（§十六）：版本 +1 让所有旧票据作废，当前浏览器换发新票据
        account.MapPost("/sessions/revoke-others", async (HttpContext ctx,
            UserRepository users, AuditLogger audit) =>
        {
            var userId = ctx.User.Identity?.Name ?? "";
            if (users.BumpSessionVersion(userId) is null) return Results.Redirect("/login");
            await AuthorizationEndpoints.SignInCookie(ctx, userId);
            audit.AccountAction("sessions-revoke-others", true, userId);
            return RedirectTo("/account/security", notice: T("Signed out of all other devices"));
        });

        // ----- 强制改密页面（首次登录 / admin 重置后）-----
        // 注意：不要求输入 current_password。理由：用户刚通过 /login 验证完，cookie
        // session 就是身份证明；多输一次只会让"管理员发临时密码 / 用户立刻改"流程更别扭。
        account.MapGet("/force-change-password", (HttpContext ctx, UserRepository users) =>
        {
            var userId = ctx.User.Identity?.Name ?? "";
            var me = users.GetById(userId);
            if (me is null || me.must_change_password == 0)
                return RedirectTo("/account", notice: T("Password change not required"));
            return Results.Content(
                HtmlTemplates.ForceChangePassword(userId, error: null),
                "text/html; charset=utf-8");
        });

        account.MapPost("/force-change-password", async (HttpContext ctx,
            UserRepository users, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var newPwd = form["new_password"].ToString();
            var confirmPwd = form["confirm_password"].ToString();
            var userId = ctx.User.Identity?.Name ?? "";

            var me = users.GetById(userId);
            if (me is null || me.must_change_password == 0)
                return RedirectTo("/account", notice: T("Password change not required"));

            if (string.IsNullOrEmpty(newPwd) || newPwd.Length < 8)
            {
                audit.AccountAction("force-change-password", false, userId, "too_short");
                return Results.Content(
                    HtmlTemplates.ForceChangePassword(userId, error: "New password must be at least 8 characters"),
                    "text/html; charset=utf-8");
            }
            if (newPwd != confirmPwd)
            {
                audit.AccountAction("force-change-password", false, userId, "mismatch");
                return Results.Content(
                    HtmlTemplates.ForceChangePassword(userId, error: "Passwords do not match"),
                    "text/html; charset=utf-8");
            }
            // 防止把临时密码当新密码（管理员刚塞进来的那个明显不算"自己的"）
            if (PasswordHasher.Verify(newPwd, me.password_hash))
            {
                audit.AccountAction("force-change-password", false, userId, "same_as_temp");
                return Results.Content(
                    HtmlTemplates.ForceChangePassword(userId, error: "New password must differ from the temporary password"),
                    "text/html; charset=utf-8");
            }

            users.UpdatePasswordHashAndClearForceChange(userId, PasswordHasher.Hash(newPwd));
            users.BumpSessionVersion(userId);
            await AuthorizationEndpoints.SignInCookie(ctx, userId);
            audit.AccountAction("force-change-password", true, userId);
            return RedirectTo(LandingFor("/account", me), notice: T("Password updated"));
        });

        // ----- 旧地址（2026-09-29 拆分前）-----
        // 账号绑定并入「登录与安全」；管理页搬到 /admin：管理员跳过去，其他人照旧 404。
        account.MapGet("/bindings", () => Results.Redirect("/account/security"));
        foreach (var (oldPath, newPath) in new[]
                 {
                     ("/users", "/admin/users"),
                     ("/users/edit", "/admin/users/edit"),
                     ("/users/resources", "/admin/users/edit"),
                     ("/approvals", "/admin/approvals"),
                     ("/clients", "/admin/apps"),
                     ("/system", "/admin/system"),
                 })
        {
            account.MapGet(oldPath, (HttpContext ctx, UserRepository users) =>
                IsAdmin(WhoAmI(ctx, users).Me) ? RedirectKeepQuery(ctx, newPath) : Results.NotFound());
        }
    }

    /// <summary>/login?notice= 的合法 key。只传 key，文案在渲染时按当前语言取。</summary>
    public const string LoginNoticeSignedOut = "signed_out";

    /// <summary>notice key → 已翻译文案；未知 key 不显示任何提示。</summary>
    public static string? LoginNotice(string? key) => key switch
    {
        LoginNoticeSignedOut => T("Signed out"),
        _ => null,
    };

    /// <summary>密码登录失败的对外文案：锁定单独提示（否则正常用户会以为自己一直输错），其余一律同一句。</summary>
    public static string SignInErrorMessage(PasswordSignInStatus status) => status == PasswordSignInStatus.Locked
        ? T("Too many failed attempts. This account is temporarily locked; try again in {0} minutes.", PasswordSignIn.LockSeconds / 60)
        : T("Username or password is incorrect");
}
