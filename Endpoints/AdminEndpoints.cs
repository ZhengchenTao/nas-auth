using System.Security.Cryptography;
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
/// 管理后台 /admin（external-auth.md §5.4 / §十六）。
/// 整组一条规则：非 is_admin 一律 404（不是 403，不暴露存在性）——由组级过滤器实时查库执行，
/// 各 handler 不再各自判断。未登录由 RequireAuthorization 带去登录页（与拆分前的 /account 管理区一致）。
/// </summary>
public static class AdminEndpoints
{
    public static void MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var admin = app.MapGroup("/admin").RequireAuthorization()
            .AddEndpointFilter(async (ic, next) =>
            {
                var ctx = ic.HttpContext;
                var (_, me) = WhoAmI(ctx, ctx.RequestServices.GetRequiredService<UserRepository>());
                return IsAdmin(me) ? await next(ic) : Results.NotFound();
            });

        static string AdminId(HttpContext ctx) => ctx.User.Identity?.Name ?? "";
        static string EditPath(string userId) => "/admin/users/edit?user=" + Uri.EscapeDataString(userId);

        // ----- 概览 -----
        admin.MapGet("", (HttpContext ctx,
            UserRepository users, ExternalIdentityRepository identities,
            RefreshTokenRepository refreshTokens, ClientRepository clients, AuditRepository audit) =>
        {
            var all = users.ListAll();
            var clientRows = clients.ListAll();
            var since = DateTimeOffset.UtcNow.AddHours(-24).ToUnixTimeSeconds();
            var stats = new AdminStats(
                Users: all.Count,
                Admins: all.Count(u => u.is_admin != 0),
                Pending: identities.ListPending().Count,
                ActiveGrants: refreshTokens.ListActiveAll().Select(r => (r.user_id, r.client_id, r.resource)).Distinct().Count(),
                PresetClients: clientRows.Count(c => c.auto_registered == 0),
                DcrClients: clientRows.Count(c => c.auto_registered != 0),
                Logins24h: audit.Count(LoginEvents, failedOnly: false, since) - audit.Count(LoginEvents, failedOnly: true, since),
                FailedLogins24h: audit.Count(LoginEvents, failedOnly: true, since));
            return Render(ctx, users, identities, DashboardSpace.Admin, "overview", "Admin overview",
                DashboardTemplates.AdminOverviewSection(stats, AuditViews(audit.Query(limit: 12))));
        });

        // ----- 用户 -----
        admin.MapGet("/users", (HttpContext ctx, UserRepository users, ExternalIdentityRepository identities) =>
            Render(ctx, users, identities, DashboardSpace.Admin, "users", "Users",
                DashboardTemplates.UsersSection(UserViews(users, AdminId(ctx)))));

        admin.MapPost("/users/create", async (HttpContext ctx, UserRepository users, AuditLogger audit) =>
        {
            var adminId = AdminId(ctx);
            var form = await ctx.Request.ReadFormAsync();
            var newUsername = form["username"].ToString().Trim();
            var tempPwd = form["temp_password"].ToString();
            var newEmail = form["email"].ToString();
            var allowPassword = form["allow_password_login"].ToString() == "1";

            if (string.IsNullOrEmpty(newUsername))
                return RedirectTo("/admin/users", error: T("Username is required"));
            if (!UsernamePattern.IsMatch(newUsername))
                return RedirectTo("/admin/users", error: T("Username may only contain letters, digits, . _ -, length 1-32"));
            if (string.IsNullOrEmpty(tempPwd) || tempPwd.Length < 8)
                return RedirectTo("/admin/users", error: T("Temporary password must be at least 8 characters"));
            if (users.GetByUsername(newUsername) is not null)
                return RedirectTo("/admin/users", error: T("Username {0} already exists", newUsername));
            if (!IsValidEmail(newEmail))
                return RedirectTo("/admin/users", error: T("Invalid email address"));

            users.Create(
                userId: newUsername,
                username: newUsername,
                passwordHash: PasswordHasher.Hash(tempPwd),
                mustChangePassword: true,
                email: newEmail,
                allowPasswordLogin: allowPassword);
            audit.AccountAction("user-create", true, adminId, $"target={newUsername}");
            return RedirectTo("/admin/users", notice: T("Created user {0}; must change password on first sign-in", newUsername));
        });

        // 单个用户编辑页：资料 / 资源授权 / 外部身份 / 授权记录 / 会话 / 重置密码 / 删除
        admin.MapGet("/users/edit", (HttpContext ctx,
            UserRepository users,
            ExternalIdentityRepository identities,
            UserResourceRepository userResources,
            RefreshTokenRepository refreshTokens,
            ClientRepository clients,
            ResourceCatalog catalog,
            AuditRepository audit) =>
        {
            var targetId = ctx.Request.Query["user"].ToString();
            var target = users.GetById(targetId);
            if (target is null)
                return RedirectTo("/admin/users", error: T("User does not exist"));

            var granted = userResources.ListByUser(targetId)
                .ToDictionary(r => r.aud, r => r.scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries));
            var rows = catalog.All
                .Select(r => new UserResourceEditView(
                    Aud: r.Aud,
                    DisplayName: r.DisplayName,
                    AllScopes: r.Scopes,
                    GrantedScopes: granted.TryGetValue(r.Aud, out var s) ? s : Array.Empty<string>(),
                    AdminOnly: r.AdminOnly))
                .ToList();

            var detail = new UserDetailView(
                User: UserView(target, AdminId(ctx)),
                Resources: rows,
                Bindings: BindingViews(targetId, identities),
                Grants: GrantViews(targetId, refreshTokens, clients, catalog),
                RecentLogins: RecentLogins(targetId, audit, 5));
            return Render(ctx, users, identities, DashboardSpace.Admin, "users", T("User · {0}", target.username),
                DashboardTemplates.UserEditSection(detail));
        });

        // §十四：编辑邮箱 / 允许密码登录（管理员可改任何人，包括自己 —— 关掉自己的密码登录是推荐做法，
        // 前提是自己绑了 Google / 微软；break-glass 见 external-auth.md §十四）
        admin.MapPost("/users/update", async (HttpContext ctx, UserRepository users, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var targetId = form["user_id"].ToString();
            var email = form["email"].ToString();
            var allowPassword = form["allow_password_login"].ToString() == "1";

            if (users.GetById(targetId) is null)
                return RedirectTo("/admin/users", error: T("User does not exist"));
            if (!IsValidEmail(email))
                return RedirectTo(EditPath(targetId), error: T("Invalid email address"));

            users.UpdateProfile(targetId, email, allowPassword);
            audit.AccountAction("user-update", true, AdminId(ctx),
                $"target={targetId} allow_password_login={(allowPassword ? 1 : 0)} email_set={(!string.IsNullOrWhiteSpace(email)).ToString().ToLowerInvariant()}");
            return RedirectTo(EditPath(targetId), notice: T("Saved {0}", targetId));
        });

        admin.MapPost("/users/delete", async (HttpContext ctx,
            UserRepository users,
            ExternalIdentityRepository identities,
            UserResourceRepository userResources,
            AuditLogger audit) =>
        {
            var adminId = AdminId(ctx);
            var form = await ctx.Request.ReadFormAsync();
            var targetId = form["user_id"].ToString();

            if (string.IsNullOrEmpty(targetId))
                return RedirectTo("/admin/users", error: T("Missing parameters"));
            if (targetId == adminId)
                return RedirectTo("/admin/users", error: T("Cannot delete yourself"));
            var target = users.GetById(targetId);
            if (target is null)
                return RedirectTo("/admin/users", error: T("User does not exist"));
            if (target.is_admin != 0)
                return RedirectTo("/admin/users", error: T("Cannot delete an admin"));

            // 删行后其登录 cookie 也随之失效（SessionValidator 查不到人即作废）
            users.Delete(targetId);
            // 连带清理外部身份与资源授权（与 refresh_tokens/auth_codes 同理，防"复活"）
            identities.DeleteByUser(targetId);
            userResources.DeleteByUser(targetId);
            audit.AccountAction("user-delete", true, adminId, $"target={targetId}");
            return RedirectTo("/admin/users", notice: T("Deleted user {0}", targetId));
        });

        admin.MapPost("/users/reset-password", async (HttpContext ctx, UserRepository users, AuditLogger audit) =>
        {
            var adminId = AdminId(ctx);
            var form = await ctx.Request.ReadFormAsync();
            var targetId = form["user_id"].ToString();
            var tempPwd = form["temp_password"].ToString();

            if (string.IsNullOrEmpty(targetId))
                return RedirectTo("/admin/users", error: T("Missing parameters"));
            if (users.GetById(targetId) is null)
                return RedirectTo("/admin/users", error: T("User does not exist"));
            if (string.IsNullOrEmpty(tempPwd) || tempPwd.Length < 8)
                return RedirectTo(EditPath(targetId), error: T("Temporary password must be at least 8 characters"));
            if (targetId == adminId)
                return RedirectTo(EditPath(targetId), error: T("Use \"Change password\" under Sign-in & security for your own password"));

            users.ResetPasswordForceChange(targetId, PasswordHasher.Hash(tempPwd));
            users.BumpSessionVersion(targetId); // 重置密码 = 旧会话一并作废（§十六）
            audit.AccountAction("user-reset-password", true, adminId, $"target={targetId}");
            return RedirectTo(EditPath(targetId), notice: T("Reset password for {0}; they must change it on next sign-in", targetId));
        });

        admin.MapPost("/users/resources", async (HttpContext ctx,
            UserRepository users, UserResourceRepository userResources, ResourceCatalog catalog, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var targetId = form["user_id"].ToString();
            var target = users.GetById(targetId);
            if (target is null)
                return RedirectTo("/admin/users", error: T("User does not exist"));

            // 每个 aud 一组 checkbox（name=scope:<aud>）。勾了的 scope 取与 catalog 的交集写入；
            // 全不勾 → 删行（该资源对该用户整体撤销）。admin_only 资源对非管理员一律按「全不勾」处理。
            foreach (var resource in catalog.All)
            {
                var requested = form[$"scope:{resource.Aud}"]
                    .Select(v => v?.ToString() ?? "")
                    .Where(v => resource.Scopes.Contains(v) && resource.AllowsUser(target.is_admin != 0))
                    .Distinct()
                    .ToList();
                if (requested.Count == 0)
                    userResources.Delete(targetId, resource.Aud);
                else
                    userResources.Upsert(targetId, resource.Aud, string.Join(' ', requested));
            }

            audit.AccountAction("user-resources-update", true, AdminId(ctx), $"target={targetId}");
            return RedirectTo(EditPath(targetId), notice: T("Grants saved"));
        });

        // 代管别人的授权（§十六）：吊销某个 (client, resource) / 全部
        admin.MapPost("/users/revoke", async (HttpContext ctx,
            UserRepository users, RefreshTokenRepository refreshTokens, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var targetId = form["user_id"].ToString();
            var clientId = form["client_id"].ToString();
            var resource = form["resource"].ToString();
            if (users.GetById(targetId) is null)
                return RedirectTo("/admin/users", error: T("User does not exist"));
            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(resource))
                return RedirectTo(EditPath(targetId), error: T("Missing parameters"));

            var n = refreshTokens.RevokeByClientResource(targetId, clientId, resource);
            audit.AccountAction("admin-revoke", true, AdminId(ctx), $"target={targetId} client={clientId} resource={resource} count={n}");
            return RedirectTo(EditPath(targetId), notice: T("Revoked {0} refresh token(s)", n));
        });

        admin.MapPost("/users/revoke-all", async (HttpContext ctx,
            UserRepository users, RefreshTokenRepository refreshTokens, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var targetId = form["user_id"].ToString();
            if (users.GetById(targetId) is null)
                return RedirectTo("/admin/users", error: T("User does not exist"));

            var n = refreshTokens.RevokeAllByUser(targetId);
            audit.AccountAction("admin-revoke-all", true, AdminId(ctx), $"target={targetId} count={n}");
            return RedirectTo(EditPath(targetId), notice: T("Revoked {0} refresh token(s)", n));
        });

        admin.MapPost("/users/unbind", async (HttpContext ctx,
            UserRepository users, ExternalIdentityRepository identities, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var targetId = form["user_id"].ToString();
            var provider = form["provider"].ToString();
            var subject = form["subject"].ToString();

            var row = identities.Get(provider, subject);
            if (row is null || row.user_id != targetId)
                return RedirectTo(EditPath(targetId), error: T("Binding not found"));

            identities.Delete(provider, subject);
            audit.AccountAction("admin-unbind-external", true, AdminId(ctx), $"target={targetId} provider={provider} subject={subject}");
            return RedirectTo(EditPath(targetId), notice: T("Unbound {0} account", provider));
        });

        // 强制下线（§十六）：该用户所有浏览器里的 nas-auth 登录立即失效；已发给应用的授权不受影响（另有吊销）
        admin.MapPost("/users/force-logout", async (HttpContext ctx, UserRepository users, AuditLogger audit) =>
        {
            var adminId = AdminId(ctx);
            var form = await ctx.Request.ReadFormAsync();
            var targetId = form["user_id"].ToString();
            if (targetId == adminId)
                return RedirectTo(EditPath(targetId), error: T("To sign yourself out elsewhere, use Sign-in & security"));
            if (users.BumpSessionVersion(targetId) is null)
                return RedirectTo("/admin/users", error: T("User does not exist"));

            audit.AccountAction("admin-force-logout", true, adminId, $"target={targetId}");
            return RedirectTo(EditPath(targetId), notice: T("{0} has been signed out on all devices", targetId));
        });

        // ----- 待批申请 -----
        admin.MapGet("/approvals", (HttpContext ctx,
            UserRepository users, ExternalIdentityRepository identities, ResourceCatalog catalog) =>
        {
            PendingApprovalView ToView(NasAuth.Data.ExternalIdentityRow r) =>
                new(r.provider, r.subject, r.email, r.display_name, TimeDisplay(r.created_at));
            // admin_only 资源不在审批页列出：审批建的是非管理员；绑到管理员头上时管理员本来就有这些授权
            var resources = catalog.All
                .Where(r => !r.AdminOnly)
                .Select(r => new UserResourceEditView(r.Aud, r.DisplayName, r.Scopes, Array.Empty<string>()))
                .ToList();
            return Render(ctx, users, identities, DashboardSpace.Admin, "approvals", "Approvals",
                DashboardTemplates.ApprovalsSection(
                    identities.ListPending().Select(ToView).ToList(),
                    identities.ListRejected().Select(ToView).ToList(),
                    UserViews(users, AdminId(ctx)), resources));
        });

        admin.MapPost("/approvals/approve", async (HttpContext ctx, ApprovalService approvals, AuditLogger audit) =>
        {
            var adminId = AdminId(ctx);
            var form = await ctx.Request.ReadFormAsync();
            var provider = form["provider"].ToString();
            var subject = form["subject"].ToString();
            var existingUser = form["existing_user"].ToString();
            var newUser = form["new_user"].ToString().Trim();
            var grantAuds = form["grant_aud"].Select(v => v?.ToString() ?? "").Where(v => v != "").ToList();

            string? error;
            string boundTo;
            if (!string.IsNullOrEmpty(newUser))
            {
                error = approvals.ApproveCreateUser(provider, subject, newUser, grantAuds);
                boundTo = newUser;
            }
            else if (!string.IsNullOrEmpty(existingUser))
            {
                error = approvals.ApproveBindExisting(provider, subject, existingUser, grantAuds);
                boundTo = existingUser;
            }
            else
            {
                return RedirectTo("/admin/approvals", error: T("Select an existing user or enter a new user id"));
            }

            if (error is not null)
            {
                audit.AccountAction("approval-approve", false, adminId, $"provider={provider} subject={subject} reason={error}");
                return RedirectTo("/admin/approvals", error: error);
            }

            // §九：审批写审计日志（谁批了哪个 provider/subject → 哪个 user_id）
            audit.AccountAction("approval-approve", true, adminId,
                $"provider={provider} subject={subject} user={boundTo} auds={string.Join(',', grantAuds)}");
            return RedirectTo("/admin/approvals", notice: T("Approved: {0} identity bound to {1}", provider, boundTo));
        });

        admin.MapPost("/approvals/reject", async (HttpContext ctx, ApprovalService approvals, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var provider = form["provider"].ToString();
            var subject = form["subject"].ToString();

            var error = approvals.Reject(provider, subject);
            if (error is not null)
                return RedirectTo("/admin/approvals", error: error);

            audit.AccountAction("approval-reject", true, AdminId(ctx), $"provider={provider} subject={subject}");
            return RedirectTo("/admin/approvals", notice: T("Rejected; the record is kept so repeat attempts stay blocked"));
        });

        // ----- 应用与资源：resources.json 的资源 + OAuth 客户端 -----
        admin.MapGet("/apps", (HttpContext ctx,
            UserRepository users, ExternalIdentityRepository identities,
            ClientRepository clients, RefreshTokenRepository refreshTokens,
            UserResourceRepository userResources, ResourceCatalog catalog) =>
        {
            var active = refreshTokens.ListActiveAll();
            var userCounts = userResources.CountByAud();
            var resources = catalog.All.Select(r =>
            {
                var url = r.ResourceUrl.TrimEnd('/');
                var grants = active
                    .Where(t => t.resource.Split(' ', StringSplitOptions.RemoveEmptyEntries).Any(u => u.TrimEnd('/') == url))
                    .Select(t => (t.user_id, t.client_id)).Distinct().Count();
                return new ResourceAdminView(r.Aud, r.DisplayName, r.ResourceUrl, r.Scopes, r.Proxy is not null,
                    userCounts.TryGetValue(r.Aud, out var n) ? n : 0, grants);
            }).ToList();

            var grantsByClient = active.GroupBy(t => t.client_id)
                .ToDictionary(g => g.Key, g => g.Select(t => (t.user_id, t.resource)).Distinct().Count());
            var clientViews = clients.ListAll()
                .Select(c => new ClientAdminView(
                    ClientId: c.client_id,
                    ClientName: c.client_name,
                    AutoRegistered: c.auto_registered != 0,
                    TokenEndpointAuthMethod: c.token_endpoint_auth_method,
                    RedirectUris: ClientRepository.ParseRedirectUris(c.redirect_uris),
                    CreatedAtDisplay: TimeDisplay(c.created_at),
                    LastUsedDisplay: c.last_used_at is { } t ? TimeDisplay(t) : "-",
                    ActiveGrants: grantsByClient.TryGetValue(c.client_id, out var g) ? g : 0))
                .ToList();

            return Render(ctx, users, identities, DashboardSpace.Admin, "apps", "Apps & resources",
                DashboardTemplates.AppsSection(resources, clientViews));
        });

        admin.MapPost("/apps/delete-client", async (HttpContext ctx, ClientRepository clients, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var clientId = form["client_id"].ToString();
            if (!clients.DeleteAutoRegistered(clientId))
                return RedirectTo("/admin/apps", error: T("Only dynamically registered (DCR) clients can be deleted"));

            audit.AccountAction("client-delete", true, AdminId(ctx), $"client={clientId}");
            return RedirectTo("/admin/apps", notice: T("Deleted client {0} and its grants", clientId));
        });

        // ----- 审计日志 -----
        admin.MapGet("/audit", (HttpContext ctx,
            UserRepository users, ExternalIdentityRepository identities, AuditRepository audit) =>
        {
            var q = ctx.Request.Query;
            var filter = new AuditFilter(q["type"].ToString(), q["user"].ToString().Trim(), q["failed"].ToString() == "1");
            var (events, prefix) = filter.Type switch
            {
                "login" => ((IReadOnlyCollection<string>?)LoginEvents, (string?)null),
                "authorize" => (new[] { "authorize" }, null),
                "token" => (new[] { "token", "revoke" }, null),
                "account" => (null, "account."),
                "register" => (new[] { "register" }, null),
                "proxy" => (new[] { "proxy.deny" }, null),
                _ => (null, null),
            };
            var rows = audit.Query(events, prefix, string.IsNullOrEmpty(filter.User) ? null : filter.User,
                filter.FailedOnly, limit: 300);
            return Render(ctx, users, identities, DashboardSpace.Admin, "audit", "Audit log",
                DashboardTemplates.AuditSection(filter, AuditViews(rows)));
        });

        // ----- 系统 -----
        admin.MapGet("/system", (HttpContext ctx,
            UserRepository users, ExternalIdentityRepository identities, PasswordLoginGate passwordLogin, JwtOptions jwt) =>
        {
            var rotateNotice = ReadFlash(ctx, "rotated"); // 加密签名的一次性提示，见 DashboardSupport.RedirectTo
            return Render(ctx, users, identities, DashboardSpace.Admin, "system", "System",
                DashboardTemplates.SystemSection(
                    rotateNotice,
                    passwordLoginEnabled: passwordLogin.Enabled,
                    passwordLoginConfigEnabled: passwordLogin.ConfigEnabled,
                    passwordLoginOverride: passwordLogin.Override,
                    passwordLoginLockoutGuard: passwordLogin.LockoutGuardActive,
                    jwt: new JwtKeyView(jwt.UsesRs256, jwt.HasHs256Keys, jwt.AccessTokenLifetimeDays,
                        jwt.LegacyHs256NotAfterUtc?.ToString("yyyy-MM-dd HH:mm:ss 'UTC'"))));
        });

        // 密码登录运行时开关（写 settings 表立即生效）
        admin.MapPost("/password-login", async (HttpContext ctx, PasswordLoginGate passwordLogin, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var mode = form["mode"].ToString();
            if (mode is not ("enable" or "disable" or "clear"))
                return RedirectTo("/admin/system", error: T("Unknown action"));

            passwordLogin.SetOverride(mode switch { "enable" => true, "disable" => false, _ => null });
            audit.AccountAction("password-login-override", true, AdminId(ctx), $"mode={mode}");
            return RedirectTo("/admin/system", notice: mode switch
            {
                "enable" => T("Password login enabled (runtime override)"),
                "disable" => T("Password login disabled (runtime override)"),
                _ => T("Runtime override cleared; following the container config again"),
            });
        });

        admin.MapPost("/rotate-jwt-key", (HttpContext ctx,
            SettingsRepository settings, JwtOptions jwt, AuditLogger audit) =>
        {
            // RS256 模式下 HS256 密钥不再签发，生成了也用不上；RSA 钥轮换是改文件名 + 重启，页面上有步骤
            if (jwt.UsesRs256)
                return RedirectTo("/admin/system", error: T("Access tokens are signed with RS256; no HS256 key was generated. To rotate the RSA key, follow the steps on this page."));

            // 生成 64 字节随机（base64url 后 ~86 字符），远超 HS256 32 字节下限
            Span<byte> raw = stackalloc byte[64];
            RandomNumberGenerator.Fill(raw);
            var newKey = PkceVerifier.Base64UrlEncode(raw);

            // 把当前 Current 挪到 Previous，新 key 写到 settings。重启容器后被读出来。
            // 注意：实际生效点在容器重启，这里只是把"待生效配置"持久化到 SQLite，
            // 配合 UI 上的提示，要求用户手动写进部署环境（如 .env）并重启。
            settings.Set("jwt.signing_key.pending_current", newKey);
            settings.Set("jwt.signing_key.pending_previous", jwt.SigningKey.Current);
            settings.Set("jwt.signing_key.rotated_at", DateTimeOffset.UtcNow.ToString("o"));

            audit.AccountAction("rotate-jwt-key", true, AdminId(ctx));

            // 新 key 不通过 URL 传（URL 历史记录会泄漏），写到 SQLite 让用户用 sqlite3 取。
            return RedirectTo("/admin/system", rotated: "New key generated and stored in the SQLite settings table at jwt.signing_key.pending_current. Steps: 1) extract it with sqlite3 → set it as Jwt__SigningKey__Current in the deployment environment (e.g. .env); 2) move the previous Current to Jwt__SigningKey__Previous; 3) restart nas-auth and every resource server that shares the key.");
        });
    }
}
