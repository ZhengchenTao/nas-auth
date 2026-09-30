using System.Text;
using static NasAuth.Pages.I18n;
using static NasAuth.Pages.Ui;

namespace NasAuth.Pages;

/// <summary>后台分两个空间：个人中心 /account（所有人）与管理后台 /admin（仅 is_admin）。</summary>
public enum DashboardSpace { Personal, Admin }

/// <summary>
/// 个人中心 / 管理后台布局（外部认证设计 §5.4、§十六）：Basecoat sidebar + 内容区，纯 SSR。
/// 样式是本地的 Basecoat 1.0.2 + app.css（见 <see cref="Ui"/>），不引前端框架。
/// 菜单可见性在服务端渲染时决定：非 admin 的 HTML 里不出现管理后台入口；
/// /admin 路由本身另有 is_admin 实时查库 + 404 门禁（AdminEndpoints 组级过滤器）。
/// </summary>
public static class DashboardTemplates
{
    // (key, label, href)
    private static readonly (string Key, string Label, string Href)[] PersonalMenu =
    {
        ("overview", "Overview", "/account"),
        ("grants", "Authorized apps", "/account/grants"),
        ("security", "Sign-in & security", "/account/security"),
    };

    private static readonly (string Key, string Label, string Href)[] AdminMenu =
    {
        ("overview", "Overview", "/admin"),
        ("users", "Users", "/admin/users"),
        ("approvals", "Approvals", "/admin/approvals"),
        ("apps", "Apps & resources", "/admin/apps"),
        ("audit", "Audit log", "/admin/audit"),
        ("system", "System", "/admin/system"),
    };

    public static string Shell(DashboardSpace space, string activeKey, string username, bool isAdmin,
        int pendingCount, string title, string content, string? notice = null, string? error = null)
    {
        // 非 admin 永远只看到个人中心（即使调用方误传 Admin）
        if (!isAdmin) space = DashboardSpace.Personal;
        var menu = space == DashboardSpace.Admin ? AdminMenu : PersonalMenu;
        var nav = new StringBuilder();
        foreach (var (key, label, href) in menu)
        {
            var badge = key == "approvals" && pendingCount > 0
                ? $"<span class='badge nav-count' data-variant='destructive'>{pendingCount}</span>" : "";
            var current = key == activeKey ? " aria-current='page'" : "";
            nav.Append($"<li><a href='{Esc(href)}'{current}>{NavIcon(key)}<span>{Esc(T(label))}</span>{badge}</a></li>");
        }
        var groupTitle = space == DashboardSpace.Admin ? T("Administration") : T("Personal");
        var groups = $"<div role='group' aria-labelledby='nav-group'><h3 id='nav-group'>{groupTitle}</h3><ul>{nav}</ul></div>";

        // 空间切换：只有管理员有
        var switcher = "";
        if (isAdmin)
        {
            string Seg(DashboardSpace s, string href, string label, string extra) =>
                $"<a href='{href}'{(s == space ? " aria-current='page'" : "")}>{label}{extra}</a>";
            var pendingDot = pendingCount > 0 ? $"<span class='badge nav-count' data-variant='destructive'>{pendingCount}</span>" : "";
            // 用 div 不用 nav：Basecoat 把 .sidebar 里的 nav 都当侧边栏主体（fixed 定位）
            switcher = "<div class='space-switch' role='group' aria-label='space'>" +
                       Seg(DashboardSpace.Personal, "/account", T("Personal"), "") +
                       Seg(DashboardSpace.Admin, "/admin", T("Admin"), pendingDot) +
                       "</div>";
        }

        var alerts = new StringBuilder();
        if (!string.IsNullOrEmpty(notice)) alerts.Append(Alert(Esc(notice), error: false));
        if (!string.IsNullOrEmpty(error)) alerts.Append(Alert(Esc(error), error: true));
        var (langCode, langLabel) = IsZh ? ("en", "English") : ("zh", "中文");
        var initial = string.IsNullOrEmpty(username) ? "?" : username[..1];

        // sidebar 预置 data-sidebar-initialized：Basecoat 的 CSS 在 JS 初始化前把 sidebar 藏起来，
        // 预置后没 JS 也能看到菜单；sidebar.min.js 照常接管（它只在已有 toggle 方法时才跳过初始化）。
        return $@"<!doctype html>
<html lang=""{(IsZh ? "zh-CN" : "en")}"">
<head>
  <meta charset=""utf-8"">
  <meta name=""viewport"" content=""width=device-width,initial-scale=1"">
  <title>{Esc(T(title))} · nas-auth</title>
  {HeadAssets()}
  <script src=""{BasecoatDir}/basecoat.min.js?v={AssetVersion}"" defer></script>
  <script src=""{BasecoatDir}/sidebar.min.js?v={AssetVersion}"" defer></script>
</head>
<body>
  <aside class=""sidebar"" data-side=""left"" aria-hidden=""false"" data-sidebar-initialized=""true"">
    <nav aria-label=""nas-auth"">
      <header>
        <a class=""sb-brand"" href=""{(space == DashboardSpace.Admin ? "/admin" : "/account")}"">{IconLogo}<span>nas-auth</span></a>
        {switcher}
      </header>
      <section class=""scrollbar"">{groups}</section>
      <footer class=""sb-foot"">
        <div class=""sb-user""><span class=""sb-avatar"">{Esc(initial)}</span>
          <div><div class=""sb-name"">{Esc(username)}</div><div class=""sb-role"">{(isAdmin ? T("admin") : T("user"))}</div></div></div>
        <div class=""sb-links"">
          <a href=""#"" data-lang=""{langCode}"">{langLabel}</a>
          <a href=""/logout"">{T("Sign out")}</a>
        </div>
      </footer>
    </nav>
  </aside>
  <div class=""dash"">
    <header class=""topbar"">
      <button type=""button"" class=""btn"" data-variant=""ghost"" data-size=""icon"" aria-label=""{T("Menu")}""
              data-sidebar-toggle>{IconMenu}</button>
      <span>nas-auth</span>
    </header>
    <main class=""dash-main"">
      <h1>{Esc(T(title))}</h1>
      {alerts}
      {content}
    </main>
  </div>
</body>
</html>";
    }

    // ---------------------------------------------------------------- 公共小件

    /// <summary>卡片。title / hint / body 是已转义的 HTML。</summary>
    private static string Card(string title, string? hint, string body, string cls = "card", string? action = null) =>
        $"<div class='{cls}'><header><h2>{title}</h2>{(string.IsNullOrEmpty(hint) ? "" : $"<p>{hint}</p>")}" +
        $"{(action is null ? "" : $"<div class='card-action'>{action}</div>")}</header>" +
        $"<section>{body}</section></div>";

    private static string Empty(string text) => $"<p class='empty-note'>{text}</p>";

    private static string ProviderBadge(string provider) =>
        $"<span class='badge' data-variant='outline'>{ProviderIcon(provider)}{Esc(provider)}</span>";

    /// <summary>
    /// 提交前确认：输出 form 上的 data-confirm 属性，由 theme.js 事件委托弹 confirm。
    /// text 传纯文本（未转义），这里整体 HtmlEncode 一次 —— 用户可控内容（client_name 等）只落在属性值里，
    /// 浏览器解码后经 getAttribute 取回仍是纯文本，不会像原先内联 onsubmit 那样被拼进 JS 字符串执行。
    /// </summary>
    private static string Confirm(string text) => $"data-confirm='{Esc(text)}'";

    private static string Hidden(string name, string? value) =>
        $"<input type='hidden' name='{name}' value='{Esc(value)}'>";

    private static string OkBadge(bool ok) => ok
        ? $"<span class='badge ok'>{T("Success")}</span>"
        : $"<span class='badge' data-variant='destructive'>{T("Failed")}</span>";

    /// <summary>审计事件的人话名称。</summary>
    public static string EventLabel(string ev) => ev switch
    {
        "login" => T("Password sign-in"),
        "external_login" => T("External sign-in"),
        "authorize" => T("Authorization"),
        "token" => T("Token"),
        "revoke" => T("Token revocation"),
        "register" => T("Client registration"),
        "proxy.deny" => T("Proxy denied"),
        _ when ev.StartsWith("account.", StringComparison.Ordinal) => ActionLabel(ev["account.".Length..]),
        _ => ev,
    };

    // 账号 / 管理操作代号 → 人话（代号即 AuditLogger.AccountAction 的 action 参数）
    private static readonly Dictionary<string, string> Actions = new()
    {
        ["logout"] = "Sign out",
        ["revoke"] = "Revoke own grant",
        ["unbind-external"] = "Unbind own external account",
        ["change-password"] = "Change own password",
        ["force-change-password"] = "Set password after reset",
        ["sessions-revoke-others"] = "Sign out other devices",
        ["user-create"] = "Create user",
        ["user-update"] = "Edit user",
        ["user-delete"] = "Delete user",
        ["user-reset-password"] = "Reset user password",
        ["user-resources-update"] = "Edit resource grants",
        ["admin-revoke"] = "Revoke user's grant",
        ["admin-revoke-all"] = "Revoke all user's grants",
        ["admin-unbind-external"] = "Unbind user's external account",
        ["admin-force-logout"] = "Force sign-out",
        ["approval-approve"] = "Approve request",
        ["approval-reject"] = "Reject request",
        ["client-delete"] = "Delete client",
        ["password-login-override"] = "Password login switch",
        ["rotate-jwt-key"] = "Rotate JWT key",
    };

    private static string ActionLabel(string action) =>
        Actions.TryGetValue(action, out var label) ? T(label) : $"{T("Account action")} · {action}";

    /// <summary>从审计 detail（k=v 空格分隔）里取一个字段。</summary>
    private static string? DetailField(string? detail, string key)
    {
        if (string.IsNullOrEmpty(detail)) return null;
        foreach (var part in detail.Split(' '))
            if (part.StartsWith(key + "=", StringComparison.Ordinal)) return part[(key.Length + 1)..];
        return null;
    }

    private static string LoginMethod(AuditView a) => a.Event == "external_login"
        ? $"{ProviderIcon(DetailField(a.Detail, "method") ?? "")}{Esc(DetailField(a.Detail, "method") ?? "external")}"
        : T("Password");

    /// <summary>「最近登录」表（个人登录与安全页、管理员用户编辑页共用）。</summary>
    private static string LoginsTable(IReadOnlyList<AuditView> logins)
    {
        if (logins.Count == 0) return Empty(T("No sign-in records yet."));
        var sb = new StringBuilder($"<div class='table-container'><table class='table'><thead><tr><th>{T("Time")}</th><th>{T("Method")}</th><th>{T("Result")}</th><th>IP</th><th>{T("Note")}</th></tr></thead><tbody>");
        foreach (var a in logins)
        {
            var reason = DetailField(a.Detail, "reason");
            sb.Append($"<tr><td>{Esc(a.TimeDisplay)}</td><td><span class='inline-icon'>{LoginMethod(a)}</span></td><td>{OkBadge(a.Success)}</td>" +
                      $"<td class='mono'>{Esc(a.Ip ?? "-")}</td><td class='wrap'><span class='hint'>{Esc(reason ?? "")}</span></td></tr>");
        }
        return sb.Append("</tbody></table></div>").ToString();
    }

    /// <summary>
    /// 已授权应用表。个人中心（revokeAction=/account/revoke）与管理员代管（/admin/users/revoke + user_id）共用。
    /// </summary>
    private static string GrantsTable(IReadOnlyList<AccountAuthorizationView> rows, string revokeAction, string? userId)
    {
        if (rows.Count == 0)
            return Empty(T("No authorized applications yet. When an MCP client (such as Claude) completes an OAuth flow, grants appear here."));
        var sb = new StringBuilder($"<div class='table-container'><table class='table'><thead><tr><th>{T("Application")}</th><th>{T("Resource")}</th><th>{T("Scopes")}</th><th>{T("Last active")}</th><th></th></tr></thead><tbody>");
        foreach (var r in rows)
        {
            sb.Append("<tr>");
            sb.Append($"<td class='wrap'>{Esc(ClientDisplayName(r.ClientName))}<span class='sub'>{Esc(r.ClientId)}</span></td>");
            sb.Append($"<td class='wrap'>{Esc(r.ResourceDisplay)}");
            foreach (var url in r.ResourceUrl.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                sb.Append($"<span class='sub'>{Esc(url)}</span>");
            sb.Append("</td><td class='wrap'>");
            foreach (var s in r.Scopes) sb.Append($"<span class='badge mono' data-variant='secondary'>{Esc(s)}</span> ");
            sb.Append("</td>");
            sb.Append($"<td>{Esc(r.LastUsedDisplay)}</td>");
            sb.Append($"<td class='fit'><form method='post' action='{revokeAction}'>");
            if (userId is not null) sb.Append(Hidden("user_id", userId));
            sb.Append(Hidden("client_id", r.ClientId));
            sb.Append(Hidden("resource", r.ResourceUrl));
            sb.Append($"<button class='btn' data-variant='destructive' data-size='sm' type='submit'>{T("Revoke")}</button></form></td>");
            sb.Append("</tr>");
        }
        return sb.Append("</tbody></table></div>").ToString();
    }

    private static string AdminOnlyBadge(UserResourceEditView r) => r.AdminOnly
        ? $" <span class='badge' data-variant='secondary'>{T("admins only")}</span>"
        : "";

    private static string RoleBadge(UserAdminView u) => u.IsAdmin
        ? $"<span class='badge'>{T("admin")}</span>"
        : $"<span class='badge' data-variant='outline'>{T("user")}</span>";

    private static string StatusBadges(UserAdminView u)
    {
        var s = u.MustChangePassword
            ? $"<span class='badge warn'>{T("must change password")}</span>"
            : $"<span class='badge ok'>{T("active")}</span>";
        if (u.LockedUntilDisplay != null)
            s += $" <span class='badge' data-variant='destructive'>{T("locked until {0}", Esc(u.LockedUntilDisplay))}</span>";
        return s;
    }

    private static string EditHref(string userId) => $"/admin/users/edit?user={Uri.EscapeDataString(userId)}";

    // ================================================================ 个人中心

    public static string PersonalOverviewSection(ProfileView p)
    {
        var u = p.User;
        var methods = new StringBuilder();
        foreach (var b in p.Bindings) methods.Append(ProviderBadge(b.Provider)).Append(' ');
        methods.Append(p.PasswordAllowed
            ? $"<span class='badge' data-variant='outline'>{T("Password")}</span>"
            : "");
        if (methods.Length == 0) methods.Append($"<span class='hint'>—</span>");

        var info = new StringBuilder("<dl class='kv'>");
        info.Append($"<dt>{T("Username")}</dt><dd><strong>{Esc(u.Username)}</strong> {RoleBadge(u)}</dd>");
        info.Append($"<dt>{T("Email")}</dt><dd>{(string.IsNullOrEmpty(u.Email) ? "<span class='hint'>—</span>" : Esc(u.Email))}</dd>");
        info.Append($"<dt>{T("Sign-in methods")}</dt><dd>{methods}</dd>");
        info.Append($"<dt>{T("Latest sign-in")}</dt><dd>{(p.PreviousLogin is { } l ? $"{Esc(l.TimeDisplay)} · <span class='inline-icon'>{LoginMethod(l)}</span> · <span class='mono'>{Esc(l.Ip ?? "-")}</span>" : "<span class='hint'>—</span>")}</dd>");
        info.Append($"<dt>{T("Member since")}</dt><dd>{Esc(u.CreatedAtDisplay)}</dd>");
        info.Append("</dl>");
        var html = Card(T("My account"), null, info.ToString(), action:
            $"<a class='btn' data-variant='outline' data-size='sm' href='/account/security'>{T("Sign-in & security")}</a>");

        var apps = new StringBuilder();
        if (p.Apps.Count == 0)
            apps.Append(Empty(T("No apps have been opened for you yet. Ask the administrator.")));
        else
        {
            apps.Append($"<div class='table-container'><table class='table'><thead><tr><th>{T("App")}</th><th>{T("Scopes")}</th></tr></thead><tbody>");
            foreach (var a in p.Apps)
            {
                apps.Append($"<tr><td>{Esc(a.DisplayName)} <span class='badge mono' data-variant='outline'>{Esc(a.Aud)}</span></td><td class='wrap'>");
                foreach (var s in a.Scopes) apps.Append($"<span class='badge mono' data-variant='secondary'>{Esc(s)}</span> ");
                apps.Append("</td></tr>");
            }
            apps.Append("</tbody></table></div>");
        }
        html += Card(T("Apps I can use"), T("What the administrator has opened for your account. Whether an app is actually connected is under Authorized apps."), apps.ToString(),
            action: $"<a class='btn' data-variant='outline' data-size='sm' href='/account/grants'>{T("Authorized apps")} · {p.GrantCount}</a>");
        return html;
    }

    public static string GrantsSection(IReadOnlyList<AccountAuthorizationView> rows) =>
        Card(T("Authorized applications"),
            T("OAuth grants issued for your account. Revoking deletes the refresh tokens; issued access tokens remain valid until they expire."),
            GrantsTable(rows, "/account/revoke", userId: null));

    public static string SecuritySection(IReadOnlyList<BindingView> bindings,
        bool googleEnabled, bool microsoftEnabled, bool passwordEnabled, IReadOnlyList<AuditView> recentLogins)
    {
        var sb = new StringBuilder();
        if (bindings.Count == 0)
            sb.Append(Empty(T("No external identities bound yet.")));
        else
        {
            sb.Append($"<div class='table-container'><table class='table'><thead><tr><th>{T("Provider")}</th><th>{T("Account")}</th><th>{T("Bound")}</th><th></th></tr></thead><tbody>");
            foreach (var b in bindings)
            {
                sb.Append("<tr>");
                sb.Append($"<td>{ProviderBadge(b.Provider)}</td>");
                sb.Append($"<td class='wrap'>{Esc(b.DisplayName ?? "-")}<span class='sub'>{Esc(b.Email ?? b.Subject)}</span></td>");
                sb.Append($"<td>{Esc(b.BoundAtDisplay)}</td>");
                sb.Append("<td class='fit'><form method='post' action='/account/bindings/unbind'>");
                sb.Append(Hidden("provider", b.Provider));
                sb.Append(Hidden("subject", b.Subject));
                sb.Append($"<button class='btn' data-variant='destructive' data-size='sm' type='submit'>{T("Unbind")}</button></form></td>");
                sb.Append("</tr>");
            }
            sb.Append("</tbody></table></div>");
        }
        if (googleEnabled || microsoftEnabled)
        {
            sb.Append("<div class='actions' style='margin-top:16px'>");
            // 绑定是写操作：用 POST 表单（受跨源写拦截保护），不再是任何站点都能诱导跳转的 GET 链接
            if (googleEnabled)
                sb.Append($"<form method='post' action='/external/google/bind'><button class='btn' data-variant='outline' type='submit'>{IconGoogle}{T("Bind Google account")}</button></form>");
            if (microsoftEnabled)
                sb.Append($"<form method='post' action='/external/microsoft/bind'><button class='btn' data-variant='outline' type='submit'>{IconMicrosoft}{T("Bind Microsoft account")}</button></form>");
            sb.Append("</div>");
        }
        var html = Card(T("External identities"),
            T("External accounts bound to this user can sign in directly. Binding requires an active session and writes the identity as active immediately (no approval round-trip)."),
            sb.ToString());

        // 改密码：只对能用密码登录的账号显示（§十四）
        if (passwordEnabled)
        {
            var form = new StringBuilder("<form method='post' action='/account/change-password'><div class='form-grid narrow'>");
            form.Append($"<div class='field'><label for='current_password'>{T("Current password")}</label><input id='current_password' name='current_password' type='password' autocomplete='current-password' required></div>");
            form.Append($"<div class='field'><label for='new_password'>{T("New password")}</label><input id='new_password' name='new_password' type='password' autocomplete='new-password' required minlength='8'></div>");
            form.Append("</div>");
            form.Append($"<div class='form-foot'><button class='btn' type='submit'>{T("Update password")}</button></div>");
            form.Append("</form>");
            html += Card(T("Change password"), T("Changing the password also signs you out on all other devices."), form.ToString());
        }

        // 登录会话（§十六）
        var sessions = $"<form method='post' action='/account/sessions/revoke-others' {Confirm(T("Sign out of all other devices?"))}>" +
                       $"<button class='btn' data-variant='outline' type='submit'>{T("Sign out of all other devices")}</button></form>";
        html += Card(T("Sessions"),
            T("A nas-auth sign-in lasts 30 days and renews while in use. If you signed in on someone else's computer, sign out everywhere else here; this browser stays signed in. Apps you authorized keep working — revoke them under Authorized apps."),
            sessions);

        html += Card(T("Recent sign-ins"), T("Includes failed attempts. Kept for 90 days."), LoginsTable(recentLogins));
        return html;
    }

    // ================================================================ 管理后台

    public static string AdminOverviewSection(AdminStats s, IReadOnlyList<AuditView> recent)
    {
        string Tile(string label, string value, string? sub, string href, string cls = "") =>
            $"<a class='card stat{cls}' href='{href}'><section><div class='stat-label'>{label}</div>" +
            $"<div class='stat-value'>{value}</div>{(sub is null ? "" : $"<div class='stat-sub'>{sub}</div>")}</section></a>";

        var tiles = new StringBuilder("<div class='stat-grid'>");
        tiles.Append(Tile(T("Accounts"), s.Users.ToString(), T("{0} admin(s)", s.Admins), "/admin/users"));
        tiles.Append(Tile(T("Pending requests"), s.Pending.ToString(), s.Pending > 0 ? T("Needs review") : T("All clear"), "/admin/approvals", s.Pending > 0 ? " attention" : ""));
        tiles.Append(Tile(T("Active grants"), s.ActiveGrants.ToString(), T("user × app × resource"), "/admin/apps"));
        tiles.Append(Tile(T("Clients"), (s.PresetClients + s.DcrClients).ToString(), T("{0} preset · {1} DCR", s.PresetClients, s.DcrClients), "/admin/apps"));
        tiles.Append(Tile(T("Sign-ins (24h)"), s.Logins24h.ToString(),
            s.FailedLogins24h > 0 ? T("{0} failed", s.FailedLogins24h) : T("No failures"),
            "/admin/audit?type=login", s.FailedLogins24h > 0 ? " attention" : ""));
        tiles.Append("</div>");

        var html = tiles.ToString();
        html += Card(T("Recent events"), null, AuditTable(recent, compact: true),
            action: $"<a class='btn' data-variant='outline' data-size='sm' href='/admin/audit'>{T("View all")}</a>");
        return html;
    }

    // ---- 用户：列表 + 新建；单个用户的全部操作在 UserEditSection ----
    public static string UsersSection(IReadOnlyList<UserAdminView> users)
    {
        var create = new StringBuilder("<form method='post' action='/admin/users/create'><div class='form-grid'>");
        create.Append($"<div class='field'><label for='new_username'>{T("Username")}</label><input type='text' id='new_username' name='username' required pattern='[a-zA-Z0-9._-]{{1,32}}' autocomplete='off' placeholder='{T("letters, digits, . _ -")}'></div>");
        create.Append($"<div class='field'><label for='new_temp_password'>{T("Temporary password")}</label><input id='new_temp_password' name='temp_password' type='password' required minlength='8' autocomplete='new-password' placeholder='{T("≥ 8 chars")}'></div>");
        create.Append($"<div class='field'><label for='new_email'>{T("Email")}</label><input type='email' id='new_email' name='email' autocomplete='off' placeholder='{T("sent to apps as the email claim")}'></div>");
        create.Append("</div><div class='form-foot'>");
        create.Append($"<label class='label' style='gap:8px'><input class='input' type='checkbox' role='switch' name='allow_password_login' value='1' checked>{T("Allow password sign-in")}</label>");
        create.Append($"<span class='grow'></span><button class='btn' type='submit'>{T("Create")}</button>");
        create.Append("</div></form>");
        create.Append($"<p class='hint' style='margin-top:12px'>{T("Email is what apps (e.g. Immich) use to match this person to their own account — set it to the email of their account in that app. Accounts that sign in with Google / Microsoft should usually have password sign-in turned off.")}</p>");

        var sb = new StringBuilder();
        sb.Append($"<div class='table-container'><table class='table'><thead><tr><th>{T("Username")}</th><th>{T("Role")}</th><th>{T("Status")}</th><th>{T("Password sign-in")}</th><th>{T("Created")}</th><th></th></tr></thead><tbody>");
        foreach (var u in users)
        {
            sb.Append("<tr>");
            sb.Append($"<td class='wrap'><a href='{Esc(EditHref(u.UserId))}'><strong>{Esc(u.Username)}</strong></a>");
            if (u.IsSelf) sb.Append($" <span class='badge' data-variant='secondary'>{T("you")}</span>");
            sb.Append($"<span class='sub'>{(string.IsNullOrEmpty(u.Email) ? "—" : Esc(u.Email))}</span></td>");
            sb.Append($"<td>{RoleBadge(u)}</td>");
            sb.Append($"<td>{StatusBadges(u)}</td>");
            sb.Append($"<td>{(u.AllowPasswordLogin ? T("Allowed") : $"<span class='hint'>{T("Off")}</span>")}</td>");
            sb.Append($"<td>{Esc(u.CreatedAtDisplay)}</td>");
            sb.Append($"<td class='fit'><a class='btn' data-variant='outline' data-size='sm' href='{Esc(EditHref(u.UserId))}'>{T("Manage")}</a></td>");
            sb.Append("</tr>");
        }
        sb.Append("</tbody></table></div>");

        return Card(T("Users"), null, sb.ToString()) +
               Card(T("Create user"), T("Share the temporary password with the user; they must change it on first sign-in."), create.ToString());
    }

    // ---- 单个用户：资料 / 资源授权 / 外部身份 / 已授权应用 / 会话 / 重置密码 / 删除 ----
    public static string UserEditSection(UserDetailView d)
    {
        var u = d.User;
        var uid = Hidden("user_id", u.UserId);
        var html = new StringBuilder();
        html.Append($"<div class='page-actions'><a class='btn' data-variant='ghost' data-size='sm' href='/admin/users'>{IconBack}{T("Back to users")}</a></div>");

        // 资料：邮箱 + 允许密码登录（§十四）
        var profile = new StringBuilder();
        profile.Append($"<p style='margin:0 0 16px'>{RoleBadge(u)} {StatusBadges(u)}");
        if (u.IsSelf) profile.Append($" <span class='badge' data-variant='secondary'>{T("you")}</span>");
        profile.Append($" <span class='hint' style='margin-left:6px'>{T("Created")} {Esc(u.CreatedAtDisplay)}</span></p>");
        profile.Append($"<form method='post' action='/admin/users/update'>{uid}");
        profile.Append("<div class='form-grid narrow'>");
        profile.Append($"<div class='field'><label for='email'>{T("Email")}</label><input type='email' id='email' name='email' value='{Esc(u.Email)}' autocomplete='off' placeholder='{T("sent to apps as the email claim")}'></div>");
        profile.Append("</div><div class='form-foot'>");
        profile.Append($"<label class='label' style='gap:8px'><input class='input' type='checkbox' role='switch' name='allow_password_login' value='1'{(u.AllowPasswordLogin ? " checked" : "")}>{T("Allow password sign-in")}</label>");
        profile.Append($"<button class='btn' type='submit'>{T("Save")}</button>");
        profile.Append("</div></form>");
        html.Append(Card(T("Profile"),
            T("Email is what apps (e.g. Immich) use to match this person to their own account — set it to the email of their account in that app. Accounts that sign in with Google / Microsoft should usually have password sign-in turned off."),
            profile.ToString()));

        // 资源授权（checkbox）
        var res = new StringBuilder($"<form method='post' action='/admin/users/resources'>{uid}<div class='res-grid'>");
        foreach (var r in d.Resources)
        {
            // admin_only 资源对非管理员只读展示：勾不上，也提交不进去（服务端同样会丢弃）
            var locked = r.AdminOnly && !u.IsAdmin;
            res.Append($"<fieldset class='group-box'><legend>{Esc(r.DisplayName)} <span class='badge mono' data-variant='outline'>{Esc(r.Aud)}</span>{AdminOnlyBadge(r)}</legend>");
            foreach (var s in r.AllScopes)
            {
                var check = r.GrantedScopes.Contains(s) && !locked ? " checked" : "";
                var disabled = locked ? " disabled" : "";
                res.Append($"<label class='check-line'><input class='input' type='checkbox' name='scope:{Esc(r.Aud)}' value='{Esc(s)}'{check}{disabled}><span class='mono'>{Esc(s)}</span></label>");
            }
            res.Append("</fieldset>");
        }
        res.Append($"</div><div class='form-foot'><button class='btn' type='submit'>{T("Save grants")}</button></div></form>");
        html.Append(Card(T("Resource grants"),
            T("Per-resource maximum scopes for this user. Unchecking every scope of a resource removes the grant entirely; /authorize and token refresh then deny that resource for this user. Resources marked \"admins only\" use the administrator's own credentials upstream and can only be granted to admins."),
            res.ToString()));

        // 外部身份（管理员可解绑）
        var ids = new StringBuilder();
        if (d.Bindings.Count == 0) ids.Append(Empty(T("No external identities bound yet.")));
        else
        {
            ids.Append($"<div class='table-container'><table class='table'><thead><tr><th>{T("Provider")}</th><th>{T("Account")}</th><th>{T("Bound")}</th><th></th></tr></thead><tbody>");
            foreach (var b in d.Bindings)
            {
                ids.Append($"<tr><td>{ProviderBadge(b.Provider)}</td>");
                ids.Append($"<td class='wrap'>{Esc(b.DisplayName ?? "-")}<span class='sub'>{Esc(b.Email ?? b.Subject)}</span></td>");
                ids.Append($"<td>{Esc(b.BoundAtDisplay)}</td>");
                ids.Append($"<td class='fit'><form method='post' action='/admin/users/unbind' {Confirm(T("Unbind this external account?"))}>{uid}");
                ids.Append(Hidden("provider", b.Provider)).Append(Hidden("subject", b.Subject));
                ids.Append($"<button class='btn' data-variant='destructive' data-size='sm' type='submit'>{T("Unbind")}</button></form></td></tr>");
            }
            ids.Append("</tbody></table></div>");
        }
        html.Append(Card(T("External identities"), null, ids.ToString()));

        // 代管已授权应用
        var revokeAll = d.Grants.Count == 0 ? null :
            $"<form method='post' action='/admin/users/revoke-all' {Confirm(T("Revoke all grants of {0}?", u.Username))}>{uid}" +
            $"<button class='btn' data-variant='destructive' data-size='sm' type='submit'>{T("Revoke all")}</button></form>";
        html.Append(Card(T("Authorized apps"),
            T("Revoking deletes the refresh tokens; issued access tokens remain valid until they expire."),
            GrantsTable(d.Grants, "/admin/users/revoke", u.UserId), action: revokeAll));

        // 会话（§十六）：最近登录 + 强制下线
        var sess = new StringBuilder(LoginsTable(d.RecentLogins));
        if (!u.IsSelf)
            sess.Append($"<form method='post' action='/admin/users/force-logout' style='margin-top:16px' {Confirm(T("Sign {0} out on all devices?", u.Username))}>{uid}" +
                        $"<button class='btn' data-variant='outline' type='submit'>{T("Sign out on all devices")}</button></form>");
        html.Append(Card(T("Sign-ins & sessions"),
            T("Signing out ends every nas-auth browser session of this user. Apps they already authorized keep working until revoked above."),
            sess.ToString()));

        // 重置密码 / 删除：不对自己、不对管理员
        if (!u.IsSelf && !u.IsAdmin)
        {
            var reset = new StringBuilder($"<form method='post' action='/admin/users/reset-password'>{uid}");
            reset.Append($"<div class='form-grid narrow'><div class='field'><label for='temp_password'>{T("Temporary password")}</label><input id='temp_password' name='temp_password' type='password' required minlength='8' placeholder='{T("new temporary password")}' autocomplete='off'></div></div>");
            reset.Append($"<div class='form-foot'><button class='btn' data-variant='outline' type='submit'>{T("Reset password")}</button></div>");
            reset.Append("</form>");
            html.Append(Card(T("Reset password"), T("Set a temporary password; they must change it on next sign-in. Their current sessions end immediately."), reset.ToString()));

            var del = new StringBuilder($"<form method='post' action='/admin/users/delete' {Confirm(T("Delete user {0}? All of their refresh tokens will be revoked.", u.Username))}>{uid}");
            del.Append($"<button class='btn' data-variant='destructive' type='submit'>{T("Delete user")}</button></form>");
            html.Append(Card(T("Delete user"),
                T("Revokes all of their refresh tokens and removes their external identities and resource grants. Cannot be undone."),
                del.ToString(), "card danger"));
        }
        return html.ToString();
    }

    // ---- 待批申请 ----
    public static string ApprovalsSection(IReadOnlyList<PendingApprovalView> pending,
        IReadOnlyList<PendingApprovalView> rejected,
        IReadOnlyList<UserAdminView> users,
        IReadOnlyList<UserResourceEditView> resources)
    {
        var sb = new StringBuilder();
        if (pending.Count == 0)
            sb.Append(Empty(T("Nothing pending.")));
        else
        {
            var i = 0;
            foreach (var p in pending)
            {
                var rejectId = $"reject-{i++}";
                sb.Append("<fieldset class='group-box'>");
                sb.Append($"<legend>{ProviderBadge(p.Provider)} {Esc(p.Email ?? p.Subject)}</legend>");
                sb.Append($"<p class='meta'>{Esc(p.DisplayName ?? "-")} · <span class='mono'>{Esc(p.Subject)}</span> · {T("requested {0}", Esc(p.CreatedAtDisplay))}</p>");

                sb.Append("<form method='post' action='/admin/approvals/approve'>");
                sb.Append(Hidden("provider", p.Provider)).Append(Hidden("subject", p.Subject));
                sb.Append("<div class='form-grid narrow'>");
                sb.Append($"<div class='field'><label>{T("Bind to existing user")}</label><select class='select' name='existing_user'><option value=''>{T("— select —")}</option>");
                foreach (var u in users)
                    sb.Append($"<option value='{Esc(u.UserId)}'>{Esc(u.Username)}</option>");
                sb.Append("</select></div>");
                sb.Append($"<div class='field'><label>{T("… or create new user id")}</label><input type='text' name='new_user' pattern='[a-zA-Z0-9._-]{{1,32}}' autocomplete='off' placeholder='{T("leave empty to bind existing")}'></div>");
                sb.Append("</div>");

                sb.Append("<div style='margin:12px 0'>");
                foreach (var r in resources)
                    sb.Append($"<label class='check-line'><input class='input' type='checkbox' name='grant_aud' value='{Esc(r.Aud)}'>{Esc(r.DisplayName)} <span class='badge mono' data-variant='outline'>{Esc(r.Aud)}</span></label>");
                sb.Append("</div>");
                // 拒绝按钮借 form= 挂到下面独立的拒绝表单上，两个按钮能并排而表单不嵌套
                sb.Append($"<div class='actions'><button class='btn' type='submit'>{T("Approve")}</button>");
                sb.Append($"<button class='btn' data-variant='destructive' type='submit' form='{rejectId}'>{T("Reject")}</button></div>");
                sb.Append("</form>");

                sb.Append($"<form id='{rejectId}' method='post' action='/admin/approvals/reject'>");
                sb.Append(Hidden("provider", p.Provider)).Append(Hidden("subject", p.Subject));
                sb.Append("</form>");
                sb.Append("</fieldset>");
            }
        }
        var html = Card(T("Pending requests"),
            T("External sign-in attempts waiting for approval. Approve binds the identity to an existing user, or creates a new user (external sign-in only, no usable password). Checked resources are granted with their full scopes; fine-tune later under Users → Resources."),
            sb.ToString());

        var rj = new StringBuilder();
        if (rejected.Count == 0)
            rj.Append(Empty(T("None.")));
        else
        {
            rj.Append($"<div class='table-container'><table class='table'><thead><tr><th>{T("Provider")}</th><th>{T("Account")}</th><th>{T("Requested")}</th></tr></thead><tbody>");
            foreach (var p in rejected)
            {
                rj.Append("<tr>");
                rj.Append($"<td>{ProviderBadge(p.Provider)}</td>");
                rj.Append($"<td class='wrap'>{Esc(p.Email ?? "-")}<span class='sub'>{Esc(p.Subject)}</span></td>");
                rj.Append($"<td>{Esc(p.CreatedAtDisplay)}</td>");
                rj.Append("</tr>");
            }
            rj.Append("</tbody></table></div>");
        }
        html += Card(T("Rejected"), T("Kept on record so repeated sign-in attempts stay rejected instead of re-appearing as pending."), rj.ToString());
        return html;
    }

    // ---- 应用与资源 ----
    public static string AppsSection(IReadOnlyList<ResourceAdminView> resources, IReadOnlyList<ClientAdminView> clients)
    {
        var rs = new StringBuilder();
        if (resources.Count == 0) rs.Append(Empty(T("No resources.")));
        else
        {
            rs.Append($"<div class='table-container'><table class='table'><thead><tr><th>{T("Resource")}</th><th>aud</th><th>{T("Scopes")}</th><th>{T("Mode")}</th><th>{T("Granted users")}</th><th>{T("Active grants")}</th></tr></thead><tbody>");
            foreach (var r in resources)
            {
                rs.Append($"<tr><td class='wrap'>{Esc(r.DisplayName)}<span class='sub'>{Esc(r.ResourceUrl)}</span></td>");
                rs.Append($"<td><span class='badge mono' data-variant='outline'>{Esc(r.Aud)}</span></td><td class='wrap'>");
                foreach (var s in r.Scopes) rs.Append($"<span class='badge mono' data-variant='secondary'>{Esc(s)}</span> ");
                rs.Append($"</td><td>{(r.IsProxy ? T("Proxy (token translation)") : T("Direct JWT"))}</td>");
                rs.Append($"<td>{r.UserCount}</td><td>{r.ActiveGrants}</td></tr>");
            }
            rs.Append("</tbody></table></div>");
        }
        var html = Card(T("Resource catalog"), T("From resources.json (read-only; edit the file and restart to change). Users = accounts granted this resource under Users → Resource grants."), rs.ToString());

        var sb = new StringBuilder();
        if (clients.Count == 0)
            sb.Append(Empty(T("No clients.")));
        else
        {
            sb.Append($"<div class='table-container'><table class='table'><thead><tr><th>{T("Client")}</th><th>{T("Type")}</th><th>{T("Auth method")}</th><th>{T("Redirect URIs")}</th><th>{T("Active grants")}</th><th>{T("Last used")}</th><th></th></tr></thead><tbody>");
            foreach (var c in clients)
            {
                sb.Append("<tr>");
                sb.Append($"<td class='wrap'>{Esc(ClientDisplayName(c.ClientName))}<span class='sub'>{Esc(c.ClientId)}</span></td>");
                sb.Append($"<td>{(c.AutoRegistered ? "<span class='badge' data-variant='outline'>DCR</span>" : $"<span class='badge' data-variant='secondary'>{T("preset")}</span>")}</td>");
                sb.Append($"<td><span class='badge mono' data-variant='outline'>{Esc(c.TokenEndpointAuthMethod)}</span></td>");
                sb.Append("<td class='wrap'>");
                foreach (var u in c.RedirectUris) sb.Append($"<span class='sub'>{Esc(u)}</span>");
                sb.Append("</td>");
                sb.Append($"<td>{c.ActiveGrants}</td>");
                sb.Append($"<td>{Esc(c.LastUsedDisplay)}<span class='sub'>{T("created {0}", Esc(c.CreatedAtDisplay))}</span></td>");
                sb.Append("<td class='fit'>");
                if (c.AutoRegistered)
                    sb.Append($"<form method='post' action='/admin/apps/delete-client' {Confirm(T("Delete client {0}? Its grants are revoked; the app must register again.", ClientDisplayName(c.ClientName)))}>" +
                              $"{Hidden("client_id", c.ClientId)}<button class='btn' data-variant='destructive' data-size='sm' type='submit'>{T("Delete")}</button></form>");
                sb.Append("</td></tr>");
            }
            sb.Append("</tbody></table></div>");
        }
        html += Card(T("OAuth clients"),
            T("Preset clients come from clients.preset.json; DCR ones registered themselves (e.g. Claude, Grok). DCR clients unused for 30 days with no live grants are cleaned up automatically; delete one here to cut it off now."),
            sb.ToString());
        return html;
    }

    // ---- 审计日志 ----
    private static string AuditTable(IReadOnlyList<AuditView> rows, bool compact)
    {
        if (rows.Count == 0) return Empty(T("No events."));
        var sb = new StringBuilder($"<div class='table-container'><table class='table'><thead><tr><th>{T("Time")}</th><th>{T("Event")}</th><th>{T("Result")}</th><th>{T("User")}</th>" +
                                   (compact ? "" : $"<th>{T("Client")}</th>") + $"<th>IP</th><th>{T("Detail")}</th></tr></thead><tbody>");
        foreach (var a in rows)
        {
            sb.Append($"<tr><td>{Esc(a.TimeDisplay)}</td><td>{Esc(EventLabel(a.Event))}</td><td>{OkBadge(a.Success)}</td>");
            sb.Append($"<td>{(a.UserId is null ? "<span class='hint'>—</span>" : $"<a href='/admin/audit?user={Uri.EscapeDataString(a.UserId)}'>{Esc(a.UserId)}</a>")}</td>");
            if (!compact) sb.Append($"<td class='mono'>{Esc(a.ClientId ?? "")}</td>");
            sb.Append($"<td class='mono'>{Esc(a.Ip ?? "")}</td>");
            sb.Append($"<td class='wrap'><span class='sub'>{Esc(a.Detail ?? "")}</span></td></tr>");
        }
        return sb.Append("</tbody></table></div>").ToString();
    }

    public static string AuditSection(AuditFilter f, IReadOnlyList<AuditView> rows)
    {
        string Opt(string value, string label) =>
            $"<option value='{value}'{(f.Type == value ? " selected" : "")}>{label}</option>";
        var form = new StringBuilder("<form method='get' action='/admin/audit' class='filter-bar'>");
        form.Append($"<div class='field'><label for='type'>{T("Event")}</label><select class='select' id='type' name='type'>");
        form.Append(Opt("", T("All"))).Append(Opt("login", T("Sign-ins"))).Append(Opt("authorize", T("Authorization")))
            .Append(Opt("token", T("Tokens"))).Append(Opt("account", T("Account actions")))
            .Append(Opt("register", T("Client registration"))).Append(Opt("proxy", T("Proxy denied")));
        form.Append("</select></div>");
        form.Append($"<div class='field'><label for='user'>{T("User")}</label><input type='text' id='user' name='user' value='{Esc(f.User)}' placeholder='user_id'></div>");
        form.Append($"<label class='label' style='gap:8px'><input class='input' type='checkbox' name='failed' value='1'{(f.FailedOnly ? " checked" : "")}>{T("Failures only")}</label>");
        form.Append($"<button class='btn' type='submit'>{T("Filter")}</button>");
        form.Append($"<a class='btn' data-variant='ghost' href='/admin/audit'>{T("Reset")}</a>");
        form.Append("</form>");

        return Card(T("Filter"), T("Kept for 90 days; shows the latest 300 matches. High-volume proxy forwarding is only in the container log."), form.ToString()) +
               Card(T("Events"), null, AuditTable(rows, compact: false));
    }

    // ---- 系统 ----
    public static string SystemSection(string? rotateNotice,
        bool passwordLoginEnabled, bool passwordLoginConfigEnabled,
        bool? passwordLoginOverride, bool passwordLoginLockoutGuard, JwtKeyView? jwt = null)
    {
        // 密码登录运行时开关（设计 §十 二期增强）：override 写 settings 表，立即生效；
        // 配置基线 Auth__PasswordLogin__Enabled 不动，"恢复跟随配置"即清掉 override。
        var pw = new StringBuilder();
        if (passwordLoginLockoutGuard)
            pw.Append(Alert(T("No external sign-in provider is configured, so password login is forced on (lockout protection)."), error: false));
        pw.Append("<p style='margin:0 0 12px'>");
        pw.Append(passwordLoginEnabled
            ? $"<span class='badge ok'>{T("Enabled")}</span> "
            : $"<span class='badge' data-variant='outline'>{T("Disabled")}</span> ");
        pw.Append(passwordLoginOverride is null
            ? T("Following the container config (<code>Auth__PasswordLogin__Enabled</code> = {0}).",
                passwordLoginConfigEnabled ? "true" : "false")
            : T("Runtime override active; the container config (<code>Auth__PasswordLogin__Enabled</code> = {0}) is being ignored.",
                passwordLoginConfigEnabled ? "true" : "false"));
        pw.Append("</p>");
        pw.Append($"<p class='hint'>{T("Takes effect immediately, no restart. Typical use: keep password login off in config, enable it here temporarily, then restore. Password hashes stay in the database as a break-glass fallback.")}</p>");
        pw.Append($"<p class='hint' style='margin-top:6px'>{T("This is the master switch. With it on, only users whose \"Allow password sign-in\" is checked (Users page) can sign in with a password.")}</p>");
        pw.Append("<div class='actions' style='margin-top:16px'>");
        if (passwordLoginEnabled)
        {
            pw.Append("<form method='post' action='/admin/password-login'><input type='hidden' name='mode' value='disable'>");
            pw.Append($"<button class='btn' data-variant='destructive' type='submit'>{T("Disable password login")}</button></form>");
        }
        else
        {
            pw.Append("<form method='post' action='/admin/password-login'><input type='hidden' name='mode' value='enable'>");
            pw.Append($"<button class='btn' data-variant='outline' type='submit'>{T("Enable password login temporarily")}</button></form>");
        }
        if (passwordLoginOverride is not null)
        {
            pw.Append("<form method='post' action='/admin/password-login'><input type='hidden' name='mode' value='clear'>");
            pw.Append($"<button class='btn' data-variant='outline' type='submit'>{T("Restore: follow config")}</button></form>");
        }
        pw.Append("</div>");
        var html = Card(T("Password login"), null, pw.ToString());

        var key = new StringBuilder();
        if (jwt is { Rs256: true })
        {
            // RS256：RSA 钥轮换靠改文件名 + 重启（OidcKeyService），这里只给步骤，不给按钮
            key.Append($"<p class='hint'>{T("Access tokens and id_tokens are signed with the RSA key in <code>oidc_rs256_current.pem</code> (next to auth.db); resource servers verify them via <code>/.well-known/jwks.json</code>.")}</p>");
            key.Append($"<p class='hint' style='margin-top:6px'>{T("To rotate: rename <code>oidc_rs256_current.pem</code> to <code>oidc_rs256_previous.pem</code> (replacing the old one), then restart nas-auth; a new current key is generated on startup. The previous key stays in JWKS, so outstanding tokens keep validating until they expire.")}</p>");
            key.Append($"<p class='hint' style='margin-top:6px'>{T("Keep the previous key for at least the access-token lifetime ({0} days) before deleting it or rotating again, otherwise outstanding access tokens stop validating.", jwt.AccessTokenLifetimeDays)}</p>");
            if (jwt.LegacyHs256Keys)
                key.Append($"<p class='hint' style='margin-top:6px'>{T("Legacy HS256 keys (<code>Jwt__SigningKey__*</code>) are still configured and only used to validate tokens issued before the switch to RS256, and only tokens expiring by <code>Jwt__LegacyHs256NotAfter</code> = {0}. After that they are all rejected; remove the keys.", Esc(jwt.LegacyHs256NotAfter ?? "-"))}</p>");
            html += Card(T("Access token signing key (RS256)"), null, key.ToString());
            return html;
        }
        if (!string.IsNullOrEmpty(rotateNotice)) key.Append(Alert(Esc(T(rotateNotice)), error: false));
        key.Append("<form method='post' action='/admin/rotate-jwt-key' style='margin-top:4px'>");
        key.Append($"<button class='btn' data-variant='destructive' type='submit'>{T("Generate new key")}</button>");
        key.Append("</form>");
        html += Card(T("JWT signing key rotation"),
            T("Generates a new random key and stages the current key as Previous. After generating, manually update <code>Jwt__SigningKey__Current</code> / <code>Jwt__SigningKey__Previous</code> in the deployment environment (e.g. <code>.env</code>) and restart nas-auth and every resource server that shares the key."),
            key.ToString());
        return html;
    }
}

/// <summary>系统页的签名密钥卡片：RS256 模式换成 RSA 轮换说明，HS256 模式保留原来的生成按钮。</summary>
public record JwtKeyView(bool Rs256, bool LegacyHs256Keys, int AccessTokenLifetimeDays, string? LegacyHs256NotAfter = null);

public record BindingView(
    string Provider,
    string Subject,
    string? Email,
    string? DisplayName,
    string BoundAtDisplay
);

public record PendingApprovalView(
    string Provider,
    string Subject,
    string? Email,
    string? DisplayName,
    string CreatedAtDisplay
);

public record UserResourceEditView(
    string Aud,
    string DisplayName,
    IReadOnlyList<string> AllScopes,
    IReadOnlyList<string> GrantedScopes,
    bool AdminOnly = false
);

public record ClientAdminView(
    string ClientId,
    string ClientName,
    bool AutoRegistered,
    string TokenEndpointAuthMethod,
    IReadOnlyList<string> RedirectUris,
    string CreatedAtDisplay,
    string LastUsedDisplay,
    int ActiveGrants = 0
);

public record ProfileAppView(string DisplayName, string Aud, IReadOnlyList<string> Scopes);

public record ProfileView(
    UserAdminView User,
    IReadOnlyList<BindingView> Bindings,
    bool PasswordAllowed,
    IReadOnlyList<ProfileAppView> Apps,
    int GrantCount,
    AuditView? PreviousLogin
);

public record UserDetailView(
    UserAdminView User,
    IReadOnlyList<UserResourceEditView> Resources,
    IReadOnlyList<BindingView> Bindings,
    IReadOnlyList<AccountAuthorizationView> Grants,
    IReadOnlyList<AuditView> RecentLogins
);

public record AdminStats(int Users, int Admins, int Pending, int ActiveGrants,
    int PresetClients, int DcrClients, int Logins24h, int FailedLogins24h);

public record AuditView(string TimeDisplay, string Event, bool Success,
    string? UserId, string? ClientId, string? Ip, string? Detail);

public record AuditFilter(string Type, string User, bool FailedOnly);

public record ResourceAdminView(string Aud, string DisplayName, string ResourceUrl,
    IReadOnlyList<string> Scopes, bool IsProxy, int UserCount, int ActiveGrants);
