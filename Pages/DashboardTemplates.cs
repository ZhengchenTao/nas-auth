using System.Text;
using NasAuth.Config;
using NasAuth.Data;
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
public static partial class DashboardTemplates
{
    // (key, label, href)
    private static readonly (string Key, string Label, string Href)[] PersonalMenu =
    {
        ("overview", "Overview", "/account"),
        ("grants", "Authorized apps", "/account/grants"),
        ("security", "Sign-in & security", "/account/security"),
        ("sessions", "Devices and sessions", "/account/sessions"),
    };

    private static readonly (string Key, string Label, string Href)[] AdminMenu =
    {
        ("overview", "Overview", "/admin"),
        ("users", "Users", "/admin/users"),
        ("groups", "Groups", "/admin/groups"),
        ("approvals", "Approvals", "/admin/approvals"),
        ("apps", "Apps & resources", "/admin/apps"),
        ("audit", "Audit log", "/admin/audit"),
        ("system", "System", "/admin/system"),
    };

    public static string Shell(DashboardSpace space, string activeKey, string username, bool isAdmin,
        int pendingCount, string title, string content, string? notice = null, string? error = null,
        string? displayName = null, string? avatarFile = null)
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
            nav.Append($"<li><a href='{Esc(href)}'{current}>{NavIcon(key)}<span>{Esc(Label(key, label))}</span>{badge}</a></li>");
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
                       Seg(DashboardSpace.Personal, "/account", Esc(Label("personal", "Personal")), "") +
                       Seg(DashboardSpace.Admin, "/admin", Esc(Label("admin", "Admin")), pendingDot) +
                       "</div>";
        }

        var alerts = new StringBuilder();
        if (!string.IsNullOrEmpty(notice)) alerts.Append(Alert(Esc(notice), error: false));
        if (!string.IsNullOrEmpty(error)) alerts.Append(Alert(Esc(error), error: true));
        var (langCode, langLabel) = IsZh ? ("en", "English") : ("zh", "中文");
        // 侧边栏底部：昵称 + 头像（§十九），点击回个人中心概览
        var shownName = string.IsNullOrEmpty(displayName) ? username : displayName;
        var sbAvatar = !string.IsNullOrEmpty(avatarFile)
            ? $"<img class=\"sb-avatar\" src=\"/avatars/{Esc(avatarFile)}\" alt=\"\">"
            : $"<span class=\"sb-avatar\">{Esc(string.IsNullOrEmpty(shownName) ? "?" : shownName.Trim()[..1])}</span>";

        // sidebar 预置 data-sidebar-initialized：Basecoat 的 CSS 在 JS 初始化前把 sidebar 藏起来，
        // 预置后没 JS 也能看到菜单；sidebar.min.js 照常接管（它只在已有 toggle 方法时才跳过初始化）。
        return ApplyPathBase($@"<!doctype html>
<html lang=""{(IsZh ? "zh-CN" : "en")}"">
<head>
  <meta charset=""utf-8"">
  <meta name=""viewport"" content=""width=device-width,initial-scale=1"">
  <title>{Esc(T(title))} · {Esc(Branding.SiteName)}</title>
  {HeadAssets()}
  <script src=""{BasecoatDir}/basecoat.min.js?v={AssetVersion}"" defer></script>
  <script src=""{BasecoatDir}/sidebar.min.js?v={AssetVersion}"" defer></script>
</head>
<body>
  <aside class=""sidebar"" data-side=""left"" aria-hidden=""false"" data-sidebar-initialized=""true"">
    <nav aria-label=""{Esc(Branding.SiteName)}"">
      <header>
        <a class=""sb-brand"" href=""{(space == DashboardSpace.Admin ? "/admin" : "/account")}"">{BrandIcon}<span>{Esc(Branding.SiteName)}</span></a>
        {switcher}
      </header>
      <section class=""scrollbar"">{groups}</section>
      <footer class=""sb-foot"">
        <a class=""sb-user"" href=""/account"" title=""{T("Overview")}"">{sbAvatar}
          <div><div class=""sb-name"">{Esc(shownName)}</div><div class=""sb-role"">{Esc(username)} · {(isAdmin ? T("admin") : T("user"))}</div></div></a>
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
      <span>{Esc(Branding.SiteName)}</span>
    </header>
    <main class=""dash-main"">
      <h1>{Esc(T(title))}</h1>
      {alerts}
      {content}
    </main>
  </div>
</body>
</html>");
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
        "forward_auth" => T("Site access"),
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
        ["session-revoke"] = "Sign out device",
        ["admin-session-revoke"] = "Sign out device",
        ["session-name"] = "Rename device",
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

        var info = new StringBuilder($"<div class='profile-head'>{Avatar(u.AvatarFile, u.DisplayName ?? u.Username, "avatar-lg")}<div><strong>{Esc(u.DisplayName ?? u.Username)}</strong><span class='sub mono'>{Esc(u.Username)}</span></div></div>");
        info.Append("<dl class='kv'>");
        info.Append($"<dt>{T("Username")}</dt><dd><strong>{Esc(u.Username)}</strong> {RoleBadge(u)}</dd>");
        info.Append($"<dt>{T("Nickname")}</dt><dd>{(string.IsNullOrEmpty(u.DisplayName) ? "<span class='hint'>—</span>" : Esc(u.DisplayName))}</dd>");
        info.Append($"<dt>{T("Email")}</dt><dd>{(string.IsNullOrEmpty(u.Email) ? "<span class='hint'>—</span>" : Esc(u.Email))}</dd>");
        info.Append($"<dt>{T("Sign-in methods")}</dt><dd>{methods}</dd>");
        info.Append($"<dt>{T("Latest sign-in")}</dt><dd>{(p.PreviousLogin is { } l ? $"{Esc(l.TimeDisplay)} · <span class='inline-icon'>{LoginMethod(l)}</span> · <span class='mono'>{Esc(l.Ip ?? "-")}</span>" : "<span class='hint'>—</span>")}</dd>");
        info.Append($"<dt>{T("Member since")}</dt><dd>{Esc(u.CreatedAtDisplay)}</dd>");
        info.Append("</dl>");
        var html = Card(T("My account"), null, info.ToString(), action:
            $"<a class='btn' data-variant='outline' data-size='sm' href='/account/security'>{T("Sign-in & security")}</a>");
        html += ExternalProfilesSection(p.Bindings, self: true);
        html += ProfileEditCard(u, p.Bindings);

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

    /// <summary>
    /// §十九 资料卡片：昵称、头像（上传 / 去掉 / 用已绑定外部账号的）。用户名（user_id）不可改：各应用按它认人。
    /// </summary>
    private static string ExternalProfilesSection(IReadOnlyList<BindingView> bindings, bool self = false)
    {
        var html = new StringBuilder();
        foreach (var binding in bindings.Where(x => x.ProfileDefinition is not null))
        {
            var provider = binding.ProfileDefinition!;
            var name = binding.Profile?.GetValueOrDefault(provider.NameField) ?? binding.DisplayName ?? provider.DisplayName;
            var facts = new StringBuilder();
            var details = new StringBuilder();
            foreach (var definition in provider.Fields.Where(x => x.Value.Visible).OrderBy(x => x.Value.Order).ThenBy(x => x.Key))
            {
                var value = binding.Profile?.GetValueOrDefault(definition.Key);
                if (string.IsNullOrWhiteSpace(value) || definition.Key == provider.NameField) continue;
                if (definition.Value.Detail)
                    details.Append($"<dt>{Esc(definition.Value.Label)}</dt><dd>{Esc(value)}</dd>");
                else
                    facts.Append($"<div><dt>{Esc(definition.Value.Label)}</dt><dd>{Esc(value)}</dd></div>");
            }
            html.Append("<div class='card external-identity'><div class='identity-heading'><div class='identity-person'>");
            html.Append(Avatar(binding.AvatarFile, name, "avatar-sm"));
            html.Append($"<div><p class='identity-provider'>{Esc(provider.DisplayName)}</p><h2>{Esc(name)}</h2></div></div><span class='identity-linked'>{T("Identity linked")}</span></div>");
            if (facts.Length > 0) html.Append($"<dl class='identity-facts'>{facts}</dl>");
            if (details.Length > 0) html.Append($"<details class='identity-details'><summary>{T("Identity details")}</summary><dl class='kv'>{details}</dl></details>");
            html.Append($"<div class='identity-bottom'><span class='identity-updated'>{T("Updated at")} · {Esc(binding.ProfileUpdatedAt ?? "—")}</span>");
            var canRefresh = provider.BrowserLookupUrl.Length > 0 && (!self || provider.AllowSelfRefresh);
            if (self && canRefresh) html.Append(DirectoryWidget(binding.Provider, provider, binding.Subject, self, binding.Profile));
            html.Append("</div>");
            if (!self && canRefresh) html.Append("<div class='identity-admin-update'>" + DirectoryWidget(binding.Provider, provider, binding.Subject, self, binding.Profile) + "</div>");
            html.Append("</div>");
        }
        return html.ToString();
    }

    private static string DirectoryWidget(string provider, NasAuth.Config.ExternalProfileProvider definition,
        string? subject, bool self, IReadOnlyDictionary<string, string>? profile, NasAuth.Services.ResourceCatalog? catalog = null)
    {
        var name = profile?.GetValueOrDefault(definition.NameField) ?? "";
        if (string.IsNullOrWhiteSpace(name)) name = profile?.GetValueOrDefault(definition.UsernameField) ?? subject ?? "";
        var config = System.Text.Json.JsonSerializer.Serialize(new { provider, bridge = definition.BrowserLookupUrl,
            subject, self, name, localNetwork = definition.BrowserLookupNeedsLocalNetwork,
            subjectField = definition.SubjectField, nameField = definition.NameField, usernameField = definition.UsernameField, emailField = definition.EmailField,
            fields = definition.Fields.ToDictionary(x => x.Key, x => x.Value.Label),
            visible = definition.Fields.Where(x => x.Value.Visible && !x.Value.Detail).OrderBy(x => x.Value.Order).ThenBy(x => x.Key).Select(x => x.Key).ToArray() });
        var action = subject is null ? "/admin/directory/create" : self ? "/account/directory/import" : "/admin/directory/import";
        var query = self
            ? $"<input type='hidden' data-directory-query value='{Esc(name)}'><div class='directory-actions'><button type='button' class='btn' data-variant='outline' data-size='sm' data-directory-search>{T("Refresh profile")}</button>"
            : $"<div class='directory-search-row'><div class='field'><label>{T("Search people")}</label><input class='input' data-directory-query value='{Esc(name)}' maxlength='80' autocomplete='off' placeholder='{T("Search by part of a name or account")}'></div><button type='button' class='btn' data-directory-search>{T("Search")}</button></div><div class='directory-actions'>";
        return $"<div class='directory-widget{(self ? " identity-update" : "")}' data-directory='{Esc(config)}'>" + query +
            $"<a class='directory-login' data-directory-login hidden href='/external/{Esc(provider)}/start?return_url=%2Faccount'>{T("Sign in to identity provider")}</a></div>" +
            "<p class='hint directory-status' data-directory-status role='status'></p><div class='directory-results' data-directory-results></div>" +
            $"<form method='post' action='{action}' data-directory-save hidden><input type='hidden' name='provider' value='{Esc(provider)}'>" +
            $"<input type='hidden' name='subject' value='{Esc(subject ?? "")}'>" +
            "<input type='hidden' name='profile_json'><input type='hidden' name='return_url'>" +
            "<p data-directory-preview></p>" + (self || subject is null ? "" : $"<label class='check-line'><input type='checkbox' name='use_email' value='1'>{T("Use directory email as account email")}</label>") +
            (subject is null ? ApplicationChoices(catalog) : "") +
            $"<button class='btn' type='submit'>{T(subject is null ? "Create selected account" : "Save selected profile")}</button></form></div>";
    }

    private static string ProfileEditCard(UserAdminView u, IReadOnlyList<BindingView> bindings)
    {
        var sb = new StringBuilder();
        sb.Append("<form method='post' action='/account/profile'><div class='form-grid narrow'>");
        sb.Append($"<div class='field'><label for='display_name'>{T("Nickname")}</label><input id='display_name' name='display_name' maxlength='64' value='{Esc(u.DisplayName ?? "")}' placeholder='{Esc(u.Username)}' autocomplete='nickname'></div>");
        sb.Append($"</div><div class='form-foot'><button class='btn' type='submit'>{T("Save")}</button></div></form>");

        sb.Append($"<h3 class='subhead'>{T("Avatar")}</h3><div class='avatar-row'>{Avatar(u.AvatarFile, u.DisplayName ?? u.Username, "avatar-lg")}");
        sb.Append("<form method='post' action='/account/avatar' enctype='multipart/form-data' class='avatar-upload'>");
        sb.Append("<input class='input' type='file' name='avatar' accept='image/png,image/jpeg,image/webp' required>");
        sb.Append($"<button class='btn' data-variant='outline' type='submit'>{T("Upload")}</button></form>");
        if (!string.IsNullOrEmpty(u.AvatarFile))
            sb.Append($"<form method='post' action='/account/avatar/remove'><button class='btn' data-variant='ghost' type='submit'>{T("Remove")}</button></form>");
        sb.Append("</div>");

        var copyable = bindings.Where(b => !string.IsNullOrEmpty(b.AvatarFile) || !string.IsNullOrEmpty(b.DisplayName)).ToList();
        if (copyable.Count > 0)
        {
            sb.Append($"<h3 class='subhead'>{T("Use a linked account")}</h3><div class='table-container'><table class='table'><tbody>");
            foreach (var b in copyable)
            {
                sb.Append($"<tr><td class='fit'>{Avatar(b.AvatarFile, b.DisplayName ?? b.Provider, "avatar-sm")}</td>");
                sb.Append($"<td class='wrap'>{ProviderBadge(b.Provider)} {Esc(b.DisplayName ?? "-")}<span class='sub'>{Esc(b.Email ?? b.Subject)}</span></td><td class='fit actions'>");
                if (!string.IsNullOrEmpty(b.AvatarFile))
                    sb.Append(CopyFromIdentityForm(b, "avatar", T("Use this avatar")));
                if (!string.IsNullOrEmpty(b.DisplayName))
                    sb.Append(CopyFromIdentityForm(b, "name", T("Use this name")));
                sb.Append("</td></tr>");
            }
            sb.Append("</tbody></table></div>");
        }
        return Card(T("Nickname & avatar"),
            T("Connected apps can use your nickname and avatar. Each app determines when changes appear. Your username identifies your account and cannot be changed after creation."),
            sb.ToString());
    }

    private static string CopyFromIdentityForm(BindingView b, string field, string label) =>
        $"<form method='post' action='/account/profile/from-identity'>{Hidden("provider", b.Provider)}{Hidden("subject", b.Subject)}{Hidden("field", field)}" +
        $"<button class='btn' data-variant='outline' data-size='sm' type='submit'>{label}</button></form>";

    /// <summary>头像：有就是 /avatars/ 下的图片，没有就是名字首字母的圆。</summary>
    private static string Avatar(string? file, string name, string cls)
    {
        if (!string.IsNullOrEmpty(file))
            return $"<img class='avatar {cls}' src='/avatars/{Esc(file)}' alt=''>";
        var initial = string.IsNullOrEmpty(name) ? "?" : char.ToUpperInvariant(name.Trim()[0]).ToString();
        return $"<span class='avatar avatar-initial {cls}' aria-hidden='true'>{Esc(initial)}</span>";
    }

    public static string GrantsSection(IReadOnlyList<AccountAuthorizationView> rows) =>
        Card(T("Authorized applications"),
            T("OAuth grants issued for your account. Revoking deletes the refresh tokens; issued access tokens remain valid until they expire."),
            GrantsTable(rows, "/account/revoke", userId: null));

    public static string SecuritySection(IReadOnlyList<BindingView> bindings,
        bool googleEnabled, bool microsoftEnabled, bool passwordEnabled, IReadOnlyList<AuditView> recentLogins,
        IReadOnlyList<ExternalProviderChoice>? providerChoices = null)
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
        var providers = providerChoices ?? LegacyChoices(googleEnabled, microsoftEnabled);
        if (providers.Count > 0)
        {
            sb.Append("<div class='actions' style='margin-top:16px'>");
            // 绑定是写操作：用 POST 表单（受跨源写拦截保护），不再是任何站点都能诱导跳转的 GET 链接
            foreach (var provider in providers.Where(p => p.CanBind))
            {
                var icon = provider.Id switch { "google" => IconGoogle, "microsoft" => IconMicrosoft, _ => "" };
                sb.Append($"<form method='post' action='/external/{Esc(Uri.EscapeDataString(provider.Id))}/bind'><button class='btn' data-variant='outline' type='submit'>{icon}{T("Bind {0} account", Esc(provider.DisplayName))}</button></form>");
            }
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
        var sessions = $"<p><a class='btn' data-variant='outline' href='/account/sessions'>{T("Manage device sessions")}</a></p><form method='post' action='/account/sessions/revoke-others' {Confirm(T("Sign out of all other devices?"))}>" +
                       $"<button class='btn' data-variant='outline' type='submit'>{T("Sign out of all other devices")}</button></form>";
        html += Card(T("Sessions"),
            T("Review and revoke individual devices. Signing out other devices keeps this session and its linked credentials; older unlinked authorizations may require sign-in again."),
            sessions);

        html += Card(T("Recent sign-ins"), T("Includes failed attempts. Kept for 90 days."), LoginsTable(recentLogins));
        return html;
    }

    private static IReadOnlyList<ExternalProviderChoice> LegacyChoices(bool googleEnabled, bool microsoftEnabled)
    {
        var providers = new List<ExternalProviderChoice>();
        if (googleEnabled) providers.Add(new("google", "Google", "Google"));
        if (microsoftEnabled) providers.Add(new("microsoft", "Microsoft", "Microsoft"));
        return providers;
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
            s.FailedLogins24h > 0 ? $"<span class='stat-failure'>{T("{0} failed", s.FailedLogins24h)}</span>" : T("No failures"),
            "/admin/audit?type=login"));
        tiles.Append("</div>");

        var html = tiles.ToString();
        html += Card(T("Recent events"), null, AuditTable(recent, compact: true),
            action: $"<a class='btn' data-variant='outline' data-size='sm' href='/admin/audit'>{T("View all")}</a>");
        return html;
    }

    // ---- 用户：列表 + 新建；单个用户的全部操作在 UserEditSection ----
    public static string UsersSection(IReadOnlyList<UserAdminView> users, NasAuth.Config.ExternalProfilesOptions? profiles = null, bool externalSignInEnabled = true, NasAuth.Services.ResourceCatalog? catalog = null, UserDirectoryPage? directory = null)
    {
        var create = new StringBuilder("<form method='post' action='/admin/users/create'><div class='form-grid'>");
        create.Append($"<div class='field'><label for='new_username'>{T("Username")}</label><input type='text' id='new_username' name='username' required pattern='[a-zA-Z0-9._-]{{1,32}}' autocomplete='off' placeholder='{T("letters, digits, . _ -")}'></div>");
        create.Append($"<div class='field'><label for='new_temp_password'>{T("Password")}</label><input id='new_temp_password' name='temp_password' type='password' minlength='8' autocomplete='new-password' placeholder='{T("≥ 8 chars; only when password sign-in is allowed")}'></div>");
        create.Append($"<div class='field'><label for='new_email'>{T("Email")}</label><input type='email' id='new_email' name='email' autocomplete='off' placeholder='{T("sent to apps as the email claim")}'></div>");
        create.Append("</div>" + ApplicationChoices(catalog));
        create.Append(Hidden("allow_password_login", "1"));
        create.Append($"<label class='check-line'><input type='checkbox' name='credential_invite' value='1'>{T("Let the recipient set their password using an expiring invitation link (leave Password empty).")}</label>");
        create.Append($"<details class='advanced-resources'><summary>{T("Reuse a deleted username")}</summary><label class='check-line'><input type='checkbox' name='reuse_username' value='1'>{T("This is a different person. I have checked existing app bindings. Grant apps after creation.")}</label></details>");
        create.Append("<div class='form-foot'>");
        create.Append($"<label class='label' style='gap:8px'><input class='input' type='checkbox' role='switch' name='must_change_password' value='1'>{T("Must change password on first sign-in")}</label>");
        create.Append($"<span class='grow'></span><button class='btn' type='submit'>{T("Create")}</button>");
        create.Append("</div></form>");
        create.Append($"<p class='hint' style='margin-top:12px'>{T("Some connected apps use email to match existing accounts. Use a consistent email where required. Enable password sign-in only when this account needs it.")}</p>");

        var sb = new StringBuilder(UserDirectoryControls(directory));
        sb.Append($"<div class='table-container'><table class='table user-directory-table'><thead><tr><th>{T("Username")}</th><th>{T("Role")}</th><th>{T("Status")}</th><th>{T("Password sign-in")}</th><th>{T("Created")}</th><th></th></tr></thead><tbody>");
        foreach (var u in users)
        {
            sb.Append("<tr>");
            // §十九：头像 + 昵称；用户名（不可改）和邮箱放第二行
            sb.Append($"<td class='wrap'><div class='user-cell'>{Avatar(u.AvatarFile, u.DisplayName ?? u.Username, "avatar-sm")}<div>");
            sb.Append($"<a href='{Esc(EditHref(u.UserId))}'><strong>{Esc(u.DisplayName ?? u.Username)}</strong></a>");
            if (u.IsSelf) sb.Append($" <span class='badge' data-variant='secondary'>{T("you")}</span>");
            sb.Append($"<span class='sub'><span class='mono'>{Esc(u.Username)}</span> · {(string.IsNullOrEmpty(u.Email) ? "—" : Esc(u.Email))}</span></div></div></td>");
            sb.Append($"<td>{RoleBadge(u)}</td>");
            sb.Append($"<td>{StatusBadges(u)}</td>");
            sb.Append($"<td>{(u.AllowPasswordLogin ? T("Allowed") : $"<span class='hint'>{T("Off")}</span>")}</td>");
            sb.Append($"<td>{Esc(u.CreatedAtDisplay)}</td>");
            sb.Append($"<td class='fit'><a class='btn' data-variant='outline' data-size='sm' href='{Esc(EditHref(u.UserId))}'>{T("Manage")}</a></td>");
            sb.Append("</tr>");
        }
        if (users.Count == 0) sb.Append("<tr><td colspan='6'>" + Empty(T("No matching accounts")) + "</td></tr>");
        sb.Append("</tbody></table></div>" + UserDirectoryFooter(directory));

        var external = new StringBuilder();
        foreach (var (id, provider) in profiles?.Providers ?? new Dictionary<string, NasAuth.Config.ExternalProfileProvider>())
            if (provider.AllowAdminCreate && provider.BrowserLookupUrl.Length > 0)
                external.Append(DirectoryWidget(id, provider, null, false, null, catalog));
        if (external.Length == 0)
            external.Append($"<form method='post' action='/admin/users/create'><input type='hidden' name='invite_by_email' value='1'><div class='field'><label>{T("Email")}</label><input class='input' type='email' name='email' required autocomplete='off'></div><p class='hint'>{T("The first verified external sign-in will bind this account. No password is created.")}</p>" + ApplicationChoices(catalog) + $"<button class='btn'>{T("Create external account")}</button></form>");
        return UserLifecycleNavigation("active", directory) + Card(T("Users"), null, sb.ToString()) + (externalSignInEnabled ? Card(T("Create external account"), null, external.ToString()) : "") +
            $"<details class='card account-create'{(externalSignInEnabled ? "" : " open")}><summary><span class='account-create-heading'><span class='account-create-title'>{T("Create password account")}</span><span class='hint'>{T("For accounts that sign in with a username and password")}</span></span><span class='account-create-chevron' aria-hidden='true'></span></summary>" +
            $"<div class='account-create-body'><p class='hint'>{T("Choose a password, or use an invitation link so the recipient can set one.")}</p>" + create.ToString() + "</div></details>";
    }

    private static string ApplicationChoices(NasAuth.Services.ResourceCatalog? catalog)
    {
        var resources = catalog?.All.Where(r => r.AllowsUser(false)).Select(r => new UserResourceEditView(
            r.Aud, r.DisplayName, r.Scopes, [], ApplicationId: r.App?.Id, ApplicationName: r.App?.Name)).ToList();
        return resources is { Count: > 0 }
            ? $"<details class='advanced-resources'><summary>{T("Application access")}</summary>{AccessFields(resources)}</details>"
            : "";
    }

    private static string AccessFields(IReadOnlyList<UserResourceEditView> resources, UserDetailView? detail = null)
    {
        var body = new StringBuilder("<div class='res-grid'>");
        foreach (var application in resources.GroupBy(r => (r.ApplicationId ?? "resource:" + r.Aud, r.ApplicationName ?? r.DisplayName)))
        {
            body.Append($"<fieldset class='group-box'><legend>{Esc(application.Key.Item2)}</legend>");
            foreach (var resource in application)
            {
                var locked = resource.AdminOnly && detail?.User.IsAdmin != true;
                foreach (var scope in resource.AllScopes)
                {
                    var direct = !locked && resource.GrantedScopes.Contains(scope);
                    var inherited = !locked && detail?.GrantSources?.Any(g => g.Aud == resource.Aud &&
                        g.GroupId is not null && g.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains(scope)) == true;
                    var label = resource.AllScopes.Count == 1 ? resource.DisplayName : $"{resource.DisplayName} · {scope}";
                    body.Append($"<label class='check-line'><input type='checkbox' name='scope:{Esc(resource.Aud)}' value='{Esc(scope)}'{(direct ? " checked" : "")}{(locked ? " disabled" : "")}>{Esc(label)}{AdminOnlyBadge(resource)}{(inherited ? $" <span class='hint'>{T("Granted by group")}</span>" : "")}</label>");
                }
            }
            body.Append("</fieldset>");
        }
        return body.Append("</div>").ToString();
    }

    public static string ProvisioningSection(string userId, NasAuth.Config.ProvisioningOptions options, IReadOnlyList<NasAuth.Services.ProvisioningStatus> statuses,
        IReadOnlyList<UserResourceEditView>? resources=null,bool isAdmin=false)
    {
        if (options.Applications.Count == 0) return "";
        var body = new StringBuilder("<div class='table-container'><table class='table'><thead><tr><th>" + T("Application") + "</th><th>" + T("Access") + "</th><th>" + T("Account sync") + "</th></tr></thead><tbody>");
        var visible = 0;
        foreach (var (id, app) in options.Applications)
        {
            var row = statuses.SingleOrDefault(x => x.application_id == id);
            var granted=resources is null ? row is {enabled:1} : app.RequiredResources.All(x=>resources.Any(r=>r.Aud==x.Key && (!r.AdminOnly || isAdmin) && x.Value.All(r.GrantedScopes.Contains)));
            if (!granted && row is null) continue;
            visible++;
            var state = row is null ? T("Not synchronized") : T(row.state == "synced" ? "Synchronized" : row.state == "failed" ? "Retry scheduled" : "Pending synchronization");
            var stale=row is not null && granted!=(row.enabled==1);
            if(stale)state=T("Pending synchronization");
            body.Append($"<tr><td>{Esc(app.Name)}</td><td>{T(granted ? "Granted" : "Not granted")}</td><td>{state}");
            if (!stale && row?.error_code is { } code)
            {
                body.Append($"<span class='sub mono'>{Esc(code)}</span>");
                if(code.EndsWith(":manual_resume_required",StringComparison.Ordinal))
                    body.Append("<span class='sub'>"+T("This app retains a local account hold. An app administrator must resume the account, then retry synchronization.")+"</span>");
                else if(code.EndsWith(":email_required",StringComparison.Ordinal))
                    body.Append("<span class='sub'>"+T("Set a valid account email, then retry synchronization.")+"</span>");
                else if(code.EndsWith(":identity_conflict",StringComparison.Ordinal))
                    body.Append("<span class='sub'>"+T("An existing account conflicts with this identity. Review the binding in the app; accounts are never merged by email.")+"</span>");
            }
            body.Append("</td></tr>");
        }
        if (visible == 0) return "";
        body.Append("</tbody></table></div><p class='hint'>" + T("Account synchronization runs in the background. Manage roles and data permissions in the app.") + "</p>");
        body.Append($"<form method='post' action='/admin/users/provisioning/retry'>{Hidden("user_id", userId)}<button class='btn' data-variant='outline'>{T("Synchronize / retry")}</button></form>");
        return Card(T("Account sync"), T("Account creation and access changes are delivered in the background; failures are retried automatically."), body.ToString());
    }

    private static string UserLifecycleNavigation(string selected, UserDirectoryPage? directory = null) =>
        "<nav class='page-actions lifecycle-nav' aria-label='" + T("Account status") + "'>" +
        string.Join("",new[]{("active","Active accounts"),("disabled","Disabled accounts"),("deleted","Deleted identities")}.Select(x=>
            $"<a class='btn' data-variant='{(selected==x.Item1?"secondary":"ghost")}'{(selected==x.Item1?" aria-current='page'":"")} href='{Esc(DirectoryHref(directory?.Filter ?? UserDirectoryFilter.Normalize(), view:x.Item1))}'>{T(x.Item2)}" +
            (directory is null ? "" : $"<span class='user-state-count'>{(x.Item1=="active"?directory.ActiveCount:x.Item1=="disabled"?directory.DisabledCount:directory.DeletedCount)}</span>") + "</a>"))+"</nav>";

    private static string DirectoryHref(UserDirectoryFilter filter, int page = 1, string? view = null)
    {
        var f = UserDirectoryFilter.Normalize(filter.Query, view ?? filter.View, filter.Role, page, filter.PageSize);
        return "/admin/users?view=" + f.View + "&q=" + Uri.EscapeDataString(f.Query) + "&role=" + f.Role + "&size=" + f.PageSize + "&page=" + f.Page;
    }

    private static string UserDirectoryControls(UserDirectoryPage? directory)
    {
        if (directory is null) return "";
        var f = directory.Filter;
        string Option(string value, string label, string selected) => $"<option value='{value}'{(value==selected?" selected":"")}>{label}</option>";
        var body = new StringBuilder("<form method='get' action='/admin/users' class='user-filter' role='search'>" + Hidden("view", f.View));
        body.Append($"<div class='field user-filter-query'><label for='user_search'>{T("Find accounts")}</label><input id='user_search' type='search' name='q' maxlength='128' value='{Esc(f.Query)}' placeholder='{T(f.View=="deleted"?"Search by original account ID":"Name, username or email")}'></div>");
        if (f.View == "active")
            body.Append($"<div class='field'><label for='user_role'>{T("Role")}</label><select id='user_role' name='role'>" + Option("all",T("All roles"),f.Role) + Option("admin",T("Administrators"),f.Role) + Option("member",T("User"),f.Role) + "</select></div>");
        body.Append($"<div class='field'><label for='user_size'>{T("Rows per page")}</label><select id='user_size' name='size'>" + string.Join("",new[]{25,50,100}.Select(n=>Option(n.ToString(),n.ToString(),f.PageSize.ToString()))) + "</select></div>");
        body.Append($"<div class='user-filter-actions'><button class='btn' type='submit'>{T("Search")}</button>");
        if (f.Query.Length > 0 || f.Role != "all") body.Append($"<a class='btn' data-variant='ghost' href='{Esc(DirectoryHref(f with {Query="",Role="all"}))}'>{T("Clear filters")}</a>");
        return body.Append("</div></form>").ToString();
    }

    private static string UserDirectoryFooter(UserDirectoryPage? directory)
    {
        if (directory is null) return "";
        var f = directory.Filter;
        var body = new StringBuilder("<div class='user-list-footer'><p class='hint' role='status'>" + T("Showing {0}–{1} of {2}",directory.First,directory.Last,directory.Total) + "</p>");
        if (directory.PageCount > 1)
        {
            body.Append($"<nav class='user-pagination' aria-label='{T("User list pages")}'>");
            if (f.Page > 1) body.Append($"<a class='btn' data-variant='outline' data-size='sm' rel='prev' href='{Esc(DirectoryHref(f,f.Page-1))}'>{T("Previous page")}</a>");
            body.Append($"<span class='hint'>{T("Page {0} of {1}",f.Page,directory.PageCount)}</span>");
            if (f.Page < directory.PageCount) body.Append($"<a class='btn' data-variant='outline' data-size='sm' rel='next' href='{Esc(DirectoryHref(f,f.Page+1))}'>{T("Next page")}</a>");
            body.Append("</nav>");
        }
        return body.Append("</div>").ToString();
    }

    public static string InactiveUsersSection(string view,IReadOnlyList<NasAuth.Data.UserRow> disabled,IReadOnlyList<string> deleted, UserDirectoryPage? directory = null)
    {
        var sb=new StringBuilder("<div class='table-container'><table class='table user-directory-table inactive'><thead><tr><th>"+T("Username")+"</th><th>"+T("Status")+"</th><th></th></tr></thead><tbody>");
        var ids=view=="disabled"?disabled.Select(x=>x.user_id):deleted;
        foreach(var id in ids)
        {
            var row = view == "disabled" ? disabled.First(x=>x.user_id==id) : null;
            var profile = row is null ? $"<span class='mono'>{Esc(id)}</span>" : $"<strong>{Esc(row.display_name ?? row.username)}</strong><span class='sub'>{Esc(row.username)} · {Esc(row.email ?? "—")}</span>";
            sb.Append($"<tr><td>{profile}</td><td><span class='badge' data-variant='outline'>{T(view=="disabled"?"Disabled":"Deleted identity")}</span></td><td class='fit'><a class='btn' data-variant='outline' data-size='sm' href='/admin/users/restore?user={Uri.EscapeDataString(id)}'>{T("Restore original identity")}</a>");
            if(view=="disabled") sb.Append($"<form method='post' action='/admin/users/delete' class='lifecycle-delete' {Confirm(T("Permanently delete {0}? The identity remains reserved.",id))}>{Hidden("user_id",id)}<button class='btn' data-variant='ghost' data-size='sm'>{T("Permanently delete")}</button></form>");
            sb.Append("</td></tr>");
        }
        sb.Append("</tbody></table></div>");
        return UserLifecycleNavigation(view, directory)+Card(T(view=="disabled"?"Disabled accounts":"Deleted identities"),
            T("Restore only the same person. A restored identity may reconnect to their existing application accounts. Application access must be granted again."),
            UserDirectoryControls(directory) + (ids.Any()?sb.ToString():Empty(T(directory is null?"No accounts in this state":"No matching accounts"))) + UserDirectoryFooter(directory));
    }

    public static string RestoreIdentitySection(string id,bool deleted)
    {
        var sb=new StringBuilder($"<form method='post' action='/admin/users/restore'>{Hidden("user_id",id)}{Hidden("deleted",deleted?"1":"0")}");
        sb.Append($"<div class='restore-identity'><span class='hint'>{T("Original account ID")}</span><strong class='mono'>{Esc(id)}</strong></div>");
        sb.Append($"<div class='form-grid narrow'><div class='field'><label for='restore_password'>{T("New password")}</label><input id='restore_password' name='new_password' type='password' minlength='8' autocomplete='new-password'></div>");
        if(deleted) sb.Append($"<div class='field'><label for='restore_email'>{T("Email")}</label><input id='restore_email' name='email' type='email' autocomplete='off'></div>");
        sb.Append($"</div><div class='restore-confirmations'><label class='check-line'><input type='checkbox' name='allow_password_login' value='1'>{T("Enable new password sign-in")}</label><label class='check-line'><input type='checkbox' name='acknowledge' value='1' required>{T("I confirm this restores the same person, not a new owner of this username")}</label></div>");
        sb.Append($"<div class='form-foot'><a class='btn' data-variant='ghost' href='/admin/users?view={(deleted?"deleted":"disabled")}'>{T("Cancel")}</a><button class='btn'>{T("Restore original identity")}</button></div></form>");
        return Card(T("Restore original identity"),T("Restoring keeps the original ID and may reconnect existing application accounts. Old passwords, sessions, administrator roles and application grants are not restored. Existing external bindings are kept only for disabled accounts; otherwise bind them again after restoring."),sb.ToString());
    }

    // ---- 单个用户：资料 / 资源授权 / 外部身份 / 已授权应用 / 会话 / 重置密码 / 删除 ----
    public static string UserEditSection(UserDetailView d,NasAuth.Config.ProvisioningOptions? provisioning=null,
        IReadOnlyList<NasAuth.Services.ProvisioningStatus>? provisioningStatuses=null, string? credentialSection=null, string? deviceSection=null)
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
        profile.Append($"<div class='avatar-row'>{Avatar(u.AvatarFile, u.DisplayName ?? u.Username, "avatar-lg")}");
        profile.Append($"<form method='post' action='/admin/users/avatar' enctype='multipart/form-data' class='avatar-upload'>{uid}");
        profile.Append("<input class='input' type='file' name='avatar' accept='image/png,image/jpeg,image/webp' required>");
        profile.Append($"<button class='btn' data-variant='outline' type='submit'>{T("Upload avatar")}</button></form>");
        if (!string.IsNullOrEmpty(u.AvatarFile))
            profile.Append($"<form method='post' action='/admin/users/avatar/remove'>{uid}<button class='btn' data-variant='ghost' type='submit'>{T("Remove")}</button></form>");
        profile.Append("</div>");
        profile.Append($"<form method='post' action='/admin/users/update'>{uid}");
        profile.Append("<div class='form-grid narrow'>");
        profile.Append($"<div class='field'><label for='display_name'>{T("Nickname")}</label><input id='display_name' name='display_name' maxlength='64' value='{Esc(u.DisplayName ?? "")}' placeholder='{Esc(u.Username)}' autocomplete='off'></div>");
        profile.Append($"<div class='field'><label for='email'>{T("Email")}</label><input type='email' id='email' name='email' value='{Esc(u.Email)}' autocomplete='off' placeholder='{T("sent to apps as the email claim")}'></div>");
        profile.Append("</div><div class='form-foot'>");
        profile.Append($"<label class='label' style='gap:8px'><input class='input' type='checkbox' role='switch' name='allow_password_login' value='1'{(u.AllowPasswordLogin ? " checked" : "")}>{T("Allow password sign-in")}</label>");
        profile.Append($"<button class='btn' type='submit'>{T("Save")}</button>");
        profile.Append("</div></form>");
        html.Append(Card(T("Profile"),
            T("Some connected apps use email to match existing accounts. Use a consistent email where required. Enable password sign-in only when this account needs it."),
            profile.ToString()));

        var role = new StringBuilder($"<div class='admin-role-row'><div class='admin-role-status'><span class='hint'>{T("Role")}</span>{RoleBadge(u)}</div>");
        if (!u.IsSelf)
            role.Append($"<form method='post' action='/admin/users/administrator' {Confirm(T("Change administrator role for {0}?", u.Username))}>{uid}{Hidden("is_admin", u.IsAdmin ? "0" : "1")}<button class='btn' data-variant='outline' type='submit'>{T(u.IsAdmin ? "Remove administrator" : "Make administrator")}</button></form>");
        else
            role.Append($"<p class='hint'>{T("You cannot remove your own administrator role")}</p>");
        role.Append("</div>");
        html.Append(Card(T("Administrator access"), T("Administrators can manage users, identity providers and application access. Application permissions remain separate."), role.ToString()));
        html.Append(ExternalProfilesSection(d.Bindings));
        // 资源授权（checkbox）
        var res = $"<form method='post' action='/admin/users/resources'>{uid}{AccessFields(d.Resources, d)}<div class='form-foot'><button class='btn' type='submit'>{T("Save grants")}</button></div></form>";
        html.Append(Card(T("Application access"),
            T("Edit this user's direct grants. Access from their groups still applies. Resources marked \"admins only\" can only be granted to administrators."), res));
        if (provisioning is { Applications.Count: > 0 } && provisioningStatuses is not null)
        {
            var effective = d.Resources.Select(r => r with { GrantedScopes = EffectiveScopes(d, r) }).ToList();
            html.Append(ProvisioningSection(u.UserId, provisioning, provisioningStatuses, effective, u.IsAdmin));
        }
        if (d.GrantSources is not null) html.Append(UserGrantSourcesSection(d));

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

        // 预绑定邮箱（§十八）：首次用 Google 登录、且 Google 验证过这个邮箱的人直接绑到本用户，不进待批
        ids.Append($"<h3 class='subhead'>{T("Pending first bindings")}</h3>");
        if (d.Invites is { Count: > 0 } invites)
        {
            ids.Append($"<div class='table-container'><table class='table'><thead><tr><th>{T("Email")}</th><th>{T("Added")}</th><th></th></tr></thead><tbody>");
            foreach (var i in invites)
            {
                ids.Append($"<tr><td class='wrap mono'>{Esc(i.Email)}</td><td>{Esc(i.CreatedAtDisplay)}</td>");
                ids.Append($"<td class='fit'><form method='post' action='/admin/users/invites/delete'>{uid}{Hidden("email", i.Email)}");
                ids.Append($"<button class='btn' data-variant='outline' data-size='sm' type='submit'>{T("Remove")}</button></form></td></tr>");
            }
            ids.Append("</tbody></table></div>");
        }
        ids.Append($"<form method='post' action='/admin/users/invites/add' class='form-foot'>{uid}");
        ids.Append(Hidden("email", u.Email ?? ""));
        ids.Append($"<button class='btn' data-variant='outline' type='submit'{(string.IsNullOrEmpty(u.Email) ? " disabled" : "")}>{T("Enable first binding for account email")}</button></form>");
        html.Append(Card(T("External identities"),
            T("Pre-bound email: the first time someone signs in with this email, that account is bound to this user directly without going through approvals. Used once, then removed. Requires the provider to vouch for the email: Google must report it as verified; for a personal Microsoft account it must be the sign-in name. Otherwise it still goes to approvals."),
            ids.ToString()));

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
            T("Signing out ends all Auth device sessions and their linked credentials. Application-owned sessions follow the application's own logout rules."),
            sess.ToString()));

        if (deviceSection is not null) html.Append(deviceSection);
        if (credentialSection is not null) html.Append(credentialSection);
        if (!u.IsSelf)
            html.Append(Card(T("Disable account"),T("Stop sign-in and revoke sessions. Keep identity and profile for recovery; restore application access explicitly later."),
                $"<form method='post' action='/admin/users/disable' {Confirm(T("Disable {0}? They will be signed out.",u.Username))}>{uid}<button class='btn' data-variant='outline'>{T("Disable account")}</button></form>"));

        // 重置密码 / 删除：不对自己、不对管理员
        if (!u.IsSelf && !u.IsAdmin)
        {
            var reset = new StringBuilder($"<form method='post' action='/admin/users/reset-password'>{uid}");
            reset.Append($"<div class='form-grid narrow'><div class='field'><label for='temp_password'>{T("New password")}</label><input id='temp_password' name='temp_password' type='password' required minlength='8' placeholder='{T("≥ 8 chars")}' autocomplete='off'></div></div>");
            reset.Append($"<div class='form-foot'><label class='label' style='gap:8px'><input class='input' type='checkbox' role='switch' name='must_change_password' value='1'>{T("Must change password on first sign-in")}</label><span class='grow'></span><button class='btn' data-variant='outline' type='submit'>{T("Reset password")}</button></div>");
            reset.Append("</form>");
            html.Append(Card(T("Reset password"), T("Set a new password and tell them. Their current sessions end immediately."), reset.ToString()));

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
    private static string CapabilityLabel(ResourceAdminView r) => r.App?.Capability switch
    {
        "web" => T("Web sign-in"),
        "mcp" => T("MCP access"),
        "gateway" => T("Protected entry"),
        _ => r.IsForwardAuth ? T("Protected entry") : T("API access")
    };

    public static string AppsSection(IReadOnlyList<ResourceAdminView> resources, IReadOnlyList<ClientAdminView> clients, string? view = null)
    {
        view = view is "clients" or "resources" ? view : "apps";
        var nav = new StringBuilder($"<nav class='app-tabs' aria-label='{T("Application views")}'>");
        foreach (var (key, label) in new[] { ("apps", "Connected apps"), ("clients", "OAuth clients"), ("resources", "Technical details") })
            nav.Append($"<a href='/admin/apps?view={key}'{(view == key ? " aria-current='page'" : "")}>{Esc(Label("apps-" + key, label))}</a>");
        nav.Append($"<a href='/admin/apps/new'>{T("Connect an application")}</a></nav>");
        var overview = new StringBuilder();
        if (resources.Count == 0) overview.Append(Empty(T("No resources.")));
        else
        {
            overview.Append("<div class='application-list'>");
            foreach (var group in resources.GroupBy(r => r.App is null ? "resource:" + r.Aud : "app:" + r.App.Id))
            {
                var first = group.First();
                overview.Append($"<details class='application-row'><summary><span class='application-name'><strong>{Esc(first.App?.Name ?? first.DisplayName)}</strong>");
                if (!string.IsNullOrEmpty(first.App?.Description))
                    overview.Append($"<span class='sub'>{Esc(first.App.Description)}</span>");
                overview.Append("</span><span class='application-capabilities'>");
                foreach (var r in group)
                    overview.Append($"<span class='capability-summary'><span class='badge' data-variant='secondary'>{CapabilityLabel(r)}</span><span>{T("{0} users", r.UserCount)}</span></span>");
                overview.Append($"</span><span class='application-disclosure'>{T("Details")}</span></summary><div class='application-details'>");
                foreach (var r in group)
                {
                    overview.Append($"<section class='capability-detail'><h3>{CapabilityLabel(r)} <span class='hint'>{Esc(r.DisplayName)}</span></h3>");
                    if (r.AdminOnly) overview.Append($"<p class='hint'>{T("Administrators only")}</p>");
                    overview.Append($"<dl class='kv'><dt>{T("Authorized users")}</dt><dd>");
                    if (r.GrantedUserIds is { Count: > 0 })
                        foreach (var id in r.GrantedUserIds) overview.Append($"<a href='{Esc(EditHref(id))}'>{Esc(id)}</a> ");
                    else overview.Append(r.UserCount == 0 ? T("No users granted") : r.UserCount.ToString());
                    overview.Append($"</dd><dt>{T("Resource")}</dt><dd class='mono'>{Esc(r.Aud)}</dd><dt>{T("Address")}</dt><dd>{Esc(r.ResourceUrl)}</dd><dt>{T("Scopes")}</dt><dd>");
                    foreach (var s in r.Scopes) overview.Append($"<span class='badge mono' data-variant='outline'>{Esc(s)}</span> ");
                    overview.Append($"</dd><dt>{T("Mode")}</dt><dd>{(r.IsForwardAuth ? T("Forward-auth (site gate)") : r.IsProxy ? T("Proxy (token translation)") : T("Direct JWT"))}</dd>");
                    if (!r.IsForwardAuth)
                        overview.Append($"<dt>{T("Active grants")}</dt><dd>{r.ActiveGrants} <span class='hint'>{T("Refresh-token grants, not online users.")}</span></dd>");
                    var linked = clients.Where(c => !c.AutoRegistered && c.DefaultResource?.TrimEnd('/') == r.ResourceUrl.TrimEnd('/')).ToList();
                    if (linked.Count > 0)
                    {
                        overview.Append($"<dt>{T("OIDC clients")}</dt><dd>");
                        foreach (var c in linked) overview.Append($"<span>{Esc(c.ClientName)} <span class='mono hint'>{Esc(c.ClientId)}</span></span>");
                        overview.Append("</dd>");
                    }
                    overview.Append($"</dl><a class='btn' data-variant='outline' data-size='sm' href='/admin/apps/diagnostics?aud={Uri.EscapeDataString(r.Aud)}'>{T("Check configuration and access")}</a></section>");
                }
                overview.Append($"<p class='hint application-source'>{T("Read-only configuration: resources.json; preset clients: clients.preset.json. Edit the files and restart. Manage user access under Users.")}</p></div></details>");
            }
            overview.Append("</div>");
        }
        var html = Card(T("Connected apps"), T("Apps and their sign-in or access capabilities. User counts are shown separately for each capability."), overview.ToString());

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
                rs.Append($"</td><td>{(r.IsForwardAuth ? T("Forward-auth (site gate)") : r.IsProxy ? T("Proxy (token translation)") : T("Direct JWT"))}</td>");
                rs.Append($"<td>{r.UserCount}</td><td>{r.ActiveGrants}</td></tr>");
            }
            rs.Append("</tbody></table></div>");
        }
        var resourceTable = Card(T("Resource catalog"), T("From resources.json (read-only; edit the file and restart to change). Users = accounts granted this resource under Users → Resource grants."), rs.ToString());

        var sb = new StringBuilder();
        if (clients.Count == 0)
            sb.Append(Empty(T("No clients.")));
        else
        {
            sb.Append($"<div class='table-container'><table class='table'><thead><tr><th>{T("Client")}</th><th>{T("Type")}</th><th>{T("Auth method")}</th><th>{T("Redirect URIs")}</th><th>{T("Active grants")}</th><th>{T("Last used")}</th><th></th></tr></thead><tbody>");
            foreach (var c in clients)
            {
                sb.Append("<tr>");
                sb.Append($"<td class='wrap'>{Esc(ClientDisplayName(c.ClientName))}<span class='sub'>{Esc(c.ClientId)}</span>");
                if (c.ExtraClaimNames is { Count: > 0 })
                    sb.Append($"<span class='sub'>{T("extra claims")}: {Esc(string.Join(", ", c.ExtraClaimNames))}</span>");
                sb.Append("</td>");
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
        var clientTable = Card(T("OAuth clients"),
            T("Preset clients come from clients.preset.json; DCR ones registered themselves (e.g. Claude, Grok). DCR clients unused for 30 days with no live grants are cleaned up automatically; delete one here to cut it off now."),
            sb.ToString());
        return nav + (view == "clients" ? clientTable : view == "resources" ? resourceTable : html);
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
            .Append(Opt("register", T("Client registration"))).Append(Opt("proxy", T("Proxy denied")))
            .Append(Opt("forward_auth", T("Site access")));
        form.Append("</select></div>");
        form.Append($"<div class='field'><label for='user'>{T("User")}</label><input type='text' id='user' name='user' value='{Esc(f.User)}' placeholder='user_id'></div>");
        form.Append($"<div class='filter-actions'><label class='label filter-failures'><input class='input' type='checkbox' name='failed' value='1'{(f.FailedOnly ? " checked" : "")}>{T("Failures only")}</label>");
        form.Append($"<button class='btn' type='submit'>{T("Filter")}</button>");
        form.Append($"<a class='btn' data-variant='ghost' href='/admin/audit'>{T("Reset")}</a></div>");
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
            var lifetime = jwt.AccessTokenLifetimeMinutes is { } minutes ? T("{0} minutes", minutes) : T("{0} days", jwt.AccessTokenLifetimeDays);
            key.Append($"<p class='hint' style='margin-top:6px'>{T("Current access-token lifetime: {0}. Keep previous keys until all tokens signed with them have expired, including tokens issued under an earlier, longer lifetime.", lifetime)}</p>");
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
public record JwtKeyView(bool Rs256, bool LegacyHs256Keys, int AccessTokenLifetimeDays, string? LegacyHs256NotAfter = null, int? AccessTokenLifetimeMinutes = null);

public record BindingView(
    string Provider,
    string Subject,
    string? Email,
    string? DisplayName,
    string BoundAtDisplay,
    string? AvatarFile = null,
    IReadOnlyDictionary<string, string>? Profile = null,
    string? ProfileUpdatedAt = null,
    NasAuth.Config.ExternalProfileProvider? ProfileDefinition = null
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
    bool AdminOnly = false,
    string? ApplicationId = null,
    string? ApplicationName = null
);

public record ClientAdminView(
    string ClientId,
    string ClientName,
    bool AutoRegistered,
    string TokenEndpointAuthMethod,
    IReadOnlyList<string> RedirectUris,
    string CreatedAtDisplay,
    string LastUsedDisplay,
    int ActiveGrants = 0,
    IReadOnlyList<string>? ExtraClaimNames = null,
    string? DefaultResource = null
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
    IReadOnlyList<AuditView> RecentLogins,
    IReadOnlyList<InviteView>? Invites = null,
    IReadOnlyList<NasAuth.Services.AccessGroup>? Groups = null,
    IReadOnlyList<NasAuth.Services.GroupGrantSource>? GrantSources = null
);

public record InviteView(string Email, string CreatedAtDisplay);

public record AdminStats(int Users, int Admins, int Pending, int ActiveGrants,
    int PresetClients, int DcrClients, int Logins24h, int FailedLogins24h);

public record AuditView(string TimeDisplay, string Event, bool Success,
    string? UserId, string? ClientId, string? Ip, string? Detail);

public record AuditFilter(string Type, string User, bool FailedOnly);

public record ResourceAdminView(string Aud, string DisplayName, string ResourceUrl,
    IReadOnlyList<string> Scopes, bool IsProxy, int UserCount, int ActiveGrants, bool IsForwardAuth = false,
    ResourceAppConfig? App = null, bool AdminOnly = false, IReadOnlyList<string>? GrantedUserIds = null);
