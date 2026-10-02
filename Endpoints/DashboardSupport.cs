using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Pages;
using NasAuth.Services;
using static NasAuth.Pages.I18n;

namespace NasAuth.Endpoints;

/// <summary>个人中心（AccountEndpoints）与管理后台（AdminEndpoints）共用的渲染与查询辅助。</summary>
public static class DashboardSupport
{
    // 用户名字符集：字母 / 数字 / . _ -，长度 1-32。
    // 跟 user_id 同源（创建时直接拿 username 当 user_id），所以也卡死了 user_id 的字符集。
    public static readonly Regex UsernamePattern = new(@"^[a-zA-Z0-9._-]{1,32}$", RegexOptions.Compiled);

    /// <summary>审计里算「登录」的事件。</summary>
    public static readonly string[] LoginEvents = { "login", "external_login" };

    public static (string UserId, UserRow? Me) WhoAmI(HttpContext ctx, UserRepository users)
    {
        var userId = ctx.User.Identity?.Name ?? "";
        return (userId, string.IsNullOrEmpty(userId) ? null : users.GetById(userId));
    }

    public static bool IsAdmin(UserRow? u) => u is not null && u.is_admin != 0;

    /// <summary>
    /// 渲染后台页：菜单可见性由 is_admin 实时查库决定（SSR，非 admin 的 HTML 不出现管理项）；
    /// admin 才查 pending 数量给角标。
    /// </summary>
    public static IResult Render(HttpContext ctx, UserRepository users, ExternalIdentityRepository identities,
        DashboardSpace space, string activeKey, string title, string content)
    {
        var (userId, me) = WhoAmI(ctx, users);
        var isAdmin = IsAdmin(me);
        var pendingCount = isAdmin ? identities.ListPending().Count : 0;
        return Results.Content(
            DashboardTemplates.Shell(space, activeKey, me?.username ?? userId, isAdmin, pendingCount, title, content,
                notice: ReadFlash(ctx, "notice"),
                error: ReadFlash(ctx, "error"),
                displayName: me?.display_name,
                avatarFile: me?.avatar),
            "text/html; charset=utf-8");
    }

    /// <summary>
    /// 登录成功后的落点：没指定去处（默认 /account）的管理员落到管理后台概览。
    /// 入参可能来自表单 / OAuth state，先过 <see cref="ReturnUrl.SafeLocal"/>，站外地址一律回落 /account（防开放跳转）。
    /// </summary>
    public static string LandingFor(string? returnUrl, UserRow user)
    {
        var target = ReturnUrl.SafeLocal(returnUrl);
        return target == ReturnUrl.DefaultTarget && user.is_admin != 0 ? "/admin" : target;
    }

    public static List<UserAdminView> UserViews(UserRepository users, string selfId) =>
        users.ListAll().Select(u => UserView(u, selfId)).ToList();

    public static UserAdminView UserView(UserRow u, string selfId) => new(
        UserId: u.user_id,
        Username: u.username,
        IsAdmin: u.is_admin != 0,
        MustChangePassword: u.must_change_password != 0,
        IsSelf: u.user_id == selfId,
        CreatedAtDisplay: TimeDisplay(u.created_at),
        Email: u.email,
        AllowPasswordLogin: u.allow_password_login != 0,
        LockedUntilDisplay: u.locked_until is { } lu && lu > DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            ? TimeDisplay(lu) : null,
        DisplayName: u.display_name,
        AvatarFile: u.avatar);

    /// <summary>某用户的已授权应用：按 (client, resource) 聚合其有效 refresh token。</summary>
    public static List<AccountAuthorizationView> GrantViews(string userId,
        RefreshTokenRepository refreshTokens, ClientRepository clients, ResourceCatalog catalog) =>
        refreshTokens.ListActiveByUser(userId)
            .GroupBy(r => (r.client_id, r.resource))
            .Select(g =>
            {
                var first = g.First();
                var client = clients.GetById(first.client_id);
                // 多 aud 授权（§十三，Grok 等）的 resource 列是空格分隔的多个 URL，逐个查显示名
                var resourceNames = first.resource.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .Select(u => catalog.FindByUrl(u)?.DisplayName ?? u);
                var scopes = g.SelectMany(r => r.scope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                    .Distinct()
                    .ToList();
                var lastUsed = g.Max(r => r.last_used_at ?? r.created_at);
                return new AccountAuthorizationView(
                    ClientId: first.client_id,
                    ClientName: client?.client_name ?? "(deleted)",
                    ResourceUrl: first.resource,
                    ResourceDisplay: string.Join(" · ", resourceNames),
                    Scopes: scopes,
                    LastUsedDisplay: TimeDisplay(lastUsed));
            })
            .ToList();

    public static List<BindingView> BindingViews(string userId, ExternalIdentityRepository identities) =>
        identities.ListByUser(userId)
            .Where(r => r.status == "active")
            .Select(r => new BindingView(r.provider, r.subject, r.email, r.display_name,
                TimeDisplay(r.approved_at ?? r.created_at), r.avatar))
            .ToList();

    public static List<AuditView> AuditViews(IEnumerable<AuditRow> rows) =>
        rows.Select(r => new AuditView(TimeDisplay(r.ts), r.@event, r.success != 0,
            r.user_id, r.client_id, r.ip, r.detail)).ToList();

    public static List<AuditView> RecentLogins(string userId, AuditRepository audit, int limit = 10) =>
        AuditViews(audit.Query(events: LoginEvents, userId: userId, limit: limit));

    /// <summary>空 = 不设邮箱（合法）；否则要像个邮箱：有 @、两边非空、无空白、不超 254。</summary>
    public static bool IsValidEmail(string? email)
    {
        var e = email?.Trim() ?? "";
        if (e.Length == 0) return true;
        var at = e.IndexOf('@');
        return e.Length <= 254 && at > 0 && at == e.LastIndexOf('@') && at < e.Length - 1
               && !e.Any(char.IsWhiteSpace);
    }

    public static string TimeDisplay(long unixSeconds) =>
        DateTimeOffset.FromUnixTimeSeconds(unixSeconds).ToLocalTime().ToString("yyyy-MM-dd HH:mm");

    // HTTP Location header 必须 ASCII，中文 query 值要先 percent-encode，
    // 不然 Kestrel 直接 throw InvalidOperationException ("Invalid non-ASCII or
    // control character in header")，整个请求 500。统一走这个 helper。
    //
    // 提示文案不再明文进 query（2026-09-29 安全修复）：原先 /account?notice=任意文本 会原样印在可信后台页上，
    // 能被拿来做钓鱼文案。现在 notice / error / rotated 都用 DataProtection 加密签名（密钥与会话 cookie 同一套，
    // 持久化在 dp-keys/），purpose 绑定当前登录用户、10 分钟过期；解不开 / 过期 / 换了人 → 什么都不显示。
    // 文案里有动态部分（"Revoked {0} refresh token(s)"、"Created user {0}"），所以不用固定 key 表。
    public static IResult RedirectTo(string path, string? notice = null, string? error = null, string? rotated = null) =>
        notice is null && error is null && rotated is null
            ? Results.Redirect(path)
            : new FlashRedirect(path, notice, error, rotated);

    private static readonly TimeSpan FlashLifetime = TimeSpan.FromMinutes(10);

    private static ITimeLimitedDataProtector FlashProtector(HttpContext ctx) =>
        ctx.RequestServices.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("nas-auth.dashboard-flash", ctx.User.Identity?.Name ?? "-")
            .ToTimeLimitedDataProtector();

    /// <summary>读 <see cref="RedirectTo"/> 写进 query 的提示；缺失、被篡改、过期、不是发给当前用户的 → null。</summary>
    public static string? ReadFlash(HttpContext ctx, string key)
    {
        var raw = ctx.Request.Query[key].ToString();
        if (string.IsNullOrEmpty(raw)) return null;
        try
        {
            var text = FlashProtector(ctx).Unprotect(raw);
            return string.IsNullOrEmpty(text) ? null : text;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }

    /// <summary>执行时才拿到 HttpContext（取 DataProtection 与当前用户），调用方签名不用变。</summary>
    private sealed class FlashRedirect(string path, string? notice, string? error, string? rotated) : IResult
    {
        public Task ExecuteAsync(HttpContext ctx)
        {
            var protector = FlashProtector(ctx);
            var parts = new List<string>(3);
            void Add(string key, string? text)
            {
                if (text != null) parts.Add(key + "=" + Uri.EscapeDataString(protector.Protect(text, FlashLifetime)));
            }
            Add("notice", notice);
            Add("error", error);
            Add("rotated", rotated);
            var sep = path.Contains('?') ? '&' : '?';
            return Results.Redirect(path + sep + string.Join("&", parts)).ExecuteAsync(ctx);
        }
    }

    /// <summary>旧地址跳新地址时保留原 query。</summary>
    public static IResult RedirectKeepQuery(HttpContext ctx, string path) =>
        Results.Redirect(path + ctx.Request.QueryString.Value);
}
