using System.Security.Claims;
using NasAuth.Data;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

/// <summary>外部登录回调的状态机结果（外部认证设计 §5.2）。</summary>
public enum ExternalSignInStatus
{
    /// <summary>active 且用户存在 → 调用方建立会话，回到 OAuth 流程。</summary>
    Active,
    /// <summary>首见身份，已插入 pending 行 → 等待页，不建会话。</summary>
    PendingNew,
    /// <summary>已有 pending 行 → 等待页，不建会话。</summary>
    PendingExisting,
    /// <summary>已被管理员拒绝 → 403，不建会话。</summary>
    Rejected,
    /// <summary>active 但绑定的 user 已被删除（数据残留）→ 按拒绝处理，不建会话。</summary>
    OrphanedActive,
    /// <summary>命中管理员登记的预绑定邮箱（§十八），刚绑成 active → 调用方建立会话。</summary>
    ActiveByInvite,
}

public record ExternalSignInResult(ExternalSignInStatus Status, UserRow? User);

/// <summary>
/// 外部登录回调逻辑（两个 provider 共用，设计 §5.2）。
/// 不变量：禁止 auto-provisioning —— 只有 status=active 且 user 存在才返回可建会话的结果，
/// 其余一律不建会话、不签发任何 token。会话建立本身留在 endpoint 层（这里不碰 HttpContext）。
/// </summary>
public class ExternalSignInService
{
    private readonly ExternalIdentityRepository _identities;
    private readonly UserRepository _users;
    private readonly ExternalInviteRepository? _invites;

    public ExternalSignInService(ExternalIdentityRepository identities, UserRepository users,
        ExternalInviteRepository? invites = null)
    {
        _identities = identities;
        _users = users;
        _invites = invites;
    }

    /// <param name="emailVerified">IdP 是否声明 <paramref name="email"/> 已验证（只信 Google 的 email_verified，见 <see cref="ExternalClaims.IsEmailVerified"/>）。</param>
    public ExternalSignInResult Resolve(string provider, string subject, string? email, string? displayName,
        bool emailVerified = false)
    {
        var row = _identities.Get(provider, subject);

        // §十八 预绑定邮箱：首见或仍在待批的身份，邮箱经 IdP 验证且命中管理员的登记 → 直接绑定。
        // 已 active（属于谁已定）/ rejected（管理员已表态）的不走这条。
        if ((row is null || row.status == "pending") && TryRedeemInvite(provider, subject, email, displayName, emailVerified) is { } invited)
            return new ExternalSignInResult(ExternalSignInStatus.ActiveByInvite, invited);

        if (row is null)
        {
            // 首见：插 pending 行（email/display_name 供审批页辨认），等管理员批准
            _identities.InsertPending(provider, subject, email, displayName);
            return new ExternalSignInResult(ExternalSignInStatus.PendingNew, null);
        }

        return row.status switch
        {
            "active" when row.user_id is not null && _users.GetById(row.user_id) is { } user
                => new ExternalSignInResult(ExternalSignInStatus.Active, user),
            "active" => new ExternalSignInResult(ExternalSignInStatus.OrphanedActive, null),
            "rejected" => new ExternalSignInResult(ExternalSignInStatus.Rejected, null),
            _ => new ExternalSignInResult(ExternalSignInStatus.PendingExisting, null),
        };
    }

    private UserRow? TryRedeemInvite(string provider, string subject, string? email, string? displayName, bool emailVerified)
    {
        if (_invites is null || !emailVerified || string.IsNullOrWhiteSpace(email)) return null;
        var invite = _invites.Consume(email);
        if (invite is null) return null;
        // 登记的用户已被删（理论上删用户会连带删预绑定）→ 预绑定作废，照常进待批
        if (_users.GetById(invite.user_id) is not { } user) return null;
        _identities.BindActive(provider, subject, user.user_id, email, displayName);
        return user;
    }

    /// <summary>
    /// 自绑定（设计 §5.3）：把外部身份绑到 userId（调用方已确认活跃会话归属）。
    /// 返回 null 成功，否则给页面显示的错误文案。
    /// 守护：active 且属于别人 → 拒绝（防身份抢占）；rejected → 拒绝（管理员已表态，
    /// 不允许普通用户用自绑定绕过，解铃还须 admin 删行）；null / pending / 自己的 active → 绑定。
    /// </summary>
    public string? BindToUser(string provider, string subject, string userId, string? email, string? displayName)
    {
        var row = _identities.Get(provider, subject);
        if (row is not null && row.status == "active" && row.user_id != userId)
            return "This external account is already bound to another user.";
        if (row is not null && row.status == "rejected")
            return "This external account was rejected by an administrator and cannot be self-bound.";

        _identities.BindActive(provider, subject, userId, email, displayName);
        return null;
    }
}

/// <summary>
/// 从外部 IdP 回调的 ClaimsPrincipal 里取身份字段。
/// 身份主键只认 Google sub / Microsoft oid（fallback sub），绝不用 email（设计 §六 / §九）。
/// 注：AddMicrosoftAccount 走 Graph /me，把稳定的 Graph user id 映射到 NameIdentifier，
/// 不带 oid claim —— fallback 链 oid → NameIdentifier 两种部署形态都覆盖。
/// </summary>
public static class ExternalClaims
{
    public const string OidClaimType = "http://schemas.microsoft.com/identity/claims/objectidentifier";

    public static string? GetSubject(string provider, ClaimsPrincipal principal) => provider switch
    {
        "google" => principal.FindFirstValue(ClaimTypes.NameIdentifier),
        "microsoft" => principal.FindFirstValue(OidClaimType)
                       ?? principal.FindFirstValue("oid")
                       ?? principal.FindFirstValue(ClaimTypes.NameIdentifier),
        _ => null,
    };

    public static string? GetEmail(ClaimsPrincipal principal) =>
        principal.FindFirstValue(ClaimTypes.Email);

    public static string? GetDisplayName(ClaimsPrincipal principal) =>
        principal.FindFirstValue(ClaimTypes.Name);

    /// <summary>§十九：回调时下载好的外部头像文件名（<see cref="Endpoints.ExternalLoginEndpoints.AttachAvatarAsync"/> 加的）。</summary>
    public const string AvatarClaimType = "nas_avatar";

    public static string? GetAvatar(ClaimsPrincipal principal) => principal.FindFirstValue(AvatarClaimType);

    /// <summary>Google userinfo 的 email_verified 映射成的 claim 类型（Program.cs 里 MapJsonKey）。</summary>
    public const string EmailVerifiedClaimType = "email_verified";

    /// <summary>微软账号的登录名（Graph /me 的 userPrincipalName）映射成的 claim 类型（Program.cs 里 MapJsonKey）。</summary>
    public const string MicrosoftUpnClaimType = "ms_upn";

    /// <summary>
    /// 邮箱是否经 IdP 验证（§十八 预绑定只认这个）。判据是「IdP 能不能证明他拥有这个邮箱」，与域名无关。
    /// Google：userinfo 的 email_verified（Google 账号可用任意邮箱注册，但要收验证码才标 verified）。
    /// 微软：只接个人账号（Program.cs 写死 /consumers/ 端点），个人账号的登录名注册时就要验证邮箱；
    /// Graph /me 不给标记，所以认「登录名（userPrincipalName）就是下发的这个邮箱」——ASP.NET 的 Email claim
    /// 取 mail ?? userPrincipalName，mail 可能是另一个地址，要求两者相同。
    /// 工作 / 学校账号的 email 可由租户管理员随意设置（nOAuth），那条路不走 /consumers/ 进不来；以后若改成 /common/，这里必须重审。
    /// </summary>
    public static bool IsEmailVerified(string provider, ClaimsPrincipal principal) => provider switch
    {
        "google" => string.Equals(principal.FindFirstValue(EmailVerifiedClaimType), "true", StringComparison.OrdinalIgnoreCase),
        "microsoft" => IsSignInEmail(principal.FindFirstValue(MicrosoftUpnClaimType), GetEmail(principal)),
        _ => false,
    };

    private static bool IsSignInEmail(string? upn, string? email) =>
        !string.IsNullOrWhiteSpace(upn) && upn.Contains('@')
        && string.Equals(upn.Trim(), email?.Trim(), StringComparison.OrdinalIgnoreCase);
}
