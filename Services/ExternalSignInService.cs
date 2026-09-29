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

    public ExternalSignInService(ExternalIdentityRepository identities, UserRepository users)
    {
        _identities = identities;
        _users = users;
    }

    public ExternalSignInResult Resolve(string provider, string subject, string? email, string? displayName)
    {
        var row = _identities.Get(provider, subject);
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
}
