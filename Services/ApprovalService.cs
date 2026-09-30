using System.Security.Cryptography;
using System.Text.RegularExpressions;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

/// <summary>
/// 待批申请的批准 / 拒绝（外部认证设计 §5.4）。
/// 批准 = 绑现有用户 或 新建 user_id，外加按 aud 勾选的 user_resources 授权（全量 scope，
/// 细粒度 scope 收窄走用户管理页）。拒绝保留记录（防重复申请刷屏）。
/// 返回 null 表示成功，否则是给页面显示的错误文案。
/// </summary>
public class ApprovalService
{
    // 与 AccountEndpoints 的用户名约束同源：字母/数字/. _ -，1-32。
    private static readonly Regex UserIdPattern = new(@"^[a-zA-Z0-9._-]{1,32}$", RegexOptions.Compiled);

    private readonly ExternalIdentityRepository _identities;
    private readonly UserRepository _users;
    private readonly UserResourceRepository _userResources;
    private readonly ResourceCatalog _catalog;

    public ApprovalService(ExternalIdentityRepository identities, UserRepository users,
        UserResourceRepository userResources, ResourceCatalog catalog)
    {
        _identities = identities;
        _users = users;
        _userResources = userResources;
        _catalog = catalog;
    }

    /// <summary>批准并绑定到现有用户。</summary>
    public string? ApproveBindExisting(string provider, string subject, string userId, IReadOnlyList<string> grantAuds)
    {
        if (_users.GetById(userId) is null)
            return $"User {userId} does not exist";
        return ApproveCore(provider, subject, userId, grantAuds);
    }

    /// <summary>
    /// 批准并新建用户。新用户没有可用密码（置随机不可知 hash）：
    /// 它的登录通道就是这条外部身份，密码兜底只属于管理员（设计 §十）。
    /// </summary>
    public string? ApproveCreateUser(string provider, string subject, string newUserId, IReadOnlyList<string> grantAuds)
    {
        if (!UserIdPattern.IsMatch(newUserId))
            return "User id may only contain letters, digits, . _ -, length 1-32";
        if (_users.GetByUsername(newUserId) is not null)
            return $"User {newUserId} already exists";

        // 随机 32 字节、不落任何人之手 → 密码登录对该用户事实禁用，不设强制改密
        Span<byte> raw = stackalloc byte[32];
        RandomNumberGenerator.Fill(raw);
        var unusable = PasswordHasher.Hash(Convert.ToBase64String(raw));
        _users.Create(newUserId, newUserId, unusable, mustChangePassword: false);

        var err = ApproveCore(provider, subject, newUserId, grantAuds);
        if (err is not null)
        {
            // 审批没成立（身份已不是 pending 等），回滚刚建的空用户
            _users.Delete(newUserId);
            return err;
        }
        return null;
    }

    public string? Reject(string provider, string subject)
    {
        return _identities.Reject(provider, subject)
            ? null
            : "Request is no longer pending";
    }

    private string? ApproveCore(string provider, string subject, string userId, IReadOnlyList<string> grantAuds)
    {
        if (!_identities.Approve(provider, subject, userId))
            return "Request is no longer pending";

        var isAdmin = _users.GetById(userId)?.is_admin > 0;
        foreach (var aud in grantAuds)
        {
            var resource = _catalog.FindByAud(aud);
            if (resource is null) continue; // 不认识的 aud 静默跳过（表单被篡改/资源下线）
            if (!resource.AllowsUser(isAdmin)) continue; // admin_only 不授给非管理员（审批页本就不列，这里防表单篡改）
            _userResources.Upsert(userId, aud, string.Join(' ', resource.Scopes));
        }
        return null;
    }
}
