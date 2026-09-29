using NasAuth.Data;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

public enum PasswordSignInStatus
{
    Ok,
    /// <summary>用户不存在 / 密码错 / 该用户不允许密码登录 —— 对外一律同一句「用户名或密码错误」，不暴露是哪种。</summary>
    BadCredentials,
    /// <summary>连续失败次数到上限，锁定中。</summary>
    Locked,
}

public record PasswordSignInResult(PasswordSignInStatus Status, UserRow? User, string AuditReason);

/// <summary>
/// 密码登录的唯一判定点（external-auth.md §十四），<c>POST /login</c> 与 <c>POST /authorize</c> 的密码分支共用。
/// 调用方先自己判总闸（<see cref="PasswordLoginGate.Enabled"/>，关了是 404 / 403，语义各自不同），这里只管具体账号：
/// <list type="number">
///   <item>锁定中 → Locked（不校验密码，不延长锁定）</item>
///   <item>校验密码 —— 用户不存在也跑一次 hash，免得靠响应时间枚举用户名</item>
///   <item>密码对但该用户不允许密码登录（如管理员只许 Google / 微软登录）→ 当作密码错：
///         既不让人知道密码其实是对的，也照样计入失败次数</item>
///   <item>失败累计 <see cref="FailureThreshold"/> 次锁 <see cref="LockSeconds"/> 秒；成功清零</item>
/// </list>
/// 按 IP 的限速（Program.cs 的 auth-sensitive 策略）挡单一来源的高频；这里的按账号锁定挡分布式慢速撞库。
/// </summary>
public class PasswordSignIn
{
    public const int FailureThreshold = 10;
    public const long LockSeconds = 15 * 60;

    // 用户不存在时拿来空跑一次 Verify 的 hash（argon2id，内容无意义）；静态懒生成，只算一次
    private static readonly Lazy<string> DummyHash = new(() => PasswordHasher.Hash(Guid.NewGuid().ToString("N")));

    private readonly UserRepository _users;
    private readonly PasswordLoginGate _gate;

    public PasswordSignIn(UserRepository users, PasswordLoginGate gate)
    {
        _users = users;
        _gate = gate;
    }

    public PasswordSignInResult Attempt(string username, string password)
    {
        var user = string.IsNullOrEmpty(username) ? null : _users.GetByUsername(username);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        if (user is not null && user.locked_until is { } until && until > now)
            return new(PasswordSignInStatus.Locked, user, "locked");

        var passwordOk = PasswordHasher.Verify(password, user?.password_hash ?? DummyHash.Value);

        if (user is null)
            return new(PasswordSignInStatus.BadCredentials, null, "bad_credentials");

        if (!passwordOk || !_gate.AllowsUser(user))
        {
            var after = _users.RecordFailedLogin(user.user_id, FailureThreshold, LockSeconds);
            var reason = passwordOk ? "password_not_allowed_for_user" : "bad_credentials";
            // 这一次正好触发锁定：记审计时标出来，对外仍是「用户名或密码错误」
            if (after?.locked_until is { } lockedUntil && lockedUntil > now) reason += "+locked";
            return new(PasswordSignInStatus.BadCredentials, user, reason);
        }

        _users.ResetFailedLogins(user.user_id);
        return new(PasswordSignInStatus.Ok, user, "-");
    }
}
