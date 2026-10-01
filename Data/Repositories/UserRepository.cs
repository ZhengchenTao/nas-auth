using Dapper;

namespace NasAuth.Data.Repositories;

public class UserRepository
{
    private readonly AuthDb _db;
    public UserRepository(AuthDb db) => _db = db;

    // 显式列序：必须与 UserRow 构造参数顺序一致，Dapper positional record 按列序绑定。
    private const string UserCols =
        "user_id, username, password_hash, created_at, updated_at, is_admin, must_change_password, " +
        "email, allow_password_login, failed_login_count, locked_until, session_version";

    /// <summary>邮箱统一存小写、去空白；空串视为未设置（null）。</summary>
    public static string? NormalizeEmail(string? email)
    {
        var e = email?.Trim().ToLowerInvariant();
        return string.IsNullOrEmpty(e) ? null : e;
    }

    public UserRow? GetByUsername(string username)
    {
        using var conn = _db.OpenConnection();
        return conn.QuerySingleOrDefault<UserRow>(
            $"SELECT {UserCols} FROM users WHERE username = @u", new { u = username });
    }

    public UserRow? GetById(string userId)
    {
        using var conn = _db.OpenConnection();
        return conn.QuerySingleOrDefault<UserRow>(
            $"SELECT {UserCols} FROM users WHERE user_id = @id", new { id = userId });
    }

    public IReadOnlyList<UserRow> ListAll()
    {
        using var conn = _db.OpenConnection();
        return conn.Query<UserRow>(
            $"SELECT {UserCols} FROM users ORDER BY is_admin DESC, created_at ASC").AsList();
    }

    /// <summary>
    /// 启动期 admin bootstrap 用。INSERT 时设 is_admin，ON CONFLICT 时强制重置 is_admin
    /// 并清掉 must_change_password —— 配置里的密码视为权威。
    /// </summary>
    public void Upsert(string userId, string username, string passwordHash, bool isAdmin)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            INSERT INTO users (user_id, username, password_hash, is_admin, must_change_password, created_at, updated_at)
            VALUES (@user_id, @username, @password_hash, @is_admin, 0, @now, @now)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                password_hash = excluded.password_hash,
                is_admin = excluded.is_admin,
                must_change_password = 0,
                updated_at = @now",
            new { user_id = userId, username, password_hash = passwordHash, is_admin = isAdmin ? 1 : 0, now });
    }

    /// <summary>
    /// 管理员从 /account 页面新建用户（普通用户，is_admin=0），或审批外部身份时建用户。
    /// <paramref name="allowPasswordLogin"/>：本地密码用户要开；外部登录用户（密码不可用）保持关。
    /// </summary>
    public void Create(string userId, string username, string passwordHash, bool mustChangePassword,
        string? email = null, bool allowPasswordLogin = false)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            INSERT INTO users (user_id, username, password_hash, is_admin, must_change_password,
                               created_at, updated_at, email, allow_password_login)
            VALUES (@user_id, @username, @password_hash, 0, @must_change, @now, @now, @email, @allow)",
            new
            {
                user_id = userId,
                username,
                password_hash = passwordHash,
                must_change = mustChangePassword ? 1 : 0,
                now,
                email = NormalizeEmail(email),
                allow = allowPasswordLogin ? 1 : 0,
            });
    }

    /// <summary>管理员编辑用户的邮箱与「允许密码登录」开关。</summary>
    public void UpdateProfile(string userId, string? email, bool allowPasswordLogin)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute(
            "UPDATE users SET email = @email, allow_password_login = @allow, updated_at = @now WHERE user_id = @id",
            new { email = NormalizeEmail(email), allow = allowPasswordLogin ? 1 : 0, now, id = userId });
    }

    /// <summary>
    /// 记一次密码失败；累计到 <paramref name="threshold"/> 次时锁 <paramref name="lockSeconds"/> 秒并清零计数。
    /// 单条 UPDATE 完成读改写，并发失败不会漏计。返回更新后的行。
    /// </summary>
    public UserRow? RecordFailedLogin(string userId, int threshold, long lockSeconds)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            UPDATE users SET
                locked_until = CASE WHEN failed_login_count + 1 >= @threshold THEN @now + @lock ELSE locked_until END,
                failed_login_count = CASE WHEN failed_login_count + 1 >= @threshold THEN 0 ELSE failed_login_count + 1 END
            WHERE user_id = @id",
            new { threshold, now, @lock = lockSeconds, id = userId });
        return conn.QuerySingleOrDefault<UserRow>(
            $"SELECT {UserCols} FROM users WHERE user_id = @id", new { id = userId });
    }

    /// <summary>密码登录成功：清掉失败计数与锁定。</summary>
    public void ResetFailedLogins(string userId)
    {
        using var conn = _db.OpenConnection();
        conn.Execute(
            "UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE user_id = @id AND (failed_login_count <> 0 OR locked_until IS NOT NULL)",
            new { id = userId });
    }

    /// <summary>
    /// 删除用户：连带删掉 refresh_tokens / auth_codes 里所有指向他的行，
    /// 防止已签发的 refresh token 把账号 "复活"（access JWT 还能用到过期，这是 JWT 设计代价）。
    /// </summary>
    /// <param name="retireId">登记为删过的 id、之后不许复用（§十八）。只有「建了又立刻回滚」这种从没对外用过的才传 false。</param>
    public void Delete(string userId, bool retireId = true)
    {
        using var conn = _db.OpenConnection();
        using var tx = conn.BeginTransaction();
        conn.Execute("DELETE FROM refresh_tokens WHERE user_id = @id", new { id = userId }, tx);
        conn.Execute("DELETE FROM auth_codes WHERE user_id = @id", new { id = userId }, tx);
        conn.Execute("DELETE FROM users WHERE user_id = @id", new { id = userId }, tx);
        // §十八：登记删过的 id，之后不许再建同名用户（各应用按这个 id 认账号）
        if (retireId)
            conn.Execute(@"INSERT INTO deleted_user_ids (user_id, deleted_at) VALUES (@id, @now)
                       ON CONFLICT(user_id) DO NOTHING",
            new { id = userId, now = DateTimeOffset.UtcNow.ToUnixTimeSeconds() }, tx);
        tx.Commit();
    }

    /// <summary>这个 user_id 是否被删过（大小写不敏感，§十八）。新建 / 审批建号前查。</summary>
    public bool IsRetiredId(string userId)
    {
        using var conn = _db.OpenConnection();
        return conn.ExecuteScalar<long>("SELECT COUNT(*) FROM deleted_user_ids WHERE user_id = @id",
            new { id = userId }) > 0;
    }

    /// <summary>
    /// 会话版本 +1（§十六）：该用户所有已发出的登录 cookie 立即失效（SessionValidator 比对不上）。
    /// 用于退出其他设备、改密、管理员重置密码 / 强制下线。返回新版本号；用户不存在返回 null。
    /// </summary>
    public long? BumpSessionVersion(string userId)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        var n = conn.Execute(
            "UPDATE users SET session_version = session_version + 1, updated_at = @now WHERE user_id = @id",
            new { now, id = userId });
        if (n == 0) return null;
        return conn.ExecuteScalar<long>("SELECT session_version FROM users WHERE user_id = @id", new { id = userId });
    }

    /// <summary>
    /// 自助修改密码（仅 /account/change-password 用），不动 must_change_password。
    /// </summary>
    public void UpdatePasswordHash(string userId, string newHash)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute(
            "UPDATE users SET password_hash = @hash, updated_at = @now WHERE user_id = @id",
            new { hash = newHash, now, id = userId });
    }

    /// <summary>
    /// 强制改密页面提交后：写入新 hash + 清掉 must_change_password 标志。
    /// </summary>
    public void UpdatePasswordHashAndClearForceChange(string userId, string newHash)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute(
            "UPDATE users SET password_hash = @hash, must_change_password = 0, updated_at = @now WHERE user_id = @id",
            new { hash = newHash, now, id = userId });
    }

    /// <summary>
    /// 管理员重置某用户密码：写新 hash + 置 must_change_password=1，强制对方下次登录改。
    /// </summary>
    public void ResetPasswordForceChange(string userId, string newHash)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute(
            "UPDATE users SET password_hash = @hash, must_change_password = 1, updated_at = @now WHERE user_id = @id",
            new { hash = newHash, now, id = userId });
    }
}
