using Dapper;

namespace NasAuth.Data.Repositories;

public class UserRepository
{
    private readonly AuthDb _db;
    public UserRepository(AuthDb db) => _db = db;

    // 显式列序：必须与 UserRow 构造参数顺序一致，Dapper positional record 按列序绑定。
    private const string UserCols =
        "user_id, username, password_hash, created_at, updated_at, is_admin, must_change_password, " +
        "email, allow_password_login, failed_login_count, locked_until, session_version, display_name, avatar, is_disabled, session_epoch";

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
            $"SELECT {UserCols} FROM users WHERE username = @u AND is_disabled=0", new { u = username });
    }

    public UserRow? GetById(string userId)
    {
        using var conn = _db.OpenConnection();
        return conn.QuerySingleOrDefault<UserRow>(
            $"SELECT {UserCols} FROM users WHERE user_id = @id AND is_disabled=0", new { id = userId });
    }

    public bool SetAdministrator(string actorId, string targetId, bool enabled, string bootstrapUsername)
    {
        using var conn = _db.OpenConnection();
        return conn.Execute(@"UPDATE users SET is_admin=@role, session_version=session_version+1, updated_at=@now
            WHERE user_id=@targetId AND is_disabled=0 AND is_admin<>@role
            AND EXISTS(SELECT 1 FROM users actor WHERE actor.user_id=@actorId AND actor.is_admin=1 AND actor.is_disabled=0)
            AND (@role=1 OR (user_id<>@actorId AND username<>@bootstrapUsername))",
            new { actorId, targetId, role=enabled ? 1 : 0, bootstrapUsername, now=DateTimeOffset.UtcNow.ToUnixTimeSeconds() }) == 1;
    }

    public IReadOnlyList<UserRow> ListAll()
    {
        using var conn = _db.OpenConnection();
        return conn.Query<UserRow>(
            $"SELECT {UserCols} FROM users WHERE is_disabled=0 ORDER BY is_admin DESC, created_at ASC").AsList();
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
        string? email = null, bool allowPasswordLogin = false, string? displayName = null,
        string? inviteEmail = null, string? createdBy = null, IReadOnlyDictionary<string,string>? applicationGrants = null)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        using var transaction = conn.BeginTransaction();
        conn.Execute(@"
            INSERT INTO users (user_id, username, password_hash, is_admin, must_change_password,
                               created_at, updated_at, email, allow_password_login, display_name)
            VALUES (@user_id, @username, @password_hash, 0, @must_change, @now, @now, @email, @allow, @display_name)",
            new
            {
                user_id = userId,
                username,
                password_hash = passwordHash,
                must_change = mustChangePassword ? 1 : 0,
                now,
                email = NormalizeEmail(email),
                allow = allowPasswordLogin ? 1 : 0,
                display_name = NormalizeDisplayName(displayName),
            }, transaction);
        if (!string.IsNullOrWhiteSpace(inviteEmail))
            conn.Execute("INSERT INTO external_invites(email,user_id,created_at,created_by) VALUES(@email,@userId,@now,@createdBy)",
                new { email = NormalizeEmail(inviteEmail), userId, now, createdBy }, transaction);
        foreach (var (aud, scopes) in applicationGrants ?? new Dictionary<string,string>())
            conn.Execute("INSERT INTO user_resources(user_id,aud,scopes) VALUES(@userId,@aud,@scopes)", new { userId, aud, scopes }, transaction);
        transaction.Commit();
    }

    /// <summary>昵称去首尾空白、截到 64 字符；空串视为未设置（null）。</summary>
    public static string? NormalizeDisplayName(string? name)
    {
        var n = name?.Trim();
        if (string.IsNullOrEmpty(n)) return null;
        return n.Length > 64 ? n[..64] : n;
    }

    /// <summary>改昵称（§十九）。null / 空串 = 清空，下发时回落到外部账号名 / user_id。</summary>
    public void UpdateDisplayName(string userId, string? displayName)
    {
        using var conn = _db.OpenConnection();
        conn.Execute("UPDATE users SET display_name = @n, updated_at = @now WHERE user_id = @id",
            new { n = NormalizeDisplayName(displayName), now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), id = userId });
    }

    /// <summary>换头像（§十九）：存 avatars/ 下的文件名；null = 去掉头像。</summary>
    public void UpdateAvatar(string userId, string? avatarFile)
    {
        using var conn = _db.OpenConnection();
        conn.Execute("UPDATE users SET avatar = @a, updated_at = @now WHERE user_id = @id",
            new { a = avatarFile, now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), id = userId });
    }

    /// <summary>
    /// 首次绑定外部账号时用它的昵称 / 头像补空（§十九）：只填空着的，不覆盖用户自己设过的。
    /// 单条 UPDATE 用 COALESCE 完成，不先读后写。
    /// </summary>
    public void FillProfileIfEmpty(string userId, string? displayName, string? avatarFile)
    {
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            UPDATE users SET
                display_name = COALESCE(NULLIF(display_name, ''), @n),
                avatar = COALESCE(avatar, @a)
            WHERE user_id = @id",
            new { n = NormalizeDisplayName(displayName), a = avatarFile, id = userId });
    }

    /// <summary>管理员编辑用户的邮箱与「允许密码登录」开关。</summary>
    public void UpdateProfile(string userId, string? email, bool allowPasswordLogin)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        using var transaction = conn.BeginTransaction();
        var oldEmail = conn.QuerySingleOrDefault<string>("SELECT email FROM users WHERE user_id=@id", new { id = userId }, transaction);
        var newEmail = NormalizeEmail(email);
        if (!string.Equals(oldEmail, newEmail, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(oldEmail))
        {
            var pending = conn.QuerySingleOrDefault<ExternalInviteRow>("SELECT email,user_id,created_at,created_by FROM external_invites WHERE user_id=@id AND email=@oldEmail",
                new { id = userId, oldEmail }, transaction);
            if (pending is not null)
            {
                conn.Execute("DELETE FROM external_invites WHERE user_id=@id AND email=@oldEmail", new { id = userId, oldEmail }, transaction);
                if (newEmail is not null)
                    conn.Execute("INSERT INTO external_invites(email,user_id,created_at,created_by) VALUES(@newEmail,@id,@now,@by)",
                        new { newEmail, id = userId, now, by = pending.created_by }, transaction);
            }
        }
        conn.Execute(
            "UPDATE users SET email = @email, allow_password_login = @allow, updated_at = @now WHERE user_id = @id",
            new { email = newEmail, allow = allowPasswordLogin ? 1 : 0, now, id = userId }, transaction);
        transaction.Commit();
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
    /// 管理员重置某用户密码：写新 hash；<paramref name="mustChangePassword"/> 为 true 时强制对方下次登录改，
    /// 否则清掉标志（管理员定的密码就是正式密码，家人用不着再改一次）。
    /// </summary>
    public void ResetPassword(string userId, string newHash, bool mustChangePassword)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute(
            "UPDATE users SET password_hash = @hash, must_change_password = @must, updated_at = @now WHERE user_id = @id",
            new { hash = newHash, must = mustChangePassword ? 1 : 0, now, id = userId });
    }
    public UserRow? GetStoredById(string id)
    {
        using var c = _db.OpenConnection();
        return c.QuerySingleOrDefault<UserRow>($"SELECT {UserCols} FROM users WHERE user_id=@id", new { id });
    }

    public IReadOnlyList<UserRow> ListDisabled()
    {
        using var c = _db.OpenConnection();
        return c.Query<UserRow>($"SELECT {UserCols} FROM users WHERE is_disabled=1 ORDER BY username").AsList();
    }

    public IReadOnlyList<string> ListDeletedIds()
    {
        using var c = _db.OpenConnection();
        return c.Query<string>("SELECT user_id FROM deleted_user_ids WHERE NOT EXISTS(SELECT 1 FROM users WHERE users.user_id=deleted_user_ids.user_id COLLATE NOCASE) ORDER BY deleted_at DESC").AsList();
    }

    public bool Disable(string actorId, string id, string bootstrap)
    {
        using var c = _db.OpenConnection(); using var tx = c.BeginTransaction();
        var changed=c.Execute(@"UPDATE users SET is_disabled=1, is_admin=0, password_hash=@hash, allow_password_login=0,
            session_version=session_version+1, session_epoch=@epoch, updated_at=@now
            WHERE user_id=@id AND is_disabled=0 AND user_id<>@actorId AND username<>@bootstrap
            AND EXISTS(SELECT 1 FROM users a WHERE a.user_id=@actorId AND a.is_admin=1 AND a.is_disabled=0)",
            new { id,actorId,bootstrap,hash=NasAuth.Services.PasswordHasher.UnusableHash(),epoch=Guid.NewGuid().ToString("N"),now=DateTimeOffset.UtcNow.ToUnixTimeSeconds() },tx);
        if(changed==0) return false;
        c.Execute("DELETE FROM refresh_tokens WHERE user_id=@id; DELETE FROM auth_codes WHERE user_id=@id; DELETE FROM external_invites WHERE user_id=@id",new{id},tx);
        tx.Commit(); return true;
    }

    public bool RestoreIdentity(string actorId,string id,bool deleted,string hash,bool password,string? email)
    {
        using var c=_db.OpenConnection();using var tx=c.BeginTransaction();
        if(c.ExecuteScalar<long>("SELECT COUNT(*) FROM users WHERE user_id=@actorId AND is_admin=1 AND is_disabled=0",new{actorId},tx)!=1) return false;
        var args=new{id,hash,allow=password?1:0,email=NormalizeEmail(email),epoch=Guid.NewGuid().ToString("N"),now=DateTimeOffset.UtcNow.ToUnixTimeSeconds()};
        int n;
        if(deleted)
            n=c.Execute(@"INSERT INTO users(user_id,username,password_hash,is_admin,must_change_password,created_at,updated_at,email,allow_password_login,session_epoch)
                SELECT user_id,user_id,@hash,0,0,@now,@now,@email,@allow,@epoch FROM deleted_user_ids WHERE user_id=@id COLLATE NOCASE
                AND NOT EXISTS(SELECT 1 FROM users WHERE user_id=@id COLLATE NOCASE OR username=@id COLLATE NOCASE)",args,tx);
        else
            n=c.Execute(@"UPDATE users SET is_disabled=0,is_admin=0,password_hash=@hash,allow_password_login=@allow,must_change_password=0,
                failed_login_count=0,locked_until=NULL,session_version=session_version+1,session_epoch=@epoch,updated_at=@now
                WHERE user_id=@id AND is_disabled=1",args,tx);
        if(n!=1) return false;
        c.Execute("DELETE FROM refresh_tokens WHERE user_id=@id; DELETE FROM auth_codes WHERE user_id=@id; DELETE FROM user_resources WHERE user_id=@id; DELETE FROM external_invites WHERE user_id=@id",new{id},tx);
        if(deleted) c.Execute("DELETE FROM external_identities WHERE user_id=@id",new{id},tx);
        tx.Commit();return true;
    }

}
