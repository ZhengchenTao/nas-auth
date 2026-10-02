using Dapper;

namespace NasAuth.Data.Repositories;

/// <summary>
/// external_identities 表（外部认证设计 §四 / §五）。
/// 状态机：不存在 → pending（外部回调首见）→ active（管理员批准 / 已登录用户自绑定）
///        或 rejected（管理员拒绝，记录保留防重复申请刷屏）。
/// 身份匹配只认 (provider, subject)，绝不用 email 匹配账号。
/// </summary>
public class ExternalIdentityRepository
{
    private readonly AuthDb _db;
    public ExternalIdentityRepository(AuthDb db) => _db = db;

    private const string Cols =
        "provider, subject, user_id, email, display_name, status, created_at, approved_at, avatar";

    public ExternalIdentityRow? Get(string provider, string subject)
    {
        using var conn = _db.OpenConnection();
        return conn.QuerySingleOrDefault<ExternalIdentityRow>(
            $"SELECT {Cols} FROM external_identities WHERE provider = @provider AND subject = @subject",
            new { provider, subject });
    }

    /// <summary>
    /// 外部回调首见该身份时插入 pending 行（user_id 为 NULL），等管理员批准。
    /// email / display_name 仅供审批页辨认用。
    /// 已存在则不动（保留原 status，rejected 的不能靠重复申请洗白）。
    /// </summary>
    public void InsertPending(string provider, string subject, string? email, string? displayName)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            INSERT INTO external_identities (provider, subject, user_id, email, display_name, status, created_at)
            VALUES (@provider, @subject, NULL, @email, @display_name, 'pending', @now)
            ON CONFLICT(provider, subject) DO NOTHING",
            new { provider, subject, email, display_name = displayName, now });
    }

    /// <summary>
    /// 已登录用户自绑定（bootstrap 路径，设计 §5.3）：直接写 active 行，不走审批。
    /// upsert：同一身份重复绑定 / 由 pending 转正都收敛到 active + 当前 user_id。
    /// </summary>
    public void BindActive(string provider, string subject, string userId, string? email, string? displayName)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            INSERT INTO external_identities (provider, subject, user_id, email, display_name, status, created_at, approved_at)
            VALUES (@provider, @subject, @user_id, @email, @display_name, 'active', @now, @now)
            ON CONFLICT(provider, subject) DO UPDATE SET
                user_id = excluded.user_id,
                email = excluded.email,
                display_name = excluded.display_name,
                status = 'active',
                approved_at = @now",
            new { provider, subject, user_id = userId, email, display_name = displayName, now });
    }

    /// <summary>
    /// 每次外部登录后刷新该外部账号的名字 / 头像快照（§十九）：供用户手动「用这个账号的头像 / 昵称」，
    /// 以及审批时给新用户补空。传 null 的字段保持原值。
    /// </summary>
    public void UpdateSnapshot(string provider, string subject, string? displayName, string? avatarFile)
    {
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            UPDATE external_identities SET
                display_name = COALESCE(@n, display_name),
                avatar = COALESCE(@a, avatar)
            WHERE provider = @provider AND subject = @subject",
            new { provider, subject, n = string.IsNullOrWhiteSpace(displayName) ? null : displayName.Trim(), a = avatarFile });
    }

    /// <summary>管理员批准 pending 申请：绑定到 userId 并置 active。只对 pending 行生效。</summary>
    public bool Approve(string provider, string subject, string userId)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        return conn.Execute(@"
            UPDATE external_identities
            SET user_id = @user_id, status = 'active', approved_at = @now
            WHERE provider = @provider AND subject = @subject AND status = 'pending'",
            new { provider, subject, user_id = userId, now }) > 0;
    }

    /// <summary>管理员拒绝 pending 申请。行保留（status='rejected'），防止反复申请刷屏。</summary>
    public bool Reject(string provider, string subject)
    {
        using var conn = _db.OpenConnection();
        return conn.Execute(@"
            UPDATE external_identities
            SET status = 'rejected'
            WHERE provider = @provider AND subject = @subject AND status = 'pending'",
            new { provider, subject }) > 0;
    }

    /// <summary>待批列表（审批页用），按申请时间升序。</summary>
    public IReadOnlyList<ExternalIdentityRow> ListPending()
    {
        using var conn = _db.OpenConnection();
        return conn.Query<ExternalIdentityRow>(
            $"SELECT {Cols} FROM external_identities WHERE status = 'pending' ORDER BY created_at ASC").AsList();
    }

    /// <summary>已拒绝列表（审批页 Rejected 区块用），按申请时间倒序。</summary>
    public IReadOnlyList<ExternalIdentityRow> ListRejected()
    {
        using var conn = _db.OpenConnection();
        return conn.Query<ExternalIdentityRow>(
            $"SELECT {Cols} FROM external_identities WHERE status = 'rejected' ORDER BY created_at DESC").AsList();
    }
    /// <summary>某用户已绑定的外部身份（账号绑定页用）。</summary>
    public IReadOnlyList<ExternalIdentityRow> ListByUser(string userId)
    {
        using var conn = _db.OpenConnection();
        return conn.Query<ExternalIdentityRow>(
            $"SELECT {Cols} FROM external_identities WHERE user_id = @id ORDER BY provider ASC",
            new { id = userId }).AsList();
    }

    /// <summary>解绑 / 删除一条身份记录。</summary>
    public void Delete(string provider, string subject)
    {
        using var conn = _db.OpenConnection();
        conn.Execute(
            "DELETE FROM external_identities WHERE provider = @provider AND subject = @subject",
            new { provider, subject });
    }

    /// <summary>删除用户时清理其全部外部身份（UserRepository.Delete 的姊妹操作）。</summary>
    public void DeleteByUser(string userId)
    {
        using var conn = _db.OpenConnection();
        conn.Execute("DELETE FROM external_identities WHERE user_id = @id", new { id = userId });
    }
}
