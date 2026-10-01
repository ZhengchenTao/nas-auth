using Dapper;

namespace NasAuth.Data.Repositories;

/// <summary>
/// 预绑定邮箱（external-auth.md §十八）：email（小写）→ user_id。
/// 日后首次用 Google 登录、且 Google 声明该邮箱已验证的外部身份，直接绑到 user_id，不进待批；用一次即删。
/// </summary>
public class ExternalInviteRepository
{
    private readonly AuthDb _db;
    public ExternalInviteRepository(AuthDb db) => _db = db;

    /// <summary>登记。邮箱已被别的（或同一个）用户登记过返回 false。</summary>
    public bool Add(string email, string userId, string? createdBy)
    {
        var normalized = UserRepository.NormalizeEmail(email);
        if (string.IsNullOrEmpty(normalized)) return false;
        using var conn = _db.OpenConnection();
        return conn.Execute(@"
            INSERT INTO external_invites (email, user_id, created_at, created_by)
            VALUES (@email, @user_id, @now, @by)
            ON CONFLICT(email) DO NOTHING",
            new { email = normalized, user_id = userId, now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), by = createdBy }) == 1;
    }

    public IReadOnlyList<ExternalInviteRow> ListByUser(string userId)
    {
        using var conn = _db.OpenConnection();
        return conn.Query<ExternalInviteRow>(
            "SELECT email, user_id, created_at, created_by FROM external_invites WHERE user_id = @id ORDER BY created_at",
            new { id = userId }).AsList();
    }

    /// <summary>
    /// 取出并删除（一次性）。用 DELETE … RETURNING 原子完成：两个并发登录不会把同一条预绑定用两次。
    /// </summary>
    public ExternalInviteRow? Consume(string email)
    {
        var normalized = UserRepository.NormalizeEmail(email);
        if (string.IsNullOrEmpty(normalized)) return null;
        using var conn = _db.OpenConnection();
        return conn.QuerySingleOrDefault<ExternalInviteRow>(
            "DELETE FROM external_invites WHERE email = @email RETURNING email, user_id, created_at, created_by",
            new { email = normalized });
    }

    /// <summary>撤销某个用户名下的一条预绑定；不属于该用户返回 false。</summary>
    public bool Delete(string email, string userId)
    {
        using var conn = _db.OpenConnection();
        return conn.Execute("DELETE FROM external_invites WHERE email = @email AND user_id = @id",
            new { email = UserRepository.NormalizeEmail(email), id = userId }) == 1;
    }

    /// <summary>删除用户时连带清掉（同 identities / user_resources）。</summary>
    public void DeleteByUser(string userId)
    {
        using var conn = _db.OpenConnection();
        conn.Execute("DELETE FROM external_invites WHERE user_id = @id", new { id = userId });
    }
}
