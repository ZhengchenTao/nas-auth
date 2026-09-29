using Dapper;

namespace NasAuth.Data.Repositories;

/// <summary>
/// user_resources 表（外部认证设计 §四）：(user, aud) → 授予的最大 scope（空格分隔）。
/// /authorize 的用户级授权检查（P4）：行存在 且 请求 scope ⊆ 授予 scopes，否则 access_denied。
/// </summary>
public class UserResourceRepository
{
    private readonly AuthDb _db;
    public UserResourceRepository(AuthDb db) => _db = db;

    public UserResourceRow? Get(string userId, string aud)
    {
        using var conn = _db.OpenConnection();
        return conn.QuerySingleOrDefault<UserResourceRow>(
            "SELECT user_id, aud, scopes FROM user_resources WHERE user_id = @id AND aud = @aud",
            new { id = userId, aud });
    }

    public IReadOnlyList<UserResourceRow> ListByUser(string userId)
    {
        using var conn = _db.OpenConnection();
        return conn.Query<UserResourceRow>(
            "SELECT user_id, aud, scopes FROM user_resources WHERE user_id = @id ORDER BY aud ASC",
            new { id = userId }).AsList();
    }

    /// <summary>每个资源被授予了几个用户（应用与资源页用）。</summary>
    public IReadOnlyDictionary<string, int> CountByAud()
    {
        using var conn = _db.OpenConnection();
        return conn.Query<(string aud, long n)>("SELECT aud, COUNT(*) FROM user_resources GROUP BY aud")
            .ToDictionary(r => r.aud, r => (int)r.n);
    }

    public void Upsert(string userId, string aud, string scopes)
    {
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            INSERT INTO user_resources (user_id, aud, scopes) VALUES (@user_id, @aud, @scopes)
            ON CONFLICT(user_id, aud) DO UPDATE SET scopes = excluded.scopes",
            new { user_id = userId, aud, scopes });
    }

    /// <summary>撤销某用户对某 aud 的授权。</summary>
    public void Delete(string userId, string aud)
    {
        using var conn = _db.OpenConnection();
        conn.Execute(
            "DELETE FROM user_resources WHERE user_id = @id AND aud = @aud",
            new { id = userId, aud });
    }

    /// <summary>删除用户时清理其全部授权（UserRepository.Delete 的姊妹操作）。</summary>
    public void DeleteByUser(string userId)
    {
        using var conn = _db.OpenConnection();
        conn.Execute("DELETE FROM user_resources WHERE user_id = @id", new { id = userId });
    }

    /// <summary>
    /// 检查请求 scope 是否落在授权范围内：行存在 且 requestedScopes ⊆ 授予 scopes。
    /// 空请求（不带 scope）只要求行存在。
    /// </summary>
    public bool IsAllowed(string userId, string aud, IEnumerable<string> requestedScopes)
    {
        var row = Get(userId, aud);
        if (row is null) return false;
        var granted = row.scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
        return requestedScopes.All(granted.Contains);
    }
}
