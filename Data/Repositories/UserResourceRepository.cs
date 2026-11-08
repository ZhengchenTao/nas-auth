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
        return Merge(conn.Query<UserResourceRow>(
            "SELECT user_id, aud, scopes FROM resource_grant_sources WHERE user_id=@id AND aud=@aud",
            new { id = userId, aud })).SingleOrDefault();
    }

    public IReadOnlyList<UserResourceRow> ListByUser(string userId)
    {
        using var conn = _db.OpenConnection();
        return conn.Query<UserResourceRow>(
            "SELECT user_id, aud, scopes FROM user_resources WHERE user_id = @id ORDER BY aud ASC",
            new { id = userId }).AsList();
    }

    public IReadOnlyList<UserResourceRow> ListEffectiveByUser(string userId)
    {
        using var conn = _db.OpenConnection();
        return Effective(conn, userId, null);
    }

    internal static IReadOnlyList<UserResourceRow> Effective(Microsoft.Data.Sqlite.SqliteConnection conn,
        string userId, System.Data.IDbTransaction? transaction, string? excludeGroup = null) =>
        Merge(conn.Query<UserResourceRow>("""
            SELECT user_id,aud,scopes FROM resource_grant_sources
            WHERE user_id=@userId AND (group_id IS NULL OR @excludeGroup IS NULL OR group_id<>@excludeGroup)
            """, new { userId, excludeGroup }, transaction));

    internal static IReadOnlyList<UserResourceRow> Merge(IEnumerable<UserResourceRow> rows) => rows
        .GroupBy(r => (r.user_id, r.aud))
        .OrderBy(g => g.Key.aud, StringComparer.Ordinal)
        .Select(g => new UserResourceRow(g.Key.user_id, g.Key.aud, string.Join(' ', g
            .SelectMany(r => r.scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))))
        .ToList();

    /// <summary>每个资源被授予了几个用户（应用与资源页用）。</summary>
    public IReadOnlyDictionary<string, int> CountByAud()
    {
        using var conn = _db.OpenConnection();
        return conn.Query<(string aud, long n)>("SELECT aud, COUNT(DISTINCT user_id) FROM resource_grant_sources GROUP BY aud")
            .ToDictionary(r => r.aud, r => (int)r.n);
    }

    public IReadOnlyDictionary<string, IReadOnlyList<string>> UserIdsByAud()
    {
        using var conn = _db.OpenConnection();
        return conn.Query<(string aud, string user_id)>("SELECT DISTINCT aud, user_id FROM resource_grant_sources ORDER BY user_id")
            .GroupBy(r => r.aud).ToDictionary(g => g.Key,
                g => (IReadOnlyList<string>)g.Select(r => r.user_id).ToList());
    }

    public void Upsert(string userId, string aud, string scopes)
    {
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            INSERT INTO user_resources (user_id, aud, scopes) VALUES (@user_id, @aud, @scopes)
            ON CONFLICT(user_id, aud) DO UPDATE SET scopes = excluded.scopes",
            new { user_id = userId, aud, scopes });
    }

    /// <summary>Replace a whole editor submission atomically, including provisioning invalidations.</summary>
    public void Replace(string userId, IReadOnlyDictionary<string, string> grants)
    {
        using var conn = _db.OpenConnection();
        using var tx = conn.BeginTransaction();
        conn.Execute("DELETE FROM user_resources WHERE user_id=@userId", new { userId }, tx);
        foreach (var (aud, scopes) in grants)
            conn.Execute("INSERT INTO user_resources(user_id,aud,scopes) VALUES(@userId,@aud,@scopes)", new { userId, aud, scopes }, tx);
        tx.Commit();
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
