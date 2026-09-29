using Dapper;

namespace NasAuth.Data.Repositories;

public class RefreshTokenRepository
{
    private readonly AuthDb _db;
    public RefreshTokenRepository(AuthDb db) => _db = db;

    public void Insert(RefreshTokenRow row)
    {
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            INSERT INTO refresh_tokens (token_hash, client_id, resource, scope, user_id,
                                        expires_at, revoked, created_at, last_used_at)
            VALUES (@token_hash, @client_id, @resource, @scope, @user_id,
                    @expires_at, @revoked, @created_at, @last_used_at)", row);
    }

    public RefreshTokenRow? GetByHash(string tokenHash)
    {
        using var conn = _db.OpenConnection();
        return conn.QuerySingleOrDefault<RefreshTokenRow>(
            "SELECT * FROM refresh_tokens WHERE token_hash = @hash", new { hash = tokenHash });
    }

    /// <summary>
    /// rotation 原子：UPDATE WHERE revoked=0 AND expires_at>now，
    /// changes==1 才认作合法 + 已作废的当前 token。
    /// </summary>
    public bool RevokeIfActive(string tokenHash)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        var changes = conn.Execute(@"
            UPDATE refresh_tokens
            SET revoked = 1
            WHERE token_hash = @hash AND revoked = 0 AND expires_at > @now",
            new { hash = tokenHash, now });
        return changes == 1;
    }

    public void Revoke(string tokenHash)
    {
        using var conn = _db.OpenConnection();
        conn.Execute("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = @hash",
            new { hash = tokenHash });
    }

    public IReadOnlyList<RefreshTokenRow> ListActiveByUser(string userId)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        return conn.Query<RefreshTokenRow>(@"
            SELECT * FROM refresh_tokens
            WHERE user_id = @userId AND revoked = 0 AND expires_at > @now
            ORDER BY created_at DESC",
            new { userId, now }).AsList();
    }

    /// <summary>
    /// 用户在 /account 页吊销某个 client 在某 resource 下的所有 refresh token。
    /// </summary>
    public int RevokeByClientResource(string userId, string clientId, string resource)
    {
        using var conn = _db.OpenConnection();
        return conn.Execute(@"
            UPDATE refresh_tokens
            SET revoked = 1
            WHERE user_id = @userId AND client_id = @clientId AND resource = @resource AND revoked = 0",
            new { userId, clientId, resource });
    }

    /// <summary>吊销某用户的全部 refresh token（管理员「吊销全部授权」）。</summary>
    public int RevokeAllByUser(string userId)
    {
        using var conn = _db.OpenConnection();
        return conn.Execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = @userId AND revoked = 0",
            new { userId });
    }

    /// <summary>全部仍有效的 refresh token（管理后台统计用，量级是家用规模）。</summary>
    public IReadOnlyList<RefreshTokenRow> ListActiveAll()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        return conn.Query<RefreshTokenRow>(
            "SELECT * FROM refresh_tokens WHERE revoked = 0 AND expires_at > @now", new { now }).AsList();
    }

    public int CleanupExpired()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // 留 7 天的 revoked 记录用于审计
        var revokedCutoff = DateTimeOffset.UtcNow.AddDays(-7).ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        return conn.Execute(
            "DELETE FROM refresh_tokens WHERE expires_at < @now OR (revoked = 1 AND created_at < @cutoff)",
            new { now, cutoff = revokedCutoff });
    }
}
