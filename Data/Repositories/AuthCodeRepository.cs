using Dapper;

namespace NasAuth.Data.Repositories;

public class AuthCodeRepository
{
    private readonly AuthDb _db;
    public AuthCodeRepository(AuthDb db) => _db = db;

    public void Insert(AuthCodeRow row)
    {
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            INSERT INTO auth_codes (code, client_id, resource, scope, redirect_uri,
                                    code_challenge, code_challenge_method, user_id,
                                    expires_at, consumed, created_at, nonce)
            VALUES (@code, @client_id, @resource, @scope, @redirect_uri,
                    @code_challenge, @code_challenge_method, @user_id,
                    @expires_at, @consumed, @created_at, @nonce)", row);
    }

    /// <summary>
    /// 原子消费授权码：UPDATE ... WHERE consumed=0，再返回行 —— 授权码只能用一次。
    /// changes==1 才表示真消费成功；0 说明已被消费过 / 不存在 / 已过期。
    /// </summary>
    public AuthCodeRow? ConsumeAtomic(string code)
    {
        using var conn = _db.OpenConnection();
        using var tx = conn.BeginTransaction();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var changes = conn.Execute(@"
            UPDATE auth_codes
            SET consumed = 1
            WHERE code = @code AND consumed = 0 AND expires_at > @now",
            new { code, now }, tx);

        if (changes != 1)
        {
            tx.Rollback();
            return null;
        }

        var row = conn.QuerySingle<AuthCodeRow>(
            "SELECT * FROM auth_codes WHERE code = @code", new { code }, tx);
        tx.Commit();
        return row;
    }

    public int CleanupExpired()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        // 已消费的也清理掉，留 1 天审计窗口
        var keepConsumed = DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds();
        return conn.Execute(
            "DELETE FROM auth_codes WHERE expires_at < @now OR (consumed = 1 AND created_at < @keep)",
            new { now, keep = keepConsumed });
    }
}
