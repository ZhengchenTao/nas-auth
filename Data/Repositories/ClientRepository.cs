using System.Text.Json;
using Dapper;
using NasAuth.Config;

namespace NasAuth.Data.Repositories;

public class ClientRepository
{
    private readonly AuthDb _db;
    public ClientRepository(AuthDb db) => _db = db;

    public ClientRow? GetById(string clientId)
    {
        using var conn = _db.OpenConnection();
        return conn.QuerySingleOrDefault<ClientRow>(
            "SELECT * FROM clients WHERE client_id = @id", new { id = clientId });
    }

    public IReadOnlyList<ClientRow> ListAll()
    {
        using var conn = _db.OpenConnection();
        return conn.Query<ClientRow>("SELECT * FROM clients ORDER BY created_at DESC").AsList();
    }

    /// <summary>
    /// DCR 注册：写入新 client。client_id / client_secret_hash 由调用方生成（hash 用 SHA-256 即可）。
    /// </summary>
    public void Insert(
        string clientId,
        string? clientSecretHash,
        string clientName,
        IEnumerable<string> redirectUris,
        string tokenEndpointAuthMethod,
        bool autoRegistered)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            INSERT INTO clients (client_id, client_secret_hash, client_name, redirect_uris,
                                 token_endpoint_auth_method, auto_registered, created_at)
            VALUES (@client_id, @client_secret_hash, @client_name, @redirect_uris,
                    @token_endpoint_auth_method, @auto_registered, @created_at)",
            new
            {
                client_id = clientId,
                client_secret_hash = clientSecretHash,
                client_name = clientName,
                redirect_uris = JsonSerializer.Serialize(redirectUris),
                token_endpoint_auth_method = tokenEndpointAuthMethod,
                auto_registered = autoRegistered ? 1 : 0,
                created_at = now,
            });
    }

    /// <summary>
    /// 预置 client upsert：相同 client_id 覆盖（除 created_at），auto_registered 强制 0。
    /// </summary>
    public void UpsertPreset(PresetClientConfig preset, string? secretHash)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            INSERT INTO clients (client_id, client_secret_hash, client_name, redirect_uris,
                                 token_endpoint_auth_method, auto_registered, created_at, default_resource)
            VALUES (@client_id, @client_secret_hash, @client_name, @redirect_uris,
                    @token_endpoint_auth_method, 0, @created_at, @default_resource)
            ON CONFLICT(client_id) DO UPDATE SET
                client_secret_hash = excluded.client_secret_hash,
                client_name = excluded.client_name,
                redirect_uris = excluded.redirect_uris,
                token_endpoint_auth_method = excluded.token_endpoint_auth_method,
                auto_registered = 0,
                default_resource = excluded.default_resource",
            new
            {
                client_id = preset.ClientId,
                client_secret_hash = secretHash,
                client_name = preset.ClientName,
                redirect_uris = JsonSerializer.Serialize(preset.RedirectUris),
                token_endpoint_auth_method = preset.TokenEndpointAuthMethod,
                created_at = now,
                default_resource = preset.DefaultResource,
            });
    }

    public void TouchLastUsed(string clientId)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute("UPDATE clients SET last_used_at = @now WHERE client_id = @id",
            new { now, id = clientId });
    }

    /// <summary>
    /// 后台清理：auto_registered=1 且 30 天内未用过的 client（last_used_at 为 NULL 用 created_at 兜底）。
    /// 但保留还持有未过期 refresh_token 的 client：否则 client 比它签发的 refresh token（90 天）
    /// 死得早，下一次静默续期会因查不到 client 而 client_auth_failed，把 connector 永久打挂
    /// （TouchLastUsed 只在续期成功时刷，续期一旦断一次就再也不被 touch → 30 天后被清 → 死循环）。
    /// </summary>
    public int CleanupStale(TimeSpan staleThreshold)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var cutoff = DateTimeOffset.UtcNow.Subtract(staleThreshold).ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        return conn.Execute(@"
            DELETE FROM clients
            WHERE auto_registered = 1
              AND COALESCE(last_used_at, created_at) < @cutoff
              AND NOT EXISTS (
                  SELECT 1 FROM refresh_tokens rt
                  WHERE rt.client_id = clients.client_id
                    AND rt.revoked = 0
                    AND rt.expires_at > @now)",
            new { cutoff, now });
    }

    /// <summary>
    /// 管理员手动删除一个 DCR 自助注册的客户端，连带它的 refresh token 与授权码。
    /// 预置客户端（auto_registered=0）不删 —— 它由 clients.preset.json 管，删了下次启动又会 upsert 回来。
    /// 返回是否删掉。
    /// </summary>
    public bool DeleteAutoRegistered(string clientId)
    {
        using var conn = _db.OpenConnection();
        using var tx = conn.BeginTransaction();
        var n = conn.Execute("DELETE FROM clients WHERE client_id = @id AND auto_registered = 1", new { id = clientId }, tx);
        if (n == 0) { tx.Rollback(); return false; }
        conn.Execute("DELETE FROM refresh_tokens WHERE client_id = @id", new { id = clientId }, tx);
        conn.Execute("DELETE FROM auth_codes WHERE client_id = @id", new { id = clientId }, tx);
        tx.Commit();
        return true;
    }

    public static List<string> ParseRedirectUris(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return new();
        try { return JsonSerializer.Deserialize<List<string>>(raw) ?? new(); }
        catch { return new(); }
    }
}
