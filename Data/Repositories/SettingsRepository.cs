using Dapper;

namespace NasAuth.Data.Repositories;

public class SettingsRepository
{
    private readonly AuthDb _db;
    public SettingsRepository(AuthDb db) => _db = db;

    public string? Get(string key)
    {
        using var conn = _db.OpenConnection();
        return conn.QuerySingleOrDefault<string>(
            "SELECT value FROM settings WHERE key = @key", new { key });
    }

    public void Set(string key, string value)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            INSERT INTO settings (key, value, updated_at) VALUES (@key, @value, @now)
            ON CONFLICT(key) DO UPDATE SET value = @value, updated_at = @now",
            new { key, value, now });
    }

    public void Delete(string key)
    {
        using var conn = _db.OpenConnection();
        conn.Execute("DELETE FROM settings WHERE key = @key", new { key });
    }
}
