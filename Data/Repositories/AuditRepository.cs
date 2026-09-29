using Dapper;

namespace NasAuth.Data.Repositories;

/// <summary>
/// 审计事件入库（external-auth.md §十六）。只由 <see cref="NasAuth.Services.AuditLogger"/> 写，
/// 后台「审计日志」「最近登录」读。单例安全：每次调用自己开连接。
/// </summary>
public class AuditRepository
{
    public const int RetentionDays = 90;

    private readonly AuthDb _db;
    public AuditRepository(AuthDb db) => _db = db;

    public void Insert(string @event, bool success, string? userId, string? clientId, string? ip, string? detail)
    {
        using var conn = _db.OpenConnection();
        conn.Execute(@"
            INSERT INTO audit_log (ts, event, success, user_id, client_id, ip, detail)
            VALUES (@ts, @event, @success, @user_id, @client_id, @ip, @detail)",
            new
            {
                ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                @event,
                success = success ? 1 : 0,
                user_id = NullIfDash(userId),
                client_id = NullIfDash(clientId),
                ip = NullIfDash(ip),
                detail = NullIfDash(detail),
            });
    }

    /// <summary>
    /// 查询。<paramref name="eventPrefix"/>：按事件前缀筛（"login" 同时命中 login 与 external_login 由调用方传多个）；
    /// <paramref name="userId"/> 精确匹配；<paramref name="failedOnly"/> 只看失败。按时间倒序。
    /// </summary>
    public IReadOnlyList<AuditRow> Query(IReadOnlyCollection<string>? events = null, string? eventPrefix = null,
        string? userId = null, bool failedOnly = false, long? since = null, int limit = 200)
    {
        var where = new List<string>();
        var p = new DynamicParameters();
        if (events is { Count: > 0 }) { where.Add("event IN @events"); p.Add("events", events); }
        if (!string.IsNullOrEmpty(eventPrefix)) { where.Add("event LIKE @prefix"); p.Add("prefix", eventPrefix + "%"); }
        if (!string.IsNullOrEmpty(userId)) { where.Add("user_id = @user"); p.Add("user", userId); }
        if (failedOnly) where.Add("success = 0");
        if (since is not null) { where.Add("ts >= @since"); p.Add("since", since); }
        p.Add("limit", limit);
        var sql = "SELECT id, ts, event, success, user_id, client_id, ip, detail FROM audit_log" +
                  (where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : "") +
                  " ORDER BY id DESC LIMIT @limit";
        using var conn = _db.OpenConnection();
        return conn.Query<AuditRow>(sql, p).AsList();
    }

    public int Count(IReadOnlyCollection<string> events, bool failedOnly, long since)
    {
        using var conn = _db.OpenConnection();
        return conn.ExecuteScalar<int>(
            "SELECT COUNT(*) FROM audit_log WHERE event IN @events AND ts >= @since" + (failedOnly ? " AND success = 0" : ""),
            new { events, since });
    }

    /// <summary>清掉 <see cref="RetentionDays"/> 天前的记录（TokenCleanupService 每小时调）。</summary>
    public int Purge()
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-RetentionDays).ToUnixTimeSeconds();
        using var conn = _db.OpenConnection();
        return conn.Execute("DELETE FROM audit_log WHERE ts < @cutoff", new { cutoff });
    }

    private static string? NullIfDash(string? s) => string.IsNullOrEmpty(s) || s == "-" ? null : s;
}
