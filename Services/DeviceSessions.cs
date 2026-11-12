using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Microsoft.Data.Sqlite;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

public sealed class DeviceSessionRow
{
    public string id { get; set; } = "";
    public string user_id { get; set; } = "";
    public string? name { get; set; }
    public string browser { get; set; } = "";
    public string platform { get; set; } = "";
    public string last_ip { get; set; } = "";
    public long created_at { get; set; }
    public long last_seen_at { get; set; }
    public long expires_at { get; set; }
    public long? revoked_at { get; set; }
    public long session_version { get; set; }
    public string session_epoch { get; set; } = "";
    public long? legacy_cookie_expires_at { get; set; }
}

/// <summary>Server-owned browser sessions. Session IDs alone are not bearer credentials.</summary>
public sealed class DeviceSessions(AuthDb db, DeviceSessionOptions options, TimeProvider time)
{
    public const string ClaimType = "nas_sid";
    private long Now => time.GetUtcNow().ToUnixTimeSeconds();
    public static string? CurrentId(ClaimsPrincipal? principal) => principal?.FindFirst(ClaimType)?.Value;
    public long EffectiveExpiry(DeviceSessionRow row) => Math.Min(row.expires_at,
        Math.Min(row.last_seen_at + options.IdleHours * 3600L, options.AbsoluteHours == 0 ? long.MaxValue : row.created_at + options.AbsoluteHours * 3600L));
    public bool Available(DeviceSessionRow row) => row.revoked_at is null && EffectiveExpiry(row) > Now;
    private bool Current(DeviceSessionRow? row, UserRow? user) => row is not null && user is { is_disabled: 0 }
        && row.user_id == user.user_id && row.revoked_at is null && row.session_version == user.session_version
        && row.session_epoch == user.session_epoch && EffectiveExpiry(row) > Now;
    private static UserRow? User(SqliteConnection c, string id, SqliteTransaction? tx = null) =>
        c.QuerySingleOrDefault<UserRow>($"SELECT {UserRepository.UserCols} FROM users WHERE user_id=@id AND is_disabled=0", new { id }, tx);
    private static DeviceSessionRow? Get(SqliteConnection c, string id, SqliteTransaction? tx = null) =>
        c.QuerySingleOrDefault<DeviceSessionRow>("SELECT * FROM device_sessions WHERE id=@id", new { id }, tx);

    public string? SignIn(HttpContext context, UserRow proof, bool freshAuthentication)
    {
        using var c = db.OpenConnection(); using var tx = c.BeginTransaction(deferred: false);
        var user = User(c, proof.user_id, tx);
        if (user is null || user.session_version != proof.session_version || user.session_epoch != proof.session_epoch
            || user.password_hash != proof.password_hash) return null;
        var currentId = context.User.Identity?.Name == user.user_id ? CurrentId(context.User) : null;
        if (currentId is not null && Current(Get(c, currentId, tx), user)) { tx.Commit(); return currentId; }
        // A revoked authenticated cookie may not silently create a replacement during consent.
        if (!freshAuthentication) return null;
        var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        Insert(c, tx, context, user, id, null);
        tx.Commit(); return id;
    }

    public string? AdoptLegacy(HttpContext context, UserRow user, string protectedCookie, DateTimeOffset? cookieExpiry)
    {
        if (string.IsNullOrEmpty(protectedCookie) || cookieExpiry is null || cookieExpiry <= time.GetUtcNow()) return null;
        // Deterministic for the same old signed cookie: its replay cannot create another session after revocation.
        var id = "legacy-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(protectedCookie))).ToLowerInvariant();
        using var c = db.OpenConnection(); using var tx = c.BeginTransaction(deferred: false);
        var current = User(c, user.user_id, tx);
        if (current is null || current.session_version != user.session_version || current.session_epoch != user.session_epoch) return null;
        if (Get(c, id, tx) is null) Insert(c, tx, context, user, id, cookieExpiry?.ToUnixTimeSeconds() ?? Now + options.IdleHours * 3600L);
        if (!Current(Get(c, id, tx), current)) return null;
        tx.Commit(); return id;
    }

    private void Insert(SqliteConnection c, SqliteTransaction tx, HttpContext context, UserRow user, string id, long? legacyExpiry)
    {
        var (browser, platform) = Describe(context);
        var now = Now;
        var expiry = Math.Min(now + options.IdleHours * 3600L, options.AbsoluteHours == 0 ? long.MaxValue : now + options.AbsoluteHours * 3600L);
        c.Execute("""
            INSERT INTO device_sessions(id,user_id,browser,platform,last_ip,created_at,last_seen_at,expires_at,session_version,session_epoch,legacy_cookie_expires_at)
            VALUES(@id,@userId,@browser,@platform,@ip,@now,@now,@expiry,@version,@epoch,@legacyExpiry)
            """, new { id, userId = user.user_id, browser, platform, ip = Ip(context), now, expiry,
                version = user.session_version, epoch = user.session_epoch, legacyExpiry }, tx);
    }

    private static string Ip(HttpContext context) => context.Connection.RemoteIpAddress?.ToString() ?? "";
    private static (string Browser, string Platform) Describe(HttpContext context)
    {
        var agent = context.Request.Headers.UserAgent.ToString();
        var browser = agent.Contains("Edg/") || agent.Contains("EdgA/") || agent.Contains("EdgiOS/") ? "Edge"
            : agent.Contains("Firefox/") || agent.Contains("FxiOS/") ? "Firefox"
            : agent.Contains("Chrome/") || agent.Contains("CriOS/") ? "Chrome"
            : agent.Contains("Safari/") ? "Safari" : "Unknown browser";
        var platform = agent.Contains("Android") ? "Android" : agent.Contains("iPhone") ? "iPhone" : agent.Contains("iPad") ? "iPad"
            : agent.Contains("Windows") ? "Windows" : agent.Contains("Macintosh") ? "macOS" : agent.Contains("Linux") ? "Linux" : "Unknown device";
        return (browser, platform);
    }

    public bool Validate(string id, string userId, HttpContext? browserContext = null, bool touch = false)
    {
        using var c = db.OpenConnection();
        var row = c.QuerySingleOrDefault<DeviceSessionRow>("""
            SELECT d.* FROM device_sessions d JOIN users u ON u.user_id=d.user_id
            WHERE d.id=@id AND d.user_id=@userId AND u.is_disabled=0
                AND d.session_version=u.session_version AND d.session_epoch=u.session_epoch
            """, new { id, userId });
        if (row is null || row.revoked_at is not null || EffectiveExpiry(row) <= Now) return false;
        // A proxy subrequest may migrate an old cookie without a User-Agent. Fill only missing
        // labels on a later browser request, even within the activity-write throttle window.
        // Token requests have no browserContext; neither they nor stripped headers erase labels.
        if (touch && browserContext is not null && (row.browser == "Unknown browser" || row.platform == "Unknown device"))
        {
            var (browser, platform) = Describe(browserContext);
            if ((row.browser == "Unknown browser" && browser != "Unknown browser") ||
                (row.platform == "Unknown device" && platform != "Unknown device"))
                c.Execute("""
                    UPDATE device_sessions SET
                        browser=CASE WHEN browser='Unknown browser' THEN @browser ELSE browser END,
                        platform=CASE WHEN platform='Unknown device' THEN @platform ELSE platform END
                    WHERE id=@id AND user_id=@userId AND revoked_at IS NULL AND session_version=@version AND session_epoch=@epoch
                    """, new { browser, platform, id, userId, version = row.session_version, epoch = row.session_epoch });
        }
        if (touch && row!.last_seen_at <= Now - 60)
        {
            var now = Now;
            var expiry = Math.Min(now + options.IdleHours * 3600L, options.AbsoluteHours == 0 ? long.MaxValue : row.created_at + options.AbsoluteHours * 3600L);
            c.Execute("""
                UPDATE device_sessions SET last_seen_at=@now,expires_at=@expiry,last_ip=COALESCE(@ip,last_ip)
                WHERE id=@id AND user_id=@userId AND revoked_at IS NULL AND session_version=@version AND session_epoch=@epoch
                """, new { now, expiry, ip = browserContext is null ? null : Ip(browserContext), id, userId, version = row.session_version, epoch = row.session_epoch });
        }
        return true;
    }

    public bool CredentialIsActive(string? id, string userId, bool touch = false) => id is null || Validate(id, userId, touch: touch);
    public IReadOnlyList<DeviceSessionRow> List(string userId)
    {
        using var c = db.OpenConnection();
        return c.Query<DeviceSessionRow>("SELECT * FROM device_sessions WHERE user_id=@userId ORDER BY (revoked_at IS NULL) DESC,last_seen_at DESC,id LIMIT 50", new { userId }).AsList();
    }
    public bool Rename(string userId, string id, string name)
    {
        name = name.Trim(); if (name.Length is < 1 or > 64 || name.Any(char.IsControl)) return false;
        using var c = db.OpenConnection();
        return c.Execute("UPDATE device_sessions SET name=@name WHERE id=@id AND user_id=@userId AND revoked_at IS NULL", new { name, id, userId }) == 1;
    }
    public bool Revoke(string userId, string id)
    {
        using var c = db.OpenConnection(); using var tx = c.BeginTransaction(deferred: false);
        var n = c.Execute("UPDATE device_sessions SET revoked_at=@now WHERE id=@id AND user_id=@userId AND revoked_at IS NULL", new { now = Now, id, userId }, tx);
        if (n == 0) return false;
        c.Execute("UPDATE refresh_tokens SET revoked=1 WHERE user_id=@userId AND session_id=@id; DELETE FROM auth_codes WHERE user_id=@userId AND session_id=@id", new { userId, id }, tx);
        tx.Commit(); return true;
    }

    public bool RevokeOthers(string userId, string currentId)
    {
        using var c = db.OpenConnection(); using var tx = c.BeginTransaction(deferred: false);
        var user = User(c, userId, tx);
        if (!Current(Get(c, currentId, tx), user)) return false;
        // The existing version invalidates not-yet-migrated legacy cookies too. Preserve this exact device atomically.
        c.Execute("UPDATE users SET session_version=session_version+1 WHERE user_id=@userId", new { userId }, tx);
        c.Execute("UPDATE device_sessions SET revoked_at=NULL,session_version=@version WHERE id=@currentId AND user_id=@userId", new { version = user!.session_version + 1, currentId, userId }, tx);
        c.Execute("""
            UPDATE refresh_tokens SET revoked=1 WHERE user_id=@userId AND (session_id IS NULL OR session_id<>@currentId);
            DELETE FROM auth_codes WHERE user_id=@userId AND (session_id IS NULL OR session_id<>@currentId);
            """, new { userId, currentId }, tx);
        tx.Commit(); return true;
    }

    public int Cleanup()
    {
        using var c = db.OpenConnection();
        return c.Execute("DELETE FROM device_sessions WHERE expires_at<@cutoff AND (legacy_cookie_expires_at IS NULL OR legacy_cookie_expires_at<@now)",
            new { cutoff = Now - 90 * 86400L, now = Now });
    }
}
