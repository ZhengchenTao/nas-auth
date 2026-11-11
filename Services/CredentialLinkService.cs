using System.Security.Cryptography;
using System.Text;
using Dapper;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

public sealed record CredentialLinkRow(string id, string user_id, string purpose, long created_at,
    long expires_at, string state, long? used_at, string created_by, string stamp);
public sealed record IssuedCredentialLink(string Id, string Token, string UserId, string Purpose, long ExpiresAt);

/// <summary>Administrator-assisted, expiring, one-use local credential setup. No email or external identities are changed.</summary>
public sealed class CredentialLinkService(AuthDb db, CredentialLinkOptions options, PasswordLoginGate passwords, TimeProvider time)
{
    private long Now => time.GetUtcNow().ToUnixTimeSeconds();
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static string Stamp(UserRow user) => Hash(string.Join('\0', user.password_hash, user.session_epoch,
        user.session_version.ToString(), user.allow_password_login.ToString(), user.is_admin.ToString(), user.email ?? ""));

    public IssuedCredentialLink? Issue(string actor, string userId, string purpose = "recovery")
    {
        if (purpose is not ("invitation" or "recovery") || !passwords.Enabled) return null;
        using var c = db.OpenConnection(); using var tx = c.BeginTransaction(deferred: false);
        if (c.ExecuteScalar<long>("SELECT COUNT(*) FROM users WHERE user_id=@actor AND is_admin=1 AND is_disabled=0", new { actor }, tx) != 1) return null;
        var user = c.QuerySingleOrDefault<UserRow>($"SELECT {UserRepository.UserCols} FROM users WHERE user_id=@userId AND is_disabled=0 AND allow_password_login=1", new { userId }, tx);
        if (user is null) return null;
        var now = Now;
        var expiry = now + (purpose == "invitation" ? options.InvitationHours * 3600L : options.RecoveryMinutes * 60L);
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var id = Guid.NewGuid().ToString("N");
        c.Execute("UPDATE credential_links SET state='revoked' WHERE user_id=@userId AND state='pending'", new { userId }, tx);
        c.Execute("""
            INSERT INTO credential_links(id,token_hash,user_id,purpose,created_at,expires_at,state,created_by,stamp)
            VALUES(@id,@hash,@userId,@purpose,@now,@expiry,'pending',@actor,@stamp)
            """, new { id, hash = Hash(token), userId, purpose, now, expiry, actor, stamp = Stamp(user) }, tx);
        tx.Commit();
        return new(id, token, userId, purpose, expiry);
    }

    public IReadOnlyList<CredentialLinkRow> List(string userId)
    {
        using var c = db.OpenConnection();
        return c.Query<CredentialLinkRow>("""
            SELECT id,user_id,purpose,created_at,expires_at,state,
                used_at,created_by,stamp FROM credential_links WHERE user_id=@userId ORDER BY created_at DESC,rowid DESC LIMIT 20
            """, new { userId }).Select(row => row.state == "pending" && row.expires_at <= Now ? row with { state = "expired" } : row).ToList();
    }

    public bool Cancel(string actor, string userId, string id)
    {
        using var c = db.OpenConnection();
        return c.Execute("""
            UPDATE credential_links SET state='revoked' WHERE id=@id AND user_id=@userId AND state='pending'
            AND EXISTS(SELECT 1 FROM users WHERE user_id=@actor AND is_admin=1 AND is_disabled=0)
            """, new { actor, userId, id }) == 1;
    }

    public string? Redeem(string token, string password)
    {
        if (!passwords.Enabled || token.Length != 64 || !token.All(Uri.IsHexDigit) || password.Length is < 8 or > 256) return null;
        using var c = db.OpenConnection(); using var tx = c.BeginTransaction(deferred: false);
        var link = c.QuerySingleOrDefault<CredentialLinkRow>("""
            SELECT id,user_id,purpose,created_at,expires_at,state,used_at,created_by,stamp
            FROM credential_links WHERE token_hash=@hash AND state='pending' AND expires_at>@now
            """, new { hash = Hash(token), now = Now }, tx);
        if (link is null) return null;
        var user = c.QuerySingleOrDefault<UserRow>($"SELECT {UserRepository.UserCols} FROM users WHERE user_id=@id AND is_disabled=0 AND allow_password_login=1", new { id = link.user_id }, tx);
        if (user is null || Stamp(user) != link.stamp) return null;
        var hash = PasswordHasher.Hash(password);
        c.Execute("UPDATE credential_links SET state='used',used_at=@now WHERE id=@id", new { now = Now, link.id }, tx);
        c.Execute("""
            UPDATE users SET password_hash=@hash,must_change_password=0,failed_login_count=0,locked_until=NULL,
                session_version=session_version+1,session_epoch=@epoch,updated_at=@now WHERE user_id=@id;
            DELETE FROM refresh_tokens WHERE user_id=@id;
            DELETE FROM auth_codes WHERE user_id=@id;
            """, new { hash, epoch = Guid.NewGuid().ToString("N"), now = Now, id = user.user_id }, tx);
        tx.Commit();
        return user.user_id;
    }
}
