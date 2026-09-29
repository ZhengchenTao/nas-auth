using System.Security.Claims;
using Dapper;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Endpoints;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// external-auth.md §十六：会话版本（服务端作废登录）、审计入库、管理员代管授权 / 删 DCR 客户端。
/// </summary>
public class AdminConsoleTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly AuthDb _db;
    private readonly UserRepository _users;

    public AdminConsoleTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
        _db = new AuthDb(new AuthOptions { Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}" });
        _db.EnsureCreated();
        _users = new UserRepository(_db);
        _users.Create("bob", "bob", PasswordHasher.Hash("temp-password"), mustChangePassword: false);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    private static ClaimsPrincipal Ticket(string userId, long? version)
    {
        var claims = new List<Claim> { new(ClaimTypes.Name, userId) };
        if (version is not null) claims.Add(new Claim(SessionValidator.ClaimType, version.Value.ToString()));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    // ---------------- 会话版本 ----------------

    [Fact]
    public void OldTicketWithoutVersion_StillValid_UntilBumped()
    {
        // 升级前发的 cookie 没有 nas_sv：按 0 算，不掉线
        Assert.True(SessionValidator.IsCurrent(Ticket("bob", null), _users.GetById("bob")));

        Assert.Equal(1, _users.BumpSessionVersion("bob"));
        Assert.False(SessionValidator.IsCurrent(Ticket("bob", null), _users.GetById("bob")));
        Assert.True(SessionValidator.IsCurrent(Ticket("bob", 1), _users.GetById("bob")));
    }

    [Fact]
    public void Bump_InvalidatesEveryOlderTicket()
    {
        _users.BumpSessionVersion("bob");
        _users.BumpSessionVersion("bob");
        var u = _users.GetById("bob");
        Assert.False(SessionValidator.IsCurrent(Ticket("bob", 0), u));
        Assert.False(SessionValidator.IsCurrent(Ticket("bob", 1), u));
        Assert.True(SessionValidator.IsCurrent(Ticket("bob", 2), u));
    }

    [Fact]
    public void DeletedUser_TicketInvalid()
    {
        _users.Delete("bob");
        Assert.False(SessionValidator.IsCurrent(Ticket("bob", 0), _users.GetById("bob")));
        Assert.Null(_users.BumpSessionVersion("bob"));
    }

    [Fact]
    public void OldDatabase_GainsSessionVersionColumn()
    {
        // §十四之前的老库：users 没有 session_version，EnsureCreated 补列，已有用户为 0
        var path = Path.Combine(_tmpDir, "old.db");
        using (var conn = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path}"))
        {
            conn.Open();
            conn.Execute(@"CREATE TABLE users (user_id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                INSERT INTO users VALUES ('admin','admin','h',1,1);");
        }
        var db = new AuthDb(new AuthOptions { Database = $"Data Source={path}" });
        db.EnsureCreated();
        Assert.Equal(0, new UserRepository(db).GetById("admin")!.session_version);
    }

    // ---------------- 审计入库 ----------------

    [Fact]
    public void Audit_InsertQueryFilter()
    {
        var audit = new AuditRepository(_db);
        audit.Insert("login", true, "bob", null, "1.2.3.4", "method=password");
        audit.Insert("external_login", false, "-", "-", "5.6.7.8", "method=google reason=pending");
        audit.Insert("account.user-create", true, "admin", null, null, "target=bob");
        audit.Insert("authorize", true, "bob", "claude", "1.2.3.4", null);

        Assert.Equal(4, audit.Query().Count);
        Assert.Equal("authorize", audit.Query()[0].@event); // 倒序

        var logins = audit.Query(events: DashboardSupport.LoginEvents);
        Assert.Equal(2, logins.Count);
        Assert.Null(logins.Single(r => r.@event == "external_login").user_id); // "-" 存成 NULL

        Assert.Single(audit.Query(eventPrefix: "account."));
        Assert.Equal(2, audit.Query(userId: "bob").Count);
        Assert.Single(audit.Query(failedOnly: true));

        var since = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
        Assert.Equal(1, audit.Count(DashboardSupport.LoginEvents, failedOnly: true, since));
    }

    [Fact]
    public void Audit_PurgeDropsOldRowsOnly()
    {
        var audit = new AuditRepository(_db);
        audit.Insert("login", true, "bob", null, null, null);
        using (var conn = _db.OpenConnection())
        {
            var old = DateTimeOffset.UtcNow.AddDays(-(AuditRepository.RetentionDays + 1)).ToUnixTimeSeconds();
            conn.Execute("INSERT INTO audit_log (ts, event, success) VALUES (@old, 'login', 1)", new { old });
        }
        Assert.Equal(1, audit.Purge());
        Assert.Single(audit.Query());
    }

    // ---------------- 代管授权 / 客户端 ----------------

    private static RefreshTokenRow Rt(string hash, string client, string user) =>
        new(hash, client, "https://res.example", "read:x", user,
            DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds(), 0, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), null);

    [Fact]
    public void RevokeAllByUser_OnlyThatUser()
    {
        var rt = new RefreshTokenRepository(_db);
        rt.Insert(Rt("h1", "c1", "bob"));
        rt.Insert(Rt("h2", "c2", "bob"));
        rt.Insert(Rt("h3", "c1", "admin"));
        Assert.Equal(2, rt.RevokeAllByUser("bob"));
        Assert.Empty(rt.ListActiveByUser("bob"));
        Assert.Single(rt.ListActiveByUser("admin"));
        Assert.Single(rt.ListActiveAll());
    }

    [Fact]
    public void DeleteAutoRegistered_CascadesAndSparesPreset()
    {
        var clients = new ClientRepository(_db);
        var rt = new RefreshTokenRepository(_db);
        clients.Insert("dcr1", null, "Grok", new[] { "https://grok.example/cb" }, "none", autoRegistered: true);
        clients.Insert("preset1", "h", "Immich", new[] { "https://photo.example/cb" }, "client_secret_post", autoRegistered: false);
        rt.Insert(Rt("h1", "dcr1", "bob"));
        rt.Insert(Rt("h2", "preset1", "bob"));

        Assert.False(clients.DeleteAutoRegistered("preset1"));
        Assert.NotNull(clients.GetById("preset1"));

        Assert.True(clients.DeleteAutoRegistered("dcr1"));
        Assert.Null(clients.GetById("dcr1"));
        Assert.Null(rt.GetByHash("h1"));
        Assert.NotNull(rt.GetByHash("h2"));
    }

    [Fact]
    public void AdminLanding_OnlyForDefaultTarget()
    {
        var admin = _users.GetById("bob")! with { is_admin = 1 };
        var user = _users.GetById("bob")!;
        Assert.Equal("/admin", DashboardSupport.LandingFor("/account", admin));
        Assert.Equal("/authorize?x=1", DashboardSupport.LandingFor("/authorize?x=1", admin));
        Assert.Equal("/account", DashboardSupport.LandingFor("/account", user));
    }
}
