using Dapper;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Endpoints;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// external-auth.md §十四 统一账号中心：按用户的密码登录开关、按账号失败锁定、users.email、老库升级。
/// </summary>
public class UnifiedAccountTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly AuthDb _db;
    private readonly UserRepository _users;
    private readonly SettingsRepository _settings;

    // 典型形态：Google / 微软都配了（防锁死兜底不生效），总闸由各用例决定
    private static readonly ExternalProviderOptions ProvidersOn = new()
    {
        GoogleClientId = "g", GoogleClientSecret = "g", MicrosoftClientId = "m", MicrosoftClientSecret = "m",
    };

    public UnifiedAccountTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
        _db = new AuthDb(new AuthOptions { Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}" });
        _db.EnsureCreated();
        _users = new UserRepository(_db);
        _settings = new SettingsRepository(_db);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    private PasswordSignIn SignIn(bool masterSwitch = true, ExternalProviderOptions? providers = null)
    {
        var auth = new AuthOptions { PasswordLogin = new PasswordLoginOptions { Enabled = masterSwitch } };
        return new PasswordSignIn(_users, new PasswordLoginGate(auth, _settings, providers ?? ProvidersOn));
    }

    private void CreateUser(string id, string password, bool allowPassword, string? email = null)
        => _users.Create(id, id, PasswordHasher.Hash(password), mustChangePassword: false,
            email: email, allowPasswordLogin: allowPassword);

    // ---------------- 按用户开关 ----------------

    [Fact]
    public void AllowedUser_CorrectPassword_Ok()
    {
        CreateUser("carol", "correct-horse", allowPassword: true);
        var r = SignIn().Attempt("carol", "correct-horse");
        Assert.Equal(PasswordSignInStatus.Ok, r.Status);
        Assert.Equal("carol", r.User!.user_id);
    }

    [Fact]
    public void NotAllowedUser_CorrectPassword_LooksLikeWrongPassword_AndCountsAsFailure()
    {
        CreateUser("admin", "correct-horse", allowPassword: false);
        var r = SignIn().Attempt("admin", "correct-horse");
        Assert.Equal(PasswordSignInStatus.BadCredentials, r.Status);
        Assert.Equal("password_not_allowed_for_user", r.AuditReason);
        Assert.Equal(1, _users.GetById("admin")!.failed_login_count);
    }

    [Fact]
    public void MasterSwitchOff_EvenAllowedUserRejected()
    {
        CreateUser("carol", "correct-horse", allowPassword: true);
        var r = SignIn(masterSwitch: false).Attempt("carol", "correct-horse");
        Assert.Equal(PasswordSignInStatus.BadCredentials, r.Status);
    }

    [Fact]
    public void LockoutGuard_NoExternalProviders_AdminCanStillUsePassword()
    {
        // 没配任何外部 provider：不放行密码的话连管理员都进不来
        CreateUser("admin", "correct-horse", allowPassword: false);
        var r = SignIn(masterSwitch: false, providers: new ExternalProviderOptions()).Attempt("admin", "correct-horse");
        Assert.Equal(PasswordSignInStatus.Ok, r.Status);
    }

    [Fact]
    public void UnknownUser_BadCredentials()
    {
        var r = SignIn().Attempt("nobody", "whatever");
        Assert.Equal(PasswordSignInStatus.BadCredentials, r.Status);
        Assert.Null(r.User);
    }

    // ---------------- 按账号锁定 ----------------

    [Fact]
    public void TenFailures_LocksAccount_EvenCorrectPasswordThenRejected()
    {
        CreateUser("carol", "correct-horse", allowPassword: true);
        var signIn = SignIn();
        for (var i = 0; i < PasswordSignIn.FailureThreshold - 1; i++)
            Assert.Equal(PasswordSignInStatus.BadCredentials, signIn.Attempt("carol", "wrong").Status);

        var tenth = signIn.Attempt("carol", "wrong");
        Assert.Equal(PasswordSignInStatus.BadCredentials, tenth.Status);
        Assert.EndsWith("+locked", tenth.AuditReason);

        var row = _users.GetById("carol")!;
        Assert.NotNull(row.locked_until);
        Assert.Equal(0, row.failed_login_count); // 锁定时清零，解锁后重新数

        Assert.Equal(PasswordSignInStatus.Locked, signIn.Attempt("carol", "correct-horse").Status);
    }

    [Fact]
    public void LockExpired_CorrectPasswordOk_AndClearsLock()
    {
        CreateUser("carol", "correct-horse", allowPassword: true);
        using (var conn = _db.OpenConnection())
            conn.Execute("UPDATE users SET locked_until = @t, failed_login_count = 3 WHERE user_id = 'carol'",
                new { t = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 1 });

        Assert.Equal(PasswordSignInStatus.Ok, SignIn().Attempt("carol", "correct-horse").Status);
        var row = _users.GetById("carol")!;
        Assert.Null(row.locked_until);
        Assert.Equal(0, row.failed_login_count);
    }

    [Fact]
    public void Success_ResetsFailureCounter()
    {
        CreateUser("carol", "correct-horse", allowPassword: true);
        var signIn = SignIn();
        signIn.Attempt("carol", "wrong");
        signIn.Attempt("carol", "wrong");
        Assert.Equal(2, _users.GetById("carol")!.failed_login_count);

        signIn.Attempt("carol", "correct-horse");
        Assert.Equal(0, _users.GetById("carol")!.failed_login_count);
    }

    // ---------------- users.email ----------------

    [Fact]
    public void Email_StoredNormalized_AndUpdatable()
    {
        CreateUser("admin", "x-password", allowPassword: false, email: "  Admin@Example.COM ");
        Assert.Equal("admin@example.com", _users.GetById("admin")!.email);

        _users.UpdateProfile("admin", "", allowPasswordLogin: true);
        var row = _users.GetById("admin")!;
        Assert.Null(row.email);
        Assert.Equal(1, row.allow_password_login);
    }

    [Fact]
    public void ResolveProfile_PrefersUserEmail_OverExternalIdentity()
    {
        // 典型形态：同一个用户绑了 google 与 microsoft 两个外部账号，退回逻辑取 google 那条的邮箱 ——
        // 它可能恰好是下游应用（如 Immich）里另一个账号的邮箱。设了 users.email 就以它为准。
        CreateUser("admin", "x-password", allowPassword: false);
        var identities = new ExternalIdentityRepository(_db);
        identities.BindActive("google", "g-sub", "admin", "admin.google@example.com", "Admin");
        identities.BindActive("microsoft", "m-oid", "admin", "Admin.MS@Example.org", "Admin");

        Assert.Equal("admin.google@example.com", OidcEndpoints.ResolveProfile(identities, _users, "admin").Email);

        _users.UpdateProfile("admin", "admin.ms@example.org", allowPasswordLogin: false);
        var (email, name) = OidcEndpoints.ResolveProfile(identities, _users, "admin");
        Assert.Equal("admin.ms@example.org", email);
        Assert.Equal("Admin", name);
    }

    [Fact]
    public void ResolveProfile_LocalPasswordUser_UsesOwnEmail()
    {
        CreateUser("carol", "correct-horse", allowPassword: true, email: "carol@example.com");
        var (email, name) = OidcEndpoints.ResolveProfile(new ExternalIdentityRepository(_db), _users, "carol");
        Assert.Equal("carol@example.com", email);
        Assert.Equal("carol", name);
    }

    // ---------------- 老库升级 ----------------

    [Fact]
    public void OldSchema_UpgradedInPlace_ExistingUsersKeepWorking_PasswordOffByDefault()
    {
        var path = Path.Combine(_tmpDir, "old.db");
        using (var conn = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path}"))
        {
            conn.Open();
            // §十四 之前版本的 users 表形态（没有那四列）
            conn.Execute(@"CREATE TABLE users (
                user_id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0, must_change_password INTEGER NOT NULL DEFAULT 0)");
            conn.Execute("INSERT INTO users VALUES ('admin','admin',@h,1,1,1,0)", new { h = PasswordHasher.Hash("pw-123456") });
        }
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

        var db = new AuthDb(new AuthOptions { Database = $"Data Source={path}" });
        db.EnsureCreated();
        db.EnsureCreated(); // 幂等：第二次不能因为列已存在而失败
        var users = new UserRepository(db);

        var adminRow = users.GetById("admin")!;
        Assert.Equal(1, adminRow.is_admin);
        Assert.Null(adminRow.email);
        Assert.Equal(0, adminRow.allow_password_login); // 升级后默认不许密码，与升级前「总闸关」一致
        Assert.Equal(0, adminRow.failed_login_count);
        Assert.Null(adminRow.locked_until);
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
    }
}
