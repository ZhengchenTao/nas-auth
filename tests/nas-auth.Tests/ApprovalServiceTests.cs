using Microsoft.Extensions.Logging.Abstractions;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// 覆盖待批申请的批准 / 拒绝（外部认证设计 §5.4）。
/// 不变量：只有 pending 行能被批准 / 拒绝；rejected 记录保留；
/// 新建用户路径的密码不可用且失败时回滚。
/// </summary>
public class ApprovalServiceTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly ExternalIdentityRepository _identities;
    private readonly UserRepository _users;
    private readonly UserResourceRepository _userResources;
    private readonly ApprovalService _service;

    public ApprovalServiceTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
        var db = new AuthDb(new AuthOptions { Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}" });
        db.EnsureCreated();
        _identities = new ExternalIdentityRepository(db);
        _users = new UserRepository(db);
        _userResources = new UserResourceRepository(db);

        var resourcesPath = Path.Combine(_tmpDir, "resources.json");
        File.WriteAllText(resourcesPath, """
            [
              { "aud": "obsidian", "resource_url": "https://obsidian.example.com",
                "display_name": "Obsidian", "scopes": ["read:obsidian", "write:obsidian"] },
              { "aud": "gitea", "resource_url": "https://gitea.example.com",
                "display_name": "Gitea", "scopes": ["read:gitea"] }
            ]
            """);
        var catalog = new ResourceCatalog(
            new AuthOptions { ResourcesPath = resourcesPath }, NullLogger<ResourceCatalog>.Instance);
        _service = new ApprovalService(_identities, _users, _userResources, catalog);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    [Fact]
    public void ApproveBindExisting_ActivatesIdentity_AndGrantsFullScopes()
    {
        _users.Upsert("admin", "admin", "hash", isAdmin: true);
        _identities.InsertPending("google", "sub-1", "a@example.com", "Admin");

        var err = _service.ApproveBindExisting("google", "sub-1", "admin", new[] { "obsidian" });

        Assert.Null(err);
        var row = _identities.Get("google", "sub-1")!;
        Assert.Equal("active", row.status);
        Assert.Equal("admin", row.user_id);
        var grant = Assert.Single(_userResources.ListByUser("admin"));
        Assert.Equal("obsidian", grant.aud);
        Assert.Equal("read:obsidian write:obsidian", grant.scopes);
    }

    [Fact]
    public void ApproveBindExisting_UnknownUser_Fails_StaysPending()
    {
        _identities.InsertPending("google", "sub-1", null, null);
        var err = _service.ApproveBindExisting("google", "sub-1", "ghost", Array.Empty<string>());
        Assert.NotNull(err);
        Assert.Equal("pending", _identities.Get("google", "sub-1")!.status);
    }

    [Fact]
    public void ApproveBindExisting_NotPending_Fails()
    {
        _users.Upsert("admin", "admin", "hash", isAdmin: true);
        _identities.BindActive("google", "sub-1", "admin", null, null);
        var err = _service.ApproveBindExisting("google", "sub-1", "admin", Array.Empty<string>());
        Assert.NotNull(err);
    }

    [Fact]
    public void ApproveCreateUser_CreatesUser_NoUsablePassword_NoForceChange()
    {
        _identities.InsertPending("microsoft", "oid-1", "b@example.com", null);

        var err = _service.ApproveCreateUser("microsoft", "oid-1", "guest", new[] { "gitea" });

        Assert.Null(err);
        var user = _users.GetById("guest")!;
        // 新用户密码事实禁用：随机 hash 不可能被任何已知明文命中，且不设强制改密
        Assert.Equal(0, user.must_change_password);
        Assert.False(PasswordHasher.Verify("", user.password_hash));
        Assert.Equal("guest", _identities.Get("microsoft", "oid-1")!.user_id);
        var grant = Assert.Single(_userResources.ListByUser("guest"));
        Assert.Equal("gitea", grant.aud);
    }

    [Fact]
    public void ApproveCreateUser_InvalidUserId_Fails()
    {
        _identities.InsertPending("google", "sub-1", null, null);
        Assert.NotNull(_service.ApproveCreateUser("google", "sub-1", "bad user!", Array.Empty<string>()));
        Assert.NotNull(_service.ApproveCreateUser("google", "sub-1", "", Array.Empty<string>()));
    }

    [Fact]
    public void ApproveCreateUser_ExistingUserId_Fails()
    {
        _users.Upsert("admin", "admin", "hash", isAdmin: true);
        _identities.InsertPending("google", "sub-1", null, null);
        Assert.NotNull(_service.ApproveCreateUser("google", "sub-1", "admin", Array.Empty<string>()));
    }

    [Fact]
    public void ApproveCreateUser_IdentityNotPending_RollsBackNewUser()
    {
        _users.Upsert("admin", "admin", "hash", isAdmin: true);
        _identities.BindActive("google", "sub-1", "admin", null, null);

        var err = _service.ApproveCreateUser("google", "sub-1", "guest", Array.Empty<string>());

        Assert.NotNull(err);
        Assert.Null(_users.GetById("guest")); // 回滚：不留空用户
    }

    [Fact]
    public void Approve_UnknownAud_IsSilentlySkipped()
    {
        _users.Upsert("admin", "admin", "hash", isAdmin: true);
        _identities.InsertPending("google", "sub-1", null, null);

        var err = _service.ApproveBindExisting("google", "sub-1", "admin", new[] { "nonexistent", "gitea" });

        Assert.Null(err);
        var grant = Assert.Single(_userResources.ListByUser("admin"));
        Assert.Equal("gitea", grant.aud);
    }

    [Fact]
    public void Reject_KeepsRecord_AndShowsInRejectedList()
    {
        _identities.InsertPending("google", "sub-1", "a@example.com", null);

        Assert.Null(_service.Reject("google", "sub-1"));

        var row = _identities.Get("google", "sub-1")!;
        Assert.Equal("rejected", row.status);
        var listed = Assert.Single(_identities.ListRejected());
        Assert.Equal("sub-1", listed.subject);
        Assert.Empty(_identities.ListPending());
    }

    [Fact]
    public void Reject_NotPending_Fails()
    {
        Assert.NotNull(_service.Reject("google", "never-seen"));
        _users.Upsert("admin", "admin", "hash", isAdmin: true);
        _identities.BindActive("google", "sub-1", "admin", null, null);
        Assert.NotNull(_service.Reject("google", "sub-1")); // active 不能被"拒绝"
    }
}
