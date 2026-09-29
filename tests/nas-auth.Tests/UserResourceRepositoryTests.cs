using Microsoft.Extensions.Logging.Abstractions;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// 覆盖 user_resources（外部认证设计 §四）：(user, aud) → 最大 scope，
/// IsAllowed 的 "行存在 且 请求 scope ⊆ 授予 scopes" 语义，以及启动期一次性 seed。
/// </summary>
public class UserResourceRepositoryTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly AuthDb _db;
    private readonly UserResourceRepository _repo;

    public UserResourceRepositoryTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
        _db = new AuthDb(new AuthOptions { Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}" });
        _db.EnsureCreated();
        _repo = new UserResourceRepository(_db);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    [Fact]
    public void Upsert_ThenGet_Roundtrips()
    {
        _repo.Upsert("admin", "obsidian", "read:obsidian write:obsidian");
        var row = _repo.Get("admin", "obsidian");
        Assert.NotNull(row);
        Assert.Equal("read:obsidian write:obsidian", row!.scopes);
    }

    [Fact]
    public void Upsert_Existing_ReplacesScopes()
    {
        _repo.Upsert("admin", "obsidian", "read:obsidian write:obsidian");
        _repo.Upsert("admin", "obsidian", "read:obsidian");
        Assert.Equal("read:obsidian", _repo.Get("admin", "obsidian")!.scopes);
    }

    [Fact]
    public void ListByUser_ReturnsOnlyThatUsersRows()
    {
        _repo.Upsert("admin", "obsidian", "read:obsidian");
        _repo.Upsert("admin", "gitea", "read:gitea");
        _repo.Upsert("alice", "obsidian", "read:obsidian");

        var rows = _repo.ListByUser("admin");
        Assert.Equal(2, rows.Count);
        Assert.All(rows, r => Assert.Equal("admin", r.user_id));
    }

    [Fact]
    public void Delete_RemovesSingleGrant()
    {
        _repo.Upsert("admin", "obsidian", "read:obsidian");
        _repo.Upsert("admin", "gitea", "read:gitea");
        _repo.Delete("admin", "obsidian");
        Assert.Null(_repo.Get("admin", "obsidian"));
        Assert.NotNull(_repo.Get("admin", "gitea"));
    }

    [Fact]
    public void DeleteByUser_RemovesAllGrantsOfUser()
    {
        _repo.Upsert("admin", "obsidian", "read:obsidian");
        _repo.Upsert("admin", "gitea", "read:gitea");
        _repo.Upsert("alice", "obsidian", "read:obsidian");

        _repo.DeleteByUser("admin");
        Assert.Empty(_repo.ListByUser("admin"));
        Assert.Single(_repo.ListByUser("alice"));
    }

    // ---- IsAllowed 语义 ----

    [Fact]
    public void IsAllowed_NoRow_Denied()
    {
        Assert.False(_repo.IsAllowed("admin", "obsidian", new[] { "read:obsidian" }));
    }

    [Fact]
    public void IsAllowed_RequestedSubsetOfGranted_Allowed()
    {
        _repo.Upsert("admin", "obsidian", "read:obsidian write:obsidian");
        Assert.True(_repo.IsAllowed("admin", "obsidian", new[] { "read:obsidian" }));
        Assert.True(_repo.IsAllowed("admin", "obsidian", new[] { "read:obsidian", "write:obsidian" }));
    }

    [Fact]
    public void IsAllowed_RequestedExceedsGranted_Denied()
    {
        _repo.Upsert("admin", "obsidian", "read:obsidian");
        Assert.False(_repo.IsAllowed("admin", "obsidian", new[] { "read:obsidian", "write:obsidian" }));
    }

    [Fact]
    public void IsAllowed_EmptyRequest_OnlyRequiresRow()
    {
        Assert.False(_repo.IsAllowed("admin", "obsidian", Array.Empty<string>()));
        _repo.Upsert("admin", "obsidian", "read:obsidian");
        Assert.True(_repo.IsAllowed("admin", "obsidian", Array.Empty<string>()));
    }

    // ---- 启动期一次性 seed ----

    private ResourceCatalog WriteCatalog()
    {
        var path = Path.Combine(_tmpDir, "resources.json");
        File.WriteAllText(path, """
            [
              { "aud": "obsidian", "resource_url": "https://obsidian.example.com",
                "display_name": "Obsidian", "scopes": ["read:obsidian", "write:obsidian"] },
              { "aud": "gitea", "resource_url": "https://gitea.example.com",
                "display_name": "Gitea", "scopes": ["read:gitea"] }
            ]
            """);
        return new ResourceCatalog(new AuthOptions { ResourcesPath = path }, NullLogger<ResourceCatalog>.Instance);
    }

    [Fact]
    public void Seed_GrantsFullScopes_ToAllExistingUsers()
    {
        var users = new UserRepository(_db);
        users.Upsert("admin", "admin", "hash", isAdmin: true);
        users.Create("alice", "alice", "hash", mustChangePassword: true);

        UserResourceSeeder.SeedIfNeeded(WriteCatalog(), users, _repo,
            new SettingsRepository(_db), NullLogger.Instance);

        Assert.Equal("read:obsidian write:obsidian", _repo.Get("admin", "obsidian")!.scopes);
        Assert.Equal("read:gitea", _repo.Get("admin", "gitea")!.scopes);
        Assert.Equal("read:obsidian write:obsidian", _repo.Get("alice", "obsidian")!.scopes);
    }

    [Fact]
    public void Seed_RunsOnlyOnce_ManualNarrowingSurvivesRestart()
    {
        var users = new UserRepository(_db);
        users.Upsert("admin", "admin", "hash", isAdmin: true);
        var catalog = WriteCatalog();
        var settings = new SettingsRepository(_db);

        UserResourceSeeder.SeedIfNeeded(catalog, users, _repo, settings, NullLogger.Instance);
        // 管理员手动收窄 + 删行
        _repo.Upsert("admin", "obsidian", "read:obsidian");
        _repo.Delete("admin", "gitea");

        // 模拟重启：再跑一次 seed，不得覆盖
        UserResourceSeeder.SeedIfNeeded(catalog, users, _repo, settings, NullLogger.Instance);
        Assert.Equal("read:obsidian", _repo.Get("admin", "obsidian")!.scopes);
        Assert.Null(_repo.Get("admin", "gitea"));
    }
}
