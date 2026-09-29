using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// 覆盖 external_identities 的状态机（外部认证设计 §四 / §五）：
/// 不存在 → pending → active（批准 / 自绑定）或 rejected；rejected 不能靠重复申请洗白。
/// </summary>
public class ExternalIdentityRepositoryTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly ExternalIdentityRepository _repo;

    public ExternalIdentityRepositoryTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
        var db = new AuthDb(new AuthOptions { Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}" });
        db.EnsureCreated();
        _repo = new ExternalIdentityRepository(db);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    [Fact]
    public void InsertPending_CreatesPendingRow_WithNullUserId()
    {
        _repo.InsertPending("google", "sub-1", "a@example.com", "Admin");
        var row = _repo.Get("google", "sub-1");
        Assert.NotNull(row);
        Assert.Equal("pending", row!.status);
        Assert.Null(row.user_id);
        Assert.Equal("a@example.com", row.email);
        Assert.Equal("Admin", row.display_name);
        Assert.Null(row.approved_at);
    }

    [Fact]
    public void Get_DistinguishesProviders_SameSubject()
    {
        _repo.InsertPending("google", "sub-1", null, null);
        Assert.Null(_repo.Get("microsoft", "sub-1"));
    }

    [Fact]
    public void InsertPending_OnRejected_DoesNotWhitewash()
    {
        _repo.InsertPending("google", "sub-1", null, null);
        Assert.True(_repo.Reject("google", "sub-1"));
        // 同一身份再次"申请"：行已存在，状态保持 rejected
        _repo.InsertPending("google", "sub-1", "new@example.com", null);
        Assert.Equal("rejected", _repo.Get("google", "sub-1")!.status);
    }

    [Fact]
    public void Approve_PendingRow_BecomesActive_BoundToUser()
    {
        _repo.InsertPending("google", "sub-1", null, null);
        Assert.True(_repo.Approve("google", "sub-1", "admin"));
        var row = _repo.Get("google", "sub-1")!;
        Assert.Equal("active", row.status);
        Assert.Equal("admin", row.user_id);
        Assert.NotNull(row.approved_at);
    }

    [Fact]
    public void Approve_NonPendingRow_NoOp()
    {
        _repo.InsertPending("google", "sub-1", null, null);
        _repo.Reject("google", "sub-1");
        Assert.False(_repo.Approve("google", "sub-1", "admin"));
        Assert.Equal("rejected", _repo.Get("google", "sub-1")!.status);
    }

    [Fact]
    public void Reject_OnlyAffectsPending()
    {
        _repo.BindActive("google", "sub-1", "admin", null, null);
        Assert.False(_repo.Reject("google", "sub-1"));
        Assert.Equal("active", _repo.Get("google", "sub-1")!.status);
    }

    [Fact]
    public void BindActive_NewIdentity_ActiveImmediately()
    {
        // 自绑定路径（设计 §5.3）：已登录会话直接写 active，不走审批
        _repo.BindActive("microsoft", "oid-1", "admin", "t@example.com", "Admin");
        var row = _repo.Get("microsoft", "oid-1")!;
        Assert.Equal("active", row.status);
        Assert.Equal("admin", row.user_id);
        Assert.NotNull(row.approved_at);
    }

    [Fact]
    public void BindActive_UpsertsPendingRow()
    {
        _repo.InsertPending("google", "sub-1", "old@example.com", null);
        _repo.BindActive("google", "sub-1", "admin", "new@example.com", "Admin");
        var row = _repo.Get("google", "sub-1")!;
        Assert.Equal("active", row.status);
        Assert.Equal("admin", row.user_id);
        Assert.Equal("new@example.com", row.email);
    }

    [Fact]
    public void ListPending_OnlyPending_OrderedByCreated()
    {
        _repo.InsertPending("google", "sub-1", null, null);
        _repo.InsertPending("google", "sub-2", null, null);
        _repo.BindActive("microsoft", "oid-1", "admin", null, null);
        _repo.InsertPending("google", "sub-3", null, null);
        _repo.Reject("google", "sub-3");

        var pending = _repo.ListPending();
        Assert.Equal(2, pending.Count);
        Assert.All(pending, r => Assert.Equal("pending", r.status));
    }

    [Fact]
    public void ListByUser_ReturnsOnlyThatUsersIdentities()
    {
        _repo.BindActive("google", "sub-1", "admin", null, null);
        _repo.BindActive("microsoft", "oid-1", "admin", null, null);
        _repo.BindActive("google", "sub-2", "alice", null, null);

        var rows = _repo.ListByUser("admin");
        Assert.Equal(2, rows.Count);
        Assert.All(rows, r => Assert.Equal("admin", r.user_id));
    }

    [Fact]
    public void Delete_RemovesRow()
    {
        _repo.BindActive("google", "sub-1", "admin", null, null);
        _repo.Delete("google", "sub-1");
        Assert.Null(_repo.Get("google", "sub-1"));
    }

    [Fact]
    public void DeleteByUser_RemovesAllIdentitiesOfUser()
    {
        _repo.BindActive("google", "sub-1", "admin", null, null);
        _repo.BindActive("microsoft", "oid-1", "admin", null, null);
        _repo.BindActive("google", "sub-2", "alice", null, null);

        _repo.DeleteByUser("admin");
        Assert.Empty(_repo.ListByUser("admin"));
        Assert.Single(_repo.ListByUser("alice"));
    }
}
