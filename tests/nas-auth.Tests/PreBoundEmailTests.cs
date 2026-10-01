using System.Security.Claims;
using Microsoft.Extensions.Logging.Abstractions;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// external-auth.md §十八：预绑定邮箱（首次 Google 登录且邮箱已验证 → 直接绑到登记的用户）、
/// 删过的 user_id 不许复用、只走外部登录的用户没有可用密码也不强制改密。
/// </summary>
public class PreBoundEmailTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly ExternalIdentityRepository _identities;
    private readonly UserRepository _users;
    private readonly ExternalInviteRepository _invites;
    private readonly ExternalSignInService _signIn;
    private readonly ApprovalService _approvals;

    public PreBoundEmailTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
        var db = new AuthDb(new AuthOptions { Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}" });
        db.EnsureCreated();
        _identities = new ExternalIdentityRepository(db);
        _users = new UserRepository(db);
        _invites = new ExternalInviteRepository(db);
        _signIn = new ExternalSignInService(_identities, _users, _invites);

        var resourcesPath = Path.Combine(_tmpDir, "resources.json");
        File.WriteAllText(resourcesPath, """
            [ { "aud": "immich", "resource_url": "https://photos.example.com",
                "display_name": "Immich", "scopes": ["openid", "email", "profile"] } ]
            """);
        var catalog = new ResourceCatalog(new AuthOptions { ResourcesPath = resourcesPath }, NullLogger<ResourceCatalog>.Instance);
        _approvals = new ApprovalService(_identities, _users, new UserResourceRepository(db), catalog);

        _users.Create("jelly", "jelly", PasswordHasher.UnusableHash(), mustChangePassword: false, email: "jelly@example.com");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    // ---------------- 预绑定邮箱 ----------------

    [Fact]
    public void VerifiedGoogleEmail_MatchingInvite_BindsDirectly_AndConsumesInvite()
    {
        Assert.True(_invites.Add("Jelly@Example.com", "jelly", "tao"));

        var result = _signIn.Resolve("google", "g-1", "jelly@example.COM", "Jelly", emailVerified: true);

        Assert.Equal(ExternalSignInStatus.ActiveByInvite, result.Status);
        Assert.Equal("jelly", result.User!.user_id);
        var row = _identities.Get("google", "g-1")!;
        Assert.Equal(("active", "jelly"), (row.status, row.user_id));
        Assert.Empty(_invites.ListByUser("jelly"));     // 一次性

        // 之后再登录走普通 active 分支
        Assert.Equal(ExternalSignInStatus.Active, _signIn.Resolve("google", "g-1", "jelly@example.com", "Jelly", emailVerified: true).Status);
    }

    [Fact]
    public void UnverifiedEmail_GoesPending_AndKeepsInvite()
    {
        _invites.Add("jelly@example.com", "jelly", "tao");

        var result = _signIn.Resolve("google", "g-1", "jelly@example.com", "Jelly", emailVerified: false);

        Assert.Equal(ExternalSignInStatus.PendingNew, result.Status);
        Assert.Single(_invites.ListByUser("jelly"));
    }

    [Fact]
    public void Microsoft_NeverTreatedAsVerified()
    {
        // 微软个人账号没有 email_verified，ExternalClaims 一律判未验证
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Email, "jelly@example.com"),
            new Claim(ExternalClaims.EmailVerifiedClaimType, "true"),
        }, "test"));
        Assert.False(ExternalClaims.IsEmailVerified("microsoft", principal));
        Assert.True(ExternalClaims.IsEmailVerified("google", principal));
    }

    [Theory]
    [InlineData("True", true)]     // MapJsonKey 把 JSON true 转成 "True"
    [InlineData("true", true)]
    [InlineData("false", false)]
    [InlineData(null, false)]
    public void GoogleEmailVerifiedClaim_Parsing(string? value, bool expected)
    {
        var claims = new List<Claim> { new(ClaimTypes.Email, "a@example.com") };
        if (value is not null) claims.Add(new Claim(ExternalClaims.EmailVerifiedClaimType, value));
        Assert.Equal(expected, ExternalClaims.IsEmailVerified("google", new ClaimsPrincipal(new ClaimsIdentity(claims, "test"))));
    }

    [Fact]
    public void ExistingPendingIdentity_RedeemsInviteAddedLater()
    {
        // 先登录过一次（进了待批），管理员后来才登记预绑定 → 再登录即绑定
        _signIn.Resolve("google", "g-1", "jelly@example.com", "Jelly", emailVerified: true);
        Assert.Equal("pending", _identities.Get("google", "g-1")!.status);

        _invites.Add("jelly@example.com", "jelly", "tao");
        Assert.Equal(ExternalSignInStatus.ActiveByInvite,
            _signIn.Resolve("google", "g-1", "jelly@example.com", "Jelly", emailVerified: true).Status);
    }

    [Fact]
    public void RejectedIdentity_NotRescuedByInvite()
    {
        _identities.InsertPending("google", "g-1", "jelly@example.com", null);
        _identities.Reject("google", "g-1");
        _invites.Add("jelly@example.com", "jelly", "tao");

        Assert.Equal(ExternalSignInStatus.Rejected,
            _signIn.Resolve("google", "g-1", "jelly@example.com", "Jelly", emailVerified: true).Status);
        Assert.Single(_invites.ListByUser("jelly"));    // 没被消耗
    }

    [Fact]
    public void ActiveIdentityOfAnotherUser_NotMovedByInvite()
    {
        _users.Create("other", "other", PasswordHasher.UnusableHash(), mustChangePassword: false);
        _identities.BindActive("google", "g-1", "other", "jelly@example.com", null);
        _invites.Add("jelly@example.com", "jelly", "tao");

        var result = _signIn.Resolve("google", "g-1", "jelly@example.com", "Jelly", emailVerified: true);

        Assert.Equal(ExternalSignInStatus.Active, result.Status);
        Assert.Equal("other", result.User!.user_id);
    }

    [Fact]
    public void Invite_EmailIsUnique_AndConsumedOnlyOnce()
    {
        Assert.True(_invites.Add("jelly@example.com", "jelly", "tao"));
        Assert.False(_invites.Add("JELLY@example.com", "tao", "tao"));

        Assert.NotNull(_invites.Consume("jelly@example.com"));
        Assert.Null(_invites.Consume("jelly@example.com"));
    }

    [Fact]
    public void InviteForDeletedUser_FallsBackToPending()
    {
        _invites.Add("jelly@example.com", "jelly", "tao");
        _users.Delete("jelly");   // 正常删人会连带删预绑定；这里模拟残留

        Assert.Equal(ExternalSignInStatus.PendingNew,
            _signIn.Resolve("google", "g-1", "jelly@example.com", "Jelly", emailVerified: true).Status);
    }

    // ---------------- 删过的 user_id 不复用 ----------------

    [Fact]
    public void DeletedUserId_IsRetired_CaseInsensitive()
    {
        Assert.False(_users.IsRetiredId("jelly"));
        _users.Delete("jelly");
        Assert.True(_users.IsRetiredId("jelly"));
        Assert.True(_users.IsRetiredId("JELLY"));
    }

    [Fact]
    public void ApproveCreateUser_RefusesRetiredId()
    {
        _users.Delete("jelly");
        _identities.InsertPending("google", "g-1", "x@example.com", null);

        Assert.NotNull(_approvals.ApproveCreateUser("google", "g-1", "Jelly", Array.Empty<string>()));
        Assert.Null(_users.GetById("Jelly"));
        Assert.Equal("pending", _identities.Get("google", "g-1")!.status);
    }

    [Fact]
    public void ApproveCreateUser_Rollback_DoesNotRetireId()
    {
        // 身份已不是 pending → 审批失败、回滚刚建的用户；这个 id 从没对外用过，不该被占掉
        Assert.NotNull(_approvals.ApproveCreateUser("google", "never-pending", "fresh", Array.Empty<string>()));
        Assert.Null(_users.GetById("fresh"));
        Assert.False(_users.IsRetiredId("fresh"));
    }

    // ---------------- 只走外部登录的用户 ----------------

    [Fact]
    public void UnusableHash_RejectsEveryGuess()
    {
        var hash = PasswordHasher.UnusableHash();
        Assert.False(PasswordHasher.Verify("password", hash));
        Assert.NotEqual(hash, PasswordHasher.UnusableHash());   // 每次随机
    }
}
