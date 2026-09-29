using System.Security.Claims;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Endpoints;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// 覆盖外部登录回调状态机（外部认证设计 §5.2）。
/// 不变量：只有 active 且用户存在才返回可建会话的结果，禁止 auto-provisioning。
/// </summary>
public class ExternalSignInServiceTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly ExternalIdentityRepository _identities;
    private readonly UserRepository _users;
    private readonly ExternalSignInService _service;

    public ExternalSignInServiceTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
        var db = new AuthDb(new AuthOptions { Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}" });
        db.EnsureCreated();
        _identities = new ExternalIdentityRepository(db);
        _users = new UserRepository(db);
        _service = new ExternalSignInService(_identities, _users);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    [Fact]
    public void Unknown_InsertsPending_NoSession()
    {
        var result = _service.Resolve("google", "sub-1", "a@example.com", "Admin");
        Assert.Equal(ExternalSignInStatus.PendingNew, result.Status);
        Assert.Null(result.User);

        // 禁止 auto-provisioning：没有创建任何用户，只有 pending 身份行
        var row = _identities.Get("google", "sub-1")!;
        Assert.Equal("pending", row.status);
        Assert.Null(row.user_id);
        Assert.Equal("a@example.com", row.email);
    }

    [Fact]
    public void Pending_StaysPending_NoSession()
    {
        _identities.InsertPending("google", "sub-1", null, null);
        var result = _service.Resolve("google", "sub-1", null, null);
        Assert.Equal(ExternalSignInStatus.PendingExisting, result.Status);
        Assert.Null(result.User);
    }

    [Fact]
    public void Rejected_Returns403Status_NoSession()
    {
        _identities.InsertPending("google", "sub-1", null, null);
        _identities.Reject("google", "sub-1");
        var result = _service.Resolve("google", "sub-1", null, null);
        Assert.Equal(ExternalSignInStatus.Rejected, result.Status);
        Assert.Null(result.User);
    }

    [Fact]
    public void Active_ReturnsBoundUser()
    {
        _users.Upsert("admin", "admin", "hash", isAdmin: true);
        _identities.BindActive("google", "sub-1", "admin", null, null);
        var result = _service.Resolve("google", "sub-1", null, null);
        Assert.Equal(ExternalSignInStatus.Active, result.Status);
        Assert.Equal("admin", result.User!.user_id);
    }

    [Fact]
    public void Active_ButUserDeleted_NoSession()
    {
        // 数据残留：active 行指向已删除的用户，绝不能据此建会话
        _identities.BindActive("google", "sub-1", "ghost", null, null);
        var result = _service.Resolve("google", "sub-1", null, null);
        Assert.Equal(ExternalSignInStatus.OrphanedActive, result.Status);
        Assert.Null(result.User);
    }

    [Fact]
    public void Rejected_RepeatedAttempts_DoNotWhitewash()
    {
        _identities.InsertPending("google", "sub-1", null, null);
        _identities.Reject("google", "sub-1");
        // 重复回调 N 次也洗不白
        _service.Resolve("google", "sub-1", "x@example.com", null);
        var result = _service.Resolve("google", "sub-1", "x@example.com", null);
        Assert.Equal(ExternalSignInStatus.Rejected, result.Status);
    }
}

/// <summary>身份主键提取：Google sub / Microsoft oid（fallback sub），绝不用 email。</summary>
public class ExternalClaimsTests
{
    private static ClaimsPrincipal Principal(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, "test"));

    [Fact]
    public void Google_UsesNameIdentifier()
    {
        var p = Principal(
            new Claim(ClaimTypes.NameIdentifier, "google-sub"),
            new Claim(ClaimTypes.Email, "a@example.com"));
        Assert.Equal("google-sub", ExternalClaims.GetSubject("google", p));
    }

    [Fact]
    public void Microsoft_PrefersOid_OverNameIdentifier()
    {
        var p = Principal(
            new Claim(ExternalClaims.OidClaimType, "ms-oid"),
            new Claim(ClaimTypes.NameIdentifier, "ms-sub"));
        Assert.Equal("ms-oid", ExternalClaims.GetSubject("microsoft", p));
    }

    [Fact]
    public void Microsoft_FallsBackToNameIdentifier()
    {
        // AddMicrosoftAccount（Graph /me）只给 NameIdentifier，没有 oid claim
        var p = Principal(new Claim(ClaimTypes.NameIdentifier, "graph-id"));
        Assert.Equal("graph-id", ExternalClaims.GetSubject("microsoft", p));
    }

    [Fact]
    public void EmailIsNeverASubject()
    {
        // 只有 email claim、没有任何稳定 id → 返回 null，上层拒绝登录
        var p = Principal(new Claim(ClaimTypes.Email, "a@example.com"));
        Assert.Null(ExternalClaims.GetSubject("google", p));
        Assert.Null(ExternalClaims.GetSubject("microsoft", p));
    }

    [Fact]
    public void UnknownProvider_ReturnsNull()
    {
        var p = Principal(new Claim(ClaimTypes.NameIdentifier, "x"));
        Assert.Null(ExternalClaims.GetSubject("gitee", p));
    }
}

/// <summary>provider 启用判定（env 凭证齐全才启用）与 return_url 本地校验。</summary>
public class ExternalProviderOptionsTests
{
    [Fact]
    public void BothCredentials_Enabled()
    {
        var o = new ExternalProviderOptions
        {
            GoogleClientId = "id",
            GoogleClientSecret = "secret",
        };
        Assert.True(o.GoogleEnabled);
        Assert.True(o.IsEnabled("google"));
        Assert.False(o.MicrosoftEnabled);
        Assert.False(o.IsEnabled("microsoft"));
    }

    [Fact]
    public void MissingSecret_Disabled()
    {
        var o = new ExternalProviderOptions { MicrosoftClientId = "id" };
        Assert.False(o.MicrosoftEnabled);
    }

    [Fact]
    public void UnknownProvider_Disabled()
    {
        var o = new ExternalProviderOptions
        {
            GoogleClientId = "id",
            GoogleClientSecret = "secret",
        };
        Assert.False(o.IsEnabled("gitee"));
    }

    [Theory]
    [InlineData("/account", true)]
    [InlineData("/authorize?client_id=x&state=y", true)]
    [InlineData("/", true)]
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData("//evil.example.com", false)]
    [InlineData("/\\evil.example.com", false)]
    [InlineData("https://evil.example.com/", false)]
    public void IsLocalUrl_BlocksOpenRedirect(string? url, bool expected)
    {
        Assert.Equal(expected, ReturnUrl.IsLocalUrl(url));
    }
}
