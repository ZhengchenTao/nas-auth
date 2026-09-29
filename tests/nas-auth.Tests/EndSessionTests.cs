using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>external-auth.md §十五：RP-Initiated Logout 的回跳地址校验（防开放跳转）。</summary>
public class EndSessionTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly ClientRepository _clients;

    public EndSessionTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
        var db = new AuthDb(new AuthOptions { Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}" });
        db.EnsureCreated();
        _clients = new ClientRepository(db);

        // 预置：Immich（两个入口 + 手机自定义 scheme）、一个内部应用
        _clients.Insert("immich", "h", "Immich", new[]
        {
            "https://photos.example.com/auth/login",
            "https://photos-lan.example.com:8443/auth/login",
            "app.immich:///oauth-callback",
        }, "client_secret_post", autoRegistered: false);
        _clients.Insert("internal-app", "h", "Internal App", new[] { "https://app.internal.example/signin-oidc" },
            "client_secret_post", autoRegistered: false);
        // DCR 自助注册的：任何人都能注册，绝不能算进回跳白名单
        _clients.Insert("c_evil", null, "Evil", new[] { "https://evil.example/callback" }, "none", autoRegistered: true);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    private string? R(string? uri, string? clientId = null, string? state = null)
        => EndSession.ResolveRedirect(uri, clientId, state, _clients);

    [Fact]
    public void NoRedirectRequested_ReturnsNull() => Assert.Null(R(null));

    [Fact]
    public void SameOriginAsPresetClient_Allowed_AnyPath()
    {
        Assert.Equal("https://app.internal.example/signout-callback-oidc",
            R("https://app.internal.example/signout-callback-oidc"));
        Assert.Equal("https://photos.example.com/", R("https://photos.example.com/"));
    }

    [Fact]
    public void PortIsPartOfOrigin()
    {
        Assert.NotNull(R("https://photos-lan.example.com:8443/auth/login"));
        Assert.Null(R("https://photos-lan.example.com/auth/login"));      // 443 ≠ 8443
        Assert.Null(R("http://photos.example.com/"));             // scheme 不同
    }

    [Fact]
    public void DcrClientOrigin_Rejected_EvenWithItsClientId()
    {
        Assert.Null(R("https://evil.example/callback"));
        Assert.Null(R("https://evil.example/callback", clientId: "c_evil"));
    }

    [Fact]
    public void ClientId_RestrictsToThatClient()
    {
        Assert.NotNull(R("https://photos.example.com/", clientId: "immich"));
        Assert.Null(R("https://photos.example.com/", clientId: "internal-app"));
        Assert.Null(R("https://photos.example.com/", clientId: "no-such-client"));
    }

    [Fact]
    public void NonHttpOrUserInfoOrRelative_Rejected()
    {
        Assert.Null(R("app.immich:///oauth-callback"));
        Assert.Null(R("javascript:alert(1)"));
        Assert.Null(R("/relative/path"));
        Assert.Null(R("https://user@photos.example.com/"));
    }

    [Fact]
    public void State_AppendedAndEscaped()
    {
        Assert.Equal("https://app.internal.example/signout-callback-oidc?state=a%2Bb%3D%26c",
            R("https://app.internal.example/signout-callback-oidc", state: "a+b=&c"));
        Assert.Equal("https://photos.example.com/x?y=1&state=s",
            R("https://photos.example.com/x?y=1", state: "s"));
    }
}
