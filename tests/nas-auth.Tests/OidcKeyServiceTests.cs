using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using NasAuth.Config;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// 覆盖最小 OIDC 的 RS256 密钥管理与 id_token 签发（外部认证设计 §七）。
/// </summary>
public class OidcKeyServiceTests : IDisposable
{
    private readonly string _tmpDir;

    public OidcKeyServiceTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    private OidcKeyService Create() => new(
        new AuthOptions
        {
            Issuer = "https://auth.example.com/",
            Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}",
        },
        NullLogger<OidcKeyService>.Instance);

    [Fact]
    public void KeyIsGenerated_AndPersistedAcrossRestarts()
    {
        var first = Create();
        var pemPath = Path.Combine(_tmpDir, "oidc_rs256_current.pem");
        Assert.True(File.Exists(pemPath));

        // "重启"：新实例必须加载同一把钥（kid 一致），不能悄悄换钥让在途 id_token 失效
        var second = Create();
        Assert.Equal(KidOf(first), KidOf(second));
    }

    [Fact]
    public void Jwks_PublishesCurrentKey_NoPrivateMaterial()
    {
        var svc = Create();
        var json = JsonSerializer.Serialize(svc.BuildJwks());
        using var doc = JsonDocument.Parse(json);
        var key = doc.RootElement.GetProperty("keys")[0];

        Assert.Equal("RSA", key.GetProperty("kty").GetString());
        Assert.Equal("RS256", key.GetProperty("alg").GetString());
        Assert.Equal("sig", key.GetProperty("use").GetString());
        Assert.False(string.IsNullOrEmpty(key.GetProperty("n").GetString()));
        // 私钥参数绝不能出现在 JWKS 里
        Assert.False(key.TryGetProperty("d", out _));
        Assert.False(key.TryGetProperty("p", out _));
    }

    [Fact]
    public void IdToken_RS256_ValidatesAgainstJwks_WithExpectedClaims()
    {
        var svc = Create();
        var token = svc.IssueIdToken("admin", "gitea-web", "a@example.com", "Admin", nonce: "n-123");

        // 用 JWKS 公开的参数重建公钥验签（模拟 Gitea go-oidc 的路径）
        var jwks = JsonDocument.Parse(JsonSerializer.Serialize(svc.BuildJwks()));
        var k = jwks.RootElement.GetProperty("keys")[0];
        var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = Base64UrlEncoder.DecodeBytes(k.GetProperty("n").GetString()),
            Exponent = Base64UrlEncoder.DecodeBytes(k.GetProperty("e").GetString()),
        });

        var principal = new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
        {
            ValidIssuer = "https://auth.example.com",
            ValidAudience = "gitea-web",
            IssuerSigningKey = new RsaSecurityKey(rsa),
        }, out var validated);

        var jwt = (JwtSecurityToken)validated;
        Assert.Equal("RS256", jwt.Header.Alg);
        Assert.Equal(k.GetProperty("kid").GetString(), jwt.Header.Kid);
        Assert.Equal("admin", jwt.Claims.First(c => c.Type == "sub").Value);
        Assert.Equal("admin", jwt.Claims.First(c => c.Type == "preferred_username").Value);
        Assert.Equal("a@example.com", jwt.Claims.First(c => c.Type == "email").Value);
        Assert.Equal("Admin", jwt.Claims.First(c => c.Type == "name").Value);
        Assert.Equal("n-123", jwt.Claims.First(c => c.Type == "nonce").Value);
        // §九：id_token 短寿命 ≤ 1h
        Assert.True(jwt.ValidTo <= DateTime.UtcNow.AddHours(1).AddMinutes(1));
    }

    [Fact]
    public void IdToken_OmitsOptionalClaims_WhenAbsent()
    {
        var svc = Create();
        var token = svc.IssueIdToken("guest", "gitea-web", email: null, name: null, nonce: null);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        Assert.DoesNotContain(jwt.Claims, c => c.Type == "email");
        Assert.DoesNotContain(jwt.Claims, c => c.Type == "nonce");
    }

    [Fact]
    public void KeyFile_CreatedAtomically_NoTempLeftovers_Mode600()
    {
        Create();
        var files = Directory.GetFiles(_tmpDir).Select(Path.GetFileName).ToArray();
        Assert.Contains("oidc_rs256_current.pem", files);
        Assert.DoesNotContain(files, f => f!.EndsWith(".tmp", StringComparison.Ordinal));
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(Path.Combine(_tmpDir, "oidc_rs256_current.pem")));
    }

    [Fact]
    public void ExistingKeyFile_IsNeverOverwritten()
    {
        var pem = Path.Combine(_tmpDir, "oidc_rs256_current.pem");
        using var rsa = RSA.Create(2048);
        File.WriteAllText(pem, rsa.ExportRSAPrivateKeyPem());
        var before = File.ReadAllText(pem);
        Create();
        Assert.Equal(before, File.ReadAllText(pem));
    }

    [Theory]
    [InlineData("oidc_rs256_current.pem")]
    [InlineData("oidc_rs256_previous.pem")]
    public void CorruptPem_FailsFast_NamingTheFile(string file)
    {
        Create(); // 先有一把合法 current
        File.WriteAllText(Path.Combine(_tmpDir, file), "-----BEGIN RSA PRIVATE KEY-----\ngarbage\n-----END RSA PRIVATE KEY-----\n");
        var ex = Assert.Throws<InvalidOperationException>(() => Create());
        Assert.Contains(file, ex.Message);
        Assert.Contains("备份", ex.Message);
    }

    private static string KidOf(OidcKeyService svc)
    {
        var json = JsonSerializer.Serialize(svc.BuildJwks());
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("keys")[0].GetProperty("kid").GetString()!;
    }
}
