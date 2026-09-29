using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Logging.Abstractions;
using NasAuth.Config;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// 覆盖「DCR 客户端不发 resource → 按 scope 反推多资源 → 签多 aud token」这条回退链
/// 的两个纯逻辑单元：ResourceCatalog.ResourcesForScopes 和 JwtIssuer 的多 aud 序列化。
/// 端到端的 /authorize → /token 行为见 docs/design/external-auth.md §十三。
/// </summary>
public class MultiResourceTokenTests : IDisposable
{
    private readonly string _tmpDir;

    public MultiResourceTokenTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-mrt-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    private const string ThreeResources = """
        [
            {"aud": "ezbookkeeping", "resource_url": "https://auth.example.com/proxy/ezbookkeeping",
             "display_name": "ezBookkeeping", "scopes": ["read:ezbookkeeping", "write:ezbookkeeping"]},
            {"aud": "obsidian", "resource_url": "https://obsidian-mcp.example.com",
             "display_name": "Obsidian", "scopes": ["read:obsidian", "write:obsidian"]},
            {"aud": "gitea", "resource_url": "https://gitea-mcp.example.com",
             "display_name": "Gitea", "scopes": ["read:gitea"]},
            {"aud": "gitea-web", "resource_url": "https://git.example.com",
             "display_name": "Gitea Web SSO", "scopes": ["openid", "email", "profile"]}
        ]
        """;

    private ResourceCatalog LoadCatalog()
    {
        var path = Path.Combine(_tmpDir, "resources.json");
        File.WriteAllText(path, ThreeResources);
        return new ResourceCatalog(new AuthOptions { ResourcesPath = path }, NullLogger<ResourceCatalog>.Instance);
    }

    [Fact]
    public void ResourcesForScopes_DerivesAllOwningResources()
    {
        var cat = LoadCatalog();
        // Grok 的并集（已剔除 openid/email/profile）应反推出三个 MCP 资源，不含 gitea-web
        var derived = cat.ResourcesForScopes(new[]
        {
            "read:ezbookkeeping", "write:ezbookkeeping",
            "read:obsidian", "write:obsidian", "read:gitea",
        });
        Assert.Equal(new[] { "ezbookkeeping", "obsidian", "gitea" }, derived.Select(r => r.Aud).ToArray());
    }

    [Fact]
    public void ResourcesForScopes_SingleScope_SingleResource()
    {
        var cat = LoadCatalog();
        var derived = cat.ResourcesForScopes(new[] { "read:gitea" });
        Assert.Single(derived);
        Assert.Equal("gitea", derived[0].Aud);
    }

    [Fact]
    public void ResourcesForScopes_UnknownScope_Empty()
    {
        var cat = LoadCatalog();
        Assert.Empty(cat.ResourcesForScopes(new[] { "read:nonexistent" }));
    }

    // 默认 RS256（Jwt:AccessTokenAlgorithm 缺省值），RSA 钥生成在临时目录
    private JwtIssuer MakeIssuer()
    {
        var auth = new AuthOptions
        {
            Issuer = "https://auth.example.com",
            Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}",
        };
        return new JwtIssuer(new JwtOptions { AccessTokenLifetimeDays = 30 }, auth,
            new OidcKeyService(auth, NullLogger<OidcKeyService>.Instance));
    }

    [Fact]
    public void IssueAccessToken_MultipleAuds_SerializesAllAudiences()
    {
        var issuer = MakeIssuer();
        var jwt = issuer.IssueAccessToken("u1", "c1",
            new[] { "ezbookkeeping", "obsidian", "gitea" },
            "https://auth.example.com/proxy/ezbookkeeping https://obsidian-mcp.example.com https://gitea-mcp.example.com",
            "read:ezbookkeeping read:obsidian read:gitea");

        var parsed = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
        // 每个资源 server 都能在 aud 集合里找到自己（ProxyEndpoints 用 Contains 校验）
        Assert.Contains("ezbookkeeping", parsed.Audiences);
        Assert.Contains("obsidian", parsed.Audiences);
        Assert.Contains("gitea", parsed.Audiences);
        Assert.Equal(3, parsed.Audiences.Count());
    }

    [Fact]
    public void IssueAccessToken_SingleAud_StillValid()
    {
        var issuer = MakeIssuer();
        var jwt = issuer.IssueAccessToken("u1", "c1", new[] { "obsidian" },
            "https://obsidian-mcp.example.com", "read:obsidian");

        var parsed = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
        Assert.Equal(new[] { "obsidian" }, parsed.Audiences.ToArray());
    }

    [Fact]
    public void IssueAccessToken_EmptyAuds_Throws()
    {
        var issuer = MakeIssuer();
        Assert.Throws<ArgumentException>(() =>
            issuer.IssueAccessToken("u1", "c1", Array.Empty<string>(), "", "read:obsidian"));
    }
}
