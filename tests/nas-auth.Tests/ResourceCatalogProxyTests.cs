using Microsoft.Extensions.Logging.Abstractions;
using NasAuth.Config;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// 覆盖 ResourceCatalog 对 proxy 字段的解析与校验。
/// proxy 字段可选；一旦出现，upstream + bearer_env 必填且对应环境变量必须就绪。
/// </summary>
public class ResourceCatalogProxyTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly List<string> _envVarsToClear = new();

    public ResourceCatalogProxyTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
        foreach (var v in _envVarsToClear)
            Environment.SetEnvironmentVariable(v, null);
    }

    private string WriteResourcesJson(string content)
    {
        var path = Path.Combine(_tmpDir, $"resources-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, content);
        return path;
    }

    private void SetEnv(string name, string value)
    {
        _envVarsToClear.Add(name);
        Environment.SetEnvironmentVariable(name, value);
    }

    private static ResourceCatalog Load(string path)
        => new(new AuthOptions { ResourcesPath = path }, NullLogger<ResourceCatalog>.Instance);

    [Fact]
    public void NoProxy_LoadsOk_BackwardCompat()
    {
        var path = WriteResourcesJson("""
            [{
                "aud": "obsidian",
                "resource_url": "https://obsidian-mcp.example.com",
                "display_name": "Obsidian Vault",
                "scopes": ["read:obsidian"]
            }]
            """);
        var cat = Load(path);
        var r = cat.FindByAud("obsidian");
        Assert.NotNull(r);
        Assert.Null(r!.Proxy);
    }

    [Fact]
    public void WithProxy_AndEnvSet_LoadsOk()
    {
        SetEnv("PROXY_TEST_TOKEN_OK", "deadbeef");
        var path = WriteResourcesJson("""
            [{
                "aud": "ezbookkeeping",
                "resource_url": "https://auth.example.com/proxy/ezbookkeeping",
                "display_name": "ezBookkeeping",
                "scopes": ["read:ezbookkeeping"],
                "proxy": {
                    "upstream": "http://192.0.2.10:8089",
                    "bearer_env": "PROXY_TEST_TOKEN_OK"
                }
            }]
            """);
        var cat = Load(path);
        var r = cat.FindByAud("ezbookkeeping");
        Assert.NotNull(r);
        Assert.NotNull(r!.Proxy);
        Assert.Equal("http://192.0.2.10:8089", r.Proxy!.Upstream);
        Assert.Equal("PROXY_TEST_TOKEN_OK", r.Proxy.BearerEnv);
    }

    [Fact]
    public void WithProxy_EnvNotSet_FastFails()
    {
        // 不 SetEnv，确保该名 env 没有设置
        Environment.SetEnvironmentVariable("PROXY_TEST_MISSING_ENV", null);
        var path = WriteResourcesJson("""
            [{
                "aud": "ezbookkeeping",
                "resource_url": "https://x.example.com",
                "display_name": "x",
                "scopes": ["read:x"],
                "proxy": {
                    "upstream": "http://192.0.2.10:8089",
                    "bearer_env": "PROXY_TEST_MISSING_ENV"
                }
            }]
            """);
        var ex = Assert.Throws<InvalidOperationException>(() => Load(path));
        Assert.Contains("PROXY_TEST_MISSING_ENV", ex.Message);
    }

    [Fact]
    public void WithProxy_UpstreamMissing_FastFails()
    {
        SetEnv("PROXY_TEST_TOKEN_X", "x");
        var path = WriteResourcesJson("""
            [{
                "aud": "x",
                "resource_url": "https://x.example.com",
                "display_name": "x",
                "scopes": ["read:x"],
                "proxy": {
                    "upstream": "",
                    "bearer_env": "PROXY_TEST_TOKEN_X"
                }
            }]
            """);
        var ex = Assert.Throws<InvalidOperationException>(() => Load(path));
        Assert.Contains("upstream/bearer_env", ex.Message);
    }

    [Fact]
    public void WithProxy_BearerEnvMissing_FastFails()
    {
        var path = WriteResourcesJson("""
            [{
                "aud": "x",
                "resource_url": "https://x.example.com",
                "display_name": "x",
                "scopes": ["read:x"],
                "proxy": {
                    "upstream": "http://192.0.2.10:8089/mcp",
                    "bearer_env": ""
                }
            }]
            """);
        var ex = Assert.Throws<InvalidOperationException>(() => Load(path));
        Assert.Contains("upstream/bearer_env", ex.Message);
    }

    [Fact]
    public void WithProxy_UpstreamNotHttp_FastFails()
    {
        SetEnv("PROXY_TEST_TOKEN_Y", "y");
        var path = WriteResourcesJson("""
            [{
                "aud": "x",
                "resource_url": "https://x.example.com",
                "display_name": "x",
                "scopes": ["read:x"],
                "proxy": {
                    "upstream": "ftp://example.com/mcp",
                    "bearer_env": "PROXY_TEST_TOKEN_Y"
                }
            }]
            """);
        var ex = Assert.Throws<InvalidOperationException>(() => Load(path));
        Assert.Contains("不是合法 http(s) URL", ex.Message);
    }

    [Fact]
    public void WithProxy_UpstreamRelative_FastFails()
    {
        SetEnv("PROXY_TEST_TOKEN_Z", "z");
        var path = WriteResourcesJson("""
            [{
                "aud": "x",
                "resource_url": "https://x.example.com",
                "display_name": "x",
                "scopes": ["read:x"],
                "proxy": {
                    "upstream": "/relative/path",
                    "bearer_env": "PROXY_TEST_TOKEN_Z"
                }
            }]
            """);
        var ex = Assert.Throws<InvalidOperationException>(() => Load(path));
        Assert.Contains("不是合法 http(s) URL", ex.Message);
    }

    [Fact]
    public void WithProxy_UpstreamContainsPath_FastFails()
    {
        // upstream 含 path 时反代会路径双拼接，强制 host root
        SetEnv("PROXY_TEST_TOKEN_P", "p");
        var path = WriteResourcesJson("""
            [{
                "aud": "x",
                "resource_url": "https://x.example.com",
                "display_name": "x",
                "scopes": ["read:x"],
                "proxy": {
                    "upstream": "http://192.0.2.10:8089/mcp",
                    "bearer_env": "PROXY_TEST_TOKEN_P"
                }
            }]
            """);
        var ex = Assert.Throws<InvalidOperationException>(() => Load(path));
        Assert.Contains("不能含 path", ex.Message);
    }

    [Fact]
    public void WithProxy_UpstreamHostRootWithSlash_LoadsOk()
    {
        SetEnv("PROXY_TEST_TOKEN_HR", "hr");
        var path = WriteResourcesJson("""
            [{
                "aud": "x",
                "resource_url": "https://x.example.com",
                "display_name": "x",
                "scopes": ["read:x"],
                "proxy": {
                    "upstream": "http://192.0.2.10:8089/",
                    "bearer_env": "PROXY_TEST_TOKEN_HR"
                }
            }]
            """);
        var cat = Load(path);
        Assert.NotNull(cat.FindByAud("x")!.Proxy);
    }

    // ---- FindByUrl 匹配语义 ----

    private const string ResourcesForMatch = """
        [{
            "aud": "ezbookkeeping",
            "resource_url": "https://auth.example.com/proxy/ezbookkeeping",
            "display_name": "ezBookkeeping",
            "scopes": ["read:ezbookkeeping"]
        }]
        """;

    [Fact]
    public void FindByUrl_Exact_Matches()
    {
        var cat = Load(WriteResourcesJson(ResourcesForMatch));
        Assert.NotNull(cat.FindByUrl("https://auth.example.com/proxy/ezbookkeeping"));
    }

    [Fact]
    public void FindByUrl_TrailingSlash_Matches()
    {
        // Claude.ai 把 PRM resource 规范化成带尾斜杠
        var cat = Load(WriteResourcesJson(ResourcesForMatch));
        Assert.NotNull(cat.FindByUrl("https://auth.example.com/proxy/ezbookkeeping/"));
    }

    [Fact]
    public void FindByUrl_McpSubPath_Matches()
    {
        // Codex 用连接的 MCP 端点 URL 派生 resource，带 /mcp 子路径
        var cat = Load(WriteResourcesJson(ResourcesForMatch));
        Assert.NotNull(cat.FindByUrl("https://auth.example.com/proxy/ezbookkeeping/mcp"));
    }

    [Fact]
    public void FindByUrl_SiblingPrefix_DoesNotMatch()
    {
        // 段边界对齐：ezbookkeeping-evil 不能蹭 ezbookkeeping 的 allowlist
        var cat = Load(WriteResourcesJson(ResourcesForMatch));
        Assert.Null(cat.FindByUrl("https://auth.example.com/proxy/ezbookkeeping-evil"));
    }

    [Fact]
    public void FindByUrl_DifferentHost_DoesNotMatch()
    {
        var cat = Load(WriteResourcesJson(ResourcesForMatch));
        Assert.Null(cat.FindByUrl("https://evil.example.com/proxy/ezbookkeeping/mcp"));
    }
}
