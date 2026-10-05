using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using NasAuth.Config;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>external-auth.md §二十一：按客户端附加的固定 claim，以及 email_verified。</summary>
public class ExtraClaimsTests : IDisposable
{
    private readonly string _tmpDir;

    public ExtraClaimsTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    private static Dictionary<string, JsonElement> Raw(string json) =>
        JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)!;

    private static JsonElement Payload(string jwt)
    {
        var part = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        part = part.PadRight(part.Length + (4 - part.Length % 4) % 4, '=');
        return JsonDocument.Parse(Convert.FromBase64String(part)).RootElement.Clone();
    }

    [Fact]
    public void Normalize_AcceptsStringsAndStringArrays_RoundTripsThroughParse()
    {
        var json = ExtraClaims.Normalize("dozzle", Raw("""{ "dozzle_roles": ["all"], "tenant": "home", "https://example.com/roles": ["a", "b"] }"""));
        var parsed = ExtraClaims.Parse(json);

        Assert.Equal(new[] { "all" }, Assert.IsType<string[]>(parsed["dozzle_roles"]));
        Assert.Equal("home", parsed["tenant"]);
        Assert.Equal(new[] { "a", "b" }, Assert.IsType<string[]>(parsed["https://example.com/roles"]));
    }

    [Fact]
    public void Normalize_NullOrEmpty_IsNoClaims()
    {
        Assert.Null(ExtraClaims.Normalize("c", null));
        Assert.Null(ExtraClaims.Normalize("c", Raw("{}")));
        Assert.Empty(ExtraClaims.Parse(null));
        Assert.Empty(ExtraClaims.Parse("not json"));
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("iss")]
    [InlineData("aud")]
    [InlineData("exp")]
    [InlineData("nonce")]
    [InlineData("email")]
    [InlineData("email_verified")]
    [InlineData("Email_Verified")]          // 大小写不同也算撞名
    [InlineData("name")]
    [InlineData("preferred_username")]
    [InlineData("picture")]
    [InlineData("client_id")]
    [InlineData("scope")]
    public void Normalize_RejectsProtocolAndIdentityClaims(string name)
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            ExtraClaims.Normalize("evil", Raw($$"""{ "{{name}}": "x" }""")));
        Assert.Contains("evil", ex.Message);
    }

    [Theory]
    [InlineData("""{ "roles": 1 }""")]
    [InlineData("""{ "roles": true }""")]
    [InlineData("""{ "roles": { "all": {} } }""")]
    [InlineData("""{ "roles": ["a", 2] }""")]
    [InlineData("""{ "roles": [["nested"]] }""")]
    [InlineData("""{ "roles": "" }""")]
    [InlineData("""{ "bad name": "x" }""")]
    [InlineData("""{ "": "x" }""")]
    public void Normalize_RejectsAnythingButStringsAndStringArrays(string json) =>
        Assert.Throws<InvalidOperationException>(() => ExtraClaims.Normalize("c", Raw(json)));

    [Fact]
    public void Parse_NeverReturnsReservedNames_EvenIfTheStoredJsonHasThem()
    {
        // 库里的内容不经 Normalize（手改库、旧版本写入）也不能覆盖身份字段
        var parsed = ExtraClaims.Parse("""{ "sub": "someone-else", "email": "x@evil.example", "groups": ["g"] }""");
        Assert.Equal(new[] { "groups" }, parsed.Keys);
    }

    private OidcKeyService Keys() => new(
        new AuthOptions
        {
            Issuer = "https://auth.example.com/",
            Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}",
        },
        NullLogger<OidcKeyService>.Instance);

    [Fact]
    public void IdToken_CarriesExtraClaims_ArraysStayArraysEvenWithOneItem()
    {
        var extra = ExtraClaims.Parse(ExtraClaims.Normalize("dozzle", Raw("""{ "dozzle_roles": ["all"], "groups": ["a", "b"], "tenant": "home" }""")));
        var p = Payload(Keys().IssueIdToken("tao", "dozzle", "tao@example.com", "Tao", nonce: "n", extraClaims: extra));

        Assert.Equal(JsonValueKind.Array, p.GetProperty("dozzle_roles").ValueKind);
        Assert.Equal("all", p.GetProperty("dozzle_roles")[0].GetString());
        Assert.Equal(2, p.GetProperty("groups").GetArrayLength());
        Assert.Equal("home", p.GetProperty("tenant").GetString());
        // 身份字段不受影响
        Assert.Equal("tao", p.GetProperty("sub").GetString());
        Assert.Equal("dozzle", p.GetProperty("aud").GetString());
    }

    [Fact]
    public void IdToken_EmailVerified_IsBooleanTrue_OnlyWhenThereIsAnEmail()
    {
        var with = Payload(Keys().IssueIdToken("tao", "immich", "tao@example.com", "Tao", nonce: null));
        Assert.Equal(JsonValueKind.True, with.GetProperty("email_verified").ValueKind);

        var without = Payload(Keys().IssueIdToken("guest", "immich", email: null, name: null, nonce: null));
        Assert.False(without.TryGetProperty("email", out _));
        Assert.False(without.TryGetProperty("email_verified", out _));
    }
}
