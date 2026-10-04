using System.Text;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>客户端认证材料的两种写法：表单（client_secret_post）与 Authorization: Basic 头（client_secret_basic）。</summary>
public class ClientCredentialsTests
{
    private static string Basic(string pair) => "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(pair));

    [Fact]
    public void NoHeader_ReadsForm()
    {
        Assert.Equal(ClientCredentialsError.None, ClientCredentialsReader.Read(null, "app", "s3cret", out var c));
        Assert.Equal("app", c.ClientId);
        Assert.Equal(new[] { "s3cret" }, c.Secrets);
        Assert.False(c.ViaBasic);

        // 公开客户端：只有 client_id
        Assert.Equal(ClientCredentialsError.None, ClientCredentialsReader.Read("", "public-app", "", out c));
        Assert.Empty(c.Secrets);
    }

    [Theory]
    [InlineData("Bearer abc.def.ghi")]
    [InlineData("DPoP xyz")]
    public void OtherSchemes_AreIgnored(string header)
    {
        Assert.Equal(ClientCredentialsError.None, ClientCredentialsReader.Read(header, "app", "s3cret", out var c));
        Assert.False(c.ViaBasic);
        Assert.Equal("app", c.ClientId);
    }

    [Fact]
    public void BasicHeader_ReadsIdAndSecret_SchemeCaseInsensitive()
    {
        Assert.Equal(ClientCredentialsError.None, ClientCredentialsReader.Read(Basic("app:s3cret"), "", "", out var c));
        Assert.Equal(("app", true), (c.ClientId, c.ViaBasic));
        Assert.Equal(new[] { "s3cret" }, c.Secrets);

        var lower = "basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("app:s3cret"));
        Assert.Equal(ClientCredentialsError.None, ClientCredentialsReader.Read(lower, "", "", out c));
        Assert.Equal("app", c.ClientId);
    }

    [Fact]
    public void BasicHeader_FormEncodedSecret_BothReadingsAreCandidates()
    {
        // 规范写法：secret 先表单编码（RFC 6749 §2.3.1）；不守规范的客户端直接塞原文，原文恰好含 % 或 + 时两种读法不同
        Assert.Equal(ClientCredentialsError.None,
            ClientCredentialsReader.Read(Basic("my%20app:p%40ss+w%3Ard"), "", "", out var c));
        Assert.Equal("my app", c.ClientId);
        Assert.Equal("my%20app", c.RawClientId);
        Assert.Equal(new[] { "p@ss w:rd", "p%40ss+w%3Ard" }, c.Secrets);
    }

    [Fact]
    public void BasicHeader_SecretMayContainColons_AndMayBeEmpty()
    {
        Assert.Equal(ClientCredentialsError.None, ClientCredentialsReader.Read(Basic("app:a:b:c"), "", "", out var c));
        Assert.Equal(new[] { "a:b:c" }, c.Secrets);

        // 公开客户端把 client_id 放头里、secret 留空
        Assert.Equal(ClientCredentialsError.None, ClientCredentialsReader.Read(Basic("public-app:"), "", "", out c));
        Assert.Equal("public-app", c.ClientId);
        Assert.Empty(c.Secrets);
    }

    [Theory]
    [InlineData("Basic !!!not-base64!!!")]
    [InlineData("Basic ")]
    [InlineData("Basic bm9jb2xvbg==")]      // "nocolon"
    [InlineData("Basic OnNlY3JldA==")]      // ":secret"（没有 client_id）
    [InlineData("Basic /w==")]              // 0xFF，不是合法 UTF-8
    public void MalformedBasic_IsRejected_AndMarkedAsBasicAttempt(string header)
    {
        Assert.Equal(ClientCredentialsError.MalformedBasic, ClientCredentialsReader.Read(header, "app", "", out var c));
        Assert.True(c.ViaBasic);   // 401 要带 WWW-Authenticate
    }

    [Fact]
    public void HeaderAndBodySecret_IsRejected()
    {
        Assert.Equal(ClientCredentialsError.MultipleMethods,
            ClientCredentialsReader.Read(Basic("app:s3cret"), "app", "s3cret", out _));
    }

    [Fact]
    public void BodyClientId_MustMatchHeader()
    {
        Assert.Equal(ClientCredentialsError.None, ClientCredentialsReader.Read(Basic("app:s3cret"), "app", "", out _));
        Assert.Equal(ClientCredentialsError.ClientIdMismatch,
            ClientCredentialsReader.Read(Basic("app:s3cret"), "other", "", out _));
    }
}
