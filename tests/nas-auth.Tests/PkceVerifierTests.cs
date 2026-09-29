using System.Security.Cryptography;
using System.Text;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

public class PkceVerifierTests
{
    [Fact]
    public void S256_RoundTrip_Succeeds()
    {
        // RFC 7636 §4.6 例子：verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" → challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        Assert.True(PkceVerifier.VerifyS256(verifier, challenge));
    }

    [Fact]
    public void S256_WrongVerifier_Fails()
    {
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var wrongChallenge = "WRONG-EwoaaJ2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        Assert.False(PkceVerifier.VerifyS256(verifier, wrongChallenge));
    }

    [Fact]
    public void S256_TooShortVerifier_Rejected()
    {
        // verifier 必须 ≥ 43 字符
        var verifier = new string('a', 42);
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = PkceVerifier.Base64UrlEncode(hash);
        Assert.False(PkceVerifier.VerifyS256(verifier, challenge));
    }

    [Fact]
    public void S256_EmptyInputs_ReturnFalse()
    {
        Assert.False(PkceVerifier.VerifyS256("", "challenge"));
        Assert.False(PkceVerifier.VerifyS256("verifier", ""));
        Assert.False(PkceVerifier.VerifyS256("", ""));
    }

    [Fact]
    public void Base64UrlEncode_NoPaddingAndUrlSafe()
    {
        // 知道结果：HelloWorld → SGVsbG9Xb3JsZA
        var encoded = PkceVerifier.Base64UrlEncode(Encoding.UTF8.GetBytes("HelloWorld"));
        Assert.DoesNotContain('=', encoded);
        Assert.DoesNotContain('+', encoded);
        Assert.DoesNotContain('/', encoded);
        Assert.Equal("SGVsbG9Xb3JsZA", encoded);
    }
}
