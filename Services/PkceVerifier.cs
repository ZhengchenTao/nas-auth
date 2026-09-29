using System.Security.Cryptography;
using System.Text;

namespace NasAuth.Services;

/// <summary>
/// RFC 7636 PKCE。必须 S256，拒绝 plain。
/// </summary>
public static class PkceVerifier
{
    /// <summary>
    /// S256 验证：base64url(SHA256(verifier)) == challenge ?
    /// </summary>
    public static bool VerifyS256(string verifier, string challenge)
    {
        if (string.IsNullOrEmpty(verifier) || string.IsNullOrEmpty(challenge)) return false;
        // RFC 7636 §4.1：43–128 字符
        if (verifier.Length < 43 || verifier.Length > 128) return false;

        Span<byte> hash = stackalloc byte[32];
        if (!SHA256.TryHashData(Encoding.ASCII.GetBytes(verifier), hash, out _))
            return false;

        var encoded = Base64UrlEncode(hash);
        // 用 FixedTimeEquals 防止时序泄漏
        var expectedBytes = Encoding.ASCII.GetBytes(challenge);
        var actualBytes = Encoding.ASCII.GetBytes(encoded);
        if (expectedBytes.Length != actualBytes.Length) return false;
        return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }

    /// <summary>
    /// base64url（无 padding）。RFC 7636 §4.2 用的就是这个编码。
    /// </summary>
    public static string Base64UrlEncode(ReadOnlySpan<byte> bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
