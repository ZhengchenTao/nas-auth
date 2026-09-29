using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using NasAuth.Config;

namespace NasAuth.Services;

/// <summary>
/// 签发 access token（JWT）+ refresh token（不透明字符串，调用方负责 hash 入库）。
/// claims 含 iss / aud / sub / scope / resource / client_id / iat / exp（另有 nbf、jti）。
/// access token 算法由 Jwt:AccessTokenAlgorithm 决定：
///   RS256（默认）—— OidcKeyService 当前 RSA 私钥签，header 带 kid、typ=at+jwt（RFC 9068），资源服务器走 JWKS 验签；
///   HS256（遗留）—— 与资源服务器共享的对称密钥签，header typ=JWT，行为与改造前完全一致。
/// </summary>
public class JwtIssuer
{
    private readonly JwtOptions _jwt;
    private readonly AuthOptions _auth;
    private readonly OidcKeyService _oidcKeys;

    /// <summary>RFC 9068 §2.1：JWT access token 的 header typ。</summary>
    public const string AccessTokenType = "at+jwt";

    public JwtIssuer(JwtOptions jwt, AuthOptions auth, OidcKeyService oidcKeys)
    {
        jwt.Validate(); // 算法值 / HS256 密钥 fast fail
        _jwt = jwt;
        _auth = auth;
        _oidcKeys = oidcKeys;
    }

    /// <summary>
    /// 签发 access token。<paramref name="auds"/> 可含多个 aud（DCR 客户端不发 resource、
    /// 按 scope 反推出多资源时的多 aud token，见 docs/design/external-auth.md §十三）；
    /// 单元素时 JWT 的 aud 序列化为字符串，多元素时序列化为数组——两种形态标准校验器
    /// （含本服务 ProxyEndpoints 的 jwt.Audiences.Contains）都能吃。
    /// </summary>
    public string IssueAccessToken(string userId, string clientId, IReadOnlyList<string> auds, string resource, string scope)
    {
        if (auds is null || auds.Count == 0)
            throw new ArgumentException("auds 至少要有一个 audience", nameof(auds));

        var now = DateTimeOffset.UtcNow;
        var exp = now.AddDays(_jwt.AccessTokenLifetimeDays);

        var claims = new List<Claim>
        {
            new("sub", userId),
            new("client_id", clientId),
            new("scope", scope),
            new("resource", resource),
            new("iat", now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            // RFC 9068 §2.2 必填：每个 token 唯一的 jti（16 字节随机，base64url）。两种算法都带，HS256 多一个 claim 无副作用
            new("jti", NewJti()),
        };
        // 多个 aud claim → JwtPayload 聚合成数组；单个 → 字符串。
        // 不走 JwtSecurityToken(audience:) 构造参数，避免与这里的 aud claim 重复。
        foreach (var a in auds) claims.Add(new Claim("aud", a));

        // 与 /.well-known issuer 字段保持一致：去尾斜杠（RFC 8414 §2 要求 issuer 是
        // 不带尾斜杠的 identifier；下游 MCP 服务校验 iss 时按字面比较）。
        var payload = new JwtPayload(
            issuer: _auth.Issuer.TrimEnd('/'),
            audience: null,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: exp.UtcDateTime);

        JwtHeader header;
        if (_jwt.UsesRs256)
        {
            // JwtHeader(creds) 自动写 alg=RS256 与 kid；typ 改成 at+jwt，
            // JwtValidator 靠它把同钥签的 id_token（typ=JWT）挡在 access token 之外
            header = new JwtHeader(_oidcKeys.SigningCredentials);
            header[JwtHeaderParameterNames.Typ] = AccessTokenType;
        }
        else
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.SigningKey.Current));
            header = new JwtHeader(new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        }

        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
    }

    private static string NewJti()
    {
        Span<byte> raw = stackalloc byte[16];
        RandomNumberGenerator.Fill(raw);
        return PkceVerifier.Base64UrlEncode(raw);
    }

    /// <summary>
    /// 签发 refresh token：返回 (明文, sha256-hash)。明文回给客户端，hash 入库。
    /// </summary>
    public (string PlainText, string Hash) IssueRefreshToken()
    {
        // 32 字节随机 → 256 bit 熵，base64url 后 ~43 字符
        Span<byte> raw = stackalloc byte[32];
        RandomNumberGenerator.Fill(raw);
        var plain = PkceVerifier.Base64UrlEncode(raw);
        var hash = HashRefreshToken(plain);
        return (plain, hash);
    }

    public static string HashRefreshToken(string plainText)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.TryHashData(Encoding.ASCII.GetBytes(plainText), hash, out _);
        return Convert.ToHexString(hash);
    }

    public DateTimeOffset RefreshTokenExpiry()
        => DateTimeOffset.UtcNow.AddDays(_jwt.RefreshTokenLifetimeDays);

    public DateTimeOffset AuthCodeExpiry()
        => DateTimeOffset.UtcNow.AddMinutes(_jwt.AuthCodeLifetimeMinutes);

    public int AccessTokenLifetimeSeconds() => _jwt.AccessTokenLifetimeDays * 86400;
}
