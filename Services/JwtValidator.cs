using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Logging.Abstractions;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using NasAuth.Config;

namespace NasAuth.Services;

/// <summary>
/// 自验签 access token，给 /introspect、/userinfo、/proxy/{aud} 用。按 header alg 分两族，各自钉死算法与密钥类型：
///   RS256 —— OidcKeyService 的 current / previous 公钥（与 JWKS 一致），且必须 typ=at+jwt。
///            同钥签的 id_token（typ=JWT，aud=client_id）因此不能当 access token 用：
///            client 与 resource 同名（如都叫 immich）时 aud 会撞，只靠 aud 挡不住。
///            不看 Jwt:AccessTokenAlgorithm —— 切回 HS256 回滚时在途的 RS256 token 仍有效。
///   HS256 —— 只有配了 Jwt:SigningKey:Current / Previous 才接受。HS256 模式下照常；
///            RS256 模式下是过渡期验旧 token，受 Jwt:LegacyHs256NotAfter 封顶：没配 → 一律拒（启动期已 fast fail，这里兜底），
///            过了截止时间 → 一律拒（首次拒绝打一条 warning），之前 → 还要求 token exp ≤ 截止时间
///            （防拿到旧共享密钥的人自签远期 exp）。
/// ValidAlgorithms 按族钉死：HS256 token 不会拿 RSA 公钥当 HMAC 密钥验（经典 alg confusion），反之亦然；
/// 其余 alg（none / RS512 / ES256 …）一律拒。
/// 返回的 principal 保留 JWT 原始 claim 名（sub / aud / client_id …），不做 inbound map（sub 不会变成 NameIdentifier）。
/// </summary>
public class JwtValidator
{
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(2);

    private readonly JwtOptions _jwt;
    private readonly AuthOptions _auth;
    private readonly OidcKeyService _oidcKeys;
    private readonly ILogger _logger;
    private int _legacyExpiredLogged; // 过了截止时间后只 warn 一次，避免每个请求刷日志

    public JwtValidator(JwtOptions jwt, AuthOptions auth, OidcKeyService oidcKeys, ILogger<JwtValidator>? logger = null)
    {
        _jwt = jwt;
        _auth = auth;
        _oidcKeys = oidcKeys;
        _logger = (ILogger?)logger ?? NullLogger.Instance;
    }

    public ClaimsPrincipal? TryValidate(string token, out SecurityToken? validated)
    {
        validated = null;
        if (string.IsNullOrWhiteSpace(token)) return null;

        try
        {
            // 只在本实例关 inbound map，不动 JwtSecurityTokenHandler.DefaultMapInboundClaims 全局静态
            var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
            // 先只解析 header 选参数族；签名 / 算法 / 类型的真正把关在 ValidateToken 里
            var alg = handler.ReadJwtToken(token).Header.Alg;
            var parameters = alg switch
            {
                SecurityAlgorithms.RsaSha256 => Rs256Parameters(),
                SecurityAlgorithms.HmacSha256 when _jwt.HasHs256Keys && LegacyHs256Open() => Hs256Parameters(),
                _ => null,
            };
            if (parameters is null) return null;

            var principal = handler.ValidateToken(token, parameters, out validated);

            // RS256 模式的遗留 HS256：exp 不许越过截止时间（签名对也不行 —— 旧密钥可能已外泄）
            if (alg == SecurityAlgorithms.HmacSha256 && _jwt.UsesRs256 &&
                (validated is not JwtSecurityToken hs || hs.ValidTo > _jwt.LegacyHs256NotAfterUtc!.Value.UtcDateTime))
            {
                validated = null;
                return null;
            }
            return principal;
        }
        catch
        {
            // 格式错误 / 签名不符 / 过期 / typ 不对 —— 一律视为无效
            validated = null;
            return null;
        }
    }

    /// <summary>HS256 分支是否开放：HS256 模式恒开；RS256 模式只在 LegacyHs256NotAfter 已配且未过时开。</summary>
    private bool LegacyHs256Open()
    {
        if (!_jwt.UsesRs256) return true;
        var notAfter = _jwt.LegacyHs256NotAfterUtc;
        if (notAfter is null) return false;
        if (DateTimeOffset.UtcNow <= notAfter.Value) return true;

        if (Interlocked.Exchange(ref _legacyExpiredLogged, 1) == 0)
            _logger.LogWarning(
                "Jwt:LegacyHs256NotAfter（{NotAfter:o}）已过，遗留 HS256 token 一律拒绝；可以从配置里去掉 Jwt:SigningKey:* 与 Jwt:LegacyHs256NotAfter",
                notAfter.Value);
        return false;
    }

    private TokenValidationParameters Rs256Parameters() => BaseParameters(
        _oidcKeys.ValidationKeys,
        SecurityAlgorithms.RsaSha256,
        validTypes: new[] { JwtIssuer.AccessTokenType });

    private TokenValidationParameters Hs256Parameters() => BaseParameters(
        EnumerateHsKeys().Select(k => (SecurityKey)new SymmetricSecurityKey(Encoding.UTF8.GetBytes(k))).ToList(),
        SecurityAlgorithms.HmacSha256,
        validTypes: null); // 遗留 HS256 token 的 typ 是 JWT；id_token 从来不是 HS256，不需要靠 typ 区分

    private TokenValidationParameters BaseParameters(
        IEnumerable<SecurityKey> keys, string algorithm, IEnumerable<string>? validTypes) => new()
    {
        ValidateIssuer = true,
        ValidIssuer = _auth.Issuer.TrimEnd('/'),
        ValidateAudience = false, // /introspect 不限定 aud，由调用方决定（/proxy 自己比 aud）
        ValidateIssuerSigningKey = true,
        IssuerSigningKeys = keys,
        ValidAlgorithms = new[] { algorithm },
        ValidTypes = validTypes,
        ValidateLifetime = true,
        ClockSkew = ClockSkew,
    };

    private IEnumerable<string> EnumerateHsKeys()
    {
        if (!string.IsNullOrEmpty(_jwt.SigningKey.Current))
            yield return _jwt.SigningKey.Current;
        if (!string.IsNullOrEmpty(_jwt.SigningKey.Previous))
            yield return _jwt.SigningKey.Previous;
    }
}
