using System.Globalization;
using System.Text;

namespace NasAuth.Config;

/// <summary>
/// JWT 签名 / 生命周期配置。
/// access token 默认 RS256：用 OidcKeyService 的 RSA 私钥签，资源服务器从 JWKS 取公钥验签，不再共享对称密钥。
/// HS256 是遗留 / 过渡模式：<c>AccessTokenAlgorithm=HS256</c> 时 SigningKey.Current 必填并用于签发；
/// RS256 模式下 SigningKey 可选，配了也只用来继续验切换前签出的 HS256 token（过渡期），不再签新，
/// 且必须同时配 <see cref="LegacyHs256NotAfter"/> 给过渡期封顶。
/// </summary>
public class JwtOptions
{
    public const string SectionName = "Jwt";

    public const string Rs256 = "RS256";
    public const string Hs256 = "HS256";

    /// <summary>
    /// access token 签名算法："RS256"（默认）| "HS256"。环境变量 <c>Jwt__AccessTokenAlgorithm</c>。
    /// 空 / 纯空白按默认 RS256 处理（compose 里 <c>${VAR}</c> 未设置会得到空串）。
    /// </summary>
    public string AccessTokenAlgorithm { get; set; } = Rs256;

    /// <summary>
    /// RS256 模式下遗留 HS256 验签的截止时间（ISO 8601 绝对时间，不带时区按 UTC），环境变量 <c>Jwt__LegacyHs256NotAfter</c>。
    /// 旧共享密钥曾放在资源服务器和共用 .env 里，拿到它的人能自签任意远期 exp 的 token 打 /proxy、/userinfo ——
    /// 所以过渡期必须有终点：RS256 + 配了 HS256 密钥却没配它 → 启动失败；过了它 → HS256 一律拒；
    /// 之前 → 额外要求 token 的 exp ≤ 它。HS256 模式不看这个值。
    /// </summary>
    public string LegacyHs256NotAfter { get; set; } = "";

    public SigningKeyOptions SigningKey { get; set; } = new();
    public int AccessTokenLifetimeDays { get; set; } = 30;
    public int RefreshTokenLifetimeDays { get; set; } = 90;
    public int AuthCodeLifetimeMinutes { get; set; } = 10;

    /// <summary>规范化后的算法名（大小写不敏感，去空白，空值 = RS256）；未知值在 <see cref="Validate"/> 里 fast fail。</summary>
    public string NormalizedAlgorithm =>
        string.IsNullOrWhiteSpace(AccessTokenAlgorithm) ? Rs256 : AccessTokenAlgorithm.Trim().ToUpperInvariant();

    public bool UsesRs256 => NormalizedAlgorithm == Rs256;

    /// <summary>配了 HS256 密钥（Current 或 Previous 任一）。</summary>
    public bool HasHs256Keys =>
        !string.IsNullOrEmpty(SigningKey.Current) || !string.IsNullOrEmpty(SigningKey.Previous);

    /// <summary>解析后的 <see cref="LegacyHs256NotAfter"/>（UTC）；没配或解析失败为 null（解析失败由 <see cref="Validate"/> 报错）。</summary>
    public DateTimeOffset? LegacyHs256NotAfterUtc =>
        !string.IsNullOrWhiteSpace(LegacyHs256NotAfter) &&
        DateTimeOffset.TryParse(LegacyHs256NotAfter.Trim(), CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var v)
            ? v
            : null;

    /// <summary>
    /// 启动期校验（JwtIssuer 构造时调用）：算法值合法、HS256 模式 Current 必填、配了的 HS256 密钥 ≥ 32 字节、
    /// RS256 模式下留着 HS256 密钥就必须给出合法的 LegacyHs256NotAfter。
    /// </summary>
    public void Validate()
    {
        var alg = NormalizedAlgorithm;
        if (alg is not (Rs256 or Hs256))
            throw new InvalidOperationException(
                $"Jwt:AccessTokenAlgorithm 只能是 RS256 或 HS256，当前为 \"{AccessTokenAlgorithm}\"");

        if (alg == Hs256 && string.IsNullOrWhiteSpace(SigningKey.Current))
            throw new InvalidOperationException("Jwt:SigningKey:Current 未配置（AccessTokenAlgorithm=HS256 时必填）");

        // RS256 模式下 Current 可空；一旦配了（过渡期验旧 token）同样要满足 HS256 安全下限，Previous 同理
        if (!string.IsNullOrEmpty(SigningKey.Current) && Encoding.UTF8.GetBytes(SigningKey.Current).Length < 32)
            throw new InvalidOperationException("Jwt:SigningKey:Current 至少需要 32 字节（HS256 安全下限）");
        if (!string.IsNullOrEmpty(SigningKey.Previous) && Encoding.UTF8.GetBytes(SigningKey.Previous).Length < 32)
            throw new InvalidOperationException("Jwt:SigningKey:Previous 至少需要 32 字节（HS256 安全下限）");

        if (!string.IsNullOrWhiteSpace(LegacyHs256NotAfter) && LegacyHs256NotAfterUtc is null)
            throw new InvalidOperationException(
                $"Jwt:LegacyHs256NotAfter 不是合法的 ISO 8601 时间：\"{LegacyHs256NotAfter}\"（例：2026-10-29T00:00:00Z）");

        if (alg == Rs256 && HasHs256Keys && LegacyHs256NotAfterUtc is null)
            throw new InvalidOperationException(
                "AccessTokenAlgorithm=RS256 但仍配置了 Jwt:SigningKey:Current / Previous（遗留 HS256 验签）：" +
                "必须同时设置 Jwt:LegacyHs256NotAfter（ISO 8601 UTC，例 2026-10-29T00:00:00Z）给过渡期封顶，" +
                "或者直接去掉 HS256 密钥（推荐：客户端拿到 401 后用 refresh token 换 RS256 token）");
    }
}

public class SigningKeyOptions
{
    /// <summary>HS256 密钥。HS256 模式下是签发用密钥（必填，≥ 32 字节）；RS256 模式下可选，仅用于验过渡期的旧 HS256 token。</summary>
    public string Current { get; set; } = "";

    /// <summary>上一代密钥，仅参与验签 fallback（≥ 32 字节）。轮换期结束（旧 Token 全部过期）后清空。</summary>
    public string Previous { get; set; } = "";
}
