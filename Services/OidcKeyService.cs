using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.IdentityModel.Tokens;
using NasAuth.Config;

namespace NasAuth.Services;

/// <summary>
/// RS256 密钥管理 + id_token 签发（外部认证设计 §七）。
/// 同一把 RSA 钥签 id_token（外部 RP 如 Gitea 通过 JWKS 验签）和 access token
/// （Jwt:AccessTokenAlgorithm=RS256 时由 JwtIssuer 取 <see cref="SigningCredentials"/> 签，header typ=at+jwt）。
/// 私钥 PEM 持久化到 SQLite 同目录（容器内 /app/data），权限 600；
/// 轮换：把 current 改名成 previous（覆盖旧 previous）、重启即生成新 current。
/// previous 只参与 JWKS 发布与本服务验签，不再签新。
/// ⚠️ previous 的保留期由寿命最长的 token 决定：id_token 只有 1h，但 access token 默认 30 天
/// （Jwt:AccessTokenLifetimeDays），previous 至少留满这么久才能删 / 被再次轮换覆盖，否则在途 access token 全部验签失败。
/// </summary>
public class OidcKeyService
{
    private const string CurrentFile = "oidc_rs256_current.pem";
    private const string PreviousFile = "oidc_rs256_previous.pem";

    private readonly RSA _currentRsa;
    private readonly string _currentKid;
    private readonly RSA? _previousRsa;
    private readonly string? _previousKid;
    private readonly string _issuer;
    private readonly RsaSecurityKey _currentKey;
    private readonly RsaSecurityKey? _previousKey;

    public OidcKeyService(AuthOptions auth, ILogger<OidcKeyService> logger)
    {
        _issuer = auth.Issuer.TrimEnd('/');

        var dir = ResolveKeyDirectory(auth);
        Directory.CreateDirectory(dir);

        var currentPath = Path.Combine(dir, CurrentFile);
        if (!File.Exists(currentPath) && TryCreateKeyFile(currentPath, out var generated))
        {
            _currentRsa = generated;
            logger.LogInformation("OIDC RS256 密钥不存在，已生成并持久化：{Path}", currentPath);
        }
        else
        {
            // 已存在，或另一个实例抢先建好了 —— 读它的，绝不覆盖
            _currentRsa = LoadPem(currentPath, isCurrent: true);
            logger.LogInformation("OIDC RS256 当前密钥已加载：{Path}", currentPath);
        }
        TryChmod600(currentPath); // 已存在的文件也校正一次权限（§九 安全清单）
        _currentKid = ComputeKid(_currentRsa);
        _currentKey = new RsaSecurityKey(_currentRsa) { KeyId = _currentKid };

        var previousPath = Path.Combine(dir, PreviousFile);
        if (File.Exists(previousPath))
        {
            _previousRsa = LoadPem(previousPath, isCurrent: false);
            TryChmod600(previousPath);
            _previousKid = ComputeKid(_previousRsa);
            _previousKey = new RsaSecurityKey(_previousRsa) { KeyId = _previousKid };
            logger.LogInformation("OIDC RS256 上一代密钥已加载（仅 JWKS 发布与验签）：{Path}", previousPath);
        }
    }

    /// <summary>当前私钥的签名凭据（RS256，带 kid）。id_token 与 RS256 access token 共用。</summary>
    public SigningCredentials SigningCredentials => new(_currentKey, SecurityAlgorithms.RsaSha256);

    /// <summary>验签用公钥集合：current + 可选 previous（与 JWKS 发布的集合一致）。</summary>
    public IReadOnlyList<SecurityKey> ValidationKeys =>
        _previousKey is null ? new SecurityKey[] { _currentKey } : new SecurityKey[] { _currentKey, _previousKey };

    /// <summary>id_token：RS256，短寿命 1h（§九）。aud = client_id（OIDC Core §2）。</summary>
    public string IssueIdToken(string userId, string clientId,
        string? email, string? name, string? nonce, string? picture = null,
        IReadOnlyDictionary<string, object>? extraClaims = null)
    {
        var now = DateTimeOffset.UtcNow;
        var claims = new List<Claim>
        {
            new("sub", userId),
            new("preferred_username", userId),
            new("iat", now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
        };
        if (!string.IsNullOrEmpty(email))
        {
            claims.Add(new Claim("email", email));
            // 含义是「管理员为这个邮箱担保」，不是「发过验证邮件」：见 external-auth.md §二十一
            claims.Add(new Claim("email_verified", "true", ClaimValueTypes.Boolean));
        }
        if (!string.IsNullOrEmpty(name)) claims.Add(new Claim("name", name));
        if (!string.IsNullOrEmpty(picture)) claims.Add(new Claim("picture", picture));
        if (!string.IsNullOrEmpty(nonce)) claims.Add(new Claim("nonce", nonce));
        // 按客户端附加的固定 claim（§二十一）。数组一律按 JSON 数组写出：
        // 多个同名 Claim 只有一项时会被序列化成字符串，要 groups 是数组的应用会认不出
        if (extraClaims is not null)
        {
            foreach (var (type, value) in extraClaims)
            {
                claims.Add(value is string s
                    ? new Claim(type, s)
                    : new Claim(type, System.Text.Json.JsonSerializer.Serialize(value), JsonClaimValueTypes.JsonArray));
            }
        }

        // header typ 保持默认 JWT：JwtValidator 只收 typ=at+jwt 的 RS256 token，id_token 不能冒充 access token
        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: clientId,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: now.AddHours(1).UtcDateTime,
            signingCredentials: SigningCredentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>JWKS 文档（current + 可选 previous 的公钥）。</summary>
    public object BuildJwks()
    {
        var keys = new List<object> { ToJwk(_currentRsa, _currentKid) };
        if (_previousRsa is not null && _previousKid is not null)
            keys.Add(ToJwk(_previousRsa, _previousKid));
        return new { keys };
    }

    private static object ToJwk(RSA rsa, string kid)
    {
        var p = rsa.ExportParameters(includePrivateParameters: false);
        return new
        {
            kty = "RSA",
            use = "sig",
            alg = "RS256",
            kid,
            n = Base64UrlEncoder.Encode(p.Modulus),
            e = Base64UrlEncoder.Encode(p.Exponent),
        };
    }

    /// <summary>kid = 公钥 SPKI 的 SHA-256 前 16 个 hex 字符（密钥内容派生，轮换后自然变化）。</summary>
    private static string ComputeKid(RSA rsa)
    {
        var spki = rsa.ExportSubjectPublicKeyInfo();
        return Convert.ToHexString(SHA256.HashData(spki))[..16].ToLowerInvariant();
    }

    /// <summary>
    /// 原子地生成新私钥文件：先写同目录临时文件（非 Windows 创建即 0600，没有「先 0644 再 chmod」的窗口），
    /// 再不覆盖地 rename 到目标路径。目标已被另一个实例抢先建好 → 返回 false，由调用方读那份。
    /// 读方永远看不到写了一半的 PEM。
    /// </summary>
    private static bool TryCreateKeyFile(string path, out RSA rsa)
    {
        rsa = RSA.Create(2048);
        var tmp = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var writer = new StreamWriter(new FileStream(tmp, options)))
                writer.Write(rsa.ExportRSAPrivateKeyPem());

            File.Move(tmp, path, overwrite: false);
            return true;
        }
        catch (IOException) when (File.Exists(path))
        {
            rsa.Dispose();
            return false;
        }
        finally
        {
            try { File.Delete(tmp); } catch { /* 已 rename 走或删不掉都无所谓 */ }
        }
    }

    /// <summary>读 PEM；解析失败给出可操作的报错（点名文件、说明删 / 恢复的后果），fast fail。</summary>
    private static RSA LoadPem(string path, bool isCurrent)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(File.ReadAllText(path));
            return rsa;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            rsa.Dispose();
            var consequence = isCurrent
                ? "删掉它重启会生成新钥，但所有已签出的 access token / id_token 立即失效（客户端需重新授权或 refresh）"
                : "删掉它只影响用上一代钥签的在途 token（到期前验签失败）";
            throw new InvalidOperationException(
                $"OIDC RS256 密钥文件无法解析为 RSA 私钥 PEM：{path}（{ex.Message}）。" +
                $"处理：优先从备份恢复该文件；确认无法恢复时，{consequence}。", ex);
        }
    }

    /// <summary>密钥放 SQLite 同目录：与 auth.db 同卷持久化，不需要新增挂载点。</summary>
    private static string ResolveKeyDirectory(AuthOptions auth)
    {
        var builder = new SqliteConnectionStringBuilder(auth.Database);
        var dbPath = builder.DataSource;
        if (string.IsNullOrWhiteSpace(dbPath) || dbPath == ":memory:")
            return Directory.GetCurrentDirectory();
        return Path.GetDirectoryName(Path.GetFullPath(dbPath)) ?? Directory.GetCurrentDirectory();
    }

    private static void TryChmod600(string path)
    {
        if (OperatingSystem.IsWindows()) return; // 开发机跳过，生产容器是 Linux
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}
