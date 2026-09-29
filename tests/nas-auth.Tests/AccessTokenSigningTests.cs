using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NasAuth.Config;
using NasAuth.Pages;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>
/// access token 签名算法：默认 RS256（JWKS 验签、typ=at+jwt），HS256 作为遗留 / 过渡模式。
/// 覆盖签发 header、JwtValidator 的两族验签、id_token 冒充、alg confusion、RSA 钥轮换、多 aud、HS256 模式回归。
/// </summary>
public class AccessTokenSigningTests : IDisposable
{
    private const string Issuer = "https://auth.example.com";
    private static readonly string HsKey = new('k', 40);
    private readonly string _tmpDir;

    public AccessTokenSigningTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-ats-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    // ---------- 工厂 ----------

    private AuthOptions Auth() => new()
    {
        Issuer = Issuer + "/", // 带尾斜杠，确认签发 / 验签两侧都去掉
        Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}",
    };

    /// <summary>每次 new 一个 = 模拟一次重启（从磁盘重新加载 PEM）。</summary>
    private OidcKeyService Keys() => new(Auth(), NullLogger<OidcKeyService>.Instance);

    /// <summary>RS256 模式；留着 HS256 密钥时默认给 60 天后的 LegacyHs256NotAfter（30 天寿命的旧 token 能过）。</summary>
    private static JwtOptions Rs(string current = "", string previous = "", string? notAfter = null) => new()
    {
        SigningKey = new SigningKeyOptions { Current = current, Previous = previous },
        LegacyHs256NotAfter = notAfter
            ?? (current.Length + previous.Length == 0 ? "" : DateTimeOffset.UtcNow.AddDays(60).ToString("o")),
    };

    private static JwtOptions Hs(string current, string previous = "") => new()
    {
        AccessTokenAlgorithm = "HS256",
        SigningKey = new SigningKeyOptions { Current = current, Previous = previous },
    };

    private JwtIssuer IssuerOf(JwtOptions jwt, OidcKeyService keys) => new(jwt, Auth(), keys);
    private JwtValidator ValidatorOf(JwtOptions jwt, OidcKeyService keys) => new(jwt, Auth(), keys);

    private static string Issue(JwtIssuer issuer, params string[] auds) =>
        issuer.IssueAccessToken("admin", "claude", auds.Length == 0 ? new[] { "obsidian" } : auds,
            "https://obsidian-mcp.example.com", "read:obsidian");

    private static string KidOf(OidcKeyService svc, int index = 0)
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(svc.BuildJwks()));
        return doc.RootElement.GetProperty("keys")[index].GetProperty("kid").GetString()!;
    }

    private static RSA PublicKeyFromJwks(OidcKeyService svc)
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(svc.BuildJwks()));
        var k = doc.RootElement.GetProperty("keys")[0];
        var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = Base64UrlEncoder.DecodeBytes(k.GetProperty("n").GetString()),
            Exponent = Base64UrlEncoder.DecodeBytes(k.GetProperty("e").GetString()),
        });
        return rsa;
    }

    /// <summary>手工拼 JWT（header / payload 任意），签名由调用方给 —— 用来构造 alg confusion 之类的攻击 token。</summary>
    private static string Craft(Dictionary<string, object> header, Func<byte[], byte[]> sign, object? payload = null)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        payload ??= new Dictionary<string, object>
        {
            ["iss"] = Issuer, ["sub"] = "admin", ["client_id"] = "claude", ["aud"] = "obsidian",
            ["scope"] = "read:obsidian write:obsidian", ["iat"] = now, ["nbf"] = now, ["exp"] = now + 3600,
        };
        var h = Base64UrlEncoder.Encode(JsonSerializer.Serialize(header));
        var p = Base64UrlEncoder.Encode(JsonSerializer.Serialize(payload));
        var sig = sign(Encoding.ASCII.GetBytes($"{h}.{p}"));
        return $"{h}.{p}.{Base64UrlEncoder.Encode(sig)}";
    }

    // ---------- 配置 ----------

    [Fact]
    public void Options_DefaultIsRs256_AndHsKeysOptional()
    {
        var jwt = new JwtOptions();
        Assert.True(jwt.UsesRs256);
        jwt.Validate(); // 不配任何 HS256 密钥也能启动
        Assert.False(jwt.HasHs256Keys);
    }

    [Theory]
    [InlineData("ES256")]
    [InlineData("none")]
    public void Options_UnknownAlgorithm_FailsFast(string alg)
    {
        var jwt = new JwtOptions { AccessTokenAlgorithm = alg };
        Assert.Throws<InvalidOperationException>(jwt.Validate);
    }

    [Fact]
    public void Options_Hs256_RequiresCurrent_AtLeast32Bytes()
    {
        Assert.Throws<InvalidOperationException>(() => Hs("").Validate());
        Assert.Throws<InvalidOperationException>(() => Hs(new string('k', 31)).Validate());
        Hs(HsKey).Validate();
        new JwtOptions { AccessTokenAlgorithm = "hs256", SigningKey = { Current = HsKey } }.Validate(); // 大小写不敏感
    }

    [Fact]
    public void Options_Rs256_LegacyHsKeyStillChecked()
    {
        // RS256 模式下 HS256 key 可选，但配了就得满足 32 字节下限
        Assert.Throws<InvalidOperationException>(() => Rs(current: "short").Validate());
        Rs(current: HsKey).Validate();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Options_EmptyAlgorithm_MeansRs256(string? alg)
    {
        // compose 里 Jwt__AccessTokenAlgorithm=${VAR} 未设置时是空串
        var jwt = new JwtOptions { AccessTokenAlgorithm = alg! };
        Assert.True(jwt.UsesRs256);
        Assert.Equal("RS256", jwt.NormalizedAlgorithm);
        jwt.Validate();
    }

    [Fact]
    public void Options_PreviousKey_AtLeast32Bytes()
    {
        Assert.Throws<InvalidOperationException>(() => Hs(HsKey, previous: "short").Validate());
        Assert.Throws<InvalidOperationException>(() => Rs(previous: new string('p', 31)).Validate());
        Hs(HsKey, previous: new string('p', 32)).Validate();
    }

    [Fact]
    public void Options_Rs256WithHsKeys_RequiresNotAfter()
    {
        var jwt = new JwtOptions { SigningKey = { Current = HsKey } };
        var ex = Assert.Throws<InvalidOperationException>(jwt.Validate);
        Assert.Contains("LegacyHs256NotAfter", ex.Message);

        Assert.Throws<InvalidOperationException>(() => Rs(previous: HsKey, notAfter: "next tuesday").Validate());
        Rs(current: HsKey, notAfter: "2030-01-01T00:00:00Z").Validate();
        // HS256 模式不需要 NotAfter
        Hs(HsKey).Validate();
    }

    [Fact]
    public void Options_NotAfter_WithoutOffset_IsUtc()
    {
        var jwt = Rs(current: HsKey, notAfter: "2030-01-01T08:00:00");
        Assert.Equal(new DateTimeOffset(2030, 1, 1, 8, 0, 0, TimeSpan.Zero), jwt.LegacyHs256NotAfterUtc);
        Assert.Equal(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero),
            Rs(current: HsKey, notAfter: "2030-01-01T08:00:00+08:00").LegacyHs256NotAfterUtc);
    }

    [Fact]
    public void Issuer_UnknownAlgorithm_FailsAtConstruction()
    {
        Assert.Throws<InvalidOperationException>(() =>
            IssuerOf(new JwtOptions { AccessTokenAlgorithm = "RS512" }, Keys()));
    }

    // ---------- RS256 签发 ----------

    [Fact]
    public void Rs256_Header_HasAlgKidAndAtJwtTyp()
    {
        var keys = Keys();
        var token = Issue(IssuerOf(Rs(), keys));
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);

        Assert.Equal("RS256", jwt.Header.Alg);
        Assert.Equal("at+jwt", jwt.Header.Typ);
        Assert.Equal(KidOf(keys), jwt.Header.Kid);
    }

    [Fact]
    public void Rs256_Claims_Unchanged()
    {
        var token = Issue(IssuerOf(Rs(), Keys()));
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);

        Assert.Equal(Issuer, jwt.Issuer);
        Assert.Equal("admin", jwt.Payload.Sub);
        Assert.Equal("claude", jwt.Payload["client_id"]);
        Assert.Equal("read:obsidian", jwt.Payload["scope"]);
        Assert.Equal("https://obsidian-mcp.example.com", jwt.Payload["resource"]);
        Assert.Equal("obsidian", Assert.Single(jwt.Audiences));
        Assert.True(jwt.Payload.ContainsKey("iat"));
        Assert.True(jwt.Payload.ContainsKey("nbf"));
        Assert.True(jwt.ValidTo > DateTime.UtcNow.AddDays(29));
    }

    [Fact]
    public void Rs256_ValidatesViaJwtValidator()
    {
        var keys = Keys();
        var token = Issue(IssuerOf(Rs(), keys));

        var principal = ValidatorOf(Rs(), keys).TryValidate(token, out var validated);
        Assert.NotNull(principal);
        Assert.Equal("admin", Assert.IsType<JwtSecurityToken>(validated).Subject);
        // JwtValidator 不做 inbound claim map：sub / client_id 按原名可取，不会变成 NameIdentifier
        Assert.Equal("admin", principal!.FindFirst("sub")?.Value);
        Assert.Equal("claude", principal.FindFirst("client_id")?.Value);
        Assert.Null(principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier));
    }

    [Fact]
    public void Validator_DoesNotTouchGlobalInboundMap()
    {
        // 只在实例上关 map，全局默认值不能被改（外部登录等其他 handler 依赖它）
        var before = JwtSecurityTokenHandler.DefaultMapInboundClaims;
        var keys = Keys();
        ValidatorOf(Rs(), keys).TryValidate(Issue(IssuerOf(Rs(), keys)), out _);
        Assert.Equal(before, JwtSecurityTokenHandler.DefaultMapInboundClaims);
        Assert.NotEmpty(JwtSecurityTokenHandler.DefaultInboundClaimTypeMap);
    }

    // ---------- /introspect 响应体 ----------

    private JsonElement Introspect(JwtOptions jwt, string token)
    {
        var keys = Keys();
        Assert.NotNull(ValidatorOf(jwt, keys).TryValidate(token, out var validated));
        var body = NasAuth.Endpoints.TokenEndpoints.JwtIntrospection(Assert.IsType<JwtSecurityToken>(validated));
        return JsonDocument.Parse(JsonSerializer.Serialize(body)).RootElement.Clone();
    }

    [Fact]
    public void Introspect_MultiAud_ReturnsArray_WithSub()
    {
        var keys = Keys();
        var token = Issue(IssuerOf(Rs(), keys), "ezbookkeeping", "obsidian", "gitea");
        var r = Introspect(Rs(), token);

        Assert.True(r.GetProperty("active").GetBoolean());
        Assert.Equal("admin", r.GetProperty("sub").GetString());
        Assert.Equal("claude", r.GetProperty("client_id").GetString());
        Assert.Equal(Issuer, r.GetProperty("iss").GetString());
        Assert.Equal("read:obsidian", r.GetProperty("scope").GetString());
        var aud = r.GetProperty("aud");
        Assert.Equal(JsonValueKind.Array, aud.ValueKind);
        Assert.Equal(new[] { "ezbookkeeping", "obsidian", "gitea" }, aud.EnumerateArray().Select(e => e.GetString()).ToArray());
        Assert.True(r.GetProperty("exp").GetInt64() > DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        Assert.True(r.GetProperty("iat").GetInt64() > 0);
        Assert.Equal("Bearer", r.GetProperty("token_type").GetString());
    }

    [Fact]
    public void Introspect_SingleAud_ReturnsString()
    {
        var r = Introspect(Rs(), Issue(IssuerOf(Rs(), Keys()), "obsidian"));
        Assert.Equal(JsonValueKind.String, r.GetProperty("aud").ValueKind);
        Assert.Equal("obsidian", r.GetProperty("aud").GetString());
        Assert.Equal("admin", r.GetProperty("sub").GetString());
    }

    [Fact]
    public void Introspect_LegacyHs256_HasSub()
    {
        var r = Introspect(Rs(HsKey), Issue(IssuerOf(Hs(HsKey), Keys()), "ezbookkeeping", "obsidian"));
        Assert.Equal("admin", r.GetProperty("sub").GetString());
        Assert.Equal(2, r.GetProperty("aud").GetArrayLength());
    }

    [Fact]
    public void Rs256_ValidatesAgainstJwks_LikeAResourceServer()
    {
        // 模拟 obsidian-mcp / gitea-mcp 的 JwtBearer：只拿 JWKS 公钥，验 iss / aud / 有效期 / typ
        var keys = Keys();
        var token = Issue(IssuerOf(Rs(), keys));

        new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
        {
            ValidIssuer = Issuer,
            ValidAudience = "obsidian",
            IssuerSigningKey = new RsaSecurityKey(PublicKeyFromJwks(keys)),
            ValidAlgorithms = new[] { "RS256" },
            ValidTypes = new[] { "at+jwt" },
        }, out _);
    }

    [Fact]
    public void Rs256_MultiAud_WorksWithProxyAudCheck()
    {
        var keys = Keys();
        var token = Issue(IssuerOf(Rs(), keys), "ezbookkeeping", "obsidian", "gitea");

        var principal = ValidatorOf(Rs(), keys).TryValidate(token, out var validated);
        Assert.NotNull(principal);
        // 与 ProxyEndpoints 同一判据：validated 是 JwtSecurityToken，URL 里的 {aud} 落在 Audiences 内
        var jwt = Assert.IsType<JwtSecurityToken>(validated);
        Assert.Contains("ezbookkeeping", jwt.Audiences, StringComparer.Ordinal);
        Assert.Contains("gitea", jwt.Audiences, StringComparer.Ordinal);
        Assert.DoesNotContain("immich", jwt.Audiences, StringComparer.Ordinal);
    }

    [Fact]
    public void Rs256_WrongIssuer_Rejected()
    {
        var keys = Keys();
        var token = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            new JwtHeader(keys.SigningCredentials) { ["typ"] = "at+jwt" },
            new JwtPayload("https://evil.example.com", "obsidian", null, DateTime.UtcNow, DateTime.UtcNow.AddHours(1))));
        Assert.Null(ValidatorOf(Rs(), keys).TryValidate(token, out _));
    }

    [Fact]
    public void Rs256_Expired_Rejected()
    {
        var keys = Keys();
        var now = DateTime.UtcNow;
        var token = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            new JwtHeader(keys.SigningCredentials) { ["typ"] = "at+jwt" },
            new JwtPayload(Issuer, "obsidian", null, now.AddHours(-2), now.AddMinutes(-10))));
        Assert.Null(ValidatorOf(Rs(), keys).TryValidate(token, out _));
    }

    // ---------- id_token 不能当 access token ----------

    [Fact]
    public void IdToken_RejectedAsAccessToken_EvenWhenAudCollides()
    {
        // client 与 resource 同名（都叫 immich）：id_token 的 aud=immich 与资源 aud 撞，只能靠 typ 挡
        var keys = Keys();
        var idToken = keys.IssueIdToken("admin", "immich", "a@example.com", "Admin", nonce: null);
        Assert.Equal("JWT", new JwtSecurityTokenHandler().ReadJwtToken(idToken).Header.Typ);

        Assert.Null(ValidatorOf(Rs(), keys).TryValidate(idToken, out _));
        Assert.Null(ValidatorOf(Rs(HsKey), keys).TryValidate(idToken, out _));
        Assert.Null(ValidatorOf(Hs(HsKey), keys).TryValidate(idToken, out _));
    }

    [Fact]
    public void Rs256_WithoutTyp_Rejected()
    {
        var keys = Keys();
        var rsaKey = (RsaSecurityKey)keys.ValidationKeys[0];
        var token = Craft(new() { ["alg"] = "RS256", ["kid"] = rsaKey.KeyId },
            data => rsaKey.Rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Null(ValidatorOf(Rs(), keys).TryValidate(token, out _));

        // 同一把钥、同样的内容，补上 typ=at+jwt 就能过 —— 证明上面是被 typ 挡下的
        var ok = Craft(new() { ["alg"] = "RS256", ["kid"] = rsaKey.KeyId, ["typ"] = "at+jwt" },
            data => rsaKey.Rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.NotNull(ValidatorOf(Rs(), keys).TryValidate(ok, out _));
    }

    // ---------- HS256 遗留 ----------

    [Fact]
    public void Hs256Legacy_AcceptedOnlyWhenKeyConfigured()
    {
        var keys = Keys();
        var legacy = Issue(IssuerOf(Hs(HsKey), keys));

        // RS256 模式 + 旧 key 仍配着（Current 或 Previous 都行）→ 过渡期照常能验
        Assert.NotNull(ValidatorOf(Rs(current: HsKey), keys).TryValidate(legacy, out _));
        Assert.NotNull(ValidatorOf(Rs(previous: HsKey), keys).TryValidate(legacy, out _));
        // 旧 key 摘掉 → 拒
        Assert.Null(ValidatorOf(Rs(), keys).TryValidate(legacy, out _));
        // 配的是别的 key → 拒
        Assert.Null(ValidatorOf(Rs(current: new string('x', 40)), keys).TryValidate(legacy, out _));
    }

    // ---------- 遗留 HS256 的截止时间 ----------

    private static string ForgeHs(string key, DateTimeOffset exp)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return Craft(new() { ["alg"] = "HS256", ["typ"] = "JWT" },
            data => HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), data),
            new Dictionary<string, object>
            {
                ["iss"] = Issuer, ["sub"] = "admin", ["client_id"] = "claude", ["aud"] = "ezbookkeeping",
                ["scope"] = "read:ezbookkeeping", ["iat"] = now, ["nbf"] = now, ["exp"] = exp.ToUnixTimeSeconds(),
            });
    }

    [Fact]
    public void LegacyHs256_FarFutureExp_Rejected()
    {
        // 拿到旧共享密钥的人自签 10 年期 token：签名对，但 exp 越过截止时间 → 拒
        var keys = Keys();
        var forged = ForgeHs(HsKey, DateTimeOffset.UtcNow.AddYears(10));
        Assert.Null(ValidatorOf(Rs(current: HsKey), keys).TryValidate(forged, out _));

        // 同一把钥、exp 在截止时间之内 → 过（证明上面是被 NotAfter 挡下的）
        var ok = ForgeHs(HsKey, DateTimeOffset.UtcNow.AddDays(1));
        Assert.NotNull(ValidatorOf(Rs(current: HsKey), keys).TryValidate(ok, out _));
    }

    [Fact]
    public void LegacyHs256_ExpBeyondNotAfter_Rejected()
    {
        var keys = Keys();
        var legacy = Issue(IssuerOf(Hs(HsKey), keys)); // 30 天寿命
        var notAfter = DateTimeOffset.UtcNow.AddDays(1).ToString("o");
        Assert.Null(ValidatorOf(Rs(current: HsKey, notAfter: notAfter), keys).TryValidate(legacy, out _));
    }

    [Fact]
    public void LegacyHs256_AfterNotAfter_AllRejected_Rs256Unaffected()
    {
        var keys = Keys();
        var past = DateTimeOffset.UtcNow.AddMinutes(-1).ToString("o");
        var validator = ValidatorOf(Rs(current: HsKey, notAfter: past), keys);

        // 过了截止时间 HS256 分支整个关掉，签名再对也不收；RS256 不受影响
        Assert.Null(validator.TryValidate(ForgeHs(HsKey, DateTimeOffset.UtcNow.AddHours(1)), out _));
        Assert.NotNull(validator.TryValidate(Issue(IssuerOf(Rs(), keys)), out _));
    }

    [Fact]
    public void LegacyHs256_NotAfterMissing_ValidatorFailsClosed()
    {
        // 启动期会 fast fail；万一绕过（直接 new 的实例），验签侧也不放行
        var keys = Keys();
        var jwt = new JwtOptions { SigningKey = { Current = HsKey } };
        Assert.Null(ValidatorOf(jwt, keys).TryValidate(ForgeHs(HsKey, DateTimeOffset.UtcNow.AddHours(1)), out _));
    }

    [Fact]
    public void Hs256Mode_IgnoresNotAfter()
    {
        var keys = Keys();
        var hs = Hs(HsKey);
        hs.LegacyHs256NotAfter = DateTimeOffset.UtcNow.AddDays(-1).ToString("o");
        Assert.NotNull(ValidatorOf(hs, keys).TryValidate(Issue(IssuerOf(hs, keys)), out _));
    }

    // ---------- jti ----------

    [Fact]
    public void AccessToken_HasUniqueJti_IdTokenHasNone()
    {
        var keys = Keys();
        var issuer = IssuerOf(Rs(), keys);
        var handler = new JwtSecurityTokenHandler();
        var a = handler.ReadJwtToken(Issue(issuer)).Id;
        var b = handler.ReadJwtToken(Issue(issuer)).Id;
        Assert.False(string.IsNullOrEmpty(a));
        Assert.NotEqual(a, b);
        Assert.Equal(16, Base64UrlEncoder.DecodeBytes(a).Length);

        Assert.False(string.IsNullOrEmpty(handler.ReadJwtToken(Issue(IssuerOf(Hs(HsKey), keys))).Id));
        Assert.True(string.IsNullOrEmpty(handler.ReadJwtToken(keys.IssueIdToken("admin", "gitea-web", null, null, null)).Id));
    }

    // ---------- header 里夹带攻击者的钥 ----------

    [Theory]
    [InlineData("jwk")]
    [InlineData("jku")]
    [InlineData("x5u")]
    public void AttackerSuppliedKeyInHeader_Rejected(string param)
    {
        var keys = Keys();
        using var attacker = RSA.Create(2048);
        var p = attacker.ExportParameters(false);
        object value = param switch
        {
            "jwk" => new Dictionary<string, object>
            {
                ["kty"] = "RSA", ["use"] = "sig", ["alg"] = "RS256", ["kid"] = "evil",
                ["n"] = Base64UrlEncoder.Encode(p.Modulus), ["e"] = Base64UrlEncoder.Encode(p.Exponent),
            },
            "jku" => "https://evil.example.com/jwks.json",
            _ => "https://evil.example.com/cert.pem",
        };
        foreach (var kid in new[] { "evil", KidOf(keys) })
        {
            var token = Craft(new() { ["alg"] = "RS256", ["typ"] = "at+jwt", ["kid"] = kid, [param] = value },
                data => attacker.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            Assert.Null(ValidatorOf(Rs(), keys).TryValidate(token, out _));
            Assert.Null(ValidatorOf(Rs(HsKey), keys).TryValidate(token, out _));
        }
    }

    // ---------- 资源服务器视角：真实 JWKS JSON + JsonWebTokenHandler ----------

    private static TokenValidationParameters ResourceServerParameters(OidcKeyService keys, string aud)
    {
        // 与 /.well-known/jwks.json 输出同一份 JSON（端点就是 Results.Ok(keys.BuildJwks())）
        var jwks = new JsonWebKeySet(JsonSerializer.Serialize(keys.BuildJwks()));
        return new TokenValidationParameters
        {
            ValidIssuer = Issuer,
            ValidAudience = aud,
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidAlgorithms = new[] { "RS256" },
            ValidTypes = new[] { "at+jwt", "application/at+jwt" },
        };
    }

    [Fact]
    public async Task ResourceServer_JsonWebTokenHandler_WithParsedJwks_AcceptsAccessToken()
    {
        var keys = Keys();
        var token = Issue(IssuerOf(Rs(), keys), "ezbookkeeping", "obsidian");
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, ResourceServerParameters(keys, "obsidian"));
        Assert.True(result.IsValid, result.Exception?.ToString());
        Assert.Equal("admin", result.Claims["sub"]);
    }

    [Fact]
    public async Task ResourceServer_JsonWebTokenHandler_RejectsIdToken_WithCollidingAud()
    {
        var keys = Keys();
        var idToken = keys.IssueIdToken("admin", "immich", null, null, null);
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(idToken, ResourceServerParameters(keys, "immich"));
        Assert.False(result.IsValid);
        Assert.IsType<SecurityTokenInvalidTypeException>(result.Exception);
    }

    // ---------- client_id 与 aud 同名告警 ----------

    [Fact]
    public void AudCollisions_FindsClientIdsNamedLikeResources()
    {
        var hits = PresetClientLoader.AudCollisions(
            new[] { "gitea-web", "Immich", "claude", "dcr-3f9a" },
            new[] { "gitea-web", "immich", "obsidian" });
        Assert.Equal(new[] { "gitea-web", "Immich" }, hits.ToArray());
    }

    // ---------- alg confusion ----------

    public static IEnumerable<object[]> HsValidatorConfigs() => new[]
    {
        new object[] { "rs-no-hs" },
        new object[] { "rs-with-hs" },
        new object[] { "hs" },
    };

    private JwtOptions ConfigOf(string name) => name switch
    {
        "rs-no-hs" => Rs(),
        "rs-with-hs" => Rs(current: HsKey),
        _ => Hs(HsKey),
    };

    [Theory]
    [MemberData(nameof(HsValidatorConfigs))]
    public void AlgConfusion_Hs256SignedWithRsaPublicKey_Rejected(string config)
    {
        // 经典攻击：拿 JWKS 公开的 RSA 公钥（各种编码）当 HMAC 密钥签 HS256，header 还带上真 kid
        var keys = Keys();
        var rsa = PublicKeyFromJwks(keys);
        var secrets = new[]
        {
            rsa.ExportSubjectPublicKeyInfo(),
            Encoding.UTF8.GetBytes(rsa.ExportSubjectPublicKeyInfoPem()),
            Encoding.UTF8.GetBytes(rsa.ExportRSAPublicKeyPem()),
            rsa.ExportRSAPublicKey(),
        };
        var validator = ValidatorOf(ConfigOf(config), keys);
        foreach (var secret in secrets)
        {
            foreach (var typ in new[] { "JWT", "at+jwt" })
            {
                var token = Craft(new() { ["alg"] = "HS256", ["typ"] = typ, ["kid"] = KidOf(keys) },
                    data => HMACSHA256.HashData(secret, data));
                Assert.Null(validator.TryValidate(token, out _));
            }
        }
    }

    [Theory]
    [MemberData(nameof(HsValidatorConfigs))]
    public void AlgConfusion_Rs256HeaderWithHmacSignature_Rejected(string config)
    {
        // 反方向：header 声称 RS256，签名其实是用 HS256 密钥做的 HMAC
        var keys = Keys();
        var token = Craft(new() { ["alg"] = "RS256", ["typ"] = "at+jwt", ["kid"] = KidOf(keys) },
            data => HMACSHA256.HashData(Encoding.UTF8.GetBytes(HsKey), data));
        Assert.Null(ValidatorOf(ConfigOf(config), keys).TryValidate(token, out _));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("RS512")]
    [InlineData("HS512")]
    public void OtherAlgorithms_Rejected(string alg)
    {
        var keys = Keys();
        var rsaKey = (RsaSecurityKey)keys.ValidationKeys[0];
        var token = Craft(new() { ["alg"] = alg, ["typ"] = "at+jwt", ["kid"] = rsaKey.KeyId }, data => alg switch
        {
            "RS512" => rsaKey.Rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
            "HS512" => HMACSHA512.HashData(Encoding.UTF8.GetBytes(HsKey), data),
            _ => Array.Empty<byte>(),
        });
        Assert.Null(ValidatorOf(Rs(HsKey), keys).TryValidate(token, out _));
    }

    // ---------- RSA 钥轮换 ----------

    [Fact]
    public void RsaRotation_PreviousKeyStillValidates_UntilRemoved()
    {
        var before = Keys();
        var oldToken = Issue(IssuerOf(Rs(), before));
        var oldKid = KidOf(before);

        // 运维步骤：current 改名 previous，重启（新实例生成新 current）
        File.Move(Path.Combine(_tmpDir, "oidc_rs256_current.pem"), Path.Combine(_tmpDir, "oidc_rs256_previous.pem"));
        var after = Keys();
        Assert.NotEqual(oldKid, KidOf(after));
        Assert.Equal(oldKid, KidOf(after, 1)); // previous 仍在 JWKS 里

        var newToken = Issue(IssuerOf(Rs(), after));
        Assert.Equal(KidOf(after), new JwtSecurityTokenHandler().ReadJwtToken(newToken).Header.Kid);
        Assert.NotNull(ValidatorOf(Rs(), after).TryValidate(oldToken, out _));
        Assert.NotNull(ValidatorOf(Rs(), after).TryValidate(newToken, out _));

        // previous 删掉再重启 → 旧 token 失效，新 token 不受影响
        File.Delete(Path.Combine(_tmpDir, "oidc_rs256_previous.pem"));
        var pruned = Keys();
        Assert.Null(ValidatorOf(Rs(), pruned).TryValidate(oldToken, out _));
        Assert.NotNull(ValidatorOf(Rs(), pruned).TryValidate(newToken, out _));
    }

    // ---------- HS256 模式回归 ----------

    [Fact]
    public void Hs256Mode_EndToEnd()
    {
        var keys = Keys();
        var hs = Hs(HsKey);
        var token = Issue(IssuerOf(hs, keys), "ezbookkeeping", "obsidian");

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        Assert.Equal("HS256", jwt.Header.Alg);
        Assert.Equal("JWT", jwt.Header.Typ); // 与改造前一致
        Assert.Null(jwt.Header.Kid);

        var principal = ValidatorOf(hs, keys).TryValidate(token, out var validated);
        Assert.NotNull(principal);
        Assert.Contains("obsidian", Assert.IsType<JwtSecurityToken>(validated).Audiences);

        // 轮换：新 key 当 Current、旧 key 挪 Previous → 旧 token 仍能验
        Assert.NotNull(ValidatorOf(Hs(new string('n', 40), previous: HsKey), keys).TryValidate(token, out _));
    }

    [Fact]
    public void Hs256Mode_StillAcceptsRs256AccessTokens_ForRollback()
    {
        // 从 RS256 回滚到 HS256 时，在途的 RS256 access token 不应瞬间全部失效
        var keys = Keys();
        var rsToken = Issue(IssuerOf(Rs(), keys));
        Assert.NotNull(ValidatorOf(Hs(HsKey), keys).TryValidate(rsToken, out _));
    }

    // ---------- 管理后台系统页 ----------

    [Fact]
    public void SystemSection_Rs256_ShowsRsaRotationSteps_NoGenerateButton()
    {
        var html = DashboardTemplates.SystemSection(null, true, true, null, false,
            jwt: new JwtKeyView(Rs256: true, LegacyHs256Keys: true, AccessTokenLifetimeDays: 30));
        Assert.DoesNotContain("/admin/rotate-jwt-key", html);
        Assert.Contains("oidc_rs256_previous.pem", html);
        Assert.Contains("30", html);
        Assert.Contains("Jwt__SigningKey__", html);
    }

    [Fact]
    public void SystemSection_Hs256_KeepsGenerateButton()
    {
        var html = DashboardTemplates.SystemSection(null, true, true, null, false,
            jwt: new JwtKeyView(Rs256: false, LegacyHs256Keys: true, AccessTokenLifetimeDays: 30));
        Assert.Contains("/admin/rotate-jwt-key", html);
        Assert.DoesNotContain("oidc_rs256_previous.pem", html);
    }
}
