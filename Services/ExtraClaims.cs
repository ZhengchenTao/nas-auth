using System.Text.Json;
using System.Text.RegularExpressions;

namespace NasAuth.Services;

/// <summary>
/// 按客户端附加的固定 claim（external-auth.md §二十一）：clients.preset.json 的客户端条目里写
/// <c>"extra_claims": { "dozzle_roles": ["all"], "tenant": "home" }</c>，对这个客户端签发的 id_token 和
/// 用它的 access token 取的 userinfo 都带上。值只能是字符串或字符串数组。
///
/// 用途是喂给「没有某个 claim 就不让登录」的应用（Dozzle 要角色、有的应用要 groups）。
/// 同一客户端所有用户拿到的值相同，分不了人；以后要按用户覆盖，在条目里另加一层（例如
/// <c>extra_claims_by_user</c>）叠在这上面，不改这里的格式。
/// </summary>
public static partial class ExtraClaims
{
    public const int MaxClaims = 16;
    public const int MaxArrayItems = 64;
    public const int MaxValueLength = 256;

    /// <summary>
    /// 不许配的名字：JWT / OIDC 协议字段，和本 IdP 自己下发的身份字段。
    /// 这些要是能被配置覆盖，一个客户端条目就能改写「这个人是谁」。
    /// </summary>
    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "nonce", "auth_time", "acr", "amr", "azp",
        "at_hash", "c_hash", "s_hash", "sid", "typ", "cnf", "scope", "client_id", "resource",
        "email", "email_verified", "name", "preferred_username", "picture",
    };

    [GeneratedRegex(@"^[A-Za-z0-9_.:/-]{1,128}$")]
    private static partial Regex NamePattern();

    /// <summary>
    /// 校验预置条目里的 extra_claims 并规范化成入库的 JSON 文本（没有或为空 → null）。
    /// 不合法直接抛错：与 clients.preset.json 的其他错误一样启动即失败，免得带着半套配置跑。
    /// </summary>
    public static string? Normalize(string clientId, IReadOnlyDictionary<string, JsonElement>? raw)
    {
        if (raw is null || raw.Count == 0) return null;
        if (raw.Count > MaxClaims)
            throw Invalid(clientId, $"最多 {MaxClaims} 个");

        var result = new SortedDictionary<string, object>(StringComparer.Ordinal);
        foreach (var (name, value) in raw)
        {
            if (!NamePattern().IsMatch(name))
                throw Invalid(clientId, $"名字 \"{name}\" 不合法（只能用字母、数字和 _ . : / -，最长 128）");
            if (Reserved.Contains(name))
                throw Invalid(clientId, $"\"{name}\" 是协议或身份字段，不能用 extra_claims 覆盖");

            switch (value.ValueKind)
            {
                case JsonValueKind.String:
                    result[name] = CheckValue(clientId, name, value.GetString()!);
                    break;
                case JsonValueKind.Array:
                    if (value.GetArrayLength() > MaxArrayItems)
                        throw Invalid(clientId, $"\"{name}\" 的数组最多 {MaxArrayItems} 项");
                    var items = new List<string>();
                    foreach (var item in value.EnumerateArray())
                    {
                        if (item.ValueKind != JsonValueKind.String)
                            throw Invalid(clientId, $"\"{name}\" 的数组里只能放字符串");
                        items.Add(CheckValue(clientId, name, item.GetString()!));
                    }
                    result[name] = items;
                    break;
                default:
                    throw Invalid(clientId, $"\"{name}\" 的值只能是字符串或字符串数组");
            }
        }
        return JsonSerializer.Serialize(result);
    }

    /// <summary>读回入库的 JSON：值是 <see cref="string"/> 或 <c>string[]</c>。库里的内容坏了就当没有（不让登录链路因此 500）。</summary>
    public static IReadOnlyDictionary<string, object> Parse(string? json)
    {
        var result = new Dictionary<string, object>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(json)) return result;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return result;
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                if (Reserved.Contains(p.Name)) continue;
                if (p.Value.ValueKind == JsonValueKind.String)
                    result[p.Name] = p.Value.GetString()!;
                else if (p.Value.ValueKind == JsonValueKind.Array)
                    result[p.Name] = p.Value.EnumerateArray()
                        .Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToArray();
            }
        }
        catch (JsonException)
        {
            result.Clear();
        }
        return result;
    }

    private static string CheckValue(string clientId, string name, string value)
    {
        if (value.Length == 0 || value.Length > MaxValueLength)
            throw Invalid(clientId, $"\"{name}\" 的值长度要在 1–{MaxValueLength} 之间");
        return value;
    }

    private static InvalidOperationException Invalid(string clientId, string why) =>
        new($"clients.preset.json 里客户端 \"{clientId}\" 的 extra_claims 不合法：{why}");
}
