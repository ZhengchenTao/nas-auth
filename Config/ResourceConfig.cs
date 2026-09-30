using System.Text.Json.Serialization;

namespace NasAuth.Config;

/// <summary>
/// resources.json 中的一条记录。
/// </summary>
public class ResourceConfig
{
    [JsonPropertyName("aud")]
    public string Aud { get; set; } = "";

    [JsonPropertyName("resource_url")]
    public string ResourceUrl { get; set; } = "";

    [JsonPropertyName("display_name")]
    public string DisplayName { get; set; } = "";

    [JsonPropertyName("scopes")]
    public List<string> Scopes { get; set; } = new();

    /// <summary>
    /// 可选。出现 = 该资源走 nas-auth 自带的 /proxy 翻译层。
    /// 不出现 = 普通 JWT 模式，资源服务自己验签 nas-auth 签的 token。
    /// </summary>
    [JsonPropertyName("proxy")]
    public ProxyConfig? Proxy { get; set; }

    /// <summary>
    /// 可选，默认 false。true = 只能授给管理员（users.is_admin）。
    /// 用于资源服务端拿一把固定凭据访问上游、不区分来访者的资源（如 gitea-mcp 用管理员自己的 PAT、
    /// ezBookkeeping proxy 用管理员的账本 token）：授给别人就等于把管理员的数据交出去。
    /// 生效点：审批与用户编辑页不再能授给非管理员；/authorize 与 refresh 对非管理员一律拒（已有的授权行也挡）。
    /// </summary>
    [JsonPropertyName("admin_only")]
    public bool AdminOnly { get; set; }

    /// <summary>该用户能否持有 / 使用本资源（只看 admin_only，不看 user_resources）。</summary>
    public bool AllowsUser(bool isAdmin) => !AdminOnly || isAdmin;
}

/// <summary>
/// Proxy 资源的翻译规则。
/// 用途：把客户端拿来的 nas-auth JWT 换成预存的上游 token（如 ezBookkeeping MCP token），
/// 反代到 <see cref="Upstream"/>。
/// </summary>
public class ProxyConfig
{
    /// <summary>
    /// 上游 URL，直连上游（不绕回公网反向代理）。例：<c>http://ezbookkeeping:8080</c>（只能是 host root，见 ResourceCatalog）。
    /// </summary>
    [JsonPropertyName("upstream")]
    public string Upstream { get; set; } = "";

    /// <summary>
    /// 从哪个环境变量取上游 Bearer token。例：<c>EZBK_MCP_TOKEN</c>。
    /// 启动期校验：该环境变量必须存在且非空，否则 fast fail。
    /// </summary>
    [JsonPropertyName("bearer_env")]
    public string BearerEnv { get; set; } = "";
}

/// <summary>
/// clients.preset.json 中的一条记录。预置 client，启动时 upsert，永不被自动清理。
/// </summary>
public class PresetClientConfig
{
    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = "";

    [JsonPropertyName("client_secret")]
    public string? ClientSecret { get; set; }

    [JsonPropertyName("client_name")]
    public string ClientName { get; set; } = "";

    [JsonPropertyName("redirect_uris")]
    public List<string> RedirectUris { get; set; } = new();

    [JsonPropertyName("token_endpoint_auth_method")]
    public string TokenEndpointAuthMethod { get; set; } = "none";

    /// <summary>
    /// 可选。非 RFC 8707 客户端（如 Gitea OIDC）不会发 resource 参数，
    /// /authorize 在 resource 缺失时回退到这个值（必须在 resources.json allowlist 内）。
    /// </summary>
    [JsonPropertyName("default_resource")]
    public string? DefaultResource { get; set; }
}
