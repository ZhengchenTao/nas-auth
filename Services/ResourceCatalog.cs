using System.Text.Json;
using NasAuth.Config;

namespace NasAuth.Services;

/// <summary>
/// 启动时一次性加载 resources.json。文件不存在 / JSON 解析失败 / 列表空 → 抛 InvalidOperationException
/// 让宿主 fast fail，不掩盖配置错误。
/// 设计决策：不做热加载，重启即可。
/// </summary>
public class ResourceCatalog
{
    private readonly IReadOnlyList<ResourceConfig> _resources;
    private readonly Dictionary<string, ResourceConfig> _byUrl;

    public ResourceCatalog(AuthOptions options, ILogger<ResourceCatalog> logger)
    {
        if (string.IsNullOrWhiteSpace(options.ResourcesPath))
            throw new InvalidOperationException("Auth:ResourcesPath 未配置");

        if (!File.Exists(options.ResourcesPath))
            throw new InvalidOperationException(
                $"resources.json 不存在：{options.ResourcesPath}（fast fail，不创建空清单）");

        var json = File.ReadAllText(options.ResourcesPath);
        var list = JsonSerializer.Deserialize<List<ResourceConfig>>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        if (list is null || list.Count == 0)
            throw new InvalidOperationException(
                $"resources.json 为空或解析失败：{options.ResourcesPath}");

        // 基本校验：aud / resource_url 必填，scopes 至少一条
        var forwardAuthOrigins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in list)
        {
            // forward-auth 站点没有真正的 scope，不写时补一条，授权模型（user_resources 按 scope 勾选）照常可用
            if (r.IsForwardAuth && (r.Scopes is null || r.Scopes.Count == 0))
                r.Scopes = new List<string> { ForwardAuthScope };

            if (string.IsNullOrWhiteSpace(r.Aud) ||
                string.IsNullOrWhiteSpace(r.ResourceUrl) ||
                r.Scopes is null || r.Scopes.Count == 0)
            {
                throw new InvalidOperationException(
                    $"resources.json 中存在不合法记录（aud/resource_url/scopes 缺失）：{JsonSerializer.Serialize(r)}");
            }

            if (r.Proxy is not null && r.ForwardAuth is not null)
                throw new InvalidOperationException(
                    $"resources.json aud={r.Aud} 不能同时配 proxy 与 forward_auth");

            // proxy 字段可选；一旦出现，upstream + bearer_env 必填且对应环境变量必须就绪。
            // fast fail 不让"配错没人发现"过夜。
            if (r.Proxy is not null)
            {
                if (string.IsNullOrWhiteSpace(r.Proxy.Upstream) ||
                    string.IsNullOrWhiteSpace(r.Proxy.BearerEnv))
                {
                    throw new InvalidOperationException(
                        $"resources.json aud={r.Aud} 的 proxy 字段不合法：upstream/bearer_env 缺失");
                }

                if (!Uri.TryCreate(r.Proxy.Upstream, UriKind.Absolute, out var upstreamUri) ||
                    (upstreamUri.Scheme != "http" && upstreamUri.Scheme != "https"))
                {
                    throw new InvalidOperationException(
                        $"resources.json aud={r.Aud} 的 proxy.upstream 不是合法 http(s) URL：{r.Proxy.Upstream}");
                }

                // 约束：upstream 必须是 host root（path == "/" 或空）。
                // 否则反代时路径会被双重拼接（destinationPrefix + 入站 path）导致 404，
                // 而约束 host root 时 transformer 剥掉 "/proxy/{aud}" 前缀后直接 append 干净。
                if (upstreamUri.AbsolutePath != "/" && upstreamUri.AbsolutePath != "")
                {
                    throw new InvalidOperationException(
                        $"resources.json aud={r.Aud} 的 proxy.upstream 不能含 path（应是 host root，如 http://host:port）：{r.Proxy.Upstream}");
                }

                var envValue = Environment.GetEnvironmentVariable(r.Proxy.BearerEnv);
                if (string.IsNullOrWhiteSpace(envValue))
                {
                    throw new InvalidOperationException(
                        $"resources.json aud={r.Aud} 的 proxy.bearer_env={r.Proxy.BearerEnv} 对应环境变量未设置或为空（fast fail）");
                }
            }

            // forward_auth 字段可选；一旦出现，resource_url 就是被保护站点的来源：回跳地址、回调地址都由它拼，
            // 带路径 / query 或两个站点撞同一个来源都会让「这个请求属于哪个站」说不清，启动即失败。
            if (r.ForwardAuth is not null)
            {
                if (!Uri.TryCreate(r.ResourceUrl, UriKind.Absolute, out var siteUri) ||
                    (siteUri.Scheme != "http" && siteUri.Scheme != "https") ||
                    (siteUri.AbsolutePath != "/" && siteUri.AbsolutePath != "") ||
                    !string.IsNullOrEmpty(siteUri.Query) || !string.IsNullOrEmpty(siteUri.Fragment) ||
                    !string.IsNullOrEmpty(siteUri.UserInfo))
                {
                    throw new InvalidOperationException(
                        $"resources.json aud={r.Aud} 是 forward_auth 站点，resource_url 必须是站点来源（如 https://site.example.com，不带路径）：{r.ResourceUrl}");
                }

                if (r.ForwardAuth.SessionHours < 1 || r.ForwardAuth.SessionHours > ForwardAuthConfig.MaxSessionHours)
                    throw new InvalidOperationException(
                        $"resources.json aud={r.Aud} 的 forward_auth.session_hours 须在 1–{ForwardAuthConfig.MaxSessionHours} 之间：{r.ForwardAuth.SessionHours}");

                if (!forwardAuthOrigins.Add(SiteOrigin(r)))
                    throw new InvalidOperationException(
                        $"resources.json 里有两个 forward_auth 站点指向同一个来源：{SiteOrigin(r)}");
            }
        }

        if (list.GroupBy(r => r.Aud, StringComparer.Ordinal).FirstOrDefault(g => g.Count() > 1 && g.Any(r => r.IsForwardAuth)) is { } dup)
            throw new InvalidOperationException($"resources.json 里 forward_auth 站点的 aud 重复：{dup.Key}");

        _resources = list;
        _byUrl = list.ToDictionary(r => NormalizeResourceUrl(r.ResourceUrl), StringComparer.OrdinalIgnoreCase);

        logger.LogInformation("已加载 {Count} 条资源：{Auds}", list.Count,
            string.Join(", ", list.Select(r => r.Aud)));
    }

    public IReadOnlyList<ResourceConfig> All => _resources;

    /// <summary>
    /// 按 resource_url 匹配。
    /// 容忍尾斜杠差异：Claude.ai 会把 PRM 返回的 `https://obsidian-mcp.example.com`
    /// 规范化成 `https://obsidian-mcp.example.com/` 再发到 /authorize；
    /// RFC 3986 这两个 URI 等价，匹配时双方都先 TrimEnd('/')。
    ///
    /// 容忍 MCP 端点子路径：不同客户端对 RFC 8707 resource 取值不一致 ——
    /// Claude.ai 用 PRM 公布的 resource_url 原样回传（精确命中字典）；
    /// 而 OpenAI Codex 用它连接的 MCP 端点 URL 派生 resource，于是会带上 `/mcp`
    /// 子路径（如 `.../proxy/ezbookkeeping/mcp`），与 PRM 公布的资源标识符不等，
    /// 之前会被 allowlist 拒掉（openai/codex#13891 类问题）。退化到「同源 + 路径段
    /// 前缀」匹配放行：请求的 resource 必须是某条 resource_url 的子路径。
    /// 这不放宽授权边界 —— 签发的 token 仍用 catalog 里的规范 resource/aud，
    /// 反代只校验 JWT aud，与客户端传来的 resource 字符串无关。
    /// </summary>
    public ResourceConfig? FindByUrl(string? resourceUrl)
    {
        if (string.IsNullOrWhiteSpace(resourceUrl)) return null;
        var normalized = NormalizeResourceUrl(resourceUrl);
        // forward-auth 站点（§二十二）不是 OAuth 资源：这里是 /authorize、/token（换码与刷新）认 resource 的唯一入口，
        // 在这一处排除，哪条路径都签不出它的 token —— 包括把一个原有的 OAuth 资源原地改成 forward_auth 之后，
        // 手里还留着的 refresh token 与授权码。
        if (_byUrl.TryGetValue(normalized, out var v)) return v.IsForwardAuth ? null : v;

        // 字典精确匹配未命中 —— 退化到子资源匹配（兼容 Codex 等带 /mcp 子路径的客户端）。
        // 同样跳过站点条目：站点的来源是 host root，不跳过的话它会遮住挂在同一来源下面的 OAuth 资源。
        return _resources.FirstOrDefault(
            r => !r.IsForwardAuth && IsSubResourceOf(normalized, NormalizeResourceUrl(r.ResourceUrl)));
    }

    private static string NormalizeResourceUrl(string url) => url.TrimEnd('/');

    /// <summary>
    /// requested 是否为 configured 的子资源：相等，或在「路径段边界」上以 configured + "/"
    /// 为前缀。段边界对齐避免 `.../ezbookkeeping` 误放行 `.../ezbookkeeping-evil`。
    /// 大小写不敏感，与 _byUrl 字典的 OrdinalIgnoreCase 一致。
    /// </summary>
    private static bool IsSubResourceOf(string requested, string configured)
        => requested.Equals(configured, StringComparison.OrdinalIgnoreCase)
           || requested.StartsWith(configured + "/", StringComparison.OrdinalIgnoreCase);

    public ResourceConfig? FindByAud(string aud)
    {
        return _resources.FirstOrDefault(r =>
            string.Equals(r.Aud, aud, StringComparison.Ordinal));
    }

    /// <summary>forward-auth 站点不写 scopes 时补的那一条。</summary>
    public const string ForwardAuthScope = "access";

    /// <summary>forward-auth 站点的来源：scheme://host[:port]，不带尾斜杠。</summary>
    public static string SiteOrigin(ResourceConfig r) =>
        new Uri(r.ResourceUrl).GetLeftPart(UriPartial.Authority);

    /// <summary>按 aud 找 forward-auth 站点；aud 不存在或不是 forward-auth 资源都返回 null。</summary>
    public ResourceConfig? FindForwardAuth(string? aud) =>
        string.IsNullOrEmpty(aud) ? null : _resources.FirstOrDefault(r => r.IsForwardAuth && r.Aud == aud);

    /// <summary>
    /// 按请求的 Host 找 forward-auth 站点（回调 / 退出落在被保护站点自己的域名上）。
    /// 主机名不分大小写；Host 不带端口时按站点 scheme 的默认端口比。
    /// </summary>
    public ResourceConfig? FindForwardAuthByHost(HostString host)
    {
        if (!host.HasValue) return null;
        return _resources.FirstOrDefault(r =>
        {
            if (!r.IsForwardAuth) return false;
            var u = new Uri(r.ResourceUrl);
            return string.Equals(u.Host, host.Host, StringComparison.OrdinalIgnoreCase) &&
                   (host.Port ?? u.Port) == u.Port && (host.Port is not null || u.IsDefaultPort);
        });
    }

    /// <summary>全部 forward-auth 站点的来源（/logout 的回跳白名单用）。</summary>
    public IEnumerable<string> ForwardAuthOrigins() =>
        _resources.Where(r => r.IsForwardAuth).Select(SiteOrigin);

    /// <summary>聚合所有资源的 scope，给 /.well-known 用。forward-auth 站点不参与 OAuth，不算。</summary>
    public IReadOnlyList<string> AllScopes()
    {
        return _resources.Where(r => !r.IsForwardAuth).SelectMany(r => r.Scopes).Distinct().ToList();
    }

    /// <summary>
    /// 反查：返回拥有给定 scope 集合中任一 scope 的全部资源（去重，保持 resources.json 顺序）。
    /// 给「DCR 客户端不发 resource，按请求 scope 反推资源集合」的多 aud 回退用
    /// （AuthorizationEndpoints，见 docs/design/external-auth.md §十三）。
    /// </summary>
    public List<ResourceConfig> ResourcesForScopes(IEnumerable<string> scopes)
    {
        var set = scopes.ToHashSet(StringComparer.Ordinal);
        // forward-auth 站点不签 token：DCR 客户端请求了同名 scope 也不能把它拉进 aud
        return _resources.Where(r => !r.IsForwardAuth && r.Scopes.Any(set.Contains)).ToList();
    }
}
