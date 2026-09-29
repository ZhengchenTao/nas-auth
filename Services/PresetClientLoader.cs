using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NasAuth.Config;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

/// <summary>
/// 启动期间从 clients.preset.json upsert 预置 client（auto_registered=0，永不自动清理）。
/// 文件不存在时静默跳过（不强制要求）；存在但解析失败 → 抛错 fast fail。
/// </summary>
public static class PresetClientLoader
{
    public static void Load(AuthOptions auth, ClientRepository clients, ILogger logger)
    {
        var path = auth.ClientsPresetPath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            logger.LogInformation("未配置 / 找不到 clients.preset.json（{Path}），跳过预置 client", path ?? "");
            return;
        }

        var json = File.ReadAllText(path);
        List<PresetClientConfig>? list;
        try
        {
            list = JsonSerializer.Deserialize<List<PresetClientConfig>>(json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"clients.preset.json 解析失败：{path}", ex);
        }

        if (list is null || list.Count == 0)
        {
            logger.LogInformation("clients.preset.json 为空，跳过");
            return;
        }

        foreach (var preset in list)
        {
            if (string.IsNullOrWhiteSpace(preset.ClientId) ||
                string.IsNullOrWhiteSpace(preset.ClientName) ||
                preset.RedirectUris is null || preset.RedirectUris.Count == 0)
            {
                throw new InvalidOperationException(
                    $"clients.preset.json 中存在不合法记录：{JsonSerializer.Serialize(preset)}");
            }

            string? secretHash = null;
            if (!string.IsNullOrEmpty(preset.ClientSecret))
            {
                // client secret 用 SHA-256 hex 即可（不是密码，本身就是高熵随机串）
                var h = SHA256.HashData(Encoding.UTF8.GetBytes(preset.ClientSecret));
                secretHash = Convert.ToHexString(h);
            }

            clients.UpsertPreset(preset, secretHash);
            logger.LogInformation("预置 client upsert: {ClientId} ({Name})",
                preset.ClientId, preset.ClientName);
        }
    }

    /// <summary>
    /// client_id 与 resource aud 同名的集合（大小写不敏感，宁可多报）。
    /// id_token 的 aud = client_id，与 access token 同钥签：同名时一个不查 typ 的资源服务器会把 id_token 当 access token 收。
    /// </summary>
    public static IReadOnlyList<string> AudCollisions(IEnumerable<string> clientIds, IEnumerable<string> auds)
    {
        var audSet = new HashSet<string>(auds, StringComparer.OrdinalIgnoreCase);
        return clientIds.Where(audSet.Contains).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>启动期只告警不失败：OIDC 应用的 client 与 resource 常常同名（如 gitea-web / immich），改名要动下游 RP 配置。</summary>
    public static void WarnAudCollisions(ClientRepository clients, ResourceCatalog catalog, ILogger logger)
    {
        foreach (var id in AudCollisions(clients.ListAll().Select(c => c.client_id), catalog.All.Select(r => r.Aud)))
            logger.LogWarning(
                "client_id \"{ClientId}\" 与 resources.json 里的 aud 同名：它的 id_token（aud={ClientId}）与该资源的 access token 同钥签名，" +
                "该 aud 的资源服务器必须校验 typ=at+jwt，否则 id_token 可被当 access token 使用", id, id);
    }
}
