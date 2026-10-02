using System.Security.Cryptography;
using System.Text.RegularExpressions;
using NasAuth.Config;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

/// <summary>
/// 昵称与头像（external-auth.md §十九）。
/// 用户 id 不可改（各应用按 sub / preferred_username 认人）；昵称下发为 name，头像下发为 picture（本服务上的公开图片地址）。
/// 头像文件放在 auth.db 同目录的 avatars/ 下，文件名 = 内容 SHA-256 前 32 位 + 扩展名：内容变了地址就变，
/// 所以可以让浏览器和各应用长期缓存，也天然去重。
/// </summary>
public partial class ProfileService
{
    public const int MaxAvatarBytes = 2 * 1024 * 1024;
    public const string HttpClientName = "avatar";

    private readonly string _dir;
    private readonly string _issuer;
    private readonly ILogger<ProfileService> _logger;

    public ProfileService(AuthOptions options, ILogger<ProfileService> logger)
    {
        var dbPath = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(options.Database).DataSource;
        var dataDir = Path.GetDirectoryName(Path.GetFullPath(dbPath)) ?? AppContext.BaseDirectory;
        _dir = Path.Combine(dataDir, "avatars");
        _issuer = options.Issuer.TrimEnd('/');
        _logger = logger;
    }

    [GeneratedRegex(@"^[0-9a-f]{32}\.(png|jpg|webp)$")]
    private static partial Regex FileNamePattern();

    /// <summary>按文件头判断格式（不信扩展名 / Content-Type）。只收位图：SVG 能带脚本，GIF 没必要。</summary>
    public static string? DetectImageType(ReadOnlySpan<byte> data)
    {
        if (data.Length >= 8 && data[..8].SequenceEqual(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A })) return "png";
        if (data.Length >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) return "jpg";
        if (data.Length >= 12 && data[..4].SequenceEqual("RIFF"u8) && data[8..12].SequenceEqual("WEBP"u8)) return "webp";
        return null;
    }

    public static string ContentTypeOf(string file) => Path.GetExtension(file) switch
    {
        ".png" => "image/png",
        ".jpg" => "image/jpeg",
        ".webp" => "image/webp",
        _ => "application/octet-stream",
    };

    /// <summary>存头像，返回文件名；不是支持的图片或超过大小返回 null。</summary>
    public string? Store(byte[] data)
    {
        if (data.Length == 0 || data.Length > MaxAvatarBytes) return null;
        var ext = DetectImageType(data);
        if (ext is null) return null;
        var name = Convert.ToHexString(SHA256.HashData(data))[..32].ToLowerInvariant() + "." + ext;
        Directory.CreateDirectory(_dir);
        var path = Path.Combine(_dir, name);
        if (!File.Exists(path))
        {
            var tmp = path + ".tmp-" + Guid.NewGuid().ToString("N");
            File.WriteAllBytes(tmp, data);
            File.Move(tmp, path, overwrite: true);
        }
        return name;
    }

    /// <summary>头像文件的本地路径；文件名不合规（防路径穿越）或文件不存在返回 null。</summary>
    public string? PathFor(string file)
    {
        if (!FileNamePattern().IsMatch(file)) return null;
        var path = Path.Combine(_dir, file);
        return File.Exists(path) ? path : null;
    }

    /// <summary>下发给应用的 picture 地址。</summary>
    public string? PictureUrl(string? file) => string.IsNullOrEmpty(file) ? null : $"{_issuer}/avatars/{file}";

    /// <summary>
    /// 下载外部账号的头像存起来（Google 的 picture 地址 / 微软 Graph 的照片）。
    /// 任何失败只记日志返回 null —— 头像拿不到不能挡住登录。
    /// </summary>
    public async Task<string?> DownloadAsync(HttpClient http, string url, string? bearerToken, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            if (!string.IsNullOrEmpty(bearerToken))
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearerToken);
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!resp.IsSuccessStatusCode) return null;   // 微软账号没设照片时是 404
            if (resp.Content.Headers.ContentLength > MaxAvatarBytes) return null;
            await using var stream = await resp.Content.ReadAsStreamAsync(ct);
            using var buffer = new MemoryStream();
            var chunk = new byte[81920];
            int read;
            while ((read = await stream.ReadAsync(chunk, ct)) > 0)
            {
                if (buffer.Length + read > MaxAvatarBytes) return null;
                buffer.Write(chunk, 0, read);
            }
            return Store(buffer.ToArray());
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
        {
            _logger.LogWarning("下载外部头像失败（不影响登录）：{Message}", ex.Message);
            return null;
        }
    }

    /// <summary>
    /// 下发给应用的资料：email / name / picture。
    /// email：用户自己的 users.email 优先，没设退回第一条 active 外部身份的邮箱（google 优先，按 provider 字典序）——
    /// 下游（如 Immich）按 email 关联账号，一个用户可能绑了两个外部账号，退回值未必是他在下游的邮箱（§十四）。
    /// name：昵称（§十九），没设退回第一条 active 外部身份的名字，再退回 user_id。
    /// </summary>
    public (string? Email, string? Name, string? Picture) Resolve(
        ExternalIdentityRepository identities, UserRepository users, string userId)
    {
        var (email, name, avatar) = ResolveCore(identities, users, userId);
        return (email, name, PictureUrl(avatar));
    }

    /// <summary>不含头像地址的版本（地址要 issuer，静态场景用不到）。</summary>
    public static (string? Email, string? Name, string? AvatarFile) ResolveCore(
        ExternalIdentityRepository identities, UserRepository users, string userId)
    {
        var user = users.GetById(userId);
        var active = identities.ListByUser(userId).Where(r => r.status == "active").ToList();
        var email = !string.IsNullOrEmpty(user?.email) ? user.email
            : active.FirstOrDefault(r => !string.IsNullOrEmpty(r.email))?.email;
        var name = !string.IsNullOrEmpty(user?.display_name) ? user.display_name
            : active.FirstOrDefault(r => !string.IsNullOrEmpty(r.display_name))?.display_name
            ?? userId;
        return (email, name, user?.avatar);
    }
}
