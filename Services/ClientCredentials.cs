using System.Text;

namespace NasAuth.Services;

/// <summary>
/// 客户端在 /token /revoke /introspect 上出示的认证材料（RFC 6749 §2.3.1）。
/// <see cref="Secrets"/> 是候选列表：Basic 头里的 secret 按规范要先做表单编码再 base64，
/// 但不少客户端直接塞原文，两种读法都算数（任一命中即通过）。
/// </summary>
public sealed record ClientCredentials(
    string ClientId,
    string? RawClientId,
    IReadOnlyList<string> Secrets,
    bool ViaBasic)
{
    public static readonly ClientCredentials Empty = new("", null, Array.Empty<string>(), false);
}

public enum ClientCredentialsError
{
    None,
    /// <summary>带了 Basic 头但解不出 id:secret</summary>
    MalformedBasic,
    /// <summary>头和表单同时带 secret（RFC 6749 §2.3：一次请求只许一种认证方式）</summary>
    MultipleMethods,
    /// <summary>表单里的 client_id 与头里的不是同一个</summary>
    ClientIdMismatch,
}

/// <summary>
/// 两种写法都收：client_secret_post（表单 client_id + client_secret）与
/// client_secret_basic（<c>Authorization: Basic base64(id:secret)</c>，OIDC 的默认方式）。
/// 不按客户端登记的 token_endpoint_auth_method 区分——secret 是同一个，区分没有安全收益。
/// 公开客户端（none）只需要 client_id，放表单或放头里都行。
/// </summary>
public static class ClientCredentialsReader
{
    public static ClientCredentialsError Read(string? authorization, string? formClientId, string? formClientSecret,
        out ClientCredentials creds)
    {
        formClientId ??= "";
        formClientSecret ??= "";

        const string scheme = "Basic ";
        if (string.IsNullOrEmpty(authorization) || !authorization.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
        {
            // 没有 Basic 头（别的 scheme 一律不理）→ client_secret_post / 公开客户端
            creds = new ClientCredentials(formClientId, null,
                formClientSecret.Length == 0 ? Array.Empty<string>() : new[] { formClientSecret }, ViaBasic: false);
            return ClientCredentialsError.None;
        }

        creds = new ClientCredentials(formClientId, null, Array.Empty<string>(), ViaBasic: true);

        string decoded;
        try
        {
            decoded = new UTF8Encoding(false, throwOnInvalidBytes: true)
                .GetString(Convert.FromBase64String(authorization[scheme.Length..].Trim()));
        }
        catch (Exception e) when (e is FormatException or ArgumentException)
        {
            return ClientCredentialsError.MalformedBasic;
        }

        var colon = decoded.IndexOf(':');
        if (colon <= 0) return ClientCredentialsError.MalformedBasic;

        var rawId = decoded[..colon];
        var rawSecret = decoded[(colon + 1)..];
        var id = FormDecode(rawId);
        creds = new ClientCredentials(id, rawId == id ? null : rawId, Array.Empty<string>(), ViaBasic: true);

        if (formClientSecret.Length != 0) return ClientCredentialsError.MultipleMethods;
        if (formClientId.Length != 0 && formClientId != id && formClientId != rawId)
            return ClientCredentialsError.ClientIdMismatch;

        if (rawSecret.Length != 0)
        {
            var secret = FormDecode(rawSecret);
            creds = creds with { Secrets = secret == rawSecret ? new[] { rawSecret } : new[] { secret, rawSecret } };
        }
        return ClientCredentialsError.None;
    }

    /// <summary>application/x-www-form-urlencoded 解码：+ 是空格，%XX 是字节；坏的 % 序列原样保留。</summary>
    private static string FormDecode(string s) => Uri.UnescapeDataString(s.Replace('+', ' '));
}
