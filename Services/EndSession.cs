using NasAuth.Data;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

/// <summary>
/// OIDC RP-Initiated Logout（external-auth.md §十五）：下游应用退出时把浏览器送到 <c>/logout</c>，
/// nas-auth 清掉自己的 SSO 会话后再跳回 <c>post_logout_redirect_uri</c>。
/// <para>
/// 为什么需要：nas-auth 会话 30 天滑动。在别人电脑上登过一次，退出 Immich 后 nas-auth 还登着，
/// 下一个人点「用 nas-auth 登录」看到的是「以管理员身份授权」—— 一键进管理员账号（2026-09-29 review 查出）。
/// </para>
/// <para>
/// 回跳地址校验（防开放跳转）：只认 http/https；scheme + host + port 必须等于某个<b>预置</b>客户端
/// （auto_registered = 0）登记过的 redirect_uri 的同一来源。DCR 自助注册的客户端不算 ——
/// 任何人都能 DCR 注册一个 evil.example 的回调，算进去就等于把 /logout 变成开放跳转。
/// 带了 client_id 就只在这一个客户端里找。不合法的回跳地址不报错，照常退出、落到登录页。
/// </para>
/// </summary>
public static class EndSession
{
    /// <summary>返回最终跳转地址（已附 state）；不允许回跳时返回 null（调用方落到自己的登录页）。</summary>
    public static string? ResolveRedirect(string? postLogoutRedirectUri, string? clientId, string? state,
        ClientRepository clients)
    {
        if (string.IsNullOrWhiteSpace(postLogoutRedirectUri)) return null;
        if (!TryOrigin(postLogoutRedirectUri, out var target)) return null;

        IEnumerable<ClientRow> candidates;
        if (!string.IsNullOrEmpty(clientId))
        {
            var c = clients.GetById(clientId);
            candidates = c is not null && c.auto_registered == 0 ? new[] { c } : Array.Empty<ClientRow>();
        }
        else
        {
            candidates = clients.ListAll().Where(c => c.auto_registered == 0);
        }

        var allowed = candidates
            .SelectMany(c => ClientRepository.ParseRedirectUris(c.redirect_uris))
            .Any(r => TryOrigin(r, out var o) && o == target);
        if (!allowed) return null;

        if (string.IsNullOrEmpty(state)) return postLogoutRedirectUri;
        var sep = postLogoutRedirectUri.Contains('?') ? '&' : '?';
        return $"{postLogoutRedirectUri}{sep}state={Uri.EscapeDataString(state)}";
    }

    /// <summary>取 scheme://host:port（host 小写）。只认绝对 http/https、不带 userinfo 的地址。</summary>
    private static bool TryOrigin(string raw, out string origin)
    {
        origin = "";
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var u)) return false;
        if (u.Scheme != Uri.UriSchemeHttps && u.Scheme != Uri.UriSchemeHttp) return false;
        if (!string.IsNullOrEmpty(u.UserInfo)) return false;
        origin = $"{u.Scheme}://{u.Host.ToLowerInvariant()}:{u.Port}";
        return true;
    }
}
