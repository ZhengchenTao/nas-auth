using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace NasAuth.Services;

/// <summary>
/// forward-auth（external-auth.md §二十二）用到的三种加密载荷，以及与请求无关的纯判定。
/// <para>
/// 被保护站点与本服务不同源，主会话 cookie（<c>__Host-</c>，只在本服务的域名上）到不了那边。
/// 所以每个站点各有一张自己的 host-only cookie，靠一次带票据的回跳种下：
/// </para>
/// <list type="bullet">
/// <item><b>state</b>：反向代理来问、发现没会话时签发。记下「哪个站、原本要去哪、这个浏览器的随机数」，
/// 随机数同时种成站点上的一张临时 cookie，回调时两边要对得上 —— 别人把自己的回调链接发给你点，种不上会话。</item>
/// <item><b>ticket</b>：用户在本服务登录并通过授权检查后签发，60 秒、只能用一次，带到站点的回调地址换会话。</item>
/// <item><b>session</b>：站点 cookie 的内容。只记用户、站点、会话版本；授权每次请求实时查库。</item>
/// </list>
/// <para>
/// 三种载荷用不同的 purpose 加密，互相冒充解不开；都绑定 aud，A 站的拿到 B 站不认。
/// 密钥是会话 cookie 那一套 DataProtection 密钥（数据卷里的 dp-keys/），重启不丢。
/// 过期时间写在载荷里、按 <see cref="TimeProvider"/> 判，不用 DataProtection 自带的限时封装 —— 测试里要能拨时间。
/// </para>
/// </summary>
public sealed class ForwardAuthService
{
    /// <summary>站点 cookie。<c>__Host-</c>：浏览器强制 Secure + Path=/ + 不带 Domain，兄弟子域种不了同名的。</summary>
    public const string SessionCookie = "__Host-nas-auth-fa";
    public const string StateCookie = "__Host-nas-auth-fa-state";

    /// <summary>被保护站点要让给本服务的路径前缀（回调、退出），反向代理把它直接转过来、不过 forward-auth。</summary>
    public const string PathPrefix = "/.nas-auth";

    public static readonly TimeSpan StateLifetime = TimeSpan.FromHours(1);
    public static readonly TimeSpan TicketLifetime = TimeSpan.FromSeconds(60);

    private const int MaxReturnPathLength = 2000;

    private readonly IDataProtector _state;
    private readonly IDataProtector _ticket;
    private readonly IDataProtector _session;
    private readonly TimeProvider _time;

    // 用过的票据 id → 票据到期时间。只放内存：票据 60 秒就过期，重启丢了也只是让重启前 60 秒内签出的票据能再用一次，
    // 而重放还得过 state cookie 那一关。
    private readonly ConcurrentDictionary<string, long> _usedTickets = new(StringComparer.Ordinal);

    public ForwardAuthService(IDataProtectionProvider provider, TimeProvider? time = null)
    {
        _state = provider.CreateProtector("nas-auth.forward-auth.v1", "state");
        _ticket = provider.CreateProtector("nas-auth.forward-auth.v1", "ticket");
        _session = provider.CreateProtector("nas-auth.forward-auth.v1", "session");
        _time = time ?? TimeProvider.System;
    }

    public record State(string Aud, string ReturnPath, string Nonce, long Exp);
    public record Ticket(string Aud, string UserId, long SessionVersion, string Id, long Exp);
    public record Session(string Aud, string UserId, long SessionVersion, long Exp);

    private long Now => _time.GetUtcNow().ToUnixTimeSeconds();

    public static string NewNonce() => Base64Url(RandomNumberGenerator.GetBytes(16));

    public string CreateState(string aud, string returnPath, string nonce) =>
        Protect(_state, new State(aud, returnPath, nonce, Now + (long)StateLifetime.TotalSeconds));

    public bool TryReadState(string? raw, [NotNullWhen(true)] out State? state) =>
        TryUnprotect(_state, raw, out state) && state.Exp > Now;

    public string CreateTicket(string aud, string userId, long sessionVersion) =>
        Protect(_ticket, new Ticket(aud, userId, sessionVersion, NewNonce(), Now + (long)TicketLifetime.TotalSeconds));

    public bool TryReadTicket(string? raw, [NotNullWhen(true)] out Ticket? ticket) =>
        TryUnprotect(_ticket, raw, out ticket) && ticket.Exp > Now;

    /// <summary>票据只能用一次：第一次返回 true 并记下，之后同一张返回 false。顺手清掉已过期的记录。</summary>
    public bool TryConsume(Ticket ticket)
    {
        var now = Now;
        foreach (var (id, exp) in _usedTickets)
            if (exp <= now) _usedTickets.TryRemove(id, out _);
        return _usedTickets.TryAdd(ticket.Id, ticket.Exp);
    }

    public string CreateSession(string aud, string userId, long sessionVersion, TimeSpan lifetime) =>
        Protect(_session, new Session(aud, userId, sessionVersion, Now + (long)lifetime.TotalSeconds));

    public bool TryReadSession(string? raw, [NotNullWhen(true)] out Session? session) =>
        TryUnprotect(_session, raw, out session) && session.Exp > Now;

    /// <summary>定长时间比较回调带来的随机数与 cookie 里的那份。</summary>
    public static bool NonceMatches(string? cookieValue, string expected) =>
        !string.IsNullOrEmpty(cookieValue) &&
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(cookieValue), Encoding.UTF8.GetBytes(expected));

    /// <summary>
    /// 反向代理转来的原始路径（含 query）只有是干净的站内地址才记下来当回跳目标，否则回站点首页。
    /// 判据与 <see cref="ReturnUrl"/> 相同（防 <c>//evil</c>、控制字符、非 ASCII）；
    /// 另外不回到 <see cref="PathPrefix"/> 下面（回调 / 退出自己），太长的也不要（state 要放进 URL）。
    /// </summary>
    public static string SafeReturnPath(string? forwardedUri)
    {
        if (!ReturnUrl.IsLocalUrl(forwardedUri) || forwardedUri[0] != '/') return "/";
        if (forwardedUri.Length > MaxReturnPathLength) return "/";
        if (forwardedUri.StartsWith(PathPrefix + "/", StringComparison.OrdinalIgnoreCase) ||
            forwardedUri.Equals(PathPrefix, StringComparison.OrdinalIgnoreCase)) return "/";
        return forwardedUri;
    }

    /// <summary>
    /// 这个被拦下的请求是不是「人在浏览器里打开一个页面」。是 → 跳去登录；不是（脚本的 fetch、图片、curl）→ 直接 401，
    /// 跨域跳转对它们没有意义，还会把登录页的 HTML 当成接口响应喂给脚本。
    /// 有 <c>Sec-Fetch-Mode</c> 的浏览器按它判，老浏览器退回看 <c>Accept</c>。
    /// </summary>
    public static bool IsPageNavigation(string? method, string? secFetchMode, string? accept)
    {
        if (!string.IsNullOrEmpty(method) && !HttpMethods.IsGet(method)) return false;
        if (!string.IsNullOrEmpty(secFetchMode))
            return secFetchMode.Equals("navigate", StringComparison.OrdinalIgnoreCase);
        return accept?.Contains("text/html", StringComparison.OrdinalIgnoreCase) == true;
    }

    /// <summary>
    /// 放行时回给反向代理的身份头只能是可打印 ASCII（Kestrel 拒绝写非 ASCII 的响应头）；
    /// 含其它字符的值做百分号编码，下游按需解码。
    /// </summary>
    public static string HeaderValue(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        foreach (var c in value)
            if (c < 0x20 || c > 0x7E) return Uri.EscapeDataString(value);
        return value;
    }

    private static string Protect<T>(IDataProtector protector, T payload) =>
        Base64Url(protector.Protect(JsonSerializer.SerializeToUtf8Bytes(payload)));

    private static bool TryUnprotect<T>(IDataProtector protector, string? raw, [NotNullWhen(true)] out T? value)
        where T : class
    {
        value = null;
        if (string.IsNullOrEmpty(raw) || raw.Length > 4096) return false;
        try
        {
            var bytes = protector.Unprotect(FromBase64Url(raw));
            value = JsonSerializer.Deserialize<T>(bytes);
            return value is not null;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or JsonException)
        {
            return false;
        }
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string s)
    {
        var b64 = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '='));
    }
}
