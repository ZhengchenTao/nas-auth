using NasAuth.Data.Repositories;

namespace NasAuth.Services;

/// <summary>
/// 审计事件：结构化打到 stdout（docker logs 能看），同时写进 audit_log 表供后台查询
/// （external-auth.md §十六；高频的 proxy 转发与 introspect 只打日志不入库）。
/// 安全约束：绝不打印 / 入库 Token 本体或 Authorization header。
/// 这里只接受 client_id / user_id / 结果 / 简短原因之类。入库失败只记警告，不影响请求。
/// </summary>
public class AuditLogger
{
    private readonly ILogger<AuditLogger> _logger;
    private readonly AuditRepository _repo;
    private readonly IHttpContextAccessor _http;

    public AuditLogger(ILogger<AuditLogger> logger, AuditRepository repo, IHttpContextAccessor http)
    {
        _logger = logger;
        _repo = repo;
        _http = http;
    }

    private void Persist(string @event, bool success, string? userId, string? clientId, string? ip, string? detail)
    {
        try
        {
            _repo.Insert(@event, success, userId, clientId, ip ?? CurrentIp(), detail);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "audit 入库失败 event={Event}", @event);
        }
    }

    private string? CurrentIp() =>
        _http.HttpContext?.Connection.RemoteIpAddress?.ToString();

    private static string? Join(params (string Key, string? Value)[] parts)
    {
        var s = string.Join(' ', parts.Where(p => !string.IsNullOrEmpty(p.Value) && p.Value != "-")
            .Select(p => $"{p.Key}={p.Value}"));
        return s.Length == 0 ? null : s;
    }

    public void Authorize(bool success, string clientId, string? userId, string? resource,
        string? scope, string? remoteIp, string? reason = null)
    {
        _logger.LogInformation(
            "audit.authorize success={Success} client={Client} user={User} resource={Resource} scope={Scope} ip={Ip} reason={Reason}",
            success, clientId, userId ?? "-", resource ?? "-", scope ?? "-", remoteIp ?? "-", reason ?? "-");
        Persist("authorize", success, userId, clientId, remoteIp,
            Join(("resource", resource), ("scope", scope), ("reason", reason)));
    }

    public void Token(bool success, string grantType, string clientId, string? userId,
        string? resource, string? remoteIp, string? reason = null)
    {
        _logger.LogInformation(
            "audit.token success={Success} grant={Grant} client={Client} user={User} resource={Resource} ip={Ip} reason={Reason}",
            success, grantType, clientId, userId ?? "-", resource ?? "-", remoteIp ?? "-", reason ?? "-");
        Persist("token", success, userId, clientId, remoteIp,
            Join(("grant", grantType), ("resource", resource), ("reason", reason)));
    }

    public void Revoke(bool success, string? clientId, string? remoteIp, string? reason = null)
    {
        _logger.LogInformation(
            "audit.revoke success={Success} client={Client} ip={Ip} reason={Reason}",
            success, clientId ?? "-", remoteIp ?? "-", reason ?? "-");
        Persist("revoke", success, null, clientId, remoteIp, Join(("reason", reason)));
    }

    public void Introspect(bool active, string? clientId, string? remoteIp)
    {
        _logger.LogInformation(
            "audit.introspect active={Active} client={Client} ip={Ip}",
            active, clientId ?? "-", remoteIp ?? "-");
    }

    public void Login(bool success, string? username, string? remoteIp, string? reason = null)
    {
        _logger.LogInformation(
            "audit.login success={Success} user={User} ip={Ip} reason={Reason}",
            success, username ?? "-", remoteIp ?? "-", reason ?? "-");
        Persist("login", success, username, null, remoteIp, Join(("method", "password"), ("reason", reason)));
    }

    /// <summary>外部登录回调（subject 是 IdP 侧稳定 id，非敏感；email 不打）。</summary>
    public void ExternalLogin(bool success, string provider, string subject, string? userId,
        string? remoteIp, string? reason = null)
    {
        _logger.LogInformation(
            "audit.external_login success={Success} provider={Provider} subject={Subject} user={User} ip={Ip} reason={Reason}",
            success, provider, subject, userId ?? "-", remoteIp ?? "-", reason ?? "-");
        Persist("external_login", success, userId, null, remoteIp,
            Join(("method", provider), ("subject", subject), ("reason", reason)));
    }

    public void Register(bool success, string? clientName, string? remoteIp, string? reason = null)
    {
        _logger.LogInformation(
            "audit.register success={Success} name={Name} ip={Ip} reason={Reason}",
            success, clientName ?? "-", remoteIp ?? "-", reason ?? "-");
        Persist("register", success, null, null, remoteIp, Join(("name", clientName), ("reason", reason)));
    }

    public void AccountAction(string action, bool success, string userId, string? reason = null)
    {
        _logger.LogInformation(
            "audit.account action={Action} success={Success} user={User} reason={Reason}",
            action, success, userId, reason ?? "-");
        Persist("account." + action, success, userId, null, null, reason);
    }

    public void ProxyForward(string aud, string? userId, string? clientId, string? remoteIp,
        string method, int upstreamStatus)
    {
        _logger.LogInformation(
            "audit.proxy.fwd aud={Aud} user={User} client={Client} ip={Ip} method={Method} status={Status}",
            aud, userId ?? "-", clientId ?? "-", remoteIp ?? "-", method, upstreamStatus);
    }

    public void ProxyDenied(string aud, string? userId, string? clientId, string? remoteIp, string reason)
    {
        _logger.LogWarning(
            "audit.proxy.deny aud={Aud} user={User} client={Client} ip={Ip} reason={Reason}",
            aud, userId ?? "-", clientId ?? "-", remoteIp ?? "-", reason);
        Persist("proxy.deny", false, userId, clientId, remoteIp, Join(("aud", aud), ("reason", reason)));
    }
}
