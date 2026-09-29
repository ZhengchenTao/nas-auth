using NasAuth.Data.Repositories;

namespace NasAuth.Services;

/// <summary>
/// 后台清理：每小时跑一次，清掉
///  - 过期 / 已消费 1 天以上的 auth_codes
///  - 过期 / revoked 7 天以上的 refresh_tokens
///  - auto_registered=1 且 30 天未用过的 clients
///  - 90 天前的 audit_log（§十六）
/// </summary>
public class TokenCleanupService : BackgroundService
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<TokenCleanupService> _logger;
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);
    private static readonly TimeSpan StaleClient = TimeSpan.FromDays(30);

    public TokenCleanupService(IServiceProvider sp, ILogger<TokenCleanupService> logger)
    {
        _sp = sp;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // 启动稍延迟，避免启动 + 大表清理放一起
        try { await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken); }
        catch (TaskCanceledException) { return; }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _sp.CreateScope();
                var codes = scope.ServiceProvider.GetRequiredService<AuthCodeRepository>();
                var refresh = scope.ServiceProvider.GetRequiredService<RefreshTokenRepository>();
                var clients = scope.ServiceProvider.GetRequiredService<ClientRepository>();
                var audit = scope.ServiceProvider.GetRequiredService<AuditRepository>();

                var nCodes = codes.CleanupExpired();
                var nRefresh = refresh.CleanupExpired();
                var nClients = clients.CleanupStale(StaleClient);
                var nAudit = audit.Purge();

                if (nCodes + nRefresh + nClients + nAudit > 0)
                {
                    _logger.LogInformation(
                        "cleanup auth_codes={Codes} refresh_tokens={Refresh} clients={Clients} audit_log={Audit}",
                        nCodes, nRefresh, nClients, nAudit);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "TokenCleanupService 异常，下一轮再试");
            }

            try { await Task.Delay(Interval, stoppingToken); }
            catch (TaskCanceledException) { return; }
        }
    }
}
