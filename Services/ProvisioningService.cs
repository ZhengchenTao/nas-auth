using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dapper;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

public sealed record ProvisionedAccount(string EventId, long Revision, string ApplicationId,
    string Issuer, string Subject, string Username, string? DisplayName, string? Email, bool Enabled);
public sealed record ProvisioningStatus(string application_id, string user_id, long revision,
    long enabled, string state, long attempts, long next_attempt, string? error_code, long? delivered_at);

/// <summary>Durable desired state; no credentials or downstream response bodies are persisted.</summary>
public sealed class ProvisioningService(AuthDb db, AuthOptions auth, ProvisioningOptions options, ResourceCatalog catalog, AuditLogger? audit = null)
{
    public Dictionary<string,string> SelectedGrants(IEnumerable<string> applications, bool isAdmin = false) =>
        applications.Distinct().Where(options.Applications.ContainsKey)
            .Where(id=>options.Applications[id].RequiredResources.All(x=>catalog.All.Single(r=>r.Aud==x.Key).AllowsUser(isAdmin)))
            .SelectMany(id => options.Applications[id].RequiredResources)
            .GroupBy(x => x.Key).ToDictionary(g => g.Key, g => string.Join(' ', g.SelectMany(x => x.Value).Distinct()));

    public Dictionary<string, string> FormGrants(Microsoft.AspNetCore.Http.IFormCollection form)
    {
        var grants = SelectedGrants(form["application"].Select(value => value ?? ""));
        foreach (var resource in catalog.All.Where(resource => resource.AllowsUser(false)))
        {
            var selected = form[$"scope:{resource.Aud}"].Where(scope => scope is not null && resource.Scopes.Contains(scope));
            var scopes = string.Join(' ', selected.Concat(grants.GetValueOrDefault(resource.Aud, "").Split(' ', StringSplitOptions.RemoveEmptyEntries)).Distinct());
            if (scopes.Length > 0) grants[resource.Aud] = scopes;
        }
        return grants;
    }

    public bool SetApplications(string userId,IEnumerable<string> applications)
    {
        using var c=db.OpenConnection();using var tx=c.BeginTransaction();
        var role=c.ExecuteScalar<long?>("SELECT is_admin FROM users WHERE user_id=@userId AND is_disabled=0",new{userId},tx);
        if(role is null)return false;
        var selected=SelectedGrants(applications,role!=0);
        foreach(var aud in selected.Keys.ToArray())
        {
            var existing=c.ExecuteScalar<string?>("SELECT scopes FROM user_resources WHERE user_id=@userId AND aud=@aud",new{userId,aud},tx);
            var allowed=catalog.All.Single(r=>r.Aud==aud).Scopes;
            selected[aud]=string.Join(' ',selected[aud].Split(' ').Concat((existing??"").Split(' ',StringSplitOptions.RemoveEmptyEntries)).Where(allowed.Contains).Distinct());
        }
        foreach(var aud in options.Applications.Values.SelectMany(x=>x.RequiredResources.Keys).Distinct())
            c.Execute("DELETE FROM user_resources WHERE user_id=@userId AND aud=@aud",new{userId,aud},tx);
        foreach(var(aud,scopes) in selected)
            c.Execute("INSERT INTO user_resources(user_id,aud,scopes) VALUES(@userId,@aud,@scopes)",new{userId,aud,scopes},tx);
        tx.Commit();return true;
    }

    public void Initialize()
    {
        using var c = db.OpenConnection();
        c.Execute("INSERT INTO settings(key,value,updated_at) VALUES('provisioning_enabled',@value,0) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            new { value = options.Applications.Count > 0 ? "1" : "0" });
    }

    // Reconciliation is explicit: installing a connector never silently adopts old accounts.
    public void Reconcile(string userId)
    {
        using var c = db.OpenConnection();
        c.Execute("INSERT INTO provisioning_changes(user_id) VALUES(@userId)", new { userId });
    }

    public IReadOnlyList<ProvisioningStatus> List(string userId)
    {
        using var c = db.OpenConnection();
        return c.Query<ProvisioningStatus>("SELECT application_id,user_id,revision,enabled,state,attempts,next_attempt,error_code,delivered_at FROM provisioning_accounts WHERE user_id=@userId ORDER BY application_id", new { userId }).AsList();
    }

    public void Retry(string userId)
    {
        using var c = db.OpenConnection();
        c.Execute("UPDATE provisioning_accounts SET state='pending',next_attempt=0 WHERE user_id=@userId AND state<>'synced'", new { userId });
    }

    public void CaptureChanges()
    {
        if (options.Applications.Count == 0) return;
        using var c = db.OpenConnection();
        using var tx = c.BeginTransaction();
        var changes = c.Query<(string user_id, long revision)>(
            "SELECT user_id,MAX(revision) revision FROM provisioning_changes GROUP BY user_id LIMIT 100", transaction: tx).AsList();
        foreach (var (userId, revision) in changes)
        {
            var user = c.QuerySingleOrDefault<AccountProfile>(
                "SELECT username,display_name,email,is_admin,is_disabled FROM users WHERE user_id=@userId", new { userId }, tx);
            var grants = UserResourceRepository.Effective(c, userId, tx)
                .ToDictionary(x => x.aud, x => x.scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal));
            var affectedApps = c.Query<string?>("""
                SELECT DISTINCT application_id FROM provisioning_changes WHERE user_id=@userId AND revision<=@revision
                """, new { userId, revision }, tx).ToHashSet();
            foreach (var (id, app) in options.Applications)
            {
                if (!affectedApps.Contains(null) && !affectedApps.Contains(id)) continue;
                var previous = c.QuerySingleOrDefault<Snapshot>("SELECT payload,revision FROM provisioning_accounts WHERE application_id=@id AND user_id=@userId", new { id, userId }, tx);
                var enabled = user is { is_disabled: 0 } && app.RequiredResources.All(x =>
                    catalog.All.Single(r => r.Aud == x.Key).AllowsUser(user.is_admin != 0) &&
                    grants.TryGetValue(x.Key, out var scopes) && x.Value.All(scopes.Contains));
                // Never create a downstream account just to disable somebody who never had access.
                if (!enabled && previous is null) continue;
                var old = previous is null ? null : JsonSerializer.Deserialize<ProvisionedAccount>(previous.payload);
                var username = user?.username ?? userId;
                // A recycled local sign-in name must not match an earlier downstream login.
                if (username != userId && c.ExecuteScalar<long>("""
                    SELECT COUNT(*) FROM deleted_user_ids WHERE user_id<>@userId COLLATE NOCASE
                        AND COALESCE(username,user_id)=@username COLLATE NOCASE
                    """, new { userId, username }, tx) > 0)
                    username = userId;
                var desired = new ProvisionedAccount("", 0, id, auth.Issuer, userId,
                    old?.Username ?? username, user?.display_name ?? user?.username,
                    user?.email, enabled);
                if (old is not null && desired == old with { EventId = "", Revision = 0 }) continue;
                // Wall-clock floor makes a normal database restore newer than already delivered events.
                // Clock rollback/issuer migration requires an operator reconciliation; see operations docs.
                var version = Math.Max(DateTime.UtcNow.Ticks, (previous?.revision ?? 0) + 1);
                desired = desired with { Revision = version, EventId = Guid.NewGuid().ToString("N") };
                c.Execute(@"INSERT INTO provisioning_accounts(application_id,user_id,revision,enabled,payload,state,attempts,next_attempt)
                    VALUES(@id,@userId,@version,@enabled,@payload,'pending',0,0)
                    ON CONFLICT(application_id,user_id) DO UPDATE SET revision=excluded.revision,enabled=excluded.enabled,
                    payload=excluded.payload,state='pending',attempts=0,next_attempt=0,error_code=NULL",
                    new { id, userId, version, enabled = enabled ? 1 : 0, payload = JsonSerializer.Serialize(desired) }, tx);
            }
            c.Execute("DELETE FROM provisioning_changes WHERE user_id=@userId AND revision<=@revision", new { userId, revision }, tx);
        }
        tx.Commit();
    }

    public async Task DeliverAsync(HttpClient client, CancellationToken ct)
    {
        using var c = db.OpenConnection();
        var pending = c.Query<Delivery>("SELECT application_id,user_id,revision,payload,attempts FROM provisioning_accounts WHERE state<>'synced' AND next_attempt<=@now ORDER BY enabled ASC,next_attempt LIMIT 20",
            new { now = DateTimeOffset.UtcNow.ToUnixTimeSeconds() }).AsList();
        foreach (var row in pending)
        {
            // Prefer newly changed source state over the rest of an older batch.
            if (c.ExecuteScalar<long>("SELECT EXISTS(SELECT 1 FROM provisioning_changes)") != 0) break;
            if (!options.Applications.TryGetValue(row.application_id, out var app)) continue;
            string? error = null;
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, app.Endpoint);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Environment.GetEnvironmentVariable(app.BearerEnvironment));
                request.Content = new StringContent(row.payload, Encoding.UTF8, "application/json");
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                // 2xx means fully applied; adapters must never use 202 for queued work.
                if (response.StatusCode != System.Net.HttpStatusCode.OK && response.StatusCode != System.Net.HttpStatusCode.NoContent)
                {
                    error = "http_" + (int)response.StatusCode;
                    if (response.Headers.TryGetValues("X-Provisioning-Error",out var codes) &&
                        codes.FirstOrDefault() is { } code && System.Text.RegularExpressions.Regex.IsMatch(code,"^[a-z0-9_]{1,64}$"))
                        error += ":" + code;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException) { error = "connection_failed"; }
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            c.Execute(@"UPDATE provisioning_accounts SET state=@state,attempts=attempts+1,error_code=@error,
                next_attempt=@next,delivered_at=CASE WHEN @error IS NULL THEN @now ELSE delivered_at END
                WHERE application_id=@application_id AND user_id=@user_id AND revision=@revision",
                new { row.application_id, row.user_id, row.revision, error, state = error is null ? "synced" : "failed",
                    now, next = now + (long)Math.Min(3600, 5 * Math.Pow(2, Math.Min(row.attempts, 10))) });
            if (error is null || row.attempts == 0)
                audit?.AccountAction("provisioning-delivery",error is null,"system:provisioning",
                    $"target={row.user_id} application={row.application_id} result={error ?? "synced"}");
        }
    }

    private sealed record AccountProfile(string username, string? display_name, string? email, long is_admin, long is_disabled);
    private sealed record Snapshot(string payload, long revision);
    private sealed record Delivery(string application_id, string user_id, long revision, string payload, long attempts);
}

public sealed class ProvisioningWorker(ProvisioningService service, IHttpClientFactory clients,
    ILogger<ProvisioningWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        service.Initialize();
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                service.CaptureChanges();
                await service.DeliverAsync(clients.CreateClient("account-provisioning"), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception) { logger.LogError("Account provisioning cycle failed; durable work will be retried."); }
            try { await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
