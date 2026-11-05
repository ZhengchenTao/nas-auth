using System.Net;
using System.Text.Json;
using Dapper;
using Microsoft.Extensions.Logging.Abstractions;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

public sealed class ProvisioningTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "provisioning-" + Guid.NewGuid().ToString("N"));
    private readonly string _env = "PROVISION_TEST_" + Guid.NewGuid().ToString("N");
    private readonly AuthDb _db;
    private readonly ProvisioningService _service;
    private readonly UserRepository _users;
    private readonly UserResourceRepository _grants;

    public ProvisioningTests()
    {
        Directory.CreateDirectory(_dir);
        var resources = Path.Combine(_dir, "resources.json");
        File.WriteAllText(resources, """[{"aud":"example-web","resource_url":"https://app.example.test/","scopes":["openid","profile","manage"]}]""");
        var auth = new AuthOptions { Database = "Data Source=" + Path.Combine(_dir,"auth.db") + ";Pooling=False", Issuer="https://auth.example.test", ResourcesPath=resources };
        var catalog = new ResourceCatalog(auth, NullLogger<ResourceCatalog>.Instance);
        Environment.SetEnvironmentVariable(_env, Guid.NewGuid().ToString("N"));
        var options = new ProvisioningOptions { Applications = new() { ["example"] = new() {
            Name="Example", Endpoint="https://app.example.test/provision", BearerEnvironment=_env,
            RequiredResources = new() { ["example-web"] = ["openid","profile"] } } } };
        options.Validate(catalog);
        _db = new AuthDb(auth); _db.EnsureCreated();
        _users = new(_db); _grants = new(_db); _service = new(_db,auth,options,catalog);
        _service.Initialize();
    }

    [Fact]
    public async Task Delivery_RetriesLatestState_RetainsSameSubject_AndNeverForwardsPasswords()
    {
        _users.Create("employee","employee","opaque-test-hash",false,"employee@example.test",false,"Employee",
            applicationGrants:_service.SelectedGrants(["example"]));
        _service.CaptureChanges();
        var first = Assert.Single(_service.List("employee")); Assert.Equal(1,first.enabled);
        var handler = new Receiver(HttpStatusCode.ServiceUnavailable);
        using var client = new HttpClient(handler);
        await _service.DeliverAsync(client,default);
        Assert.Equal("failed",Assert.Single(_service.List("employee")).state);
        Assert.DoesNotContain("password",handler.Payload!,StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("opaque-test-hash",handler.Payload!);
        _grants.Delete("employee","example-web"); _service.CaptureChanges();
        handler.Status = HttpStatusCode.NoContent;
        await _service.DeliverAsync(client,default);
        var revoked = JsonSerializer.Deserialize<ProvisionedAccount>(handler.Payload!)!;
        Assert.False(revoked.Enabled); Assert.Equal("employee",revoked.Subject); Assert.True(revoked.Revision>first.revision);
        Assert.Equal("synced",Assert.Single(_service.List("employee")).state);
        // Explicit reconciliation does not send duplicate unchanged versions.
        _service.Reconcile("employee"); _service.CaptureChanges();
        Assert.Equal(revoked.Revision,Assert.Single(_service.List("employee")).revision);
    }

    [Fact]
    public void TransactionRollback_DoesNotEnqueueOrChangeAccount_AndPartialScopesDoNotGrantAccess()
    {
        _users.Create("employee","employee","opaque",false);
        _grants.Upsert("employee","example-web","openid"); _service.CaptureChanges();
        Assert.Empty(_service.List("employee"));
        using (var c=_db.OpenConnection())
        using (var tx=c.BeginTransaction())
        {
            c.Execute("UPDATE user_resources SET scopes='openid profile' WHERE user_id='employee'",transaction:tx);
            tx.Rollback();
        }
        _service.CaptureChanges(); Assert.Empty(_service.List("employee"));
        _grants.Upsert("employee","example-web","openid profile"); _service.CaptureChanges();
        Assert.Equal(1,Assert.Single(_service.List("employee")).enabled);
        using (var c=_db.OpenConnection()) c.Execute("UPDATE users SET is_disabled=1 WHERE user_id='employee'");
        _service.CaptureChanges(); Assert.Equal(0,Assert.Single(_service.List("employee")).enabled);
        using (var c=_db.OpenConnection()) c.Execute("DELETE FROM users WHERE user_id='employee'");
        _service.CaptureChanges(); Assert.Equal(0,Assert.Single(_service.List("employee")).enabled);
    }

    private sealed class Receiver(HttpStatusCode status) : HttpMessageHandler
    {
        public HttpStatusCode Status= status;
        public string? Payload;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        { Payload=await request.Content!.ReadAsStringAsync(ct); Assert.Equal("Bearer",request.Headers.Authorization!.Scheme); return new(Status); }
    }

    [Fact]
    public void Application_editor_preserves_unrelated_grants_and_requires_an_active_user()
    {
        _users.Create("employee","employee","opaque",false);
        _grants.Upsert("employee","unrelated-api","read");
        _grants.Upsert("employee","example-web","openid manage");
        Assert.True(_service.SetApplications("employee",["example"]));
        Assert.True(_grants.IsAllowed("employee","example-web",["openid","profile"]));
        Assert.True(_grants.IsAllowed("employee","example-web",["manage"]));
        Assert.True(_service.SetApplications("employee",[]));
        Assert.Null(_grants.Get("employee","example-web"));Assert.NotNull(_grants.Get("employee","unrelated-api"));
        using(var c=_db.OpenConnection())c.Execute("UPDATE users SET is_disabled=1 WHERE user_id='employee'");
        Assert.False(_service.SetApplications("employee",["example"]));Assert.Null(_grants.Get("employee","example-web"));
    }

    [Fact]
    public void Restart_bootstrap_does_not_silently_enroll_existing_grants()
    {
        using(var c=_db.OpenConnection())c.Execute("UPDATE settings SET value='0' WHERE key='provisioning_enabled'");
        _users.Create("legacy","legacy","opaque",false);
        _grants.Upsert("legacy","example-web","openid profile");
        _service.Initialize();
        _db.EnsureCreated(); // next startup suspends capture while bootstrap upserts existing rows
        _users.Upsert("legacy","legacy","opaque",false);
        _grants.Upsert("legacy","example-web","openid profile");
        _service.Initialize();_service.CaptureChanges();Assert.Empty(_service.List("legacy"));
        _service.Reconcile("legacy");_service.CaptureChanges();Assert.Equal(1,Assert.Single(_service.List("legacy")).enabled);
    }

    [Fact]
    public async Task Revocation_queued_after_capture_prevents_sending_the_known_stale_enable()
    {
        _users.Create("employee","employee","opaque",false,applicationGrants:_service.SelectedGrants(["example"]));
        _service.CaptureChanges();_grants.Delete("employee","example-web");
        var handler=new Receiver(HttpStatusCode.NoContent);using var client=new HttpClient(handler);
        await _service.DeliverAsync(client,default);Assert.Null(handler.Payload);
        _service.CaptureChanges();await _service.DeliverAsync(client,default);
        Assert.False(JsonSerializer.Deserialize<ProvisionedAccount>(handler.Payload!)!.Enabled);
    }

    [Fact]
    public void Cleared_or_deleted_profiles_do_not_retain_the_old_contact_snapshot()
    {
        _users.Create("employee","employee","opaque",false,"old@example.test",false,"Old name",
            applicationGrants:_service.SelectedGrants(["example"]));
        _service.CaptureChanges();
        _users.UpdateProfile("employee",null,false);_users.UpdateDisplayName("employee",null);_service.CaptureChanges();
        using var c=_db.OpenConnection();
        ProvisionedAccount Current()=>JsonSerializer.Deserialize<ProvisionedAccount>(c.ExecuteScalar<string>("SELECT payload FROM provisioning_accounts WHERE user_id='employee'")!)!;
        Assert.Null(Current().Email);Assert.Equal("employee",Current().DisplayName);
        c.Execute("DELETE FROM users WHERE user_id='employee'");_service.CaptureChanges();
        Assert.False(Current().Enabled);Assert.Null(Current().Email);Assert.Null(Current().DisplayName);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(_env,null);
        Directory.Delete(_dir,true);
    }
}
