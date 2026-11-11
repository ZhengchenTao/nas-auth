using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NasAuth.Config;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>The same entry point is exercised with household and path-mounted team configuration.</summary>
public sealed class DeploymentScenarioFactory(bool team) : WebApplicationFactory<Program>
{
    private readonly string dir = Path.Combine(Path.GetTempPath(), "auth-scenario-" + Guid.NewGuid().ToString("N"));
    public string Mount => team ? "/auth" : "";
    public string Issuer => "https://auth.example.test" + Mount;
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "resources.json"), """
            [{"aud":"library","resource_url":"https://apps.example.test/library","display_name":"Library","scopes":["openid","profile"],"app":{"id":"library","name":"Library","capability":"web"}},
             {"aud":"library-gate","resource_url":"https://apps.example.test/library/","display_name":"Library gate","forward_auth":{},"app":{"id":"library","name":"Library","capability":"gateway"}},
             {"aud":"private","resource_url":"https://private.example.test","display_name":"Private","scopes":["read"],"admin_only":true}]
            """);
        // Separate origins for OAuth and gateway resources avoid ambiguous resource identity.
        File.WriteAllText(Path.Combine(dir, "resources.json"), File.ReadAllText(Path.Combine(dir, "resources.json"))
            .Replace("https://apps.example.test/library/", "https://gate.example.test/library/"));
        File.WriteAllText(Path.Combine(dir, "clients.json"), """
            [{"client_id":"library-client","client_name":"Library","redirect_uris":["https://apps.example.test/callback"],"default_resource":"https://apps.example.test/library","token_endpoint_auth_method":"none"}]
            """);
        builder.UseEnvironment("Development");
        builder.UseSetting("Auth:Issuer", Issuer);
        builder.UseSetting("Auth:PathBase", Mount);
        builder.UseSetting("Auth:Database", "Data Source=" + Path.Combine(dir, "auth.db") + ";Pooling=False");
        builder.UseSetting("Auth:ResourcesPath", Path.Combine(dir, "resources.json"));
        builder.UseSetting("Auth:ClientsPresetPath", Path.Combine(dir, "clients.json"));
        builder.UseSetting("ExternalProviders:UseConfiguredProviders", "true");
        if (team)
        {
            var prefix = "ExternalProviders:TicketProviders:0:";
            foreach (var (key, value) in new Dictionary<string, string> {
                ["Id"] = "badge", ["DisplayName"] = "Badge", ["Enabled"] = "true",
                ["LoginUrl"] = "https://login.example.test/start", ["ValidationUrl"] = "https://adapter.example.test/validate",
                ["ValidationToken"] = "synthetic-test-token" }) builder.UseSetting(prefix + key, value);
            builder.UseSetting("ExternalProfiles:Providers:badge:Fields:department:Label", "Department");
            builder.UseSetting("Provisioning:Applications:library:Name", "Library");
            builder.UseSetting("Provisioning:Applications:library:Endpoint", "https://adapter.example.test/accounts");
            builder.UseSetting("Provisioning:Applications:library:BearerEnvironment", "NAS_AUTH_SCENARIO_TOKEN");
            Environment.SetEnvironmentVariable("NAS_AUTH_SCENARIO_TOKEN", "synthetic-test-token");
            builder.UseSetting("Provisioning:Applications:library:RequiredResources:library:0", "openid");
            builder.UseSetting("Provisioning:Applications:library:RequiredResources:library:1", "profile");
            builder.ConfigureServices(s => s.AddHttpClient("account-provisioning")
                .ConfigurePrimaryHttpMessageHandler(() => new AcknowledgingAdapter()));
        }
    }
    public HttpClient Browser() => CreateClient(new() { BaseAddress = new("https://auth.example.test"), AllowAutoRedirect = false });
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { Directory.Delete(dir, true); } catch (IOException) { }
    }
    private sealed class AcknowledgingAdapter : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
    }
}

public class DeploymentScenarioTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SameApplicationSupportsBothDeploymentShapes(bool team)
    {
        using var app = new DeploymentScenarioFactory(team);
        using var browser = app.Browser();
        var discovery = await browser.GetFromJsonAsync<JsonElement>(app.Mount + "/.well-known/openid-configuration");
        Assert.Equal(app.Issuer, discovery.GetProperty("issuer").GetString());
        Assert.Equal(app.Issuer + "/token", discovery.GetProperty("token_endpoint").GetString());
        var anonymous = await browser.GetAsync(app.Mount + "/admin/apps/diagnostics");
        Assert.Equal(HttpStatusCode.Redirect, anonymous.StatusCode);
        var login = await browser.PostAsync(app.Mount + "/login", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["username"] = "admin", ["password"] = "devpassword" }));
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        var page = await browser.GetAsync(app.Mount + "/admin/apps/diagnostics?aud=library&user=admin&lang=en");
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.True(page.Headers.CacheControl!.NoStore);
        var html = await page.Content.ReadAsStringAsync();
        Assert.Contains("Application diagnostics", html);
        Assert.Contains(app.Issuer + "/.well-known/openid-configuration", html);
        Assert.Contains("action='" + app.Mount + "/admin/apps/diagnostics'", html);
        Assert.DoesNotContain("synthetic-test-token", html);
        Assert.Contains("https://apps.example.test/callback", html);
        Assert.Equal(team, app.Services.GetRequiredService<ExternalProviderOptions>().IsEnabled("badge"));
        if (team)
        {
            Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync("/login")).StatusCode);
            Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync("/auth/external/badge/start")).StatusCode);
            Assert.Single(app.Services.GetRequiredService<ExternalProfilesOptions>().Providers);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DiagnosisTracksGrantUnionRevocationAndDisabledAccounts(bool team)
    {
        using var app = new DeploymentScenarioFactory(team);
        using var scope = app.Services.CreateScope();
        var s = scope.ServiceProvider;
        var users = s.GetRequiredService<UserRepository>();
        users.Create("member", "member", PasswordHasher.Hash("example-password"), false);
        var grants = s.GetRequiredService<UserResourceRepository>();
        var groups = s.GetRequiredService<AccessGroupService>();
        var diagnosis = s.GetRequiredService<ApplicationDiagnostics>();
        Assert.Contains(diagnosis.Inspect("library", "member").Access, c => c.Message.StartsWith("No effective grant"));
        grants.Upsert("member", "library", "openid");
        Assert.Contains(diagnosis.Inspect("library", "member").Access, c => c.Message.StartsWith("Only some scopes") && c.Detail == "profile");
        var group = groups.Create("Readers <script>")!;
        using var conn = s.GetRequiredService<NasAuth.Data.AuthDb>().OpenConnection();
        // Exercise the same persisted grant source used by the group workflow.
        Dapper.SqlMapper.Execute(conn, "INSERT INTO access_group_members(group_id,user_id) VALUES(@group,'member'); INSERT INTO access_group_resources(group_id,aud,scopes) VALUES(@group,'library','profile');", new { group });
        var both = diagnosis.Inspect("library", "member");
        Assert.Contains(both.Access, c => c.Message.StartsWith("All configured scopes"));
        Assert.Contains(both.Access, c => c.Message == "Group grant");
        grants.Delete("member", "library");
        Assert.DoesNotContain(diagnosis.Inspect("library", "member").Access, c => c.Message.StartsWith("No effective grant"));
        Dapper.SqlMapper.Execute(conn, "DELETE FROM access_group_members WHERE user_id='member'");
        Assert.Contains(diagnosis.Inspect("library", "member").Access, c => c.Message.StartsWith("No effective grant"));
        Dapper.SqlMapper.Execute(conn, "UPDATE users SET is_disabled=1 WHERE user_id='member'");
        Assert.Contains(diagnosis.Inspect("library", "member").Access, c => c.Level == "error" && c.Message.StartsWith("Account is disabled"));
        Assert.Contains(diagnosis.Inspect("private", "member").Access, c => c.Message.Contains("restricted"));
        var html = NasAuth.Pages.DashboardTemplates.DiagnosticsSection(s.GetRequiredService<ResourceCatalog>().All, "library", "member", both, app.Issuer);
        Assert.Contains("&lt;script&gt;", html);
        Assert.DoesNotContain("Readers <script>", html);
    }

    [Fact]
    public async Task DiagnosticsRejectsNonAdminAndReportsBrokenPresetWithoutSecrets()
    {
        using var app = new DeploymentScenarioFactory(false);
        using var scope = app.Services.CreateScope();
        var s = scope.ServiceProvider;
        s.GetRequiredService<UserRepository>().Create("reader", "reader", PasswordHasher.Hash("example-password"), false);
        using var browser = app.Browser();
        await browser.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string> { ["username"] = "reader", ["password"] = "example-password" }));
        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync("/admin/apps/diagnostics?aud=library")).StatusCode);
        s.GetRequiredService<ClientRepository>().UpsertPreset(new PresetClientConfig { ClientId = "broken", ClientName = "Broken", DefaultResource = "https://missing.example.test", TokenEndpointAuthMethod = "client_secret_basic", RedirectUris = ["https://app.example.test/callback"] }, null);
        var checks = s.GetRequiredService<ApplicationDiagnostics>().Inspect(null, null).Configuration;
        Assert.Contains(checks, c => c.Detail == "broken" && c.Message.StartsWith("Client default resource"));
        Assert.Contains(checks, c => c.Detail == "broken" && c.Message.StartsWith("Confidential client"));
    }
}

