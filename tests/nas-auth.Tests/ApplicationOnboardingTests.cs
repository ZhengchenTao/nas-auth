using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NasAuth.Config;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

public class ApplicationOnboardingTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CommandLinePreflightExitsWithoutStartingHostOrCreatingData(bool valid)
    {
        var dir = Path.Combine(Path.GetTempPath(), "auth-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var resources = Path.Combine(dir, "resources.json");
            File.WriteAllText(resources, valid ? "[{\"aud\":\"example\",\"display_name\":\"Example\",\"resource_url\":\"https://app.example.test\",\"scopes\":[\"read\"]}]" : "malformed-sensitive-config");
            var start = new System.Diagnostics.ProcessStartInfo("dotnet") { WorkingDirectory = dir, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            foreach (var arg in new[] { typeof(Program).Assembly.Location, "--check-config", "--Auth:Issuer", "https://auth.example.test",
                "--Auth:Database", "Data Source=" + Path.Combine(dir, "data", "auth.db"), "--Auth:ResourcesPath", resources,
                "--ExternalProviders:UseConfiguredProviders", "true" }) start.ArgumentList.Add(arg);
            using var process = System.Diagnostics.Process.Start(start)!;
            var output = process.StandardOutput.ReadToEndAsync(); var errors = process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try { await process.WaitForExitAsync(timeout.Token); }
            catch { process.Kill(entireProcessTree: true); throw; }
            Assert.Equal(valid ? 0 : 2, process.ExitCode);
            var stdout = await output;
            Assert.Equal(valid, JsonDocument.Parse(stdout).RootElement.GetProperty("ok").GetBoolean());
            Assert.DoesNotContain("malformed-sensitive-config", stdout + await errors);
            Assert.False(Directory.Exists(Path.Combine(dir, "data")));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WizardRequiresAdministratorAndCsrfAndProducesLoadableNonSecretConfiguration(bool team)
    {
        using var app = new DeploymentScenarioFactory(team); using var browser = app.Browser();
        var path = app.Mount + "/admin/apps/new";
        Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync(path)).StatusCode);
        await browser.PostAsync(app.Mount + "/login", new FormUrlEncodedContent(new Dictionary<string,string> { ["username"] = "admin", ["password"] = "devpassword" }));
        var values = new Dictionary<string, string> { ["id"] = "example", ["name"] = "<script>Example</script>", ["kind"] = "oidc", ["client_type"] = "confidential",
            ["url"] = "https://example.test/app", ["callbacks"] = "https://example.test/callback" };
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.PostAsync(path, new FormUrlEncodedContent(values))).StatusCode);
        var req = new HttpRequestMessage(HttpMethod.Post, path) { Content = new FormUrlEncodedContent(values) };
        req.Headers.Add(AntiforgeryGuard.HeaderName, await HttpPipelineTests.CsrfToken(browser, path));
        var response = await browser.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("<script>Example", html);
        Assert.Contains("EXAMPLE_OIDC_CLIENT_SECRET", html);
        Assert.Contains("--check-config", html);
        Assert.Contains(app.Issuer + "/.well-known/openid-configuration", html);
        Assert.Contains("no-store", response.Headers.CacheControl!.ToString());
        using var scope = app.Services.CreateScope();
        Assert.Null(scope.ServiceProvider.GetRequiredService<ClientRepository>().GetById("example-client"));
        Assert.Null(scope.ServiceProvider.GetRequiredService<ResourceCatalog>().FindByAud("example-oidc"));
    }

    [Theory]
    [InlineData("oidc")]
    [InlineData("forward-auth")]
    [InlineData("mcp")]
    public void GeneratedConfigurationPassesPreflightWithoutDatabaseOrKeyCreation(string kind)
    {
        using var app = new DeploymentScenarioFactory(false); using var scope = app.Services.CreateScope(); var sp = scope.ServiceProvider;
        var setup = sp.GetRequiredService<ApplicationOnboarding>();
        var name = "app" + Guid.NewGuid().ToString("N");
        var draft = setup.Generate(new(name, "Example", kind, "https://receiver.example.test/service", "https://receiver.example.test/callback"));
        Assert.Empty(draft.Errors);
        var dir = Path.Combine(Path.GetTempPath(), "auth-preflight-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "resources.json"), draft.Resources);
            File.WriteAllText(Path.Combine(dir, "clients.json"), draft.Clients);
            if (draft.SecretEnvironment.Length > 0) Environment.SetEnvironmentVariable(draft.SecretEnvironment, "synthetic-high-entropy-client-value");
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                ["Auth:Issuer"] = "https://auth.example.test/auth", ["Auth:PathBase"] = "/auth",
                ["Auth:Database"] = "Data Source=" + Path.Combine(dir, "data", "auth.db"),
                ["Auth:ResourcesPath"] = Path.Combine(dir, "resources.json"), ["Auth:ClientsPresetPath"] = Path.Combine(dir, "clients.json"),
                ["ExternalProviders:UseConfiguredProviders"] = "true" }).Build();
            var checks = ConfigurationPreflight.Inspect(configuration);
            Assert.All(checks, check => Assert.True(check.Ok, check.Area + ": " + check.Message));
            Assert.False(Directory.Exists(Path.Combine(dir, "data")));
            Assert.Equal(2, Directory.GetFiles(dir).Length);
            if (draft.SecretEnvironment.Length > 0)
            {
                Environment.SetEnvironmentVariable(draft.SecretEnvironment, null);
                var missing = ConfigurationPreflight.Inspect(configuration);
                Assert.Contains(missing, c => c.Area == "Clients" && !c.Ok);
                Assert.DoesNotContain("synthetic-high-entropy-client-value", JsonSerializer.Serialize(missing));
            }
            File.WriteAllText(Path.Combine(dir, "clients.json"), "[{\"client_secret\":\"sensitive-value-do-not-print\"}]");
            var invalid = ConfigurationPreflight.Inspect(configuration);
            Assert.Contains(invalid, c => c.Area == "Clients" && !c.Ok);
            Assert.DoesNotContain("sensitive-value-do-not-print", JsonSerializer.Serialize(invalid));
        }
        finally
        {
            if (draft.SecretEnvironment.Length > 0) Environment.SetEnvironmentVariable(draft.SecretEnvironment, null);
            Directory.Delete(dir, true);
        }
    }

    [Theory]
    [InlineData("https://gate.example.test/library/", "https://receiver.example.test/callback")]
    [InlineData("https://receiver.example.test/a/../b", "https://receiver.example.test/callback")]
    [InlineData("https://receiver.example.test", "https://user:secret@receiver.example.test/callback")]
    [InlineData("https://receiver.example.test", "javascript:alert(1)")]
    public void InvalidOrCollidingConfigurationIsRejected(string url, string callback)
    {
        using var app = new DeploymentScenarioFactory(false); using var scope = app.Services.CreateScope();
        var draft = scope.ServiceProvider.GetRequiredService<ApplicationOnboarding>().Generate(new("example", "Example", "oidc", url, callback));
        Assert.NotEmpty(draft.Errors); Assert.Equal("", draft.Resources); Assert.Equal("", draft.Clients);
    }
}
