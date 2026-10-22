using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NasAuth.Config;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

public class TicketProviderOptionsTests
{
    [Fact]
    public void TicketProviderIsDisabledUntilAllRuntimeValuesArePresent()
    {
        var disabled = ExternalProviderOptions.FromConfiguration(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ExternalProviders:TicketProviders:0:Id"] = "badge-login",
                ["ExternalProviders:TicketProviders:0:DisplayName"] = "Badge account",
                ["ExternalProviders:TicketProviders:0:Enabled"] = "true",
                ["ExternalProviders:TicketProviders:0:LoginUrl"] = "https://login.example.test/start",
                ["ExternalProviders:TicketProviders:0:ValidationUrl"] = "https://adapter.example.test/validate",
            }).Build());

        Assert.True(disabled.UsesConfiguredProviders);
        Assert.Empty(disabled.EnabledProviders);
        Assert.Null(disabled.SchemeFor("badge-login"));
    }

    [Fact]
    public void TicketProviderConfiguresParameterizedLoginAndCannotAssertVerifiedEmail()
    {
        var configured = ExternalProviderOptions.FromConfiguration(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ExternalProviders:TicketProviders:0:Id"] = "badge-login",
                ["ExternalProviders:TicketProviders:0:DisplayName"] = "Badge account",
                ["ExternalProviders:TicketProviders:0:Enabled"] = "true",
                ["ExternalProviders:TicketProviders:0:LoginUrl"] = "https://login.example.test/start",
                ["ExternalProviders:TicketProviders:0:ValidationUrl"] = "https://adapter.example.test/validate",
                ["ExternalProviders:TicketProviders:0:ValidationToken"] = "test-token",
                ["ExternalProviders:TicketProviders:0:ReturnUrlParameter"] = "callback_url",
                ["ExternalProviders:TicketProviders:0:LoginParameters:realm"] = "test-realm",
            }).Build());

        var provider = Assert.Single(configured.ConfiguredTicketProviders);
        Assert.Equal("external:badge-login", configured.SchemeFor("badge-login"));
        Assert.False(Assert.Single(configured.EnabledProviders).CanBind);
        Assert.Equal("test-realm", provider.LoginParameters["realm"]);
        Assert.False(ExternalClaims.IsEmailVerified("badge-login", new System.Security.Claims.ClaimsPrincipal(), provider));
    }

    [Theory]
    [InlineData("http://login.example.test/start", "https://adapter.example.test/validate")]
    [InlineData("https://login.example.test/start", "http://adapter.example.test/validate")]
    public void EnabledTicketProviderRejectsNonHttpsEndpoints(string loginUrl, string validationUrl)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ExternalProviders:TicketProviders:0:Id"] = "badge-login",
            ["ExternalProviders:TicketProviders:0:DisplayName"] = "Badge account",
            ["ExternalProviders:TicketProviders:0:Enabled"] = "true",
            ["ExternalProviders:TicketProviders:0:LoginUrl"] = loginUrl,
            ["ExternalProviders:TicketProviders:0:ValidationUrl"] = validationUrl,
            ["ExternalProviders:TicketProviders:0:ValidationToken"] = "test-token",
        }).Build();

        Assert.Throws<InvalidOperationException>(() => ExternalProviderOptions.FromConfiguration(config));
    }

    [Fact]
    public void TicketProviderAllowsLoopbackHttpValidationForPrivateLocalAdapter()
    {
        var configured = ExternalProviderOptions.FromConfiguration(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ExternalProviders:TicketProviders:0:Id"] = "badge-login",
                ["ExternalProviders:TicketProviders:0:DisplayName"] = "Badge account",
                ["ExternalProviders:TicketProviders:0:Enabled"] = "true",
                ["ExternalProviders:TicketProviders:0:LoginUrl"] = "https://login.example.test/start",
                ["ExternalProviders:TicketProviders:0:ValidationUrl"] = "http://127.0.0.1:3090/validate",
                ["ExternalProviders:TicketProviders:0:ValidationToken"] = "test-token",
            }).Build());

        Assert.Equal("badge-login", Assert.Single(configured.EnabledProviders).Id);
        Assert.Equal("http://127.0.0.1:3090/validate", Assert.Single(configured.ConfiguredTicketProviders).ValidationUrl);
    }

    [Fact]
    public void TicketReplayCacheNamespacesProvidersAndFailsClosedAtCapacity()
    {
        var now = new DateTimeOffset(2026, 10, 22, 0, 0, 0, TimeSpan.Zero);
        var clock = new ManualTicketTimeProvider(now);
        var cache = new TicketReplayCache(clock, maximumEntries: 2);
        var firstExpiry = now.AddMinutes(5);

        Assert.Equal(TicketReplayCacheResult.Accepted, cache.TryConsume("provider-a", "same-ticket", firstExpiry));
        Assert.Equal(TicketReplayCacheResult.Accepted, cache.TryConsume("provider-b", "same-ticket", now.AddMinutes(10)));
        Assert.Equal(TicketReplayCacheResult.Replayed, cache.TryConsume("provider-a", "same-ticket", firstExpiry));
        Assert.Equal(TicketReplayCacheResult.CapacityExceeded, cache.TryConsume("provider-a", "third-ticket", now.AddMinutes(10)));

        clock.Advance(TimeSpan.FromMinutes(6));
        Assert.Equal(TicketReplayCacheResult.Accepted, cache.TryConsume("provider-a", "third-ticket", clock.GetUtcNow().AddMinutes(5)));
        Assert.Equal(TicketReplayCacheResult.Replayed, cache.TryConsume("provider-a", "third-ticket", clock.GetUtcNow().AddMinutes(5)));
    }
}

internal sealed class ManualTicketTimeProvider(DateTimeOffset utcNow) : TimeProvider
{
    private DateTimeOffset _utcNow = utcNow;
    public override DateTimeOffset GetUtcNow() => _utcNow;
    public void Advance(TimeSpan duration) => _utcNow = _utcNow.Add(duration);
}

public sealed class TicketAuthFactory : WebApplicationFactory<Program>
{
    private readonly string _dataDir = Path.Combine(Path.GetTempPath(), "nas-auth-ticket-it-" + Guid.NewGuid().ToString("N"));
    public TicketAdapterProbe Probe { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Directory.CreateDirectory(_dataDir);
        var resourcesPath = Path.Combine(_dataDir, "resources.json");
        var clientsPath = Path.Combine(_dataDir, "clients.json");
        File.WriteAllText(resourcesPath, "[{ \"aud\": \"test-resource\", \"resource_url\": \"https://resource.example.test\", \"scopes\": [\"read\"] }]");
        File.WriteAllText(clientsPath, "[]");

        builder.UseEnvironment("Development");
        builder.UseSetting("Auth:Issuer", "https://auth.example.test/auth");
        builder.UseSetting("Auth:PathBase", "/auth");
        builder.UseSetting("Auth:Database", $"Data Source={Path.Combine(_dataDir, "auth.db")}");
        builder.UseSetting("Auth:ResourcesPath", resourcesPath);
        builder.UseSetting("Auth:ClientsPresetPath", clientsPath);
        builder.UseSetting("ExternalProviders:TicketProviders:0:Id", "badge-login");
        builder.UseSetting("ExternalProviders:TicketProviders:0:DisplayName", "Badge account");
        builder.UseSetting("ExternalProviders:TicketProviders:0:Enabled", "true");
        builder.UseSetting("ExternalProviders:TicketProviders:0:LoginUrl", "https://login.example.test/entry?fixed=1");
        builder.UseSetting("ExternalProviders:TicketProviders:0:ValidationUrl", "https://adapter.example.test/validate");
        builder.UseSetting("ExternalProviders:TicketProviders:0:ValidationToken", "integration-only-token");
        builder.UseSetting("ExternalProviders:TicketProviders:0:ReturnUrlParameter", "callback_url");
        builder.UseSetting("ExternalProviders:TicketProviders:0:LoginParameters:realm", "test-realm");
        builder.ConfigureServices(services =>
        {
            services.AddSingleton(Probe);
            services.AddHttpClient(ExternalTicketAuthenticationHandler.ValidationHttpClientName)
                .ConfigurePrimaryHttpMessageHandler(sp => new TicketAdapterTestHandler(sp.GetRequiredService<TicketAdapterProbe>()));
        });
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        var host = base.CreateHost(builder);
        using var scope = host.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserRepository>();
        users.Create("alice", "alice", PasswordHasher.Hash("not-used"), mustChangePassword: false,
            email: "alice@example.test", allowPasswordLogin: false);
        scope.ServiceProvider.GetRequiredService<ExternalIdentityRepository>()
            .BindActive("badge-login", "stable-person-123", "alice", "alice@example.test", "Alice Example");
        return host;
    }

    public HttpClient Browser() => CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://auth.example.test"),
        AllowAutoRedirect = false,
    });

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        using (var connection = new SqliteConnection($"Data Source={Path.Combine(_dataDir, "auth.db")}"))
            SqliteConnection.ClearPool(connection);
        try { Directory.Delete(_dataDir, recursive: true); } catch { /* ignore */ }
    }
}

public sealed class TicketAdapterProbe
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _requestCounts = new(StringComparer.Ordinal);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, TicketAdapterRequestRecord> _requests = new(StringComparer.Ordinal);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _responses = new(StringComparer.Ordinal);

    public int RequestCountFor(string ticket) => _requestCounts.TryGetValue(ticket, out var count) ? count : 0;
    public TicketAdapterRequestRecord? RequestFor(string ticket) => _requests.GetValueOrDefault(ticket);
    public void SetResponse(string ticket, string json) => _responses[ticket] = json;
    public string ResponseFor(string ticket) => _responses.GetValueOrDefault(ticket)
        ?? "{\"subject\":\"stable-person-123\",\"display_name\":\"Alice Example\",\"email\":\"alice@example.test\"}";

    public void Record(string ticket, string? authorization, string? contentType, string body)
    {
        _requestCounts.AddOrUpdate(ticket, 1, (_, count) => count + 1);
        _requests[ticket] = new TicketAdapterRequestRecord(authorization, contentType, body);
    }
}

public sealed record TicketAdapterRequestRecord(string? Authorization, string? ContentType, string Body);

public sealed class TicketAdapterTestHandler(TicketAdapterProbe probe) : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        using var json = JsonDocument.Parse(body);
        var ticket = json.RootElement.GetProperty("ticket").GetString()!;
        probe.Record(ticket, request.Headers.Authorization?.ToString(), request.Content.Headers.ContentType?.MediaType, body);
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(probe.ResponseFor(ticket), Encoding.UTF8, "application/json"),
        };
    }
}

public sealed class TicketProviderPipelineTests : IClassFixture<TicketAuthFactory>
{
    private readonly TicketAuthFactory _app;
    public TicketProviderPipelineTests(TicketAuthFactory app) => _app = app;

    [Fact]
    public async Task TicketProviderUsesCorrelationAdapterContractAndOneTimeTicketGuard()
    {
        using var browser = _app.Browser();

        var loginResponse = await browser.GetAsync("/auth/login");
        var loginPage = await loginResponse.Content.ReadAsStringAsync();
        Assert.True(loginResponse.StatusCode == HttpStatusCode.OK, loginPage);
        Assert.Contains("/auth/external/badge-login/start", loginPage);
        Assert.DoesNotContain("/auth/external/badge-login/bind", loginPage);

        var first = await Start(browser);
        var callback = await browser.GetAsync(CallbackWithTicket(first.Callback, "opaque-ticket-1"));
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("/auth/external/complete", callback.Headers.Location!.OriginalString);

        var completed = await browser.GetAsync(callback.Headers.Location);
        Assert.Equal(HttpStatusCode.Redirect, completed.StatusCode);
        Assert.Equal("/auth/account", completed.Headers.Location!.OriginalString);
        Assert.Equal(1, _app.Probe.RequestCountFor("opaque-ticket-1"));
        var adapterRequest = _app.Probe.RequestFor("opaque-ticket-1")!;
        Assert.Equal("Bearer integration-only-token", adapterRequest.Authorization);
        Assert.Equal("application/json", adapterRequest.ContentType);
        using (var body = JsonDocument.Parse(adapterRequest.Body))
        {
            Assert.Equal("opaque-ticket-1", body.RootElement.GetProperty("ticket").GetString());
            Assert.True(body.RootElement.TryGetProperty("client_ip", out _));
        }

        var account = await browser.GetAsync("/auth/account");
        Assert.Equal(HttpStatusCode.OK, account.StatusCode);
        Assert.Contains("Alice Example", await account.Content.ReadAsStringAsync());

        // A fresh correlated flow still cannot exchange the same upstream ticket twice.
        var second = await Start(browser);
        var replay = await browser.GetAsync(CallbackWithTicket(second.Callback, "opaque-ticket-1"));
        Assert.Equal(HttpStatusCode.BadGateway, replay.StatusCode);
        Assert.Equal(1, _app.Probe.RequestCountFor("opaque-ticket-1"));
    }

    [Fact]
    public async Task TicketEmailDoesNotAutoBindAndUnknownIdentityStaysPending()
    {
        _app.Probe.SetResponse("opaque-ticket-pending",
            "{\"subject\":\"pending-person-456\",\"display_name\":\"Pending Person\",\"email\":\"alice@example.test\"}");
        using var browser = _app.Browser();

        var flow = await Start(browser);
        var callback = await browser.GetAsync(CallbackWithTicket(flow.Callback, "opaque-ticket-pending"));
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        var completed = await browser.GetAsync(callback.Headers.Location);
        Assert.Equal(HttpStatusCode.OK, completed.StatusCode);

        using var scope = _app.Services.CreateScope();
        var identity = scope.ServiceProvider.GetRequiredService<ExternalIdentityRepository>()
            .Get("badge-login", "pending-person-456");
        Assert.NotNull(identity);
        Assert.Equal("pending", identity.status);
        Assert.Null(identity.user_id);
        var responseCookies = completed.Headers.TryGetValues("Set-Cookie", out var cookies)
            ? cookies
            : Array.Empty<string>();
        Assert.DoesNotContain(responseCookies, value =>
            value.StartsWith("__Host-nas-auth-session=", StringComparison.Ordinal));
    }

    private static async Task<(string LoginUrl, string Callback)> Start(HttpClient browser)
    {
        var response = await browser.GetAsync("/auth/external/badge-login/start?return_url=%2Faccount");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var loginUrl = response.Headers.Location!.OriginalString;
        var callback = QueryHelpers.ParseQuery(new Uri(loginUrl).Query)["callback_url"].ToString();
        Assert.StartsWith("https://auth.example.test/auth/signin/badge-login?state=", callback);
        Assert.Contains("realm=test-realm", new Uri(loginUrl).Query);
        return (loginUrl, callback);
    }

    private static string CallbackWithTicket(string callback, string ticket) =>
        QueryHelpers.AddQueryString(callback, "ticket", ticket);
}
