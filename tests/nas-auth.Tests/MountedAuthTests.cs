using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>Isolated integration coverage for a PathBase deployment and same-host path-mounted sites.</summary>
public sealed class MountedAuthFactory : WebApplicationFactory<Program>
{
    private readonly string _dataDir = Path.Combine(Path.GetTempPath(), "nas-auth-mounted-it-" + Guid.NewGuid().ToString("N"));

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Directory.CreateDirectory(_dataDir);
        var resourcesPath = Path.Combine(_dataDir, "resources.json");
        File.WriteAllText(resourcesPath, """
            [
              { "aud": "tools", "resource_url": "https://apps.example.test/tools/", "display_name": "Tools", "forward_auth": {} },
              { "aud": "admin", "resource_url": "https://apps.example.test/tools/admin/", "display_name": "Admin", "forward_auth": {} }
            ]
            """);
        var clientsPath = Path.Combine(_dataDir, "clients.json");
        File.WriteAllText(clientsPath, "[]");

        builder.UseEnvironment("Development");
        builder.UseSetting("Auth:Issuer", "https://auth.example.test/auth");
        builder.UseSetting("Auth:PathBase", "/auth");
        builder.UseSetting("Auth:Database", $"Data Source={Path.Combine(_dataDir, "auth.db")}");
        builder.UseSetting("Auth:ResourcesPath", resourcesPath);
        builder.UseSetting("Auth:ClientsPresetPath", clientsPath);
        builder.UseSetting("Auth:PasswordLogin:Enabled", "true");
        builder.UseSetting("ExternalProviders:UseConfiguredProviders", "true");
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        var host = base.CreateHost(builder);
        using var scope = host.Services.CreateScope();
        scope.ServiceProvider.GetRequiredService<UserRepository>().Create(
            "alice", "alice", PasswordHasher.Hash("integration-pass"), mustChangePassword: false,
            email: "alice@example.test", allowPasswordLogin: true);
        scope.ServiceProvider.GetRequiredService<UserResourceRepository>()
            .Upsert("alice", "tools", "access");
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

public sealed class MountedAuthTests : IClassFixture<MountedAuthFactory>
{
    private const string Auth = "https://auth.example.test";
    private const string Site = "https://apps.example.test";
    private const string AuthBase = "/auth";
    private readonly MountedAuthFactory _app;

    public MountedAuthTests(MountedAuthFactory app) => _app = app;

    [Fact]
    public async Task PathBaseKeepsAuthSurfaceUnderMountAndExplicitEmptyProvidersDisableLegacyEnv()
    {
        using var browser = _app.Browser();

        var login = await browser.GetAsync(Auth + AuthBase + "/login");
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var html = await login.Content.ReadAsStringAsync();
        Assert.Contains("href=\"/auth/app.css?", html);
        Assert.Contains("action='/auth/login'", html);
        Assert.DoesNotContain("Google", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Microsoft", html, StringComparison.OrdinalIgnoreCase);

        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync(Auth + "/login")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await browser.GetAsync(Auth + AuthBase + "/external/google/start")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await browser.GetAsync(Auth + AuthBase + "/signin/badge-login?state=disabled&ticket=ignored")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync(Auth + AuthBase + "/healthz")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync(Auth + "/healthz")).StatusCode);

        var discovery = await browser.GetFromJsonAsync<System.Text.Json.JsonElement>(Auth + AuthBase + "/.well-known/openid-configuration");
        Assert.Equal(Auth + AuthBase, discovery.GetProperty("issuer").GetString());
        Assert.Equal(Auth + AuthBase + "/authorize", discovery.GetProperty("authorization_endpoint").GetString());
    }

    [Fact]
    public async Task NginxAuthRequestFlowUsesPathScopedAppsAndRechecksGrant()
    {
        using var browser = _app.Browser();

        var blocked = await Verify(browser, "tools", "/tools/page?return=%2Faccount", authRequest: true);
        Assert.Equal(HttpStatusCode.Unauthorized, blocked.StatusCode);
        var redirect = blocked.Headers.GetValues("X-Auth-Redirect").Single();
        Assert.StartsWith(Auth + AuthBase + "/forward-auth/start?aud=tools&state=", redirect);
        var stateCookie = blocked.Headers.GetValues("Set-Cookie")
            .Single(v => v.StartsWith("__Host-nas-auth-fa-state-", StringComparison.Ordinal));
        Assert.Contains("; path=/", stateCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; secure", stateCookie, StringComparison.OrdinalIgnoreCase);

        var start = await browser.GetAsync(redirect);
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        Assert.StartsWith(Auth + AuthBase + "/login?return_url=", start.Headers.Location!.OriginalString);
        var loginPage = await browser.GetAsync(start.Headers.Location);
        Assert.Equal(HttpStatusCode.OK, loginPage.StatusCode);
        var page = await loginPage.Content.ReadAsStringAsync();
        var returnUrlMatch = Regex.Match(page, "name='return_url' value='([^']*)'");
        Assert.True(returnUrlMatch.Success, "Login page did not contain the local return_url field.");
        var returnUrl = WebUtility.HtmlDecode(returnUrlMatch.Groups[1].Value);

        var signedIn = await browser.PostAsync(Auth + AuthBase + "/login", new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("username", "alice"),
            new KeyValuePair<string, string>("password", "integration-pass"),
            new KeyValuePair<string, string>("return_url", returnUrl),
        }));
        Assert.Equal(HttpStatusCode.Redirect, signedIn.StatusCode);
        Assert.StartsWith(AuthBase + "/forward-auth/start?aud=tools&state=", signedIn.Headers.Location!.OriginalString);

        var ticketed = await browser.GetAsync(signedIn.Headers.Location);
        Assert.Equal(HttpStatusCode.Redirect, ticketed.StatusCode);
        Assert.StartsWith(Site + "/.nas-auth/callback?aud=tools&ticket=", ticketed.Headers.Location!.OriginalString);
        var publicCallback = new Uri(ticketed.Headers.Location!.OriginalString);
        var internalCallback = new UriBuilder(publicCallback)
        {
            Path = AuthBase + publicCallback.AbsolutePath,
        }.Uri;
        var callback = await browser.GetAsync(internalCallback);
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("/tools/page?return=%2Faccount", callback.Headers.Location!.OriginalString);
        var sessionCookie = callback.Headers.GetValues("Set-Cookie")
            .Single(v => v.StartsWith("__Host-nas-auth-fa-", StringComparison.Ordinal) &&
                         !v.StartsWith("__Host-nas-auth-fa-state-", StringComparison.Ordinal));
        Assert.Contains("; path=/", sessionCookie, StringComparison.OrdinalIgnoreCase);

        var allowed = await Verify(browser, "tools", "/tools/page?return=%2Faccount", authRequest: true,
            forwardedHost: "evil.example.test");
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);

        // Longest path match owns /tools/admin even when the caller asks for the less privileged aud.
        var wrongAudience = await Verify(browser, "tools", "/tools/admin/users", authRequest: true,
            forwardedHost: "apps.example.test");
        Assert.Equal(HttpStatusCode.Forbidden, wrongAudience.StatusCode);

        // The admin mount has its own cookie namespace and the user has no grant for it.
        var adminBlocked = await Verify(browser, "admin", "/tools/admin/users", authRequest: true);
        Assert.Equal(HttpStatusCode.Unauthorized, adminBlocked.StatusCode);
        var adminStart = await browser.GetAsync(adminBlocked.Headers.GetValues("X-Auth-Redirect").Single());
        Assert.Equal(HttpStatusCode.Forbidden, adminStart.StatusCode);

        using (var scope = _app.Services.CreateScope())
            scope.ServiceProvider.GetRequiredService<UserResourceRepository>().Delete("alice", "tools");
        var revoked = await Verify(browser, "tools", "/tools/page", authRequest: true);
        Assert.Equal(HttpStatusCode.Unauthorized, revoked.StatusCode);
        var deniedAfterRevoke = await browser.GetAsync(revoked.Headers.GetValues("X-Auth-Redirect").Single());
        Assert.Equal(HttpStatusCode.Forbidden, deniedAfterRevoke.StatusCode);
    }

    private static Task<HttpResponseMessage> Verify(HttpClient browser, string aud, string uri,
        bool authRequest, string? forwardedHost = null)
    {
        var query = $"aud={Uri.EscapeDataString(aud)}" + (authRequest ? "&response=auth_request" : "");
        var request = new HttpRequestMessage(HttpMethod.Get,
            $"{Site}{AuthBase}/forward-auth/verify?{query}");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Method", "GET");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Uri", uri);
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Mode", "navigate");
        request.Headers.TryAddWithoutValidation("Accept", "text/html");
        if (forwardedHost is not null)
            request.Headers.TryAddWithoutValidation("X-Forwarded-Host", forwardedHost);
        return browser.SendAsync(request);
    }
}
