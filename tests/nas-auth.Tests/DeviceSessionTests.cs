using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

public class DeviceSessionTests
{
    private static FormUrlEncodedContent Form(params (string, string)[] fields) => new(fields.Select(f => new KeyValuePair<string, string>(f.Item1, f.Item2)));
    private static async Task Login(HttpClient browser, string mount, string user, string password, string agent)
    {
        browser.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", agent);
        Assert.Equal(HttpStatusCode.Redirect, (await browser.PostAsync(mount + "/login", Form(("username", user), ("password", password)))).StatusCode);
    }
    private static async Task<HttpResponseMessage> Post(HttpClient browser, string mount, string target, params (string, string)[] fields)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, mount + target) { Content = Form(fields) };
        request.Headers.Add(AntiforgeryGuard.HeaderName, await HttpPipelineTests.CsrfToken(browser, mount + "/account/sessions"));
        return await browser.SendAsync(request);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SelectedDeviceRevokesItsCookieCodeRefreshAndAccessTokensOnly(bool team)
    {
        using var app = new DeploymentScenarioFactory(team); using var scope = app.Services.CreateScope(); var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserRepository>(); var sessions = services.GetRequiredService<DeviceSessions>();
        users.Create("device-user", "device-user", PasswordHasher.Hash("test-password"), false, allowPasswordLogin: true);
        services.GetRequiredService<UserResourceRepository>().Upsert("device-user", "library", "openid profile");
        using var first = app.Browser(); using var second = app.Browser(); using var outsider = app.Browser();
        await Login(first, app.Mount, "device-user", "test-password", "Mozilla/5.0 Windows Chrome/130.0");
        await Login(second, app.Mount, "device-user", "test-password", "Mozilla/5.0 iPhone Safari/605.1");
        users.Create("outsider", "outsider", PasswordHasher.Hash("other-password"), false, allowPasswordLogin: true);
        await Login(outsider, app.Mount, "outsider", "other-password", "Mozilla/5.0 Firefox/130.0");
        var own = sessions.List("device-user"); Assert.Equal(2, own.Count);
        var firstId = own.Single(s => s.browser == "Chrome").id; var secondId = own.Single(s => s.browser == "Safari").id;
        Assert.Contains("This device", await first.GetStringAsync(app.Mount + "/account/sessions"));
        Assert.Equal(HttpStatusCode.Forbidden, (await first.PostAsync(app.Mount + "/account/sessions/revoke", Form(("id", secondId)))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Post(outsider, app.Mount, "/account/sessions/revoke", ("id", secondId), ("user_id", "device-user"))).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await Post(first, app.Mount, "/account/sessions/name", ("id", firstId), ("name", "<script>My PC</script>"))).StatusCode);
        var named = await first.GetStringAsync(app.Mount + "/account/sessions");
        Assert.Contains("&lt;script&gt;My PC", named); Assert.DoesNotContain("<script>My PC", named);

        const string verifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
        var challenge = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        async Task<string> Authorize(HttpClient browser)
        {
            var response = await browser.PostAsync(app.Mount + "/authorize", Form(("response_type", "code"), ("client_id", "library-client"),
                ("redirect_uri", "https://apps.example.test/callback"), ("resource", "https://apps.example.test/library"), ("scope", "openid profile"),
                ("use_session", "1"), ("code_challenge", challenge), ("code_challenge_method", "S256")));
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            return QueryHelpers.ParseQuery(response.Headers.Location!.Query)["code"].ToString();
        }
        using var protocol = app.Browser();
        var code = await Authorize(second);
        var token = await protocol.PostAsync(app.Mount + "/token", Form(("grant_type", "authorization_code"), ("code", code),
            ("client_id", "library-client"), ("redirect_uri", "https://apps.example.test/callback"), ("code_verifier", verifier)));
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        var payload = JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement;
        var refresh = payload.GetProperty("refresh_token").GetString()!;
        var rotated = await protocol.PostAsync(app.Mount + "/token", Form(("grant_type", "refresh_token"), ("refresh_token", refresh), ("client_id", "library-client")));
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        var rotation = JsonDocument.Parse(await rotated.Content.ReadAsStringAsync()).RootElement;
        var rotatedRefresh = rotation.GetProperty("refresh_token").GetString()!;
        Assert.Equal(secondId, services.GetRequiredService<RefreshTokenRepository>().GetByHash(JwtIssuer.HashRefreshToken(rotatedRefresh))!.session_id);
        var validator = services.GetRequiredService<JwtValidator>();
        var access = rotation.GetProperty("access_token").GetString()!;
        Assert.Equal(secondId, validator.TryValidate(access, out _)!.FindFirst(DeviceSessions.ClaimType)!.Value);
        var unspent = await Authorize(second);
        Assert.Equal(2, sessions.List("device-user").Count); // consent must not manufacture another device
        Assert.Equal(HttpStatusCode.Redirect, (await Post(first, app.Mount, "/account/sessions/revoke", ("id", secondId))).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await second.GetAsync(app.Mount + "/account")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await first.GetAsync(app.Mount + "/account")).StatusCode);
        Assert.Null(validator.TryValidate(access, out _));
        Assert.Equal(HttpStatusCode.BadRequest, (await protocol.PostAsync(app.Mount + "/token", Form(("grant_type", "refresh_token"), ("refresh_token", rotatedRefresh), ("client_id", "library-client")))).StatusCode);
        Assert.Null(services.GetRequiredService<AuthCodeRepository>().ConsumeAtomic(unspent));
        Assert.True(sessions.CredentialIsActive(firstId, "device-user"));
        Assert.False(sessions.CredentialIsActive(secondId, "device-user"));
        Assert.Equal(HttpStatusCode.NotFound, (await Post(outsider, app.Mount, "/admin/users/sessions/revoke", ("id", firstId), ("user_id", "device-user"))).StatusCode);
    }

    [Fact]
    public async Task RevokeOthersPreservesCurrentForwardAuthAndToken_LogoutRevokesCurrent()
    {
        using var app = new NasAuthAppFactory(); using var scope = app.Services.CreateScope(); var sp = scope.ServiceProvider;
        var users = sp.GetRequiredService<UserRepository>(); var sessions = sp.GetRequiredService<DeviceSessions>();
        users.Create("devices", "devices", PasswordHasher.Hash("test-password"), false, allowPasswordLogin: true);
        sp.GetRequiredService<UserResourceRepository>().Upsert("devices", "docs-site", "access");
        using var first = app.Client(); using var second = app.Client(); using var site = app.Client("https://docs.example.com");
        await Login(first, "", "devices", "test-password", "Windows Chrome/130.0");
        await Login(second, "", "devices", "test-password", "iPhone Safari/605.1");
        var own = sessions.List("devices"); var firstId = own.Single(r => r.browser == "Chrome").id; var secondId = own.Single(r => r.browser == "Safari").id;
        var user = users.GetById("devices")!; var fa = sp.GetRequiredService<ForwardAuthService>();
        var cookies = own.ToDictionary(r => r.id, r => fa.CreateSession("docs-site", user.user_id, user.session_version, TimeSpan.FromHours(1), user.session_epoch, r.id));
        HttpRequestMessage Verify(string id)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/forward-auth/verify?aud=docs-site");
            request.Headers.Add("X-Forwarded-Method", "GET"); request.Headers.Add("X-Forwarded-Uri", "/"); request.Headers.Add("Sec-Fetch-Mode", "cors");
            request.Headers.Add("Cookie", ForwardAuthService.SessionCookie + "=" + cookies[id]); return request;
        }
        var jwt = sp.GetRequiredService<JwtIssuer>(); var validator = sp.GetRequiredService<JwtValidator>();
        var currentAccess = jwt.IssueAccessToken("devices", "client", ["docs-site"], "r", "access", firstId);
        var otherAccess = jwt.IssueAccessToken("devices", "client", ["docs-site"], "r", "access", secondId);
        var nonce = ForwardAuthService.NewNonce(); var state = fa.CreateState("docs-site", "/", nonce);
        var ticket = fa.CreateTicket("docs-site", "devices", user.session_version, nonce, user.session_epoch, secondId);
        var refreshes = sp.GetRequiredService<RefreshTokenRepository>();
        foreach (var (hash, sid) in new[] { ("current-refresh", (string?)firstId), ("other-refresh", secondId), ("legacy-refresh", (string?)null) })
            refreshes.Insert(new(hash, "client", "r", "access", "devices", DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds(), 0, 1, null, sid));
        Assert.Equal(HttpStatusCode.OK, (await site.SendAsync(Verify(secondId))).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await Post(first, "", "/account/sessions/revoke-others")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await first.GetAsync("/account")).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await second.GetAsync("/account")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await site.SendAsync(Verify(firstId))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await site.SendAsync(Verify(secondId))).StatusCode);
        Assert.NotNull(validator.TryValidate(currentAccess, out _)); Assert.Null(validator.TryValidate(otherAccess, out _));
        Assert.Equal(0, refreshes.GetByHash("current-refresh")!.revoked);
        Assert.Equal(1, refreshes.GetByHash("other-refresh")!.revoked);
        Assert.Equal(1, refreshes.GetByHash("legacy-refresh")!.revoked);
        var callback = new HttpRequestMessage(HttpMethod.Get, "/.nas-auth/callback?ticket=" + Uri.EscapeDataString(ticket) + "&state=" + Uri.EscapeDataString(state));
        callback.Headers.Add("Cookie", ForwardAuthService.StateCookie + "=" + nonce);
        Assert.Equal(HttpStatusCode.BadRequest, (await site.SendAsync(callback)).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await first.GetAsync("/logout")).StatusCode);
        Assert.Null(validator.TryValidate(currentAccess, out _));
        Assert.Equal(HttpStatusCode.Unauthorized, (await site.SendAsync(Verify(firstId))).StatusCode);
    }

    [Fact]
    public async Task LegacySignedCookieMigratesOnceAndCannotRecreateARevokedDevice()
    {
        using var app = new NasAuthAppFactory(); using var scope = app.Services.CreateScope(); var sp = scope.ServiceProvider;
        var user = sp.GetRequiredService<UserRepository>().GetById("admin")!;
        var options = sp.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, user.user_id), new Claim(ClaimTypes.NameIdentifier, user.user_id),
            new Claim(SessionValidator.ClaimType, user.session_version.ToString()), new Claim(SessionValidator.EpochClaimType, user.session_epoch)], CookieAuthenticationDefaults.AuthenticationScheme));
        var ticket = new AuthenticationTicket(principal, new AuthenticationProperties { IsPersistent = true, IssuedUtc = DateTimeOffset.UtcNow.AddHours(-1), ExpiresUtc = DateTimeOffset.UtcNow.AddDays(5) }, CookieAuthenticationDefaults.AuthenticationScheme);
        var cookie = options.TicketDataFormat.Protect(ticket);
        using var browser = app.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new("https://localhost"), HandleCookies = false, AllowAutoRedirect = false });
        HttpRequestMessage Request()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/account"); request.Headers.Add("Cookie", options.Cookie.Name + "=" + cookie); return request;
        }
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(Request())).StatusCode);
        var sessions = sp.GetRequiredService<DeviceSessions>(); var row = Assert.Single(sessions.List(user.user_id));
        Assert.StartsWith("legacy-", row.id);
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(Request())).StatusCode);
        Assert.Single(sessions.List(user.user_id));
        Assert.True(sessions.Revoke(user.user_id, row.id));
        Assert.Equal(HttpStatusCode.Redirect, (await browser.SendAsync(Request())).StatusCode);
        Assert.Single(sessions.List(user.user_id));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HeaderlessProxyMigrationIsEnrichedByTheNextBrowserRequest(bool team)
    {
        using var app = new DeploymentScenarioFactory(team); using var scope = app.Services.CreateScope(); var sp = scope.ServiceProvider;
        var user = sp.GetRequiredService<UserRepository>().GetById("admin")!;
        var sessions = sp.GetRequiredService<DeviceSessions>();
        var options = sp.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, user.user_id),
            new Claim(SessionValidator.ClaimType, user.session_version.ToString()), new Claim(SessionValidator.EpochClaimType, user.session_epoch)], CookieAuthenticationDefaults.AuthenticationScheme));
        var ticket = new AuthenticationTicket(principal, new AuthenticationProperties { IsPersistent = true,
            IssuedUtc = DateTimeOffset.UtcNow.AddHours(-1), ExpiresUtc = DateTimeOffset.UtcNow.AddDays(5) }, CookieAuthenticationDefaults.AuthenticationScheme);
        var cookie = options.TicketDataFormat.Protect(ticket);
        using var browser = app.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, AllowAutoRedirect = false });
        HttpRequestMessage Request(bool proxy, string? agent = null)
        {
            var url = proxy ? "https://gate.example.test" + app.Mount + "/forward-auth/verify?aud=library-gate&response=auth_request"
                : "https://auth.example.test" + app.Mount + "/account/sessions";
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Cookie", options.Cookie.Name + "=" + cookie);
            request.Headers.Add("X-Forwarded-Uri", "/library/"); request.Headers.Add("X-Forwarded-Method", "GET");
            if (agent is not null) request.Headers.Add("User-Agent", agent);
            return request;
        }
        // Nginx auth_request can forward the old Auth cookie but strip the browser headers.
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.SendAsync(Request(true))).StatusCode);
        var initial = Assert.Single(sessions.List(user.user_id));
        Assert.Equal("Unknown browser", initial.browser); Assert.Equal("Unknown device", initial.platform);
        Assert.True(sessions.Rename(user.user_id, initial.id, "My workstation"));
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(Request(false, "Mozilla/5.0 Windows Chrome/130.0"))).StatusCode);
        var enriched = Assert.Single(sessions.List(user.user_id));
        Assert.Equal(initial.id, enriched.id); Assert.Equal("Chrome", enriched.browser); Assert.Equal("Windows", enriched.platform);
        Assert.Equal("My workstation", enriched.name); Assert.Equal(initial.created_at, enriched.created_at);
        Assert.Equal(initial.expires_at, enriched.expires_at); // Metadata repair does not reset expiry or require a minute's wait.
        await browser.SendAsync(Request(true));
        await browser.SendAsync(Request(false, "iPhone Safari/605.1"));
        Assert.True(sessions.CredentialIsActive(initial.id, user.user_id, touch: true));
        Assert.Equal("Chrome", Assert.Single(sessions.List(user.user_id)).browser);
        Assert.Equal("Windows", Assert.Single(sessions.List(user.user_id)).platform);
        Assert.True(sessions.Revoke(user.user_id, initial.id));
        Assert.Equal(HttpStatusCode.Redirect, (await browser.SendAsync(Request(false, "Windows Edg/130.0"))).StatusCode);
        Assert.Equal("Chrome", Assert.Single(sessions.List(user.user_id)).browser);
    }

    [Theory]
    [InlineData("iPhone", "Mozilla/5.0 iPhone FxiOS/130.0 Safari/605.1", "Firefox", "iPhone")]
    [InlineData("Edg/130.0", "Windows Chrome/130.0", "Edge", "Windows")]
    [InlineData("", "Android Chrome/130.0 EdgA/130.0", "Edge", "Android")]
    [InlineData("", "iPhone EdgiOS/130.0 Safari/605.1", "Edge", "iPhone")]
    public void OnlyMissingDeviceLabelsAreFilled(string initialAgent, string nextAgent, string browser, string platform)
    {
        using var app = new NasAuthAppFactory(); using var scope = app.Services.CreateScope(); var sp = scope.ServiceProvider;
        var sessions = sp.GetRequiredService<DeviceSessions>(); var user = sp.GetRequiredService<UserRepository>().GetById("admin")!;
        var context = new DefaultHttpContext(); context.Request.Headers.UserAgent = initialAgent;
        var id = sessions.SignIn(context, user, true)!;
        context.Request.Headers.UserAgent = nextAgent;
        Assert.True(sessions.Validate(id, user.user_id, context, touch: true));
        var row = Assert.Single(sessions.List(user.user_id));
        Assert.Equal(browser, row.browser); Assert.Equal(platform, row.platform);
    }

    [Fact]
    public void IdleAndAbsoluteExpiryAndRevokedConsentAreEnforced()
    {
        using var app = new NasAuthAppFactory(); using var scope = app.Services.CreateScope(); var sp = scope.ServiceProvider;
        var user = sp.GetRequiredService<UserRepository>().GetById("admin")!; var clock = new Clock();
        var sessions = new DeviceSessions(sp.GetRequiredService<AuthDb>(), new DeviceSessionOptions { IdleHours = 1, AbsoluteHours = 2 }, clock);
        var context = new DefaultHttpContext(); context.Request.Headers.UserAgent = "Windows Chrome/130.0";
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.10");
        var id = sessions.SignIn(context, user, true)!;
        var idle = sessions.SignIn(context, user, true)!;
        clock.Now += TimeSpan.FromMinutes(55); Assert.True(sessions.Validate(id, user.user_id, touch: true));
        clock.Now += TimeSpan.FromMinutes(55); Assert.True(sessions.Validate(id, user.user_id, touch: true));
        Assert.False(sessions.Validate(idle, user.user_id));
        Assert.Equal("192.0.2.10", sessions.List(user.user_id).Single(r => r.id == id).last_ip);
        clock.Now += TimeSpan.FromMinutes(11); Assert.False(sessions.Validate(id, user.user_id, touch: true));
        var fresh = sessions.SignIn(context, user, true)!;
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, user.user_id), new Claim(DeviceSessions.ClaimType, fresh)], "cookie"));
        Assert.True(sessions.Revoke(user.user_id, fresh)); Assert.Null(sessions.SignIn(context, user, false));
        Assert.NotNull(sessions.SignIn(context, user, true));
    }

    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public async Task AdministratorCanEndOneUsersDeviceWithoutEndingOwnSession()
    {
        using var app = new NasAuthAppFactory(); using var scope = app.Services.CreateScope(); var sp = scope.ServiceProvider;
        sp.GetRequiredService<UserRepository>().Create("managed", "managed", PasswordHasher.Hash("test-password"), false, allowPasswordLogin: true);
        using var admin = app.Client(); using var user = app.Client();
        await Login(admin, "", "admin", "devpassword", "Windows Chrome/130.0");
        await Login(user, "", "managed", "test-password", "iPhone Safari/605.1");
        var id = Assert.Single(sp.GetRequiredService<DeviceSessions>().List("managed")).id;
        Assert.Contains("Devices and sessions", await admin.GetStringAsync("/admin/users/edit?user=managed"));
        Assert.Equal(HttpStatusCode.NotFound, (await Post(admin, "", "/admin/users/sessions/revoke", ("id", id), ("user_id", "admin"))).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await Post(admin, "", "/admin/users/sessions/revoke", ("id", id), ("user_id", "managed"))).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await user.GetAsync("/account")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/account")).StatusCode);
    }

    [Fact]
    public void LegacyRevocationTombstoneSurvivesUntilTheOriginalCookieExpires()
    {
        using var app = new NasAuthAppFactory(); using var scope = app.Services.CreateScope(); var sp = scope.ServiceProvider;
        var user = sp.GetRequiredService<UserRepository>().GetById("admin")!; var clock = new Clock();
        var sessions = new DeviceSessions(sp.GetRequiredService<AuthDb>(), new DeviceSessionOptions { IdleHours = 1 }, clock);
        var context = new DefaultHttpContext(); var expiry = clock.Now.AddDays(120);
        var id = sessions.AdoptLegacy(context, user, "synthetic-protected-cookie", expiry)!;
        Assert.True(sessions.Revoke(user.user_id, id)); clock.Now += TimeSpan.FromDays(91);
        Assert.Equal(0, sessions.Cleanup()); Assert.Null(sessions.AdoptLegacy(context, user, "synthetic-protected-cookie", expiry));
        clock.Now += TimeSpan.FromDays(30);
        Assert.Equal(1, sessions.Cleanup()); Assert.Null(sessions.AdoptLegacy(context, user, "synthetic-protected-cookie", expiry));
    }

    [Fact]
    public void StalePasswordProofAndAccountLifecycleCannotReviveSessions()
    {
        using var app = new NasAuthAppFactory(); using var scope = app.Services.CreateScope(); var sp = scope.ServiceProvider;
        var users = sp.GetRequiredService<UserRepository>(); var sessions = sp.GetRequiredService<DeviceSessions>();
        users.Create("lifecycle-device", "lifecycle-device", PasswordHasher.Hash("test-password"), false, allowPasswordLogin: true);
        var proof = users.GetById("lifecycle-device")!;
        var context = new DefaultHttpContext(); var id = sessions.SignIn(context, proof, true)!;
        users.ResetPassword(proof.user_id, PasswordHasher.Hash("new-password"), false); users.BumpSessionVersion(proof.user_id);
        Assert.Null(sessions.SignIn(context, proof, true)); Assert.False(sessions.Validate(id, proof.user_id));
        proof = users.GetById(proof.user_id)!; id = sessions.SignIn(context, proof, true)!;
        Assert.True(users.Disable("admin", proof.user_id, "admin"));
        Assert.True(users.RestoreIdentity("admin", proof.user_id, false, PasswordHasher.Hash("restored-password"), true, null));
        Assert.False(sessions.Validate(id, proof.user_id));
        Assert.Null(sessions.SignIn(context, proof, true));
    }
}
