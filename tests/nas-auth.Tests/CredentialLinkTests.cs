using System.Net;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

public class CredentialLinkTests
{
    private static FormUrlEncodedContent Form(params (string, string)[] values) => new(values.Select(x => new KeyValuePair<string, string>(x.Item1, x.Item2)));
    private static async Task<HttpResponseMessage> Post(HttpClient browser, string page, string target, params (string, string)[] values)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, target) { Content = Form(values) };
        request.Headers.Add(AntiforgeryGuard.HeaderName, await HttpPipelineTests.CsrfToken(browser, page));
        return await browser.SendAsync(request);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvitationAndRecovery_WorkThroughBothMountedPipelines(bool team)
    {
        using var app = new DeploymentScenarioFactory(team); using var admin = app.Browser();
        var mount = app.Mount;
        await admin.PostAsync(mount + "/login", Form(("username", "admin"), ("password", "devpassword")));
        var created = await Post(admin, mount + "/admin/users", mount + "/admin/users/create",
            ("username", "invited"), ("allow_password_login", "1"), ("credential_invite", "1"));
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var html = await created.Content.ReadAsStringAsync();
        var token = Regex.Match(html, "#token=([a-f0-9]{64})").Groups[1].Value;
        Assert.Equal(64, token.Length);
        Assert.Contains(app.Issuer + "/credential-link#token=", html);
        Assert.DoesNotContain(token, await admin.GetStringAsync(mount + "/admin/users/edit?user=invited"));
        using var recipient = app.Browser();
        Assert.Equal(HttpStatusCode.Redirect, (await recipient.GetAsync(mount + "/admin/apps/new")).StatusCode);
        var denied = await recipient.PostAsync(mount + "/credential-link", Form(("token", token), ("new_password", "new-password"), ("confirm_password", "new-password")));
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        var redeemed = await Post(recipient, mount + "/credential-link", mount + "/credential-link", ("token", token), ("new_password", "new-password"), ("confirm_password", "new-password"));
        Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
        Assert.Contains("no-store", redeemed.Headers.CacheControl!.ToString());
        Assert.DoesNotContain(token, await redeemed.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(recipient, mount + "/credential-link", mount + "/credential-link", ("token", token), ("new_password", "another-password"), ("confirm_password", "another-password"))).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await recipient.PostAsync(mount + "/login", Form(("username", "invited"), ("password", "new-password")))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await recipient.GetAsync(mount + "/admin/apps/new")).StatusCode);
        var recovery = await Post(admin, mount + "/admin/users/edit?user=invited", mount + "/admin/users/credential-links/issue", ("user_id", "invited"), ("verified", "1"));
        var recoveryToken = Regex.Match(await recovery.Content.ReadAsStringAsync(), "#token=([a-f0-9]{64})").Groups[1].Value;
        Assert.Equal(64, recoveryToken.Length);
        using var recoveryBrowser = app.Browser();
        Assert.Equal(HttpStatusCode.OK, (await Post(recoveryBrowser, mount + "/credential-link", mount + "/credential-link", ("token", recoveryToken), ("new_password", "recovered-password"), ("confirm_password", "recovered-password"))).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await recipient.GetAsync(mount + "/account")).StatusCode);
        using var scope = app.Services.CreateScope();
        var sp = scope.ServiceProvider;
        Assert.Empty(sp.GetRequiredService<UserResourceRepository>().ListByUser("invited"));
        Assert.DoesNotContain(sp.GetRequiredService<AuditRepository>().Query(userId: "admin"), r => r.detail?.Contains(token) == true);
        using var connection = sp.GetRequiredService<AuthDb>().OpenConnection();
        Assert.DoesNotContain(token, connection.Query<string>("SELECT token_hash FROM credential_links"));
        Assert.Equal(0, sp.GetRequiredService<UserRepository>().GetById("invited")!.is_admin);
    }

    [Fact]
    public void LinksExpireCancelReissueAndNeverSurviveCredentialOrLifecycleChanges()
    {
        using var app = new NasAuthAppFactory(); using var scope = app.Services.CreateScope(); var sp = scope.ServiceProvider;
        var users = sp.GetRequiredService<UserRepository>(); var clock = new ControlledTime();
        var links = new CredentialLinkService(sp.GetRequiredService<AuthDb>(), new(), sp.GetRequiredService<PasswordLoginGate>(), clock);
        users.Create("recipient", "recipient", PasswordHasher.Hash("old-password"), false, allowPasswordLogin: true);
        Assert.Null(links.Issue("recipient", "recipient"));
        var first = links.Issue("admin", "recipient")!;
        var second = links.Issue("admin", "recipient")!;
        Assert.Equal(second.Id, links.List("recipient")[0].id);
        Assert.Null(links.Redeem(first.Token, "new-password"));
        Assert.True(links.Cancel("admin", "recipient", second.Id));
        Assert.Null(links.Redeem(second.Token, "new-password"));
        var expired = links.Issue("admin", "recipient")!;
        clock.Value += TimeSpan.FromHours(2);
        Assert.Contains(links.List("recipient"), l => l.id == expired.Id && l.state == "expired");
        Assert.Null(links.Redeem(expired.Token, "new-password"));
        foreach (var change in new Action[] {
            () => users.ResetPassword("recipient", PasswordHasher.Hash("another-password"), false),
            () => users.BumpSessionVersion("recipient"),
            () => { users.UpdateProfile("recipient", null, false); users.UpdateProfile("recipient", null, true); },
            () => { Assert.True(users.Disable("admin", "recipient", "admin")); Assert.True(users.RestoreIdentity("admin", "recipient", false, PasswordHasher.Hash("restore-password"), true, null)); }
        })
        {
            var link = links.Issue("admin", "recipient")!; change();
            Assert.Null(links.Redeem(link.Token, "new-password"));
        }
        users.UpdateProfile("recipient", null, false);
        Assert.Null(links.Issue("admin", "recipient"));
    }

    [Fact]
    public async Task ConcurrentRedemptionSucceedsOnceAndRevokesEveryAuthCredentialType()
    {
        using var app = new NasAuthAppFactory(); using var scope = app.Services.CreateScope(); var sp = scope.ServiceProvider;
        var users = sp.GetRequiredService<UserRepository>();
        users.Create("concurrent", "concurrent", PasswordHasher.Hash("old-password"), false, allowPasswordLogin: true);
        var before = users.GetById("concurrent")!;
        sp.GetRequiredService<UserResourceRepository>().Upsert(before.user_id, "docs-site", "access");
        var forwardAuth = sp.GetRequiredService<ForwardAuthService>();
        var oldSiteCookie = forwardAuth.CreateSession("docs-site", before.user_id, before.session_version, TimeSpan.FromHours(1), before.session_epoch);
        var nonce = ForwardAuthService.NewNonce();
        var state = forwardAuth.CreateState("docs-site", "/", nonce);
        var ticket = forwardAuth.CreateTicket("docs-site", before.user_id, before.session_version, nonce, before.session_epoch);
        using var site = app.Client("https://docs.example.com");
        HttpRequestMessage VerifySite()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/forward-auth/verify?aud=docs-site");
            request.Headers.Add("X-Forwarded-Method", "GET"); request.Headers.Add("X-Forwarded-Uri", "/");
            request.Headers.Add("Sec-Fetch-Mode", "cors"); request.Headers.Add("Cookie", ForwardAuthService.SessionCookie + "=" + oldSiteCookie);
            return request;
        }
        Assert.Equal(HttpStatusCode.OK, (await site.SendAsync(VerifySite())).StatusCode);
        var issuer = sp.GetRequiredService<JwtIssuer>(); var validator = sp.GetRequiredService<JwtValidator>();
        var access = issuer.IssueAccessToken(before.user_id, "client", ["immich"], "r", "openid");
        var refresh = issuer.IssueRefreshToken();
        sp.GetRequiredService<RefreshTokenRepository>().Insert(new(refresh.Hash, "client", "r", "openid", before.user_id, DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds(), 0, 1, null));
        sp.GetRequiredService<AuthCodeRepository>().Insert(new("before-recovery", "client", "r", "openid", "https://app.example.test/callback", "challenge", "S256", before.user_id,
            DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(), 0, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), null));
        var links = sp.GetRequiredService<CredentialLinkService>(); var link = links.Issue("admin", before.user_id)!;
        var results = await Task.WhenAll(Task.Run(() => links.Redeem(link.Token, "new-password-one")), Task.Run(() => links.Redeem(link.Token, "new-password-two")));
        Assert.Single(results, r => r is not null);
        var after = users.GetById(before.user_id)!;
        Assert.NotEqual(before.session_epoch, after.session_epoch);
        Assert.Equal(before.session_version + 1, after.session_version);
        Assert.Null(validator.TryValidate(access, out _));
        Assert.Null(sp.GetRequiredService<RefreshTokenRepository>().GetByHash(refresh.Hash));
        Assert.Null(sp.GetRequiredService<AuthCodeRepository>().ConsumeAtomic("before-recovery"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await site.SendAsync(VerifySite())).StatusCode);
        var callback = new HttpRequestMessage(HttpMethod.Get, "/.nas-auth/callback?ticket=" + Uri.EscapeDataString(ticket) + "&state=" + Uri.EscapeDataString(state));
        callback.Headers.Add("Cookie", ForwardAuthService.StateCookie + "=" + nonce);
        Assert.Equal(HttpStatusCode.BadRequest, (await site.SendAsync(callback)).StatusCode);
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, before.user_id), new Claim(SessionValidator.EpochClaimType, before.session_epoch)], "cookie"));
        Assert.False(SessionValidator.IsCurrent(principal, after));
    }

    private sealed class ControlledTime : TimeProvider
    {
        public DateTimeOffset Value = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Value;
    }
}
