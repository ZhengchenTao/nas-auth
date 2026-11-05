using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using NasAuth.Config;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

public sealed class DirectoryAccountTests : IClassFixture<TicketAuthFactory>
{
    private readonly TicketAuthFactory _app;
    public DirectoryAccountTests(TicketAuthFactory app)
    {
        _app = app;
        var definitions = app.Services.GetRequiredService<ExternalProfilesOptions>();
        definitions.Providers["badge-login"] = new ExternalProfileProvider
        {
            DisplayName = "Staff directory", BrowserLookupUrl = "https://directory.example.test/lookup.html",
            SubjectField = "user_id", UsernameField = "username", NameField = "name", AllowAdminCreate = true, AllowSelfRefresh = true,
            BrowserLookupNeedsLocalNetwork = true,
            Fields = new() {
                ["user_id"] = new() { Label = "Identity", BrowserImport = true },
                ["username"] = new() { Label = "Username", BrowserImport = true },
                ["name"] = new() { Label = "Name", BrowserImport = true },
                ["email"] = new() { Label = "Email", Type = "email", BrowserImport = true },
                ["department"] = new() { Label = "Department", BrowserImport = true },
                ["private_attribute"] = new() { Label = "Internal", BrowserImport = false, Visible = false }
            }
        };
    }
    private static Dictionary<string, string> Fields(string subject, string username) => new()
    { ["user_id"] = subject, ["username"] = username, ["name"] = "Example Staff", ["email"] = "staff@example.test", ["department"] = "Example department", ["private_attribute"] = "drop-me" };

    [Fact]
    public void PasswordOnlyDeploymentDoesNotOfferUnusableDirectoryOrExternalInvitations()
    {
        var html=NasAuth.Pages.DashboardTemplates.UsersSection(Array.Empty<NasAuth.Pages.UserAdminView>(),new ExternalProfilesOptions(),false);
        Assert.DoesNotContain("data-directory=",html);
        Assert.DoesNotContain("invite_by_email",html);
        Assert.Contains("name='temp_password'",html);
        Assert.Contains("<details class='card account-create' open>",html);
    }

    [Fact]
    public void ConfiguredCreationBindsExactIdentityWithoutPasswordAdministratorOrGrants()
    {
        using var scope = _app.Services.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<DirectoryAccountService>();
        var fields = service.Validate("badge-login", "new-staff", JsonSerializer.Serialize(Fields("new-staff", "directory_staff")));
        Assert.DoesNotContain("private_attribute", fields.Keys);
        var id = service.Create("badge-login", "new-staff", fields, "admin");
        var user = scope.ServiceProvider.GetRequiredService<UserRepository>().GetById(id)!;
        Assert.Equal(0, user.is_admin); Assert.Equal(0, user.allow_password_login);
        Assert.False(PasswordHasher.Verify("anything", user.password_hash));
        var identity = scope.ServiceProvider.GetRequiredService<ExternalIdentityRepository>().Get("badge-login", "new-staff")!;
        Assert.Equal("active", identity.status); Assert.Equal(id, identity.user_id);
        Assert.Empty(scope.ServiceProvider.GetRequiredService<UserResourceRepository>().ListByUser(id));
        Assert.Throws<InvalidDataException>(() => service.Create("badge-login", "other-id", fields, "admin"));
        Assert.Null(scope.ServiceProvider.GetRequiredService<ExternalIdentityRepository>().Get("badge-login", "other-id"));
    }

    [Fact]
    public void MismatchedIdAndInvalidEmailCannotCreateAnAccount()
    {
        using var scope = _app.Services.CreateScope(); var service = scope.ServiceProvider.GetRequiredService<DirectoryAccountService>();
        Assert.Throws<InvalidDataException>(() => service.Validate("badge-login", "wrong", JsonSerializer.Serialize(Fields("real", "name"))));
        var fields = Fields("real", "name"); fields["email"] = "not-an-email";
        Assert.Throws<InvalidDataException>(() => service.Validate("badge-login", "real", JsonSerializer.Serialize(fields)));
    }

    [Fact]
    public void OptionalProfileErrorsDoNotBreakIdentityAndObsoleteFieldsArePrunedOnRefresh()
    {
        using var scope=_app.Services.CreateScope();
        var repo=scope.ServiceProvider.GetRequiredService<ExternalIdentityRepository>();
        repo.UpdateProfileSnapshot("badge-login","stable-person-123",new Dictionary<string,string>{["department"]=new string('x',257)});
        Assert.Equal("alice",repo.Get("badge-login","stable-person-123")!.user_id);
        repo.UpdateProfileSnapshot("badge-login","stable-person-123",new Dictionary<string,string>{["department"]="Current"});
        var definition=scope.ServiceProvider.GetRequiredService<ExternalProfilesOptions>().Find("badge-login")!;
        definition.Fields["obsolete"]=new() {Label="Old"};
        repo.UpdateProfileSnapshot("badge-login","stable-person-123",new Dictionary<string,string>{["obsolete"]="Old"});
        definition.Fields.Remove("obsolete");
        repo.UpdateProfileSnapshot("badge-login","stable-person-123",new Dictionary<string,string>{["department"]="Refreshed"});
        Assert.DoesNotContain("obsolete",ExternalProfileData.Read(repo.Get("badge-login","stable-person-123")!.profile_json)!.Keys);
    }

    [Fact]
    public void EmailInvitationConflictRollsBackAccountCreation()
    {
        using var scope = _app.Services.CreateScope(); var users = scope.ServiceProvider.GetRequiredService<UserRepository>();
        var invites = scope.ServiceProvider.GetRequiredService<ExternalInviteRepository>();
        Assert.True(invites.Add("reserved@example.test", "alice", "admin"));
        Assert.Throws<Microsoft.Data.Sqlite.SqliteException>(() => users.Create("rolled_back", "rolled_back", PasswordHasher.UnusableHash(), false,
            inviteEmail: "reserved@example.test", createdBy: "admin"));
        Assert.Null(users.GetById("rolled_back"));
    }

    [Fact]
    public void PrimaryEmailChangeMovesOnlyItsPendingBindingAndKeepsLegacyAliases()
    {
        using var scope = _app.Services.CreateScope(); var users=scope.ServiceProvider.GetRequiredService<UserRepository>();
        var invites=scope.ServiceProvider.GetRequiredService<ExternalInviteRepository>();
        users.Create("email_move", "email_move", PasswordHasher.UnusableHash(), false, "old@example.test", inviteEmail:"old@example.test");
        Assert.True(invites.Add("legacy@example.test","email_move","admin"));
        users.UpdateProfile("email_move", "new@example.test", false);
        Assert.Equal(new[]{"legacy@example.test","new@example.test"}, invites.ListByUser("email_move").Select(x=>x.email).Order().ToArray());
        Assert.True(invites.Add("conflict@example.test","alice","admin"));
        Assert.Throws<Microsoft.Data.Sqlite.SqliteException>(()=>users.UpdateProfile("email_move","conflict@example.test",false));
        Assert.Equal("new@example.test",users.GetById("email_move")!.email);
        Assert.Contains(invites.ListByUser("email_move"),x=>x.email=="new@example.test");
    }

    [Theory]
    [InlineData("http://lookup.example.test/page")]
    [InlineData("https://auth.example.test/page")]
    [InlineData("https://user:pass@lookup.example.test/page")]
    [InlineData("https://lookup.example.test/page?url=untrusted")]
    public void LookupOriginMustBeExplicitIsolatedHttps(string url)
    {
        var config = new ExternalProfilesOptions { Providers = new() { ["staff"] = new() { BrowserLookupUrl = url, Fields = new() { ["user_id"] = new() } } } };
        Assert.Throws<InvalidOperationException>(() => config.Validate("https://auth.example.test/auth"));
        Assert.Empty(new ExternalProfilesOptions().Providers);
    }

    [Fact]
    public async Task BrowserImportsEnforceOwnerAdminCsrfAndKeepMainEmailUnchanged()
    {
        using var browser = _app.Browser();
        var start = await browser.GetAsync("/auth/external/badge-login/start?return_url=%2Faccount");
        var callback = QueryHelpers.ParseQuery(start.Headers.Location!.Query)["callback_url"].ToString();
        var result = await browser.GetAsync(QueryHelpers.AddQueryString(callback, "ticket", "directory-owner-login"));
        await browser.GetAsync(result.Headers.Location);
        var fields = Fields("stable-person-123", "alice");
        Dictionary<string,string> form = new() { ["provider"]="badge-login", ["subject"]="stable-person-123", ["profile_json"]=JsonSerializer.Serialize(fields) };
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.PostAsync("/auth/account/directory/import",new FormUrlEncodedContent(form))).StatusCode);
        var token = await HttpPipelineTests.CsrfToken(browser, "/auth/account");
        var headers = (await browser.GetAsync("/auth/account")).Headers;
        var policy = headers.GetValues("Permissions-Policy").Single();
        Assert.Contains("https://directory.example.test", policy);
        Assert.DoesNotContain("*", policy);
        form[AntiforgeryGuard.FormFieldName] = token;
        form["use_email"] = "1"; // A forged self-import must never change the primary downstream email.
        Assert.Equal(HttpStatusCode.Redirect, (await browser.PostAsync("/auth/account/directory/import",new FormUrlEncodedContent(form))).StatusCode);
        using var scope = _app.Services.CreateScope();
        var row=scope.ServiceProvider.GetRequiredService<ExternalIdentityRepository>().Get("badge-login","stable-person-123")!;
        Assert.Equal("Example department",ExternalProfileData.Read(row.profile_json)!["department"]);
        Assert.Equal("alice@example.test", scope.ServiceProvider.GetRequiredService<UserRepository>().GetById("alice")!.email);
        Assert.Equal("alice@example.test", row.email);
        var users=scope.ServiceProvider.GetRequiredService<UserRepository>();
        users.UpdateProfile("alice", null, false);
        var (downstreamEmail,_,_)=scope.ServiceProvider.GetRequiredService<ProfileService>().Resolve(
            scope.ServiceProvider.GetRequiredService<ExternalIdentityRepository>(),users,"alice");
        Assert.Equal("alice@example.test",downstreamEmail);
        Assert.Equal(HttpStatusCode.NotFound, (await browser.PostAsync("/auth/admin/directory/create",new FormUrlEncodedContent(form))).StatusCode);
        form["subject"]="someone-else";
        Assert.Equal(HttpStatusCode.NotFound, (await browser.PostAsync("/auth/account/directory/import",new FormUrlEncodedContent(form))).StatusCode);
    }
}
