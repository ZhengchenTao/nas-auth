using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

public sealed class UserLifecycleTests : IClassFixture<NasAuthAppFactory>
{
    private readonly NasAuthAppFactory _app;
    public UserLifecycleTests(NasAuthAppFactory app) => _app=app;
    private static FormUrlEncodedContent Form(params (string,string)[] values) => new(values.Select(x=>new KeyValuePair<string,string>(x.Item1,x.Item2)));
    private async Task<HttpClient> Admin()
    {
        var c=_app.Client();
        Assert.Equal(HttpStatusCode.Redirect,(await c.PostAsync("/login",Form(("username","admin"),("password","devpassword"),("return_url","/admin/users")))).StatusCode);
        return c;
    }
    private static async Task<HttpResponseMessage> Write(HttpClient c,string path,params (string,string)[] values)
    {
        var request=new HttpRequestMessage(HttpMethod.Post,path){Content=Form(values)};
        return await HttpPipelineTests.SendCsrf(c,request);
    }

    [Fact]
    public async Task DisableAndRestore_StopsAllSignIn_PreservesIdentityAndProfile_RevokesOldCredentials()
    {
        const string id="lifecycle-disabled";
        using var scope=_app.Services.CreateScope();var sp=scope.ServiceProvider;
        var users=sp.GetRequiredService<UserRepository>();var identities=sp.GetRequiredService<ExternalIdentityRepository>();
        var grants=sp.GetRequiredService<UserResourceRepository>();var issuer=sp.GetRequiredService<JwtIssuer>();
        var validator=sp.GetRequiredService<JwtValidator>();
        users.Create(id,id,PasswordHasher.Hash("old-password"),false,"lifecycle@example.test",true,"Original person");
        identities.BindActive("google",id,id,"lifecycle@example.test","Original person");
        grants.Upsert(id,"immich","openid email profile");
        using var person=_app.Client();
        await person.PostAsync("/login",Form(("username",id),("password","old-password"),("return_url","/account")));
        var oldToken=issuer.IssueAccessToken(id,"client",["immich"],"https://localhost/immich","openid");
        Assert.NotNull(validator.TryValidate(oldToken,out _));
        var refresh=issuer.IssueRefreshToken();sp.GetRequiredService<RefreshTokenRepository>().Insert(new RefreshTokenRow(refresh.Hash,"client","r","openid",id,DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds(),0,1,null));
        using var admin=await Admin();
        Assert.Equal(HttpStatusCode.Forbidden,(await admin.PostAsync("/admin/users/disable",Form(("user_id",id)))).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect,(await Write(admin,"/admin/users/disable",("user_id",id))).StatusCode);
        Assert.Null(users.GetById(id));Assert.Null(users.GetByUsername(id));
        Assert.Equal(1,users.GetStoredById(id)!.is_disabled);
        Assert.Null(validator.TryValidate(oldToken,out _));
        Assert.Null(sp.GetRequiredService<RefreshTokenRepository>().GetByHash(refresh.Hash));
        Assert.Equal(PasswordSignInStatus.BadCredentials,sp.GetRequiredService<PasswordSignIn>().Attempt(id,"old-password").Status);
        Assert.Equal(ExternalSignInStatus.OrphanedActive,sp.GetRequiredService<ExternalSignInService>().Resolve("google",id,null,null).Status);
        Assert.Contains(id,await admin.GetStringAsync("/admin/users?view=disabled"));
        await Write(admin,"/admin/users/restore",("user_id",id),("deleted","0"),("allow_password_login","1"),("new_password","new-password"));
        Assert.Null(users.GetById(id)); // Explicit same-person acknowledgement is required.
        Assert.Equal(HttpStatusCode.Redirect,(await Write(admin,"/admin/users/restore",("user_id",id),("deleted","0"),("acknowledge","1"),("allow_password_login","1"),("new_password","new-password"))).StatusCode);
        var restored=users.GetById(id)!;
        Assert.Equal("Original person",restored.display_name);Assert.Equal("lifecycle@example.test",restored.email);
        Assert.Equal(0,restored.is_admin);Assert.Empty(grants.ListByUser(id));
        Assert.Equal(id,identities.Get("google",id)!.user_id);
        Assert.Null(validator.TryValidate(oldToken,out _));
        var oldPage=await person.GetAsync("/account");Assert.Equal(HttpStatusCode.Redirect,oldPage.StatusCode);
        Assert.Equal(PasswordSignInStatus.BadCredentials,sp.GetRequiredService<PasswordSignIn>().Attempt(id,"old-password").Status);
        Assert.Equal(PasswordSignInStatus.Ok,sp.GetRequiredService<PasswordSignIn>().Attempt(id,"new-password").Status);
        Assert.NotNull(validator.TryValidate(issuer.IssueAccessToken(id,"client",["immich"],"r","openid"),out _));
        sp.GetRequiredService<AuthDb>().EnsureCreated();Assert.Equal(restored.session_epoch,users.GetById(id)!.session_epoch);
        Assert.False(users.RestoreIdentity("admin",id,false,PasswordHasher.UnusableHash(),false,null));
    }

    [Fact]
    public async Task HardDeletedIdentity_RequiresExplicitRestoration_NewEpochCannotReviveOldCookiesOrTokens()
    {
        const string id="lifecycle-deleted";
        using var scope=_app.Services.CreateScope();var sp=scope.ServiceProvider;
        var users=sp.GetRequiredService<UserRepository>();var issuer=sp.GetRequiredService<JwtIssuer>();var validator=sp.GetRequiredService<JwtValidator>();
        users.Create(id,id,PasswordHasher.Hash("old-password"),false,allowPasswordLogin:true);
        var oldToken=issuer.IssueAccessToken(id,"client",["immich"],"r","openid");
        using var person=_app.Client();await person.PostAsync("/login",Form(("username",id),("password","old-password"),("return_url","/account")));
        using var admin=await Admin();await Write(admin,"/admin/users/delete",("user_id",id));
        Assert.Contains(id,users.ListDeletedIds());Assert.True(users.IsRetiredId(id));
        Assert.Contains(id,await admin.GetStringAsync("/admin/users?view=deleted"));
        Assert.Contains("acknowledge",await admin.GetStringAsync("/admin/users/restore?user="+id));
        await Write(admin,"/admin/users/restore",("user_id",id),("deleted","1"),("acknowledge","1"));
        var row=users.GetById(id)!;
        Assert.Equal(id,row.user_id);Assert.Equal(id,row.username);Assert.Equal(0,row.is_admin);Assert.Equal(0,row.allow_password_login);
        Assert.False(PasswordHasher.Verify("old-password",row.password_hash));
        Assert.False(SessionValidator.IsCurrent(new ClaimsPrincipal(new ClaimsIdentity(new[]{new Claim(ClaimTypes.Name,id)},"old")),row));
        Assert.Null(validator.TryValidate(oldToken,out _));
        Assert.Equal(HttpStatusCode.Redirect,(await person.GetAsync("/account")).StatusCode);
        Assert.DoesNotContain(id,users.ListDeletedIds());Assert.True(users.IsRetiredId(id));
        Assert.False(users.RestoreIdentity("admin",id,true,PasswordHasher.UnusableHash(),false,null));
        Assert.False(users.RestoreIdentity("admin","never-deleted",true,PasswordHasher.UnusableHash(),false,null));
    }

    [Fact]
    public async Task ReusedUsernameStartsWithNewSubjectAndNoApplicationAccess()
    {
        const string name = "lifecycle-reused";
        using var scope = _app.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserRepository>();
        var grants = scope.ServiceProvider.GetRequiredService<UserResourceRepository>();
        users.Create(name, name, PasswordHasher.Hash("old-password"), false, allowPasswordLogin: true);
        grants.Upsert(name, "immich", "openid");
        using var admin = await Admin();
        await Write(admin, "/admin/users/delete", ("user_id", name));
        var form = new[] { ("username", name), ("temp_password", "new-password"),
            ("allow_password_login", "1"), ("scope:immich", "openid") };
        var rejected = await Write(admin, "/admin/users/create", form);
        Assert.Contains("/admin/users/restore", rejected.Headers.Location!.OriginalString);
        Assert.Null(users.GetByUsername(name));

        var created = await Write(admin, "/admin/users/create", [.. form, ("reuse_username", "1")]);
        var replacement = users.GetByUsername(name)!;
        Assert.NotEqual(name, replacement.user_id);
        Assert.Contains(replacement.user_id, created.Headers.Location!.OriginalString);
        Assert.True(users.IsRetiredId(name));
        Assert.Empty(grants.ListByUser(replacement.user_id));
        Assert.False(users.RestoreIdentity("admin", name, true, PasswordHasher.UnusableHash(), false, null));
        Assert.Equal(PasswordSignInStatus.Ok, scope.ServiceProvider.GetRequiredService<PasswordSignIn>().Attempt(name, "new-password").Status);

        await Write(admin, "/admin/users/delete", ("user_id", replacement.user_id));
        Assert.True(users.RestoreIdentity("admin", replacement.user_id, true, PasswordHasher.UnusableHash(), false, null));
        Assert.Equal(name, users.GetById(replacement.user_id)!.username);
    }

    [Fact]
    public async Task LifecycleGuards_ProtectCurrentAndRecoveryAdministrators_RejectOrdinaryUsers()
    {
        using var scope=_app.Services.CreateScope();var sp=scope.ServiceProvider;var users=sp.GetRequiredService<UserRepository>();
        users.Create("life-ordinary","life-ordinary",PasswordHasher.Hash("ordinary-password"),false,allowPasswordLogin:true);
        users.Upsert("life-admin","life-admin",PasswordHasher.UnusableHash(),true);
        Assert.False(users.Disable("admin","admin","admin"));
        Assert.False(users.Disable("life-admin","admin","admin"));
        Assert.False(users.Disable("life-ordinary","life-admin","admin"));
        using var ordinary=_app.Client();await ordinary.PostAsync("/login",Form(("username","life-ordinary"),("password","ordinary-password"),("return_url","/account")));
        Assert.Equal(HttpStatusCode.NotFound,(await ordinary.GetAsync("/admin/users?view=deleted")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,(await ordinary.PostAsync("/admin/users/restore",Form(("user_id","life-admin"),("acknowledge","1")))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,(await ordinary.PostAsync("/admin/users/disable",Form(("user_id","life-admin")))).StatusCode);
        Assert.False(users.RestoreIdentity("life-ordinary","no-such-user",true,PasswordHasher.UnusableHash(),false,null));
    }
}
