using System.Net;
using System.Text.RegularExpressions;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

public sealed class UserDirectoryTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "directory-" + Guid.NewGuid().ToString("N"));
    private readonly AuthDb _db;
    private readonly UserRepository _users;

    public UserDirectoryTests()
    {
        Directory.CreateDirectory(_dir);
        _db = new(new AuthOptions { Database = "Data Source=" + Path.Combine(_dir,"auth.db") + ";Pooling=False" });
        _db.EnsureCreated();
        _users = new(_db);
    }

    [Theory]
    [InlineData("ALICE")]
    [InlineData("  PERSON-ID  ")]
    [InlineData("Display")]
    [InlineData("Example.Test")]
    [InlineData("测试")]
    public void SearchMatchesStableIdUsernameNameAndEmail(string query)
    {
        _users.Create("person-id","alice","unusable",false,"alice@example.test",displayName:"测试 Display");
        _users.Create("unrelated","unrelated","unusable",false);
        var page = _users.Search(UserDirectoryFilter.Normalize(query));
        Assert.Equal("person-id", Assert.Single(page.Users).user_id);
        Assert.Equal(1,page.Total);
    }

    [Theory]
    [InlineData("%")]
    [InlineData("_")]
    [InlineData("' OR 1=1 --")]
    [InlineData("<script>")]
    public void SearchTreatsUserInputAsLiteralData(string literal)
    {
        _users.Create("match","match","unusable",false,displayName:"literal " + literal);
        _users.Create("other","other","unusable",false);
        Assert.Equal("match",Assert.Single(_users.Search(UserDirectoryFilter.Normalize(literal)).Users).user_id);
    }

    [Fact]
    public void StateAndRoleFiltersDoNotMixDeletedDisabledAndRestoredIdentities()
    {
        _users.Upsert("admin","admin","unusable",true);
        _users.Create("active","active","unusable",false);
        _users.Create("disabled","disabled","unusable",false,"held@example.test",displayName:"Former Colleague");
        Assert.True(_users.Disable("admin","disabled","admin"));
        _users.Create("deleted","deleted","unusable",false);
        _users.Delete("deleted");
        Assert.Equal("admin",Assert.Single(_users.Search(UserDirectoryFilter.Normalize(role:"admin")).Users).user_id);
        Assert.Equal("active",Assert.Single(_users.Search(UserDirectoryFilter.Normalize(role:"member")).Users).user_id);
        var held = _users.Search(UserDirectoryFilter.Normalize("colleague","disabled", "admin"));
        Assert.Equal("disabled", Assert.Single(held.Users).user_id);
        Assert.Equal("all",held.Filter.Role);
        Assert.Equal(2,held.ActiveCount); Assert.Equal(1,held.DisabledCount); Assert.Equal(1,held.DeletedCount);
        Assert.Equal("deleted",Assert.Single(_users.Search(UserDirectoryFilter.Normalize("DELET","deleted")).DeletedIds));
        Assert.True(_users.RestoreIdentity("admin","deleted",true,"unusable",false,null));
        Assert.Empty(_users.Search(UserDirectoryFilter.Normalize(view:"deleted")).DeletedIds);
        Assert.Equal(0,_users.Search(UserDirectoryFilter.Normalize(view:"deleted")).DeletedCount);
    }

    [Theory]
    [InlineData(25,4,8)]
    [InlineData(50,2,33)]
    [InlineData(100,1,83)]
    public void TiedCreationTimesHaveStableBoundedPagesAndOutOfRangeClamps(int size,int pages,int lastCount)
    {
        for (var i=0;i<83;i++) _users.Create($"person-{i:D3}",$"person-{i:D3}","unusable",false);
        using (var c=_db.OpenConnection()) c.Execute("UPDATE users SET created_at=1");
        var seen = new List<string>();
        for (var p=1;p<=pages;p++)
        {
            var result=_users.Search(UserDirectoryFilter.Normalize("person",page:p,pageSize:size));
            Assert.Equal(83,result.Total); Assert.Equal(pages,result.PageCount);
            Assert.InRange(result.Users.Count,1,size);
            seen.AddRange(result.Users.Select(u=>u.user_id));
        }
        Assert.Equal(83,seen.Distinct().Count());
        Assert.Equal(seen.OrderBy(x=>x,StringComparer.Ordinal),seen);
        var last=_users.Search(UserDirectoryFilter.Normalize(page:int.MaxValue,pageSize:size));
        Assert.Equal(pages,last.Filter.Page); Assert.Equal(84-lastCount,last.First); Assert.Equal(83,last.Last);
        Assert.Equal(lastCount,last.Users.Count);
        var empty=_users.Search(UserDirectoryFilter.Normalize("missing",page:99));
        Assert.Equal(1,empty.Filter.Page); Assert.Equal(0,empty.First); Assert.Equal(0,empty.Last);
    }

    [Fact]
    public void UntrustedPagingAndFiltersAreNormalizedBeforeDatabaseQuery()
    {
        var result=_users.Search(new(new string('x',1000),"invalid","admin'",-99,int.MaxValue));
        Assert.Equal(128,result.Filter.Query.Length);
        Assert.Equal("active",result.Filter.View); Assert.Equal("all",result.Filter.Role);
        Assert.Equal(1,result.Filter.Page); Assert.Equal(25,result.Filter.PageSize);
    }

    public void Dispose() => Directory.Delete(_dir,true);
}

public sealed class UserDirectoryHttpTests(NasAuthAppFactory app) : IClassFixture<NasAuthAppFactory>
{
    [Fact]
    public async Task AdminListUsesServerPagingAndPreservesFiltersInNextLink()
    {
        using var scope=app.Services.CreateScope();
        var users=scope.ServiceProvider.GetRequiredService<UserRepository>();
        var prefix="find-"+Guid.NewGuid().ToString("N")[..8]+"-";
        try
        {
            for(var i=0;i<30;i++) users.Create(prefix+i.ToString("D2"),prefix+i.ToString("D2"),"unusable",false);
            using var browser=app.Client();
            var login=await browser.PostAsync("/login",new FormUrlEncodedContent(new Dictionary<string,string>{["username"]=NasAuthAppFactory.AdminUser,["password"]=NasAuthAppFactory.AdminPassword,["return_url"]="/admin/users"}));
            Assert.Equal(HttpStatusCode.Redirect,login.StatusCode);
            var html=await browser.GetStringAsync("/admin/users?q="+prefix+"&role=member&size=25");
            Assert.Equal(25,Regex.Matches(html,"<a href='/admin/users/edit\\?user="+prefix).Count);
            var next=WebUtility.HtmlDecode(Regex.Match(html,"rel='next' href='([^']+)'").Groups[1].Value);
            Assert.Contains("q="+prefix,next); Assert.Contains("role=member",next); Assert.Contains("page=2",next);
            var second=await browser.GetStringAsync(next);
            Assert.Equal(5,Regex.Matches(second,"<a href='/admin/users/edit\\?user="+prefix).Count);
            Assert.Contains("rel='prev'",second);
            var escaped=await browser.GetStringAsync("/admin/users?q="+Uri.EscapeDataString("\"><script>alert(1)</script>"));
            Assert.DoesNotContain("<script>alert(1)</script>",escaped);
            Assert.Contains("&lt;script&gt;",escaped);
            Assert.Contains("Clear filters",escaped);
        }
        finally { for(var i=0;i<30;i++) users.Delete(prefix+i.ToString("D2"),retireId:false); }
    }
}
