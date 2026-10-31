using Microsoft.Extensions.Logging.Abstractions;
using NasAuth.Config;
using NasAuth.Pages;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

public class ApplicationOverviewTests
{
    private static ResourceAdminView Resource(string aud, ResourceAppConfig? app, int users = 1) =>
        new(aud, aud, "https://example.com/" + aud, new[] { "read:test" }, false, users, 2,
            App: app, GrantedUserIds: new[] { "alice" });

    [Fact]
    public void Overview_GroupsOnlyExplicitMembership_AndKeepsPerCapabilityCounts()
    {
        I18n.Lang = "en";
        var rows = new[]
        {
            Resource("books-web", new() { Id = "books", Name = "Books", Capability = "web" }, 3),
            Resource("books-mcp", new() { Id = "books", Name = "Books", Capability = "mcp" }),
            Resource("books-other", null)
        };
        var html = DashboardTemplates.AppsSection(rows, Array.Empty<ClientAdminView>());
        Assert.Equal(2, html.Split("class='application-row'").Length - 1);
        Assert.Contains("Web sign-in", html);
        Assert.Contains("MCP access", html);
        Assert.Contains("3 users", html);
        Assert.Contains("1 users", html);
        Assert.DoesNotContain("4 users", html);
        Assert.Contains("/admin/users/edit?user=alice", html);
        Assert.DoesNotContain("<table", html);
        Assert.Contains("aria-current='page'>Connected apps", html);
    }

    [Fact]
    public void SeparateViews_PreserveResourceTableAndClientControls()
    {
        var rows = new[] { Resource("books", null) };
        var clients = new[] { new ClientAdminView("c1", "Tool", true, "none", Array.Empty<string>(), "-", "-") };
        var technical = DashboardTemplates.AppsSection(rows, clients, "resources");
        Assert.Contains("<table", technical);
        Assert.DoesNotContain("/apps/delete-client", technical);
        var registered = DashboardTemplates.AppsSection(rows, clients, "clients");
        Assert.Contains("/apps/delete-client", registered);
        Assert.DoesNotContain("class='application-row'", registered);
    }

    [Theory]
    [InlineData("{\"id\":\"\",\"name\":\"Books\",\"capability\":\"web\"}")]
    [InlineData("{\"id\":\"books\",\"name\":\"Books\",\"capability\":\"typo\"}")]
    [InlineData("{\"id\":\"books\",\"name\":\"Books\",\"capability\":\"gateway\"}")]
    public void Catalog_RejectsInvalidApplicationMetadata(string metadata)
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "[{\"aud\":\"books\",\"resource_url\":\"https://example.com\",\"scopes\":[\"read:test\"],\"app\":" + metadata + "}]");
            Assert.Throws<InvalidOperationException>(() => new ResourceCatalog(new AuthOptions { ResourcesPath = path }, NullLogger<ResourceCatalog>.Instance));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Catalog_RejectsConflictingNamesWithinOneApplication()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, """
                [{"aud":"a","resource_url":"https://example.com/a","scopes":["read"],"app":{"id":"same","name":"One"}},
                 {"aud":"b","resource_url":"https://example.com/b","scopes":["read"],"app":{"id":"same","name":"Two"}}]
                """);
            Assert.Throws<InvalidOperationException>(() => new ResourceCatalog(new AuthOptions { ResourcesPath = path }, NullLogger<ResourceCatalog>.Instance));
        }
        finally { File.Delete(path); }
    }
}
