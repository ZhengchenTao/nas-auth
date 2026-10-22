using Microsoft.AspNetCore.Http;
using NasAuth.Config;
using NasAuth.Pages;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

public class PathBaseTests
{
    [Fact]
    public void AuthOptions_RequiresIssuerToMatchPublicPathBase()
    {
        var options = new AuthOptions { Issuer = "https://auth.example.test/auth/", PathBase = "/auth/" };
        options.NormalizeAndValidate();
        Assert.Equal("/auth", options.PathBase);

        Assert.Throws<InvalidOperationException>(() =>
            new AuthOptions { Issuer = "https://auth.example.test", PathBase = "/auth" }.NormalizeAndValidate());
    }

    [Fact]
    public void ServerRenderedPagesPrefixAssetsFormsAndNavigationLinks()
    {
        var previous = Ui.PathBase;
        try
        {
            Ui.PathBase = "/auth";
            var login = HtmlTemplates.Login("/auth/account", null, null,
                providerChoices: new[] { new ExternalProviderChoice("employee", "Employee account", "external:employee") });
            var dashboard = DashboardTemplates.Shell(DashboardSpace.Admin, "overview", "admin", true, 0,
                "Overview", "", avatarFile: "avatar.png");

            Assert.Contains("href=\"/auth/app.css?", login);
            Assert.Contains("src=\"/auth/theme.js?", login);
            Assert.Contains("action='/auth/login'", login);
            Assert.Contains("href='/auth/external/employee/start?", login);
            Assert.Contains("href='/auth/admin'", dashboard);
            Assert.Contains("src=\"/auth/avatars/avatar.png", dashboard);
        }
        finally
        {
            Ui.PathBase = previous;
        }
    }

    [Fact]
    public async Task LocalRedirectsGetPrefix_ProtectedSiteCallbackRedirectsKeepSitePath()
    {
        var previous = Ui.PathBase;
        try
        {
            var auth = new DefaultHttpContext();
            auth.Request.PathBase = "/auth";
            auth.Request.Path = "/login";
            auth.Response.Body = new MemoryStream();
            await PathBaseUrlMiddleware.InvokeAsync(auth, ctx =>
            {
                Assert.Equal("/auth", Ui.PathBase);
                ctx.Response.Headers.Location = "/account";
                return Task.CompletedTask;
            });
            Assert.Equal("/auth/account", auth.Response.Headers.Location.ToString());

            var callback = new DefaultHttpContext();
            callback.Request.PathBase = "/auth";
            callback.Request.Path = "/.nas-auth/callback";
            callback.Response.Body = new MemoryStream();
            await PathBaseUrlMiddleware.InvokeAsync(callback, ctx =>
            {
                ctx.Response.Headers.Location = "/tools/page";
                return Task.CompletedTask;
            });
            Assert.Equal("/tools/page", callback.Response.Headers.Location.ToString());
        }
        finally
        {
            Ui.PathBase = previous;
        }
    }
}
