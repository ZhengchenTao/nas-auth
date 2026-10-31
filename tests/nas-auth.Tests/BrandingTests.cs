using NasAuth.Config;
using NasAuth.Pages;
using Xunit;

namespace NasAuth.Tests;

public class BrandingTests
{
    [Theory]
    [InlineData("https://example.com/icon.svg")]
    [InlineData("//example.com/icon.svg")]
    [InlineData("/../icon.svg")]
    [InlineData("/%2e%2e/icon.svg")]
    [InlineData("/icon.svg\r\nInjected: yes")]
    public void AssetsMustRemainLocal(string path) =>
        Assert.Throws<InvalidOperationException>(() => new BrandingOptions { FaviconPath = path }.Validate());

    [Fact]
    public void CustomizedBrandingIsEscapedAndUsesPublicMountPrefix()
    {
        var previous = Ui.Branding;
        var previousPath = Ui.PathBase;
        try
        {
            Ui.PathBase = "/auth";
            Ui.Branding = new BrandingOptions
            {
                SiteName = "Team <Auth>", LoginTitle = "Welcome <staff>", LoginSubtitle = "Your team apps",
                FaviconPath = "/branding/icon.svg", LogoPath = "/branding/logo.svg",
                NavigationLabels = new() { ["apps"] = "Team <apps>", ["apps-resources"] = "Configuration" }
            };
            Ui.Branding.Validate();
            var login = HtmlTemplates.Login("/account", null, null, googleEnabled: false, microsoftEnabled: false);
            Assert.Contains("Team &lt;Auth&gt;", login);
            Assert.Contains("Welcome &lt;staff&gt;", login);
            Assert.Contains("/auth/branding/icon.svg?v=", login);
            Assert.Contains("/auth/branding/logo.svg?v=", login);
            Assert.DoesNotContain("<staff>", login);
            var admin = DashboardTemplates.Shell(DashboardSpace.Admin, "apps", "admin", true, 0, "Apps", "");
            Assert.Contains("Team &lt;apps&gt;", admin);
            Assert.Contains("Team &lt;Auth&gt;", admin);
            Assert.Contains("Configuration", DashboardTemplates.AppsSection([], []));
        }
        finally { Ui.Branding = previous; Ui.PathBase = previousPath; }
    }
}
