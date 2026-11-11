using Microsoft.Extensions.Configuration;
using NasAuth.Config;
using Xunit;

namespace NasAuth.Tests;

// This test temporarily replaces process-wide legacy credentials. It must not run
// beside HTTP factories that read those same variables during host construction.
[CollectionDefinition("External provider environment", DisableParallelization = true)]
public sealed class ExternalProviderEnvironmentCollection { }

[Collection("External provider environment")]
public class ExternalProviderEnvironmentTests
{
    [Fact]
    public void ExplicitEmptyProviderList_DisablesLegacyEnvironmentProviders()
    {
        var oldGoogleId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID");
        var oldGoogleSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET");
        var oldMicrosoftId = Environment.GetEnvironmentVariable("MS_CLIENT_ID");
        var oldMicrosoftSecret = Environment.GetEnvironmentVariable("MS_CLIENT_SECRET");
        try
        {
            Environment.SetEnvironmentVariable("GOOGLE_CLIENT_ID", "legacy-id");
            Environment.SetEnvironmentVariable("GOOGLE_CLIENT_SECRET", "legacy-secret");
            Environment.SetEnvironmentVariable("MS_CLIENT_ID", "legacy-id");
            Environment.SetEnvironmentVariable("MS_CLIENT_SECRET", "legacy-secret");
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(
                new Dictionary<string, string?> { ["ExternalProviders:UseConfiguredProviders"] = "true" }).Build();

            var options = ExternalProviderOptions.FromConfiguration(configuration);

            Assert.True(options.UsesConfiguredProviders);
            Assert.Empty(options.EnabledProviders);
            Assert.False(options.GoogleEnabled);
            Assert.False(options.MicrosoftEnabled);
            Assert.False(options.IsEnabled("google"));
            Assert.Null(options.SchemeFor("microsoft"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("GOOGLE_CLIENT_ID", oldGoogleId);
            Environment.SetEnvironmentVariable("GOOGLE_CLIENT_SECRET", oldGoogleSecret);
            Environment.SetEnvironmentVariable("MS_CLIENT_ID", oldMicrosoftId);
            Environment.SetEnvironmentVariable("MS_CLIENT_SECRET", oldMicrosoftSecret);
        }
    }

}
