using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using NasAuth.Config;

namespace NasAuth.Services;

public sealed record ConfigurationCheck(string Area, bool Ok, string Message);

/// <summary>Configuration-only validation: no host, database, keys or external connections.</summary>
public static class ConfigurationPreflight
{
    public static IReadOnlyList<ConfigurationCheck> Inspect(IConfiguration configuration)
    {
        var checks = new List<ConfigurationCheck>();
        void Check(string area, Action action)
        {
            try { action(); checks.Add(new(area, true, "Valid")); }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                // Exception messages and configuration values can contain credentials.
                var json = error as JsonException ?? error.InnerException as JsonException;
                checks.Add(new(area, false, json is null ? "Invalid configuration; check the documented fields and required environment variables."
                    : $"Invalid JSON near line {(json.LineNumber ?? 0) + 1}, byte {json.BytePositionInLine ?? 0}."));
            }
        }
        var auth = new AuthOptions();
        ResourceCatalog? catalog = null;
        Check("Auth", () => {
            configuration.GetSection("Auth").Bind(auth); auth.NormalizeAndValidate();
            if (!Uri.TryCreate(auth.Issuer, UriKind.Absolute, out var uri) || uri.Scheme != "https" && !(uri.Scheme == "http" && uri.IsLoopback)
                || uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0
                || uri.AbsolutePath.TrimEnd('/') != auth.PathBase || string.IsNullOrWhiteSpace(auth.Database))
                throw new InvalidOperationException();
            _ = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(auth.Database);
        });
        Check("Jwt", () => (configuration.GetSection("Jwt").Get<JwtOptions>() ?? new()).Validate());
        Check("Branding", () => (configuration.GetSection("Branding").Get<BrandingOptions>() ?? new()).Validate());
        Check("ExternalProviders", () => _ = ExternalProviderOptions.FromConfiguration(configuration));
        Check("ExternalProfiles", () => (configuration.GetSection("ExternalProfiles").Get<ExternalProfilesOptions>() ?? new()).Validate(auth.Issuer));
        Check("CredentialLinks", () => (configuration.GetSection("CredentialLinks").Get<CredentialLinkOptions>() ?? new()).Validate());
        Check("DeviceSessions", () => (configuration.GetSection("DeviceSessions").Get<DeviceSessionOptions>() ?? new()).Validate());
        Check("Resources", () => {
            catalog = new ResourceCatalog(auth, NullLogger<ResourceCatalog>.Instance);
            if (catalog.All.GroupBy(r => r.Aud, StringComparer.Ordinal).Any(g => g.Count() > 1)) throw new InvalidOperationException();
        });
        Check("Clients", () => {
            if (catalog is null) throw new InvalidOperationException();
            if (!string.IsNullOrEmpty(auth.ClientsPresetPath) && !File.Exists(auth.ClientsPresetPath)) throw new InvalidOperationException();
            var clients = PresetClientLoader.Read(auth);
            if (clients.GroupBy(c => c.ClientId, StringComparer.Ordinal).Any(g => g.Count() > 1)) throw new InvalidOperationException();
            foreach (var client in clients)
            {
                var secret = PresetClientLoader.Secret(client);
                if (string.IsNullOrWhiteSpace(client.ClientId) || string.IsNullOrWhiteSpace(client.ClientName)
                    || client.RedirectUris is not { Count: > 0 } || client.RedirectUris.Any(u => !SafeCallback(u))
                    || client.TokenEndpointAuthMethod is not ("none" or "client_secret_basic" or "client_secret_post")
                    || client.TokenEndpointAuthMethod != "none" && string.IsNullOrEmpty(secret)
                    || !string.IsNullOrEmpty(client.DefaultResource) && catalog.FindByUrl(client.DefaultResource) is null)
                    throw new InvalidOperationException();
                _ = ExtraClaims.Normalize(client.ClientId, client.ExtraClaims);
            }
        });
        Check("Provisioning", () => {
            if (catalog is null) throw new InvalidOperationException();
            (configuration.GetSection("Provisioning").Get<ProvisioningOptions>() ?? new()).Validate(catalog);
        });
        return checks;
    }

    public static bool SafeCallback(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 && !value.Any(char.IsControl) && !value.Any(char.IsWhiteSpace)
        && RedirectUriPolicy.ValidateList([value], new DcrOptions()) is null;
}
