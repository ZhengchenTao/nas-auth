using NasAuth.Services;

namespace NasAuth.Config;

/// <summary>Optional outbound account provisioning. Application permissions remain downstream.</summary>
public sealed class ProvisioningOptions
{
    public Dictionary<string, ProvisioningApplication> Applications { get; set; } = new(StringComparer.Ordinal);

    public void Validate(ResourceCatalog catalog)
    {
        foreach (var (id, app) in Applications)
        {
            if (!System.Text.RegularExpressions.Regex.IsMatch(id, "^[a-zA-Z0-9_-]{1,64}$") ||
                string.IsNullOrWhiteSpace(app.Name) || app.RequiredResources.Count == 0 ||
                !Uri.TryCreate(app.Endpoint, UriKind.Absolute, out var uri) ||
                (uri.Scheme != "https" && !(uri.Scheme == "http" && uri.IsLoopback)) ||
                !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) ||
                string.IsNullOrWhiteSpace(app.BearerEnvironment) ||
                string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(app.BearerEnvironment)))
                throw new InvalidOperationException($"Invalid provisioning application: {id}");
            foreach (var (aud, scopes) in app.RequiredResources)
            {
                var resource = catalog.All.SingleOrDefault(x => x.Aud == aud);
                if (resource is null || scopes.Count == 0 || scopes.Any(x => !resource.Scopes.Contains(x)))
                    throw new InvalidOperationException($"Invalid provisioning resource: {id}/{aud}");
            }
        }
    }
}

public sealed class ProvisioningApplication
{
    public string Name { get; set; } = "";
    public string Endpoint { get; set; } = "";
    public string BearerEnvironment { get; set; } = "";
    public Dictionary<string, List<string>> RequiredResources { get; set; } = new(StringComparer.Ordinal);
}
