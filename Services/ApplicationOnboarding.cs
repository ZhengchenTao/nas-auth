using System.Text.Json;
using System.Text.RegularExpressions;
using NasAuth.Config;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

public sealed record ApplicationSetupInput(string Id = "", string Name = "", string Kind = "oidc", string Url = "", string Callbacks = "", string Scopes = "", string ClientType = "confidential");
public sealed record ApplicationSetupDraft(ApplicationSetupInput Input, IReadOnlyList<string> Errors,
    string Resources = "", string Clients = "", string Receiver = "", string SecretEnvironment = "");

public sealed class ApplicationOnboarding(ResourceCatalog catalog, ClientRepository clients, AuthOptions auth)
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Create(System.Text.Unicode.UnicodeRanges.All) };
    public ApplicationSetupDraft Generate(ApplicationSetupInput input)
    {
        var errors = new List<string>();
        if (!Regex.IsMatch(input.Id, "^[a-z][a-z0-9_-]{0,47}$")) errors.Add("Use an application ID starting with a lowercase letter, followed by letters, digits, _ or - (up to 48 characters).");
        if (string.IsNullOrWhiteSpace(input.Name) || input.Name.Length > 80 || input.Name.Any(char.IsControl)) errors.Add("Enter an application name of up to 80 characters.");
        if (input.Kind is not ("oidc" or "forward-auth" or "mcp") || input.ClientType is not ("confidential" or "public")) errors.Add("Select a supported application type.");
        if (input.Url.Length > 2048 || !Uri.TryCreate(input.Url, UriKind.Absolute, out var uri)
            || uri.Scheme != "https" && !(uri.Scheme == "http" && uri.IsLoopback)
            || uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0
            || input.Url.Any(char.IsWhiteSpace) || input.Url.Any(char.IsControl) || input.Url.Contains('\\'))
            errors.Add("Enter an HTTPS resource address without credentials, query or fragment. HTTP is allowed only for loopback development.");
        var scopes = (input.Scopes.Length == 0 ? input.Kind == "oidc" ? "openid profile email" : input.Kind == "forward-auth" ? "access" : "read" : input.Scopes)
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToArray();
        if (input.Scopes.Length > 2048 || scopes.Length is < 1 or > 32 || scopes.Any(s => !Regex.IsMatch(s, "^[\\x21\\x23-\\x5B\\x5D-\\x7E]{1,128}$"))
            || input.Kind == "oidc" && !scopes.Contains("openid") || input.Kind == "forward-auth" && !scopes.SequenceEqual(["access"]))
            errors.Add("Use valid space-separated scopes. OIDC requires openid; forward-auth uses access.");
        var callbacks = input.Callbacks.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.Ordinal).ToArray();
        if (input.Kind == "oidc" && (input.Callbacks.Length > 4096 || callbacks.Length is < 1 or > 10 || callbacks.Any(u => !ConfigurationPreflight.SafeCallback(u))))
            errors.Add("Enter one exact callback URL per line (up to 10), without credentials or fragments.");
        if (errors.Count > 0) return new(input, errors);
        if (!ResourceCatalog.IsSafeSitePath(ResourceCatalog.RawPath(input.Url)))
            return new(input, ["Use a resource path without dot segments or encoded separators."]);
        var aud = input.Id + (input.Kind == "oidc" ? "-oidc" : input.Kind == "mcp" ? "-mcp" : "-gateway");
        var clientId = input.Id + "-client";
        if (catalog.All.Any(r => r.Aud == aud || r.ResourceUrl.TrimEnd('/').Equals(input.Url.TrimEnd('/'), StringComparison.OrdinalIgnoreCase)) || catalog.FindByUrl(input.Url) is not null)
            errors.Add("The resource ID or address is already configured. Review the existing application instead.");
        if (input.Kind == "oidc" && (clients.GetById(clientId) is not null || catalog.All.Any(r => r.Aud.Equals(clientId, StringComparison.OrdinalIgnoreCase))))
            errors.Add("The generated client ID is already in use. Choose another application ID.");
        var existing = catalog.All.Select(r => r.App).FirstOrDefault(a => a?.Id == input.Id);
        if (existing is not null && existing.Name != input.Name) errors.Add("An existing application uses this ID with a different name.");
        if (errors.Count > 0) return new(input, errors);
        var resource = new Dictionary<string, object> {
            ["aud"] = aud, ["resource_url"] = input.Url, ["display_name"] = input.Name, ["scopes"] = scopes,
            ["app"] = new { id = input.Id, name = input.Name, description = existing?.Description ?? "", capability = input.Kind == "oidc" ? "web" : input.Kind == "mcp" ? "mcp" : "gateway" } };
        if (input.Kind == "forward-auth") resource["forward_auth"] = new { session_hours = 12 };
        var preset = new List<object>();
        var secretEnv = "";
        object receiver;
        if (input.Kind == "oidc")
        {
            var client = new Dictionary<string, object> { ["client_id"] = clientId, ["client_name"] = input.Name,
                ["redirect_uris"] = callbacks, ["default_resource"] = input.Url,
                ["token_endpoint_auth_method"] = input.ClientType == "public" ? "none" : "client_secret_basic" };
            if (input.ClientType == "confidential") client["client_secret_env"] = secretEnv = input.Id.Replace('-', '_').ToUpperInvariant() + "_OIDC_CLIENT_SECRET";
            preset.Add(client);
            receiver = new { issuer = auth.Issuer, discovery = auth.Issuer.TrimEnd('/') + "/.well-known/openid-configuration", client_id = clientId, redirect_uris = callbacks, scope = string.Join(' ', scopes), use_pkce = true };
        }
        else if (input.Kind == "mcp")
            receiver = new { resource = input.Url, authorization_servers = new[] { auth.Issuer }, scopes_supported = scopes, bearer_methods_supported = new[] { "header" } };
        else
            receiver = new { verify_url = auth.Issuer.TrimEnd('/') + "/forward-auth/verify?aud=" + Uri.EscapeDataString(aud), application_url = input.Url };
        return new(input, [], JsonSerializer.Serialize(new[] { resource }, Json), JsonSerializer.Serialize(preset, Json), JsonSerializer.Serialize(receiver, Json), secretEnv);
    }
}
