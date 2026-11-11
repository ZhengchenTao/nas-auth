using NasAuth.Config;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

public sealed record DiagnosticCheck(string Level, string Message, string Detail = "");
public sealed record ApplicationDiagnosis(IReadOnlyList<DiagnosticCheck> Configuration,
    IReadOnlyList<DiagnosticCheck> Access);

/// <summary>Read-only explanations of local state. Never probes adapters or changes grants.</summary>
public sealed class ApplicationDiagnostics(ResourceCatalog catalog, ClientRepository clients,
    UserRepository users, UserResourceRepository grants, AccessGroupService groups,
    ExternalIdentityRepository identities, ExternalProviderOptions providers, PasswordLoginGate passwords,
    ProvisioningOptions provisioningOptions, ProvisioningService provisioning)
{
    public ApplicationDiagnosis Inspect(string? aud, string? userId)
    {
        var configuration = new List<DiagnosticCheck>();
        var access = new List<DiagnosticCheck>();
        var registered = clients.ListAll().Where(c => c.auto_registered == 0).ToArray();
        foreach (var client in registered)
        {
            if (!string.IsNullOrEmpty(client.default_resource) && catalog.FindByUrl(client.default_resource) is null)
                configuration.Add(new("error", "Client default resource is unavailable. Update the preset configuration.", client.client_id));
            if (client.token_endpoint_auth_method != "none" && string.IsNullOrEmpty(client.client_secret_hash))
                configuration.Add(new("error", "Confidential client has no secret. Configure its credential.", client.client_id));
            var callbacks = ClientRepository.ParseRedirectUris(client.redirect_uris);
            if (callbacks.Count == 0 || callbacks.Any(url => !Uri.TryCreate(url, UriKind.Absolute, out _)))
                configuration.Add(new("error", "Client callback URLs are missing or malformed. Review the preset configuration.", client.client_id));
        }
        if (string.IsNullOrEmpty(aud)) return new(configuration, access);
        var resource = catalog.FindByAud(aud);
        if (resource is null)
        {
            configuration.Add(new("error", "Resource not found. Select a configured resource."));
            return new(configuration, access);
        }
        configuration.Add(new("info", "Configured application address", resource.ResourceUrl));
        if (resource.IsForwardAuth)
            configuration.Add(new("info", "Forward-auth requires proxy routing and trusted headers. Verify these in the deployment."));
        else
        {
            var linked = registered.Where(c => catalog.FindByUrl(c.default_resource)?.Aud == aud).ToArray();
            foreach (var client in linked)
            {
                configuration.Add(new("info", "Configured callback URLs", client.client_id + ": " + string.Join(", ", ClientRepository.ParseRedirectUris(client.redirect_uris))));
                if (catalog.All.Any(r => r.Aud.Equals(client.client_id, StringComparison.OrdinalIgnoreCase)))
                    configuration.Add(new("warning", "Client ID matches a resource audience. The receiver must validate access-token type.", client.client_id));
            }
            if (linked.Length == 0)
                configuration.Add(new("warning", "No preset client selects this resource by default. Explicit-resource and dynamic clients may still use it."));
        }
        if (string.IsNullOrWhiteSpace(userId)) return new(configuration, access);
        var user = users.GetStoredById(userId);
        if (user is null)
        {
            access.Add(new("error", "Account not found. Select an existing identity from Users."));
            return new(configuration, access);
        }
        access.Add(new(user.is_disabled != 0 ? "error" : "success",
            user.is_disabled != 0 ? "Account is disabled. Review the account before restoring it." : "Account is active.", user.username));
        var bindings = identities.ListByUser(userId).Where(i => providers.IsEnabled(i.provider)).ToArray();
        var passwordAvailable = passwords.AllowsUser(user) && !string.IsNullOrEmpty(user.password_hash);
        access.Add(new(passwordAvailable || bindings.Length > 0 ? "info" : "warning",
            passwordAvailable || bindings.Length > 0 ? "A sign-in method is configured; provider availability has not been tested." : "No usable sign-in method is configured. Review bindings or password access."));
        if (passwordAvailable && user.locked_until > DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            access.Add(new("warning", "Password sign-in is temporarily locked. External sign-in is evaluated separately."));
        if (user.must_change_password != 0)
            access.Add(new("warning", "The account must complete the required password change."));
        if (!resource.AllowsUser(user.is_admin != 0))
            access.Add(new("error", "This resource is restricted to Auth administrators."));
        var effective = grants.Get(userId, aud);
        if (effective is null)
            access.Add(new("error", "No effective grant. Assign access directly or through a group."));
        else
        {
            access.Add(new("info", "Effective scopes", effective.scopes));
            var missing = resource.Scopes.Except(effective.scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToArray();
            access.Add(new(missing.Length == 0 ? "success" : "warning", missing.Length == 0
                ? "All configured scopes are granted. This does not verify an application's own permissions."
                : "Only some scopes are granted. Requests for missing scopes will be denied.", string.Join(" ", missing)));
            foreach (var source in groups.Sources(userId).Where(s => s.Aud == aud))
                access.Add(new("info", source.GroupId is null ? "Direct grant" : "Group grant", (source.GroupName is null ? "" : source.GroupName + ": ") + source.Scopes));
        }
        var statuses = provisioning.List(userId);
        var integrations = provisioningOptions.Applications.Where(p => p.Value.RequiredResources.ContainsKey(aud)).ToArray();
        if (integrations.Length == 0)
            access.Add(new("info", "No account-sync connector is configured for this resource. Account creation and application sessions are managed downstream."));
        foreach (var (id, app) in integrations)
        {
            var enabled = user.is_disabled == 0 && app.RequiredResources.All(r =>
                catalog.FindByAud(r.Key) is { } required && required.AllowsUser(user.is_admin != 0) && grants.IsAllowed(userId, r.Key, r.Value));
            var status = statuses.FirstOrDefault(s => s.application_id == id);
            access.Add(new("info", enabled ? "Desired downstream account state: enabled" : "Desired downstream account state: disabled", app.Name));
            if (status is null || (status.enabled != 0) != enabled)
                access.Add(new("warning", "Account sync is awaiting reconciliation. Review or retry synchronization from the user page.", app.Name));
            else
                access.Add(new(status.state == "synced" ? "info" : "warning", status.state == "synced"
                    ? "Last delivery was acknowledged. Live downstream state and existing sessions have not been verified."
                    : "Account sync is pending or failed. Review or retry synchronization from the user page.",
                    app.Name + ": " + status.state + (status.error_code is null ? "" : " (" + status.error_code + ")")));
        }
        return new(configuration, access);
    }
}
