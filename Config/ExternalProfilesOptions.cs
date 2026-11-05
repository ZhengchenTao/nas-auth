using NasAuth.Services;

namespace NasAuth.Config;

public sealed class ExternalProfilesOptions
{
    public Dictionary<string, ExternalProfileProvider> Providers { get; set; } = new(StringComparer.Ordinal);
    public ExternalProfileProvider? Find(string id) => Providers.GetValueOrDefault(id);
    public void Validate(string issuer)
    {
        var auth = new Uri(issuer);
        foreach (var (id, provider) in Providers)
        {
            if (id.Length is < 1 or > 32 || id.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
                throw new InvalidOperationException("Invalid external profile provider ID.");
            if (provider.Fields.Count > 16) throw new InvalidOperationException("Too many external profile fields.");
            _ = ExternalProfileData.Encode(provider.Fields.ToDictionary(x => x.Key, _ => ""));
            foreach (var field in provider.Fields.Values)
                if (field.Label.Length is < 1 or > 80 || field.Label.Any(char.IsControl) || field.Type is not ("text" or "email"))
                    throw new InvalidOperationException("Invalid external profile field definition.");
            if (string.IsNullOrEmpty(provider.BrowserLookupUrl)) continue;
            if (!Uri.TryCreate(provider.BrowserLookupUrl, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
                uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0 ||
                uri.GetLeftPart(UriPartial.Authority) == auth.GetLeftPart(UriPartial.Authority))
                throw new InvalidOperationException("Browser lookup must use a distinct, approved HTTPS origin.");
            if (!provider.Fields.ContainsKey(provider.SubjectField)) throw new InvalidOperationException("Lookup requires a declared subject field.");
        }
    }
}

public sealed class ExternalProfileProvider
{
    public string DisplayName { get; set; } = "External identity";
    public Dictionary<string, ExternalProfileField> Fields { get; set; } = new(StringComparer.Ordinal);
    public string BrowserLookupUrl { get; set; } = "";
    public string SubjectField { get; set; } = "user_id";
    public string UsernameField { get; set; } = "username";
    public string NameField { get; set; } = "name";
    public string EmailField { get; set; } = "email";
    public bool AllowAdminCreate { get; set; }
    public bool AllowSelfRefresh { get; set; }
    public bool AutoRefreshAfterLogin { get; set; }
}

public sealed class ExternalProfileField
{
    public string Label { get; set; } = "Field";
    public string Type { get; set; } = "text";
    public bool Visible { get; set; } = true;
    public bool BrowserImport { get; set; }
    public string SourceClaim { get; set; } = "";
}
