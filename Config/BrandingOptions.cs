namespace NasAuth.Config;

/// <summary>Instance display settings only. Protocol names, cookies, issuer and user identities stay unchanged.</summary>
public class BrandingOptions
{
    public string SiteName { get; set; } = "nas-auth";
    public string? LoginTitle { get; set; }
    public string? LoginSubtitle { get; set; }
    public string FaviconPath { get; set; } = "/favicon.png";
    public string? LogoPath { get; set; }
    public Dictionary<string, string> NavigationLabels { get; set; } = new(StringComparer.Ordinal);

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(SiteName) || SiteName.Length > 80)
            throw new InvalidOperationException("Branding:SiteName must contain 1–80 characters");
        ValidatePath(FaviconPath);
        if (!string.IsNullOrEmpty(LogoPath)) ValidatePath(LogoPath);
        foreach (var label in NavigationLabels.Values)
            if (string.IsNullOrWhiteSpace(label) || label.Length > 80)
                throw new InvalidOperationException("Branding:NavigationLabels values must contain 1–80 characters");
    }

    private static void ValidatePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !path.StartsWith('/') || path.StartsWith("//") ||
            path.IndexOfAny(['\\', '?', '#', '%', '\r', '\n']) >= 0 || path.Split('/').Any(s => s is "." or ".."))
            throw new InvalidOperationException("Branding asset paths must be local absolute paths, e.g. /branding/icon.svg");
    }
}
