using System.Text.RegularExpressions;

namespace NasAuth.Config;

/// <summary>Claims names shared by external providers after their identity is validated.</summary>
public interface IExternalClaimMapping
{
    string SubjectClaim { get; }
    string EmailClaim { get; }
    string NameClaim { get; }
    string EmailVerifiedClaim { get; }
    string Scheme { get; }
}

/// <summary>
/// A ticket-based remote login provider. The login page returns an opaque, short-lived ticket;
/// a separately configured HTTPS adapter validates it and returns only the normalized identity.
/// Provider-specific protocol details belong in that adapter and private deployment settings.
/// </summary>
public sealed class ExternalTicketProviderOptions : IExternalClaimMapping
{
    private static readonly Regex IdPattern = new("^[a-z][a-z0-9-]{0,31}$", RegexOptions.CultureInvariant);

    public string Id { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public bool Enabled { get; set; }
    public string LoginUrl { get; set; } = "";
    public string ValidationUrl { get; set; } = "";
    public string ValidationToken { get; set; } = "";
    public string CallbackPath { get; set; } = "";
    public string ReturnUrlParameter { get; set; } = "return_url";
    public string StateParameter { get; set; } = "state";
    public string TicketParameter { get; set; } = "ticket";
    public Dictionary<string, string> LoginParameters { get; set; } = new(StringComparer.Ordinal);
    public string SubjectClaim { get; set; } = "sub";
    public string EmailClaim { get; set; } = "email";
    public string NameClaim { get; set; } = "name";
    public string EmailVerifiedClaim { get; set; } = "";

    public string Scheme => "external:" + Id;
    public bool CanBind => false;

    /// <summary>Unconfigured, disabled, or incomplete providers are never registered or shown.</summary>
    public bool IsEnabled => Enabled &&
        !string.IsNullOrWhiteSpace(LoginUrl) &&
        !string.IsNullOrWhiteSpace(ValidationUrl) &&
        !string.IsNullOrWhiteSpace(ValidationToken);

    public void NormalizeAndValidate()
    {
        Id = Id.Trim().ToLowerInvariant();
        DisplayName = DisplayName.Trim();
        LoginUrl = LoginUrl.Trim();
        ValidationUrl = ValidationUrl.Trim();
        CallbackPath = CallbackPath.Trim();
        ReturnUrlParameter = string.IsNullOrWhiteSpace(ReturnUrlParameter) ? "return_url" : ReturnUrlParameter.Trim();
        StateParameter = string.IsNullOrWhiteSpace(StateParameter) ? "state" : StateParameter.Trim();
        TicketParameter = string.IsNullOrWhiteSpace(TicketParameter) ? "ticket" : TicketParameter.Trim();
        SubjectClaim = string.IsNullOrWhiteSpace(SubjectClaim) ? "sub" : SubjectClaim.Trim();
        EmailClaim = string.IsNullOrWhiteSpace(EmailClaim) ? "email" : EmailClaim.Trim();
        NameClaim = string.IsNullOrWhiteSpace(NameClaim) ? "name" : NameClaim.Trim();
        EmailVerifiedClaim = EmailVerifiedClaim.Trim();
        LoginParameters = (LoginParameters ?? new Dictionary<string, string>())
            .Where(kv => !string.IsNullOrWhiteSpace(kv.Key) && kv.Value is not null)
            .ToDictionary(kv => kv.Key.Trim(), kv => kv.Value, StringComparer.Ordinal);

        if (!IdPattern.IsMatch(Id) || Id is "google" or "microsoft")
            throw new InvalidOperationException(
                $"ExternalProviders:TicketProviders Id={Id} 不合法（用小写字母、数字、连字符；google/microsoft 为保留名）");
        if (string.IsNullOrWhiteSpace(DisplayName))
            throw new InvalidOperationException($"ExternalProviders:TicketProviders Id={Id} 缺少 DisplayName");

        if (!IsEnabled) return;
        if (!IsHttpsUrl(LoginUrl) || !IsValidationUrl(ValidationUrl))
            throw new InvalidOperationException(
                $"ExternalProviders:TicketProviders Id={Id} 的 LoginUrl 必须是无凭据的 HTTPS URL，ValidationUrl 须是 HTTPS 或本机 loopback HTTP URL");
        if (!string.IsNullOrEmpty(CallbackPath) &&
            (!CallbackPath.StartsWith('/') || CallbackPath.StartsWith("//", StringComparison.Ordinal) ||
             CallbackPath.Contains('?') || CallbackPath.Contains('#') || CallbackPath.Contains('\\') ||
             CallbackPath.Contains('%') || CallbackPath.Split('/').Any(s => s is "." or "..")))
            throw new InvalidOperationException(
                $"ExternalProviders:TicketProviders Id={Id} 的 CallbackPath 必须是规范的站内绝对路径");
        if (!ValidParameter(ReturnUrlParameter) || !ValidParameter(StateParameter) ||
            !ValidParameter(TicketParameter) ||
            string.Equals(StateParameter, TicketParameter, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"ExternalProviders:TicketProviders Id={Id} 的 state/ticket/return 参数名不合法或冲突");
        if (LoginParameters.Keys.Any(k => !ValidParameter(k) ||
            string.Equals(k, ReturnUrlParameter, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException(
                $"ExternalProviders:TicketProviders Id={Id} 的 LoginParameters 含非法名称或占用 ReturnUrlParameter");
    }

    private static bool IsHttpsUrl(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps &&
        string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment);

    private static bool IsValidationUrl(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback) &&
        string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment);

    private static bool ValidParameter(string value) =>
        value.Length is > 0 and <= 64 && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-');
}
