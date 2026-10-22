using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.Extensions.Configuration;

namespace NasAuth.Config;

/// <summary>
/// 上游登录提供方。新配置使用标准 OIDC；未配置 Providers 时保留既有 Google / Microsoft 环境变量行为。
/// Providers 非空时是完整清单，旧 OAuth 环境变量不会再隐式启用登录入口。
/// </summary>
public sealed class ExternalProviderOptions
{
    public string GoogleClientId { get; init; } = "";
    public string GoogleClientSecret { get; init; } = "";
    public string MicrosoftClientId { get; init; } = "";
    public string MicrosoftClientSecret { get; init; } = "";

    public bool GoogleEnabled => !UsesConfiguredProviders &&
        !string.IsNullOrWhiteSpace(GoogleClientId) && !string.IsNullOrWhiteSpace(GoogleClientSecret);

    public bool MicrosoftEnabled => !UsesConfiguredProviders &&
        !string.IsNullOrWhiteSpace(MicrosoftClientId) && !string.IsNullOrWhiteSpace(MicrosoftClientSecret);

    public bool UsesConfiguredProviders { get; private init; }
    public IReadOnlyList<ExternalOidcProviderOptions> ConfiguredProviders { get; private init; } = [];
    public IReadOnlyList<ExternalTicketProviderOptions> ConfiguredTicketProviders { get; private init; } = [];

    public IReadOnlyList<ExternalProviderChoice> EnabledProviders
    {
        get
        {
            if (UsesConfiguredProviders)
                return ConfiguredProviders.Where(p => p.IsEnabled).Select(p =>
                        new ExternalProviderChoice(p.Id, p.DisplayName, p.Scheme, CanBind: true))
                    .Concat(ConfiguredTicketProviders.Where(p => p.IsEnabled).Select(p =>
                        new ExternalProviderChoice(p.Id, p.DisplayName, p.Scheme, CanBind: false)))
                    .ToArray();

            var providers = new List<ExternalProviderChoice>();
            if (GoogleEnabled) providers.Add(new("google", "Google", GoogleDefaults.AuthenticationScheme));
            if (MicrosoftEnabled) providers.Add(new("microsoft", "Microsoft", MicrosoftAccountDefaults.AuthenticationScheme));
            return providers;
        }
    }

    public bool IsEnabled(string provider) => FindClaimMapping(provider) is not null ||
        (!UsesConfiguredProviders && (provider == "google" ? GoogleEnabled :
            provider == "microsoft" && MicrosoftEnabled));

    public ExternalOidcProviderOptions? Find(string provider) =>
        UsesConfiguredProviders
            ? ConfiguredProviders.FirstOrDefault(p => p.IsEnabled && p.Id == provider)
            : null;

    public ExternalTicketProviderOptions? FindTicket(string provider) => UsesConfiguredProviders
        ? ConfiguredTicketProviders.FirstOrDefault(p => p.IsEnabled && p.Id == provider)
        : null;

    public IExternalClaimMapping? FindClaimMapping(string provider) => (IExternalClaimMapping?)Find(provider) ?? FindTicket(provider);

    public bool CanBind(string provider) =>
        !UsesConfiguredProviders ? (provider is "google" or "microsoft") && IsEnabled(provider)
        : Find(provider) is not null;

    public string? SchemeFor(string provider)
    {
        if (!UsesConfiguredProviders)
            return provider switch
            {
                "google" when GoogleEnabled => GoogleDefaults.AuthenticationScheme,
                "microsoft" when MicrosoftEnabled => MicrosoftAccountDefaults.AuthenticationScheme,
                _ => null,
            };

        return FindClaimMapping(provider)?.Scheme;
    }

    /// <summary>
    /// UseConfiguredProviders=true 时即使清单为空也禁用旧 provider；非空清单也自动进入显式模式。
    /// 因而可用一份独立配置排除 Google / Microsoft，即使宿主还遗留旧环境变量。
    /// </summary>
    public static ExternalProviderOptions FromConfiguration(IConfiguration configuration)
    {
        var section = configuration.GetSection("ExternalProviders:Providers");
        var children = section.GetChildren().ToArray();
        var ticketChildren = configuration.GetSection("ExternalProviders:TicketProviders").GetChildren().ToArray();
        var useConfiguredProviders = configuration.GetValue<bool>("ExternalProviders:UseConfiguredProviders") ||
                                     children.Length > 0 || ticketChildren.Length > 0;
        if (useConfiguredProviders)
        {
            var configured = new List<ExternalOidcProviderOptions>();
            foreach (var child in children)
            {
                var provider = child.Get<ExternalOidcProviderOptions>() ?? new ExternalOidcProviderOptions();
                provider.NormalizeAndValidate();
                configured.Add(provider);
            }

            var configuredTickets = new List<ExternalTicketProviderOptions>();
            foreach (var child in ticketChildren)
            {
                var provider = child.Get<ExternalTicketProviderOptions>() ?? new ExternalTicketProviderOptions();
                provider.NormalizeAndValidate();
                configuredTickets.Add(provider);
            }

            var duplicate = configured.Select(p => p.Id).Concat(configuredTickets.Select(p => p.Id))
                .GroupBy(id => id, StringComparer.Ordinal)
                .FirstOrDefault(g => g.Count() > 1);
            if (duplicate is not null)
                throw new InvalidOperationException($"ExternalProviders 配置中 Id 重复：{duplicate.Key}");

            var duplicateCallback = configured.Where(p => p.IsEnabled)
                .Select(p => string.IsNullOrWhiteSpace(p.CallbackPath) ? $"/signin/{p.Id}" : p.CallbackPath)
                .Concat(configuredTickets.Where(p => p.IsEnabled)
                    .Select(p => string.IsNullOrWhiteSpace(p.CallbackPath) ? $"/signin/{p.Id}" : p.CallbackPath))
                .GroupBy(path => path, StringComparer.Ordinal)
                .FirstOrDefault(g => g.Count() > 1);
            if (duplicateCallback is not null)
                throw new InvalidOperationException($"ExternalProviders 配置中 CallbackPath 重复：{duplicateCallback.Key}");

            return new ExternalProviderOptions
            {
                UsesConfiguredProviders = true,
                ConfiguredProviders = configured,
                ConfiguredTicketProviders = configuredTickets,
            };
        }

        return FromEnvironment();
    }

    /// <summary>旧配置兼容层：此方法只在没有显式 Providers 列表时调用。</summary>
    public static ExternalProviderOptions FromEnvironment() => new()
    {
        GoogleClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") ?? "",
        GoogleClientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET") ?? "",
        MicrosoftClientId = Environment.GetEnvironmentVariable("MS_CLIENT_ID") ?? "",
        MicrosoftClientSecret = Environment.GetEnvironmentVariable("MS_CLIENT_SECRET") ?? "",
    };
}

/// <summary>标准 OpenID Connect 上游配置。ClientSecret 应由运行时环境注入，不放进仓库。</summary>
public sealed class ExternalOidcProviderOptions : IExternalClaimMapping
{
    private static readonly Regex IdPattern = new("^[a-z][a-z0-9-]{0,31}$", RegexOptions.CultureInvariant);

    public string Id { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public string Authority { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string CallbackPath { get; set; } = "";
    public string[] Scopes { get; set; } = [];
    public string SubjectClaim { get; set; } = "sub";
    public string EmailClaim { get; set; } = "email";
    public string NameClaim { get; set; } = "name";
    public string EmailVerifiedClaim { get; set; } = "";
    public string Prompt { get; set; } = "";
    public bool GetClaimsFromUserInfoEndpoint { get; set; }

    public string Scheme => "external:" + Id;
    public bool CanBind => true;

    /// <summary>配置不完整或显式关闭时不注册 handler，也不显示登录入口。</summary>
    public bool IsEnabled => Enabled &&
        !string.IsNullOrWhiteSpace(Authority) &&
        !string.IsNullOrWhiteSpace(ClientId) &&
        !string.IsNullOrWhiteSpace(ClientSecret);

    public void NormalizeAndValidate()
    {
        Id = Id.Trim().ToLowerInvariant();
        DisplayName = DisplayName.Trim();
        Authority = Authority.Trim().TrimEnd('/');
        CallbackPath = CallbackPath.Trim();
        SubjectClaim = string.IsNullOrWhiteSpace(SubjectClaim) ? "sub" : SubjectClaim.Trim();
        EmailClaim = string.IsNullOrWhiteSpace(EmailClaim) ? "email" : EmailClaim.Trim();
        NameClaim = string.IsNullOrWhiteSpace(NameClaim) ? "name" : NameClaim.Trim();
        EmailVerifiedClaim = EmailVerifiedClaim.Trim();
        Prompt = Prompt.Trim();
        Scopes = (Scopes ?? []).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).Distinct(StringComparer.Ordinal).ToArray();

        if (!IdPattern.IsMatch(Id) || Id is "google" or "microsoft")
            throw new InvalidOperationException(
                $"ExternalProviders:Providers Id={Id} 不合法（用小写字母、数字、连字符；google/microsoft 为保留名）");

        if (string.IsNullOrWhiteSpace(DisplayName))
            throw new InvalidOperationException($"ExternalProviders:Providers Id={Id} 缺少 DisplayName");

        if (string.IsNullOrWhiteSpace(Authority) || string.IsNullOrWhiteSpace(ClientId) ||
            string.IsNullOrWhiteSpace(ClientSecret))
        {
            // 配置条目可以显式 Enabled=false 或凭据尚未注入；两种情况都安全地不注册 handler。
            return;
        }

        if (!Uri.TryCreate(Authority, UriKind.Absolute, out var authorityUri) ||
            authorityUri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(authorityUri.UserInfo) ||
            !string.IsNullOrEmpty(authorityUri.Query) || !string.IsNullOrEmpty(authorityUri.Fragment))
            throw new InvalidOperationException(
                $"ExternalProviders:Providers Id={Id} 的 Authority 必须是无凭据、无 query/fragment 的 HTTPS URL");

        if (!string.IsNullOrEmpty(CallbackPath) &&
            (!CallbackPath.StartsWith('/') || CallbackPath.StartsWith("//", StringComparison.Ordinal) ||
             CallbackPath.Contains('?') || CallbackPath.Contains('#') || CallbackPath.Contains('\\')))
            throw new InvalidOperationException(
                $"ExternalProviders:Providers Id={Id} 的 CallbackPath 必须是站内绝对路径");
    }
}

public sealed record ExternalProviderChoice(string Id, string DisplayName, string Scheme, bool CanBind = true);
