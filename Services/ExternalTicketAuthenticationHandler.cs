using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using NasAuth.Config;

namespace NasAuth.Services;

/// <summary>
/// Ticket-based remote sign-in. The remote login system only returns an opaque ticket; identity
/// claims are accepted exclusively from a private HTTPS validation adapter.
/// </summary>
public sealed class ExternalTicketAuthenticationHandler : RemoteAuthenticationHandler<ExternalTicketAuthenticationOptions>
{
    public const string ValidationHttpClientName = "external-ticket-validation";
    private const string ProviderItem = ".nas-auth.provider";
    private const int MaxStateLength = 8192;
    private const int MaxTicketLength = 4096;
    private const int MaxValidationResponseBytes = 16 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
        MaxDepth = 8,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly IDataProtectionProvider _dataProtection;
    private readonly IHttpClientFactory _httpClients;
    private readonly TicketReplayCache _replayCache;
    private readonly TimeProvider _timeProvider;

    public ExternalTicketAuthenticationHandler(
        IOptionsMonitor<ExternalTicketAuthenticationOptions> options,
        ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder,
        IDataProtectionProvider dataProtection,
        IHttpClientFactory httpClients,
        TicketReplayCache replayCache,
        TimeProvider timeProvider)
        : base(options, logger, encoder)
    {
        _dataProtection = dataProtection;
        _httpClients = httpClients;
        _replayCache = replayCache;
        _timeProvider = timeProvider;
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (string.IsNullOrWhiteSpace(Options.ProviderId) || string.IsNullOrWhiteSpace(Options.LoginUrl) ||
            string.IsNullOrWhiteSpace(Options.CallbackBaseUrl))
            throw new InvalidOperationException("Ticket provider is missing its validated login configuration.");

        GenerateCorrelationId(properties);
        properties.IssuedUtc = _timeProvider.GetUtcNow();
        properties.ExpiresUtc = _timeProvider.GetUtcNow().Add(Options.StateLifetime);
        properties.Items[ProviderItem] = Options.ProviderId;

        var emptyIdentity = new ClaimsIdentity();
        var stateTicket = new AuthenticationTicket(new ClaimsPrincipal(emptyIdentity), properties, Scheme.Name);
        var stateFormat = new TicketDataFormat(_dataProtection.CreateProtector(
            "nas-auth.external-ticket.v1", Options.ProviderId));
        var state = stateFormat.Protect(stateTicket);

        var callback = Options.CallbackBaseUrl.TrimEnd('/') + Options.CallbackPath;
        callback = QueryHelpers.AddQueryString(callback, Options.StateParameter, state);
        var loginUrl = Options.LoginUrl;
        foreach (var parameter in Options.LoginParameters)
            loginUrl = QueryHelpers.AddQueryString(loginUrl, parameter.Key, parameter.Value);
        loginUrl = QueryHelpers.AddQueryString(loginUrl, Options.LoginCallbackParameter, callback);
        Response.Redirect(loginUrl);
        return Task.CompletedTask;
    }

    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        var stateValues = Request.Query[Options.StateParameter];
        if (stateValues.Count != 1 || string.IsNullOrEmpty(stateValues[0]) || stateValues[0]!.Length > MaxStateLength)
            return HandleRequestResult.Fail("Missing or invalid remote sign-in state.");

        var stateFormat = new TicketDataFormat(_dataProtection.CreateProtector(
            "nas-auth.external-ticket.v1", Options.ProviderId));
        AuthenticationTicket? stateTicket;
        try
        {
            stateTicket = stateFormat.Unprotect(stateValues[0]!);
        }
        catch (CryptographicException)
        {
            stateTicket = null;
        }
        var properties = stateTicket?.Properties;
        if (stateTicket is null || stateTicket.AuthenticationScheme != Scheme.Name || properties is null ||
            properties.ExpiresUtc is not { } exp || exp <= _timeProvider.GetUtcNow() ||
            !properties.Items.TryGetValue(ProviderItem, out var provider) || provider != Options.ProviderId)
            return HandleRequestResult.Fail("Remote sign-in state is invalid or expired.");

        if (!ValidateCorrelationId(properties))
            return HandleRequestResult.Fail("Remote sign-in correlation check failed.");

        var ticketValues = Request.Query[Options.TicketParameter];
        if (ticketValues.Count != 1 || string.IsNullOrWhiteSpace(ticketValues[0]) ||
            ticketValues[0]!.Length > MaxTicketLength)
            return HandleRequestResult.Fail("The remote login did not return a valid ticket.");

        var opaqueTicket = ticketValues[0]!;
        var replayResult = _replayCache.TryConsume(
            Options.ProviderId, opaqueTicket, exp);
        if (replayResult != TicketReplayCacheResult.Accepted)
        {
            if (replayResult == TicketReplayCacheResult.CapacityExceeded)
                Logger.LogWarning("Ticket replay cache is full for provider {Provider}", Options.ProviderId);
            return HandleRequestResult.Fail("The remote login ticket has already been used.");
        }

        TicketValidationResponse? identity;
        try
        {
            identity = await ValidateTicketAsync(opaqueTicket, Context.Connection.RemoteIpAddress?.ToString(), Context.RequestAborted);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or InvalidDataException)
        {
            Logger.LogWarning("Ticket validation adapter failed for provider {Provider}: {FailureType}",
                Options.ProviderId, ex.GetType().Name);
            return HandleRequestResult.Fail("The remote login could not be validated.");
        }

        if (identity is null || !IsSafeClaim(identity.Subject, 512, required: true) ||
            !IsSafeClaim(identity.DisplayName, 256, required: false) ||
            !IsSafeClaim(identity.Email, 320, required: false))
            return HandleRequestResult.Fail("The validation adapter returned an invalid identity.");

        var claims = new List<Claim> { new(Options.SubjectClaim, identity.Subject!) };
        if (!string.IsNullOrWhiteSpace(identity.DisplayName))
            claims.Add(new Claim(Options.NameClaim, identity.DisplayName));
        if (!string.IsNullOrWhiteSpace(identity.Email))
            claims.Add(new Claim(Options.EmailClaim, identity.Email));

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name, Options.NameClaim, ClaimTypes.Role));
        return HandleRequestResult.Success(new AuthenticationTicket(principal, properties, Scheme.Name));
    }

    private async Task<TicketValidationResponse?> ValidateTicketAsync(string ticket, string? clientIp,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, Options.ValidationUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Options.ValidationToken);
        request.Content = JsonContent.Create(new TicketValidationRequest(ticket, clientIp), options: JsonOptions);

        var client = _httpClients.CreateClient(ValidationHttpClientName);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode) return null;
        if (response.Content.Headers.ContentLength is > MaxValidationResponseBytes) return null;
        if (response.Content.Headers.ContentType?.MediaType != "application/json") return null;

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var bytes = await ReadBoundedAsync(stream, cancellationToken);
        return JsonSerializer.Deserialize<TicketValidationResponse>(bytes, JsonOptions);
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream input, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken);
            if (read == 0) return output.ToArray();
            if (output.Length + read > MaxValidationResponseBytes)
                throw new InvalidDataException("Validation response exceeds the configured limit.");
            output.Write(buffer, 0, read);
        }
    }

    private static bool IsSafeClaim(string? value, int maxLength, bool required) =>
        required ? !string.IsNullOrWhiteSpace(value) && value.Length <= maxLength && !value.Any(char.IsControl)
                 : string.IsNullOrEmpty(value) || value.Length <= maxLength && !value.Any(char.IsControl);
}

public sealed class ExternalTicketAuthenticationOptions : RemoteAuthenticationOptions
{
    public string ProviderId { get; set; } = "";
    public string CallbackBaseUrl { get; set; } = "";
    public string LoginUrl { get; set; } = "";
    public string ValidationUrl { get; set; } = "";
    public string ValidationToken { get; set; } = "";
    public string LoginCallbackParameter { get; set; } = "return_url";
    public string StateParameter { get; set; } = "state";
    public string TicketParameter { get; set; } = "ticket";
    public Dictionary<string, string> LoginParameters { get; set; } = new(StringComparer.Ordinal);
    public string SubjectClaim { get; set; } = "sub";
    public string EmailClaim { get; set; } = "email";
    public string NameClaim { get; set; } = "name";
    public TimeSpan StateLifetime { get; set; } = TimeSpan.FromMinutes(5);
}

public sealed record TicketValidationRequest(
    [property: JsonPropertyName("ticket")] string Ticket,
    [property: JsonPropertyName("client_ip")] string? ClientIp);
public sealed class TicketValidationResponse
{
    [JsonPropertyName("subject")]
    public string? Subject { get; set; }

    [JsonPropertyName("display_name")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("email")]
    public string? Email { get; set; }
}

/// <summary>Process-local one-time use guard. Only a digest is retained; ticket values are never logged or stored.</summary>
public sealed class TicketReplayCache
{
    public const int DefaultMaximumEntries = 10_000;

    private readonly Dictionary<string, DateTimeOffset> _used = new(StringComparer.Ordinal);
    private readonly PriorityQueue<string, long> _expiryQueue = new();
    private readonly object _gate = new();
    private readonly TimeProvider _timeProvider;
    private readonly int _maximumEntries;

    public TicketReplayCache(TimeProvider timeProvider) : this(timeProvider, DefaultMaximumEntries) { }

    public TicketReplayCache(TimeProvider timeProvider, int maximumEntries)
    {
        if (maximumEntries < 1) throw new ArgumentOutOfRangeException(nameof(maximumEntries));
        _timeProvider = timeProvider;
        _maximumEntries = maximumEntries;
    }

    public TicketReplayCacheResult TryConsume(string providerId, string ticket, DateTimeOffset expiresAt)
    {
        var now = _timeProvider.GetUtcNow();
        if (expiresAt <= now) return TicketReplayCacheResult.Expired;

        // Include the provider namespace while hashing so identical opaque values from different
        // providers do not interfere. The original ticket is never retained or logged.
        var digestInput = System.Text.Encoding.UTF8.GetBytes(providerId + "\0" + ticket);
        var key = Convert.ToHexString(SHA256.HashData(digestInput));
        lock (_gate)
        {
            while (_expiryQueue.TryPeek(out var expiredKey, out var ticks) && ticks <= now.UtcDateTime.Ticks)
            {
                _expiryQueue.Dequeue();
                if (_used.TryGetValue(expiredKey, out var expiration) && expiration.UtcDateTime.Ticks <= ticks)
                    _used.Remove(expiredKey);
            }

            if (_used.ContainsKey(key)) return TicketReplayCacheResult.Replayed;
            if (_used.Count >= _maximumEntries) return TicketReplayCacheResult.CapacityExceeded;

            _used.Add(key, expiresAt);
            _expiryQueue.Enqueue(key, expiresAt.UtcDateTime.Ticks);
            return TicketReplayCacheResult.Accepted;
        }
    }
}

public enum TicketReplayCacheResult
{
    Accepted,
    Replayed,
    Expired,
    CapacityExceeded,
}
