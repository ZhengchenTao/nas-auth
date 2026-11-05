using System.Text.Json;

namespace NasAuth.Services;

/// <summary>Informational attributes only; never used to select users, roles, email verification or grants.</summary>
public static class ExternalProfileData
{
    public const string ClaimType = "nas-auth:external-profile";
    public static string? Encode(IReadOnlyDictionary<string, string>? fields)
    {
        if (fields is null) return null;
        if (fields.Count > 16 || fields.Any(x => x.Key.Length is < 1 or > 64 ||
            x.Key.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_') ||
            x.Value is null || x.Value.Length > 256 || x.Value.Any(char.IsControl)))
            throw new InvalidDataException("Invalid external profile attributes.");
        var json = JsonSerializer.Serialize(fields);
        if (json.Length > 4096) throw new InvalidDataException("External profile attributes exceed the size limit.");
        return json;
    }

    public static IReadOnlyDictionary<string, string>? Read(string? json)
    {
        if (string.IsNullOrEmpty(json) || json.Length > 4096) return null;
        try
        {
            var value = JsonSerializer.Deserialize<Dictionary<string, string>>(json, new JsonSerializerOptions { MaxDepth = 4 });
            _ = Encode(value);
            return value;
        }
        catch (Exception e) when (e is JsonException or InvalidDataException) { return null; }
    }
}
