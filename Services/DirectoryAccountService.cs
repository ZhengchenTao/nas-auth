using Dapper;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Endpoints;

namespace NasAuth.Services;

public sealed class DirectoryAccountService(AuthDb db, ExternalProfilesOptions profiles)
{
    public Dictionary<string, string> Validate(string provider, string subject, string? json)
    {
        var definition = profiles.Find(provider) ?? throw new InvalidDataException("Unknown directory provider.");
        var fields = ExternalProfileData.Read(json) ?? throw new InvalidDataException("Invalid directory profile.");
        if (string.IsNullOrWhiteSpace(subject) || subject.Length > 512 || subject.Any(char.IsControl) ||
            fields.GetValueOrDefault(definition.SubjectField) != subject)
            throw new InvalidDataException("Directory identity does not match the selected account.");
        var accepted = fields.Where(x => definition.Fields.TryGetValue(x.Key, out var d) && d.BrowserImport)
            .ToDictionary(x => x.Key, x => x.Value);
        if (accepted.GetValueOrDefault(definition.SubjectField) != subject) throw new InvalidDataException("Subject import is not configured.");
        foreach (var (key, value) in accepted)
            if (definition.Fields[key].Type == "email" && !DashboardSupport.IsValidEmail(value))
                throw new InvalidDataException("Invalid directory email.");
        return accepted;
    }

    public string Create(string provider, string subject, Dictionary<string, string> fields, string actor, IReadOnlyDictionary<string,string>? applicationGrants = null)
    {
        var definition = profiles.Find(provider)!;
        if (fields.GetValueOrDefault(definition.SubjectField) != subject) throw new InvalidDataException("Directory identity mismatch.");
        if (!definition.AllowAdminCreate) throw new InvalidDataException("Directory account creation is disabled.");
        var username = fields.GetValueOrDefault(definition.UsernameField)?.Trim();
        if (username is null || !DashboardSupport.UsernamePattern.IsMatch(username))
            throw new InvalidDataException("The directory username is invalid; no account was created.");
        using var connection = db.OpenConnection();
        using var transaction = connection.BeginTransaction();
        if (connection.ExecuteScalar<long>("SELECT COUNT(*) FROM users WHERE user_id=@username OR username=@username", new { username }, transaction) > 0 ||
            connection.ExecuteScalar<long>("SELECT COUNT(*) FROM deleted_user_ids WHERE user_id=@username", new { username }, transaction) > 0 ||
            connection.ExecuteScalar<long>("SELECT COUNT(*) FROM external_identities WHERE provider=@provider AND subject=@subject", new { provider, subject }, transaction) > 0)
            throw new InvalidDataException("This username or external identity already exists. Use the existing account approval flow.");
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var email = fields.GetValueOrDefault(definition.EmailField);
        var name = UserRepository.NormalizeDisplayName(fields.GetValueOrDefault(definition.NameField));
        connection.Execute(@"INSERT INTO users(user_id,username,password_hash,is_admin,must_change_password,created_at,updated_at,email,allow_password_login,display_name)
            VALUES(@username,@username,@password,0,0,@now,@now,@email,0,@name)",
            new { username, password = PasswordHasher.UnusableHash(), now, email, name }, transaction);
        connection.Execute(@"INSERT INTO external_identities(provider,subject,user_id,email,display_name,status,created_at,approved_at,profile_json,profile_updated_at)
            VALUES(@provider,@subject,@username,@email,@name,'active',@now,@now,@json,@now)",
            new { provider, subject, username, email, name, now, json = ExternalProfileData.Encode(fields) }, transaction);
        foreach (var (aud, scopes) in applicationGrants ?? new Dictionary<string,string>())
            connection.Execute("INSERT INTO user_resources(user_id,aud,scopes) VALUES(@username,@aud,@scopes)", new { username, aud, scopes }, transaction);
        transaction.Commit();
        return username;
    }
}
