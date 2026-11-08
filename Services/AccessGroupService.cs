using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Microsoft.Data.Sqlite;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

public sealed class AccessGroup
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public long MemberCount { get; init; }
}
public sealed record GroupMember(string UserId, string Username, string? DisplayName, long Admin);
public sealed record GroupApplication(string Key, string Name, IReadOnlyDictionary<string, string> Grants);
public sealed class GroupGrantSource
{
    public string Aud { get; init; } = "";
    public string Scopes { get; init; } = "";
    public string? GroupId { get; init; }
    public string? GroupName { get; init; }
}
public sealed record GroupResourceChange(string Name, string? Before, string? After);
public sealed record GroupProvisioningChange(string Id, bool Enabled);
public sealed record GroupImpact(string UserId, string Username, string? DisplayName,
    IReadOnlyList<GroupResourceChange> Resources, IReadOnlyList<GroupProvisioningChange> ProvisionedApps);
public sealed record GroupGrantPreview(string Stamp, IReadOnlyList<GroupImpact> Changes);

public sealed class AccessGroupService(AuthDb db, ResourceCatalog catalog, ProvisioningOptions provisioning)
{
    private const string GroupSelect = """
        SELECT g.id,g.name,(SELECT COUNT(*) FROM access_group_members m WHERE m.group_id=g.id) AS MemberCount
        FROM access_groups g
        """;
    private const string MemberSelect = """
        SELECT u.user_id AS UserId,u.username,u.display_name AS DisplayName,u.is_admin AS Admin
        FROM users u JOIN access_group_members m ON m.user_id=u.user_id
        WHERE m.group_id=@id AND u.is_disabled=0 ORDER BY u.username,u.user_id
        """;

    public IReadOnlyList<AccessGroup> List()
    {
        using var conn = db.OpenConnection();
        return conn.Query<AccessGroup>(GroupSelect + " ORDER BY g.name COLLATE NOCASE,g.id").AsList();
    }

    public AccessGroup? Find(string id)
    {
        using var conn = db.OpenConnection();
        return Find(conn, null, id);
    }

    private static AccessGroup? Find(SqliteConnection conn, SqliteTransaction? tx, string id) =>
        conn.QuerySingleOrDefault<AccessGroup>(GroupSelect + " WHERE g.id=@id", new { id }, tx);

    public string? Create(string name)
    {
        var id = Guid.NewGuid().ToString("N");
        using var conn = db.OpenConnection();
        return conn.Execute("INSERT INTO access_groups(id,name) VALUES(@id,@name) ON CONFLICT(name) DO NOTHING",
            new { id, name }) == 1 ? id : null;
    }

    public bool Rename(string id, string name)
    {
        using var conn = db.OpenConnection();
        return conn.Execute("UPDATE OR IGNORE access_groups SET name=@name WHERE id=@id", new { id, name }) == 1;
    }

    public bool DeleteEmpty(string id)
    {
        using var conn = db.OpenConnection();
        return conn.Execute("""
            DELETE FROM access_groups WHERE id=@id
            AND NOT EXISTS (SELECT 1 FROM access_group_members WHERE group_id=@id)
            """, new { id }) == 1;
    }

    public IReadOnlyList<GroupMember> Members(string id)
    {
        using var conn = db.OpenConnection();
        return conn.Query<GroupMember>(MemberSelect, new { id }).AsList();
    }

    public IReadOnlyList<AccessGroup> Memberships(string userId)
    {
        using var conn = db.OpenConnection();
        return conn.Query<AccessGroup>(GroupSelect + """
             WHERE EXISTS (SELECT 1 FROM access_group_members WHERE group_id=g.id AND user_id=@userId)
             ORDER BY g.name COLLATE NOCASE,g.id
            """, new { userId }).AsList();
    }

    public IReadOnlyList<GroupGrantSource> Sources(string userId)
    {
        using var conn = db.OpenConnection();
        return conn.Query<GroupGrantSource>("""
            SELECT s.aud,s.scopes,s.group_id AS GroupId,g.name AS GroupName
            FROM resource_grant_sources s LEFT JOIN access_groups g ON g.id=s.group_id
            WHERE s.user_id=@userId ORDER BY s.aud,g.name,g.id
            """, new { userId }).AsList();
    }

    public IReadOnlyList<GroupApplication> Applications()
    {
        var apps = new List<GroupApplication>();
        var covered = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (id, app) in provisioning.Applications)
        {
            if (app.RequiredResources.Keys.Any(aud => catalog.All.Single(r => r.Aud == aud).AdminOnly))
                continue;
            var grants = app.RequiredResources.ToDictionary(p => p.Key, p => string.Join(' ', p.Value));
            apps.Add(new("provisioned:" + id, app.Name, grants));
            covered.UnionWith(grants.Keys);
        }
        foreach (var resources in catalog.All.Where(r => !r.AdminOnly && !covered.Contains(r.Aud))
                     .GroupBy(r => r.App is null ? "resource:" + r.Aud : "app:" + r.App.Id))
        {
            var first = resources.First();
            apps.Add(new(resources.Key, first.App?.Name ?? first.DisplayName,
                resources.ToDictionary(r => r.Aud, r => string.Join(' ', r.Scopes))));
        }
        return apps.OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public IReadOnlyDictionary<string, string> Grants(string id)
    {
        using var conn = db.OpenConnection();
        return ReadGrants(conn, null, id);
    }

    private static Dictionary<string, string> ReadGrants(SqliteConnection conn, SqliteTransaction? tx, string id) =>
        conn.Query<(string Aud, string Scopes)>("SELECT aud,scopes FROM access_group_resources WHERE group_id=@id ORDER BY aud",
            new { id }, tx).ToDictionary(g => g.Aud, g => g.Scopes, StringComparer.Ordinal);

    public GroupGrantPreview? ChangeGrants(string id, IEnumerable<string> selected, string? confirmation, out bool saved)
    {
        saved = false;
        var keys = selected.ToHashSet(StringComparer.Ordinal);
        var apps = Applications();
        if (keys.Any(key => !apps.Any(app => app.Key == key))) return null;
        var next = apps.Where(a => keys.Contains(a.Key)).SelectMany(a => a.Grants)
            .GroupBy(r => r.Key, StringComparer.Ordinal).OrderBy(g => g.Key, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => string.Join(' ', g.SelectMany(p => Scopes(p.Value))
                .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)), StringComparer.Ordinal);
        using var conn = db.OpenConnection();
        using var tx = conn.BeginTransaction(deferred: confirmation is null);
        var group = Find(conn, tx, id);
        if (group is null) return null;
        var previous = ReadGrants(conn, tx, id);
        var members = conn.Query<GroupMember>(MemberSelect, new { id }, tx).AsList();
        var changes = members.Select(m => Impact(conn, tx, id, m, previous, next))
            .Where(i => i.Resources.Count > 0).ToList();
        // The confirmation is valid only for the reviewed selection and affected accounts.
        var stamp = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(
            new { group, previous, next, members, changes })));
        var preview = new GroupGrantPreview(stamp, changes);
        if (confirmation != stamp) return preview;

        conn.Execute("DELETE FROM access_group_resources WHERE group_id=@id", new { id }, tx);
        foreach (var (aud, scopes) in next)
            conn.Execute("INSERT INTO access_group_resources(group_id,aud,scopes) VALUES(@id,@aud,@scopes)",
                new { id, aud, scopes }, tx);
        foreach (var change in changes) Queue(conn, tx, change);
        tx.Commit();
        saved = true;
        return preview;
    }

    public bool ChangeMember(string id, string userId, bool add)
    {
        using var conn = db.OpenConnection();
        using var tx = conn.BeginTransaction();
        if (Find(conn, tx, id) is null) return false;
        var member = conn.QuerySingleOrDefault<GroupMember>("""
            SELECT user_id AS UserId,username,display_name AS DisplayName,is_admin AS Admin
            FROM users WHERE user_id=@userId AND is_disabled=0
            """, new { userId }, tx);
        if (member is null) return false;
        var grants = ReadGrants(conn, tx, id);
        var empty = new Dictionary<string, string>();
        var impact = Impact(conn, tx, id, member, add ? empty : grants, add ? grants : empty);
        var affected = conn.Execute(add
            ? "INSERT INTO access_group_members(group_id,user_id) VALUES(@id,@userId) ON CONFLICT DO NOTHING"
            : "DELETE FROM access_group_members WHERE group_id=@id AND user_id=@userId", new { id, userId }, tx);
        if (affected > 0) Queue(conn, tx, impact);
        tx.Commit();
        return affected > 0;
    }

    private GroupImpact Impact(SqliteConnection conn, SqliteTransaction tx, string id, GroupMember member,
        IReadOnlyDictionary<string, string> previous, IReadOnlyDictionary<string, string> next)
    {
        var other = UserResourceRepository.Effective(conn, member.UserId, tx, id);
        var before = Combine(other, previous, member.UserId);
        var after = Combine(other, next, member.UserId);
        var isAdmin = member.Admin != 0;
        var resources = catalog.All.Where(r => r.AllowsUser(isAdmin))
            .Select(r => new GroupResourceChange(r.DisplayName, before.GetValueOrDefault(r.Aud), after.GetValueOrDefault(r.Aud)))
            .Where(r => r.Before != r.After).ToList();
        var apps = new List<GroupProvisioningChange>();
        foreach (var (appId, app) in provisioning.Applications)
        {
            var wasAllowed = Allowed(app.RequiredResources, before, isAdmin);
            var isAllowed = Allowed(app.RequiredResources, after, isAdmin);
            if (wasAllowed != isAllowed) apps.Add(new(appId, isAllowed));
        }
        return new(member.UserId, member.Username, member.DisplayName, resources, apps);
    }

    private bool Allowed(Dictionary<string, List<string>> required, Dictionary<string, string> grants, bool isAdmin) =>
        required.All(r => catalog.All.Single(c => c.Aud == r.Key).AllowsUser(isAdmin) &&
            grants.TryGetValue(r.Key, out var granted) && r.Value.All(Scopes(granted).Contains));

    private static Dictionary<string, string> Combine(IReadOnlyList<UserResourceRow> other,
        IReadOnlyDictionary<string, string> group, string userId) =>
        UserResourceRepository.Merge(other.Concat(group.Select(g => new UserResourceRow(userId, g.Key, g.Value))))
            .ToDictionary(r => r.aud, r => r.scopes, StringComparer.Ordinal);

    private static string[] Scopes(string value) => value.Split(' ', StringSplitOptions.RemoveEmptyEntries);

    private static void Queue(SqliteConnection conn, SqliteTransaction tx, GroupImpact impact)
    {
        foreach (var app in impact.ProvisionedApps)
            conn.Execute("""
                INSERT INTO provisioning_changes(user_id,application_id)
                SELECT @UserId,@app WHERE (SELECT value FROM settings WHERE key='provisioning_enabled')='1'
                """, new { impact.UserId, app = app.Id }, tx);
    }
}
