using System.Text;
using NasAuth.Config;
using NasAuth.Services;
using static NasAuth.Endpoints.AccessGroupEndpoints;
using static NasAuth.Pages.I18n;
using static NasAuth.Pages.Ui;

namespace NasAuth.Pages;

public static partial class DashboardTemplates
{
    public static string GroupsSection(IReadOnlyList<AccessGroup> groups)
    {
        var body = new StringBuilder();
        if (groups.Count == 0) body.Append(Empty(T("No groups yet.")));
        else
        {
            body.Append($"<div class='table-container'><table class='table'><thead><tr><th>{T("Group name")}</th><th>{T("Members")}</th><th></th></tr></thead><tbody>");
            foreach (var group in groups)
                body.Append($"<tr><td class='wrap'><strong>{Esc(group.Name)}</strong></td><td>{group.MemberCount}</td><td class='fit'><a class='btn' data-variant='outline' data-size='sm' href='{GroupPath(group.Id)}'>{T("Manage")}</a></td></tr>");
            body.Append("</tbody></table></div>");
        }
        return Card(T("User groups"), T("Give a set of people access to the same applications."), body.ToString(),
            action: $"<a class='btn' data-variant='outline' data-size='sm' href='/admin/groups/new'>{T("New group")}</a>");
    }

    public static string NewGroupSection() => BackToGroups() +
        Card(T("Group details"), null, GroupNameForm("/admin/groups/new", "", T("Create")));

    public static string GroupSection(AccessGroup group, IReadOnlyList<GroupApplication> applications,
        IReadOnlyDictionary<string, string> grants, IReadOnlyList<GroupMember> members,
        string query, IReadOnlyList<GroupMember>? candidates, bool moreCandidates)
    {
        var path = GroupPath(group.Id);
        var access = new StringBuilder($"<form method='post' action='{path}/grants'>");
        if (applications.Count == 0) access.Append(Empty(T("No applications are available for group access.")));
        else
        {
            access.Append("<div class='application-choice-grid'>");
            foreach (var app in applications)
            {
                var selected = app.Grants.All(g => grants.TryGetValue(g.Key, out var current) &&
                    g.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                        .All(current.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains));
                access.Append($"<label class='application-option'><input type='checkbox' name='application' value='{Esc(app.Key)}'{(selected ? " checked" : "")}>{Esc(app.Name)}</label>");
            }
            access.Append("</div>");
        }
        if (applications.Count > 0 || grants.Count > 0)
            access.Append($"<div class='form-foot'><button class='btn' type='submit'>{T("Review changes")}</button></div>");
        access.Append("</form>");

        var people = new StringBuilder(MemberTable(path, members, add: false));
        people.Append($"<h3 class='subhead'>{T("Add a member")}</h3><form method='get' action='{path}' class='user-filter'>");
        people.Append($"<div class='field user-filter-query'><label for='group_member_search'>{T("Find accounts")}</label><input id='group_member_search' type='search' name='q' maxlength='128' value='{Esc(query)}' placeholder='{T("Name, username or email")}' required></div>");
        people.Append($"<button class='btn' data-variant='outline'>{T("Search")}</button></form>");
        if (candidates is not null) people.Append(MemberTable(path, candidates, add: true));
        if (moreCandidates) people.Append($"<p class='hint'>{T("Refine your search to find more accounts.")}</p>");

        var settings = GroupNameForm(path + "/name", group.Name, T("Save"));
        var delete = group.MemberCount == 0
            ? Card(T("Delete group"), null, $"<form method='post' action='{path}/delete' {Confirm(T("Delete this group?"))}><button class='btn' data-variant='destructive'>{T("Delete group")}</button></form>", "card danger")
            : "";
        return BackToGroups() +
            Card(T("Application access"), T("Members receive these grants in addition to their direct grants and grants from other groups."), access.ToString()) +
            Card(T("Members"), T("Adding an account gives it the group's current application access."), people.ToString()) +
            Card(T("Group details"), null, settings) + delete;
    }

    public static string GroupPreviewSection(AccessGroup group, IReadOnlyList<GroupApplication> applications,
        IReadOnlyList<string> selected, GroupGrantPreview preview, ProvisioningOptions options, bool stale)
    {
        var path = GroupPath(group.Id);
        var body = new StringBuilder();
        if (stale) body.Append(Alert(Esc(T("The impact changed while you were reviewing it. Review the updated list before saving.")), true));
        var names = applications.Where(a => selected.Contains(a.Key)).Select(a => a.Name).ToList();
        body.Append($"<p class='hint'>{T("Selected applications · {0}", Esc(names.Count == 0 ? T("None") : string.Join(", ", names)))}</p>");
        if (preview.Changes.Count == 0) body.Append(Empty(T("No current member's effective access will change.")));
        else
        {
            var showSync = preview.Changes.Any(change => change.ProvisionedApps.Count > 0);
            var syncHeader = showSync ? $"<th>{T("Account sync")}</th>" : "";
            body.Append($"<div class='table-container'><table class='table'><thead><tr><th>{T("Members")}</th><th>{T("Access changes")}</th>{syncHeader}</tr></thead><tbody>");
            foreach (var change in preview.Changes)
            {
                body.Append($"<tr><td class='wrap'>{PersonName(change.Username, change.DisplayName)}</td><td class='wrap'>");
                foreach (var resource in change.Resources)
                    body.Append($"<div>{Esc(resource.Name)}<span class='sub'>{Esc(resource.Before ?? "—")} → {Esc(resource.After ?? "—")}</span></div>");
                body.Append("</td>");
                if (showSync)
                {
                    body.Append("<td class='wrap'>");
                    if (change.ProvisionedApps.Count == 0) body.Append("—");
                    foreach (var app in change.ProvisionedApps)
                        body.Append($"<div>{Esc(options.Applications[app.Id].Name)}<span class='sub'>{T(app.Enabled ? "Enable account access" : "Revoke account access")}</span></div>");
                    body.Append("</td>");
                }
                body.Append("</tr>");
            }
            body.Append("</tbody></table></div>");
        }
        body.Append($"<form method='post' action='{path}/grants'>{Hidden("stamp", preview.Stamp)}");
        foreach (var key in selected) body.Append(Hidden("application", key));
        body.Append($"<div class='form-foot'><button class='btn'>{T("Save grants")}</button><a class='btn' data-variant='ghost' href='{path}'>{T("Cancel")}</a></div></form>");
        return Card(Esc(group.Name), T("Review the changes to members' effective access before saving."), body.ToString());
    }

    private static string MemberTable(string path, IReadOnlyList<GroupMember> members, bool add)
    {
        if (members.Count == 0) return Empty(T(add ? "No matching accounts to add." : "No members yet."));
        var body = new StringBuilder($"<div class='table-container'><table class='table'><thead><tr><th>{T("Username")}</th><th></th></tr></thead><tbody>");
        foreach (var member in members)
        {
            var confirm = add ? "" : Confirm(T("Remove {0} from this group?", member.Username));
            body.Append($"<tr><td class='wrap'><a href='{Esc(EditHref(member.UserId))}'>{PersonName(member.Username, member.DisplayName)}</a></td>");
            body.Append($"<td class='fit'><form method='post' action='{path}/members' {confirm}>{Hidden("user_id", member.UserId)}{Hidden("action", add ? "add" : "remove")}<button class='btn' data-variant='outline' data-size='sm'>{T(add ? "Add" : "Remove")}</button></form></td></tr>");
        }
        return body.Append("</tbody></table></div>").ToString();
    }

    private static string BackToGroups() =>
        $"<div class='page-actions'><a class='btn' data-variant='ghost' data-size='sm' href='/admin/groups'>{IconBack}{T("Back to groups")}</a></div>";

    private static string PersonName(string username, string? displayName) =>
        $"<strong>{Esc(displayName ?? username)}</strong>" +
        (string.IsNullOrEmpty(displayName) || displayName == username ? "" : $"<span class='sub'>{Esc(username)}</span>");

    private static string GroupNameForm(string action, string name, string button) =>
        $"<form method='post' action='{action}'><div class='form-grid narrow'><div class='field'><label for='group_name'>{T("Group name")}</label><input id='group_name' name='name' maxlength='64' value='{Esc(name)}' required></div></div><div class='form-foot'><button class='btn'>{button}</button></div></form>";

    private static IReadOnlyList<string> EffectiveScopes(UserDetailView detail, UserResourceEditView resource) =>
        (detail.GrantSources?.Where(s => s.Aud == resource.Aud)
            .SelectMany(s => s.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries)) ?? resource.GrantedScopes)
            .Distinct(StringComparer.Ordinal).ToList();

    private static string UserGrantSourcesSection(UserDetailView detail)
    {
        var body = new StringBuilder();
        if (detail.Groups is { Count: > 0 })
        {
            body.Append("<div class='actions'>");
            foreach (var group in detail.Groups)
                body.Append($"<a class='badge' data-variant='outline' href='{GroupPath(group.Id)}'>{Esc(group.Name)}</a>");
            body.Append("</div>");
        }
        var resources = detail.Resources.Where(r => !r.AdminOnly || detail.User.IsAdmin).ToDictionary(r => r.Aud);
        var sources = detail.GrantSources!.Where(s => resources.ContainsKey(s.Aud)).ToList();
        if (sources.Count == 0) body.Append(Empty(T("No application grants.")));
        else
        {
            body.Append($"<div class='table-container'><table class='table'><thead><tr><th>{T("Resource")}</th><th>{T("Grant source")}</th><th>{T("Scopes")}</th></tr></thead><tbody>");
            foreach (var source in sources)
            {
                var label = source.GroupId is null ? T("Direct assignment") :
                    $"<a href='{GroupPath(source.GroupId)}'>{Esc(source.GroupName)}</a>";
                body.Append($"<tr><td class='wrap'>{Esc(resources[source.Aud].DisplayName)}</td><td class='wrap'>{label}</td><td class='wrap mono'>{Esc(source.Scopes)}</td></tr>");
            }
            body.Append("</tbody></table></div>");
        }
        return Card(T("Grant sources"), T("Effective access combines direct grants and grants from all groups."), body.ToString());
    }
}
