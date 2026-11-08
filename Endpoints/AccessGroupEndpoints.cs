using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Pages;
using NasAuth.Services;
using static NasAuth.Endpoints.DashboardSupport;
using static NasAuth.Pages.I18n;

namespace NasAuth.Endpoints;

internal static class AccessGroupEndpoints
{
    internal static void MapAccessGroupEndpoints(this RouteGroupBuilder admin)
    {
        var routes = admin.MapGroup("/groups");
        routes.MapGet("", (HttpContext ctx, AccessGroupService groups, UserRepository users,
            ExternalIdentityRepository identities) =>
            Render(ctx, users, identities, DashboardSpace.Admin, "groups", "Groups",
                DashboardTemplates.GroupsSection(groups.List())));

        routes.MapGet("/new", (HttpContext ctx, UserRepository users, ExternalIdentityRepository identities) =>
            Render(ctx, users, identities, DashboardSpace.Admin, "groups", "New group",
                DashboardTemplates.NewGroupSection()));

        routes.MapPost("/new", async (HttpContext ctx, AccessGroupService groups, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var name = ValidName(form["name"].ToString());
            if (name is null) return RedirectTo("/admin/groups/new", error: T("Enter a group name of up to 64 characters."));
            var id = groups.Create(name);
            if (id is null) return RedirectTo("/admin/groups/new", error: T("A group with this name already exists."));
            Log(ctx, audit, "group-create", id);
            return RedirectTo(GroupPath(id), notice: T("Group created."));
        });

        routes.MapGet("/{id}", (string id, HttpContext ctx, AccessGroupService groups, UserRepository users,
            ExternalIdentityRepository identities) =>
        {
            var group = groups.Find(id);
            if (group is null) return Results.NotFound();
            var members = groups.Members(id);
            var filter = UserDirectoryFilter.Normalize(ctx.Request.Query["q"]);
            var search = filter.Query.Length == 0 ? null : users.Search(filter, excludeGroup: id);
            var candidates = search?.Users
                .Select(u => new GroupMember(u.user_id, u.username, u.display_name, u.is_admin)).ToList();
            return Render(ctx, users, identities, DashboardSpace.Admin, "groups", T("Group · {0}", group.Name),
                DashboardTemplates.GroupSection(group, groups.Applications(), groups.Grants(id), members,
                    filter.Query, candidates, search is not null && search.Total > search.Users.Count));
        });

        routes.MapPost("/{id}/name", async (string id, HttpContext ctx, AccessGroupService groups, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var name = ValidName(form["name"].ToString());
            if (name is null) return RedirectTo(GroupPath(id), error: T("Enter a group name of up to 64 characters."));
            if (!groups.Rename(id, name)) return RedirectTo(GroupPath(id), error: T("Could not save the group name."));
            Log(ctx, audit, "group-rename", id);
            return RedirectTo(GroupPath(id), notice: T("Group name saved."));
        });

        routes.MapPost("/{id}/members", async (string id, HttpContext ctx, AccessGroupService groups, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var userId = form["user_id"].ToString();
            var action = form["action"].ToString();
            if (action is not ("add" or "remove")) return Results.BadRequest();
            if (!groups.ChangeMember(id, userId, action == "add"))
                return RedirectTo(GroupPath(id), error: T("Membership has changed. Reload the group and try again."));
            Log(ctx, audit, "group-member-" + action, id, userId);
            return RedirectTo(GroupPath(id), notice: T(action == "add" ? "Member added." : "Member removed."));
        });

        routes.MapPost("/{id}/grants", async (string id, HttpContext ctx, AccessGroupService groups,
            UserRepository users, ExternalIdentityRepository identities, NasAuth.Config.ProvisioningOptions options, AuditLogger audit) =>
        {
            var group = groups.Find(id);
            if (group is null) return Results.NotFound();
            var form = await ctx.Request.ReadFormAsync();
            var selected = form["application"].Select(x => x ?? "").Distinct(StringComparer.Ordinal).ToList();
            var stamp = form["stamp"].FirstOrDefault();
            var preview = groups.ChangeGrants(id, selected, stamp, out var saved);
            if (preview is null) return RedirectTo(GroupPath(id), error: T("The application selection has changed. Try again."));
            if (saved)
            {
                Log(ctx, audit, "group-grants-update", id);
                return RedirectTo(GroupPath(id), notice: T("Group access saved."));
            }
            return Render(ctx, users, identities, DashboardSpace.Admin, "groups", "Review group access",
                DashboardTemplates.GroupPreviewSection(group, groups.Applications(), selected, preview, options, stamp is not null));
        });

        routes.MapPost("/{id}/delete", (string id, HttpContext ctx, AccessGroupService groups, AuditLogger audit) =>
        {
            if (!groups.DeleteEmpty(id)) return RedirectTo(GroupPath(id), error: T("Remove all members before deleting the group."));
            Log(ctx, audit, "group-delete", id);
            return RedirectTo("/admin/groups", notice: T("Group deleted."));
        });
    }

    internal static string GroupPath(string id) => "/admin/groups/" + Uri.EscapeDataString(id);

    private static string? ValidName(string value)
    {
        var name = value.Trim();
        return name.Length is > 0 and <= 64 && !name.Any(char.IsControl) ? name : null;
    }

    private static void Log(HttpContext ctx, AuditLogger audit, string action, string id, string? userId = null) =>
        audit.AccountAction(action, true, ctx.User.Identity?.Name ?? "", $"group={id} target={userId ?? "-"}");
}
