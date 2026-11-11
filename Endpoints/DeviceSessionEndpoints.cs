using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using NasAuth.Data.Repositories;
using NasAuth.Pages;
using NasAuth.Services;
using static NasAuth.Endpoints.DashboardSupport;
using static NasAuth.Pages.I18n;

namespace NasAuth.Endpoints;

public static class DeviceSessionEndpoints
{
    private static string AuditId(string id) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(id)))[..12];

    internal static void MapPersonalDeviceEndpoints(this RouteGroupBuilder account)
    {
        account.MapGet("/sessions", (HttpContext ctx, UserRepository users, ExternalIdentityRepository identities, DeviceSessions sessions) => {
            var userId = ctx.User.Identity!.Name!;
            return Render(ctx, users, identities, DashboardSpace.Personal, "sessions", "Devices and sessions",
                DashboardTemplates.DeviceSessionsSection(sessions.List(userId), DeviceSessions.CurrentId(ctx.User), sessions, userId));
        });
        account.MapPost("/sessions/name", async (HttpContext ctx, DeviceSessions sessions, AuditLogger audit) => {
            var form = await ctx.Request.ReadFormAsync(); var id = form["id"].ToString(); var userId = ctx.User.Identity!.Name!;
            if (!sessions.Rename(userId, id, form["name"].ToString())) return Results.BadRequest(T("The device name or session is unavailable."));
            audit.AccountAction("session-name", true, userId, "session=" + AuditId(id));
            return RedirectTo("/account/sessions", notice: T("Device name saved."));
        });
        account.MapPost("/sessions/revoke", async (HttpContext ctx, DeviceSessions sessions, AuditLogger audit) => {
            var form = await ctx.Request.ReadFormAsync(); var id = form["id"].ToString(); var userId = ctx.User.Identity!.Name!;
            if (!sessions.Revoke(userId, id)) return Results.NotFound();
            audit.AccountAction("session-revoke", true, userId, "session=" + AuditId(id));
            if (id == DeviceSessions.CurrentId(ctx.User)) { await ctx.SignOutAsync(); return Results.Redirect("/login?notice=" + AccountEndpoints.LoginNoticeSignedOut); }
            return RedirectTo("/account/sessions", notice: T("The selected device has been signed out."));
        });
    }

    internal static void MapAdminDeviceEndpoints(this RouteGroupBuilder admin)
    {
        admin.MapPost("/users/sessions/revoke", async (HttpContext ctx, DeviceSessions sessions, AuditLogger audit) => {
            var form = await ctx.Request.ReadFormAsync(); var id = form["id"].ToString(); var userId = form["user_id"].ToString();
            if (!sessions.Revoke(userId, id)) return Results.NotFound();
            audit.AccountAction("admin-session-revoke", true, ctx.User.Identity!.Name!, $"target={userId} session={AuditId(id)}");
            if (id == DeviceSessions.CurrentId(ctx.User)) { await ctx.SignOutAsync(); return Results.Redirect("/login?notice=" + AccountEndpoints.LoginNoticeSignedOut); }
            return RedirectTo("/admin/users/edit?user=" + Uri.EscapeDataString(userId), notice: T("The selected device has been signed out."));
        });
    }
}
