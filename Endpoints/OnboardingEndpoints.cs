using Microsoft.AspNetCore.Authentication;
using NasAuth.Config;
using NasAuth.Data.Repositories;
using NasAuth.Pages;
using NasAuth.Services;
using static NasAuth.Endpoints.DashboardSupport;
using static NasAuth.Pages.I18n;

namespace NasAuth.Endpoints;

public static class OnboardingEndpoints
{
    internal static void MapOnboardingAdminEndpoints(this RouteGroupBuilder admin)
    {
        admin.MapGet("/apps/new", (HttpContext ctx, UserRepository users, ExternalIdentityRepository identities) =>
            Render(ctx, users, identities, DashboardSpace.Admin, "apps", "Connect an application",
                DashboardTemplates.ApplicationSetupSection(new(new(), []))));
        admin.MapPost("/apps/new", async (HttpContext ctx, UserRepository users, ExternalIdentityRepository identities, ApplicationOnboarding onboarding) => {
            var form = await ctx.Request.ReadFormAsync();
            string Read(string key, int max) => form[key].ToString().Trim() is var value && value.Length <= max ? value : value[..(max + 1)];
            var input = new ApplicationSetupInput(Read("id", 48), Read("name", 80), Read("kind", 20), Read("url", 2048), Read("callbacks", 4096), Read("scopes", 2048), Read("client_type", 20));
            return Render(ctx, users, identities, DashboardSpace.Admin, "apps", "Connect an application", DashboardTemplates.ApplicationSetupSection(onboarding.Generate(input)));
        });
        admin.MapPost("/users/credential-links/issue", async (HttpContext ctx, UserRepository users,
            ExternalIdentityRepository identities, CredentialLinkService links, AuthOptions auth, AuditLogger audit) => {
            var form = await ctx.Request.ReadFormAsync();
            var id = form["user_id"].ToString();
            if (form["verified"] != "1") return RedirectTo("/admin/users/edit?user=" + Uri.EscapeDataString(id), error: T("Verify the recipient's identity before issuing a link."));
            var history = links.List(id);
            var purpose = history.Any(l => l.purpose == "invitation") && !history.Any(l => l.state == "used") ? "invitation" : "recovery";
            var issued = links.Issue(ctx.User.Identity!.Name!, id, purpose);
            if (issued is null) return RedirectTo("/admin/users/edit?user=" + Uri.EscapeDataString(id), error: T("A password link cannot be issued for this account. Check its status and password access."));
            audit.AccountAction("credential-link-issue", true, ctx.User.Identity.Name!, $"target={id} link={issued.Id} purpose={purpose}");
            return Render(ctx, users, identities, DashboardSpace.Admin, "users", "Password link created", DashboardTemplates.IssuedCredentialSection(issued, auth.Issuer));
        });
        admin.MapPost("/users/credential-links/cancel", async (HttpContext ctx, CredentialLinkService links, AuditLogger audit) => {
            var form = await ctx.Request.ReadFormAsync(); var id = form["user_id"].ToString();
            var cancelled = links.Cancel(ctx.User.Identity!.Name!, id, form["id"].ToString());
            audit.AccountAction("credential-link-cancel", cancelled, ctx.User.Identity.Name!, $"target={id}");
            return RedirectTo("/admin/users/edit?user=" + Uri.EscapeDataString(id), notice: T("Link status updated."));
        });
    }

    public static void MapCredentialLinkEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/credential-link", (HttpContext ctx) => Results.Content(AntiforgeryGuard.Protect(ctx,
            DashboardTemplates.CredentialEntryPage()), "text/html; charset=utf-8"));
        app.MapPost("/credential-link", async (HttpContext ctx, CredentialLinkService links, AuditLogger audit) => {
            var form = await ctx.Request.ReadFormAsync();
            var password = form["new_password"].ToString(); var token = form["token"].ToString();
            if (token.Length != 64 || !token.All(Uri.IsHexDigit)) token = "";
            string? error = password.Length is < 8 or > 256 ? "Use a password between 8 and 256 characters."
                : password != form["confirm_password"].ToString() ? "Passwords do not match" : null;
            var userId = error is null ? links.Redeem(token, password) : null;
            if (error is null && userId is null) error = "This link is invalid, expired or no longer available. Ask your administrator for a new link.";
            audit.AccountAction("credential-link-redeem", userId is not null, userId ?? "-", userId is null ? "rejected" : "password-set");
            if (userId is not null && ctx.User.Identity?.Name == userId) await ctx.SignOutAsync();
            return Results.Content(AntiforgeryGuard.Protect(ctx,
                DashboardTemplates.CredentialEntryPage(error, userId is not null, error is not null ? token : "")),
                "text/html; charset=utf-8", statusCode: error is null ? 200 : 400);
        }).RequireCsrfToken(includeAnonymous: true).RequireRateLimiting("auth-sensitive");
    }
}
