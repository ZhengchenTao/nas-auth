using NasAuth.Config;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using static NasAuth.Endpoints.DashboardSupport;

namespace NasAuth.Endpoints;

public static class ExternalProfileEndpoints
{
    public static void MapExternalProfileEndpoints(this IEndpointRouteBuilder app)
    {
        var admin = app.MapGroup("/admin/directory").RequireAuthorization().AddEndpointFilter(async (context, next) =>
        {
            var ctx = context.HttpContext;
            var (_, user) = WhoAmI(ctx, ctx.RequestServices.GetRequiredService<UserRepository>());
            return IsAdmin(user) ? await next(context) : Results.NotFound();
        }).RequireCsrfToken();
        admin.MapPost("/create", async (HttpContext ctx, DirectoryAccountService directory, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var provider = form["provider"].ToString(); var subject = form["subject"].ToString();
            try
            {
                var fields = directory.Validate(provider, subject, form["profile_json"]);
                var user = directory.Create(provider, subject, fields, ctx.User.Identity!.Name!);
                audit.AccountAction("directory-create", true, ctx.User.Identity.Name!, $"target={user} provider={provider}");
                return Results.Redirect("/admin/users/edit?user=" + Uri.EscapeDataString(user));
            }
            catch (InvalidDataException error) { return Results.BadRequest(new { error = error.Message }); }
        });
        admin.MapPost("/import", (Func<HttpContext, Task<IResult>>)(ctx => Import(ctx, self: false)));
        app.MapGroup("/account/directory").RequireAuthorization().RequireCsrfToken()
            .MapPost("/import", (Func<HttpContext, Task<IResult>>)(ctx => Import(ctx, self: true)));
    }

    private static async Task<IResult> Import(HttpContext ctx, bool self)
    {
        var form = await ctx.Request.ReadFormAsync();
        var provider = form["provider"].ToString(); var subject = form["subject"].ToString();
        var identities = ctx.RequestServices.GetRequiredService<ExternalIdentityRepository>();
        var definition = ctx.RequestServices.GetRequiredService<ExternalProfilesOptions>().Find(provider);
        var row = identities.Get(provider, subject);
        if (row?.status != "active" || row.user_id is null || definition is null ||
            (self && (!definition.AllowSelfRefresh || row.user_id != ctx.User.Identity!.Name))) return Results.NotFound();
        try
        {
            var fields = ctx.RequestServices.GetRequiredService<DirectoryAccountService>().Validate(provider, subject, form["profile_json"]);
            identities.UpdateProfileSnapshot(provider, subject, fields);
            if (!self && form["use_email"] == "1" && fields.TryGetValue(definition.EmailField, out var email))
            {
                var users = ctx.RequestServices.GetRequiredService<UserRepository>();
                var user = users.GetById(row.user_id)!;
                users.UpdateProfile(row.user_id, email, user.allow_password_login != 0);
            }
            ctx.RequestServices.GetRequiredService<AuditLogger>().AccountAction("directory-import", true,
                ctx.User.Identity!.Name!, $"target={row.user_id} provider={provider} mode={(self ? "self" : "admin")} fields={string.Join(',', fields.Keys)}");
            return Results.Redirect(self ? ReturnUrl.SafeLocal(form["return_url"]) : "/admin/users/edit?user=" + Uri.EscapeDataString(row.user_id));
        }
        catch (InvalidDataException error) { return Results.BadRequest(new { error = error.Message }); }
    }
}
