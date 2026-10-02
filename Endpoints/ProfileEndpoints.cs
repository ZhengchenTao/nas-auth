using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using static NasAuth.Endpoints.DashboardSupport;
using static NasAuth.Pages.I18n;

namespace NasAuth.Endpoints;

/// <summary>
/// 昵称与头像（external-auth.md §十九）：公开的头像文件、个人中心自己改、管理后台替人改。
/// </summary>
public static class ProfileEndpoints
{
    public static void MapProfileEndpoints(this IEndpointRouteBuilder app)
    {
        // 头像文件：下发的 picture 指向这里，各应用（Gitea / Immich / Open WebUI）服务端或浏览器直接拉，所以不要求登录。
        // 文件名是内容哈希、改头像就换地址 → 可以长期缓存。图片之外的东西进不来（ProfileService 按文件头只收 PNG / JPG / WebP），
        // 再加 nosniff + 沙箱 CSP：万一被当页面打开也不执行任何东西。
        app.MapGet("/avatars/{file}", (HttpContext ctx, string file, ProfileService profiles) =>
        {
            var path = profiles.PathFor(file);
            if (path is null) return Results.NotFound();
            var h = ctx.Response.Headers;
            h.CacheControl = "public, max-age=31536000, immutable";
            h.Pragma = Microsoft.Extensions.Primitives.StringValues.Empty;
            h.ContentSecurityPolicy = "default-src 'none'; sandbox";
            h.XContentTypeOptions = "nosniff";
            return Results.File(path, ProfileService.ContentTypeOf(file));
        });

        // ----- 个人中心：自己改 -----
        var account = app.MapGroup("/account").RequireAuthorization();

        account.MapPost("/profile", async (HttpContext ctx, UserRepository users, AuditLogger audit) =>
        {
            var userId = ctx.User.Identity?.Name ?? "";
            var form = await ctx.Request.ReadFormAsync();
            users.UpdateDisplayName(userId, form["display_name"].ToString());
            audit.AccountAction("profile-update", true, userId, "field=display_name");
            return RedirectTo("/account", notice: T("Profile saved"));
        });

        account.MapPost("/avatar", async (HttpContext ctx, UserRepository users, ProfileService profiles, AuditLogger audit) =>
        {
            var userId = ctx.User.Identity?.Name ?? "";
            var (file, error) = await ReadUploadAsync(ctx, profiles);
            if (error is not null) return RedirectTo("/account", error: error);
            users.UpdateAvatar(userId, file);
            audit.AccountAction("profile-update", true, userId, "field=avatar source=upload");
            return RedirectTo("/account", notice: T("Avatar updated"));
        });

        account.MapPost("/avatar/remove", (HttpContext ctx, UserRepository users, AuditLogger audit) =>
        {
            var userId = ctx.User.Identity?.Name ?? "";
            users.UpdateAvatar(userId, null);
            audit.AccountAction("profile-update", true, userId, "field=avatar source=removed");
            return RedirectTo("/account", notice: T("Avatar removed"));
        });

        // 用某个已绑定外部账号（最近一次登录时缓存）的头像 / 名字
        account.MapPost("/profile/from-identity", async (HttpContext ctx,
            UserRepository users, ExternalIdentityRepository identities, AuditLogger audit) =>
        {
            var userId = ctx.User.Identity?.Name ?? "";
            var form = await ctx.Request.ReadFormAsync();
            var provider = form["provider"].ToString();
            var row = identities.Get(provider, form["subject"].ToString());
            if (row is null || row.user_id != userId || row.status != "active")
                return RedirectTo("/account", error: T("Binding not found"));

            var field = form["field"].ToString();
            if (field == "avatar" && !string.IsNullOrEmpty(row.avatar))
                users.UpdateAvatar(userId, row.avatar);
            else if (field == "name" && !string.IsNullOrEmpty(row.display_name))
                users.UpdateDisplayName(userId, row.display_name);
            else
                return RedirectTo("/account", error: T("Nothing to copy from that account yet; sign in with it once first"));

            audit.AccountAction("profile-update", true, userId, $"field={field} source={provider}");
            return RedirectTo("/account", notice: T("Profile saved"));
        });

        // ----- 管理后台：替人改头像（昵称随 /admin/users/update 一起改）-----
        var admin = app.MapGroup("/admin").RequireAuthorization()
            .AddEndpointFilter(async (ic, next) =>   // 同 AdminEndpoints 的门禁：非管理员一律 404
            {
                var c = ic.HttpContext;
                var (_, me) = WhoAmI(c, c.RequestServices.GetRequiredService<UserRepository>());
                return IsAdmin(me) ? await next(ic) : Results.NotFound();
            });

        admin.MapPost("/users/avatar", async (HttpContext ctx, UserRepository users, ProfileService profiles, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var targetId = form["user_id"].ToString();
            if (users.GetById(targetId) is null) return RedirectTo("/admin/users", error: T("User does not exist"));
            var (file, error) = await ReadUploadAsync(ctx, profiles);
            if (error is not null) return RedirectTo(EditPath(targetId), error: error);
            users.UpdateAvatar(targetId, file);
            audit.AccountAction("admin-profile-update", true, AdminId(ctx), $"target={targetId} field=avatar");
            return RedirectTo(EditPath(targetId), notice: T("Avatar updated"));
        });

        admin.MapPost("/users/avatar/remove", async (HttpContext ctx, UserRepository users, AuditLogger audit) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var targetId = form["user_id"].ToString();
            if (users.GetById(targetId) is null) return RedirectTo("/admin/users", error: T("User does not exist"));
            users.UpdateAvatar(targetId, null);
            audit.AccountAction("admin-profile-update", true, AdminId(ctx), $"target={targetId} field=avatar removed");
            return RedirectTo(EditPath(targetId), notice: T("Avatar removed"));
        });
    }

    private static string EditPath(string userId) => "/admin/users/edit?user=" + Uri.EscapeDataString(userId);
    private static string AdminId(HttpContext ctx) => ctx.User.Identity?.Name ?? "";

    /// <summary>读上传的头像（字段名 avatar）并存好；返回 (文件名, 错误文案)。</summary>
    private static async Task<(string? File, string? Error)> ReadUploadAsync(HttpContext ctx, ProfileService profiles)
    {
        var form = await ctx.Request.ReadFormAsync();
        var upload = form.Files.GetFile("avatar");
        if (upload is null || upload.Length == 0) return (null, T("Choose an image file"));
        if (upload.Length > ProfileService.MaxAvatarBytes) return (null, T("Image is larger than 2 MB"));
        using var ms = new MemoryStream();
        await upload.CopyToAsync(ms);
        var file = profiles.Store(ms.ToArray());
        return file is null ? (null, T("Only PNG, JPEG or WebP images are accepted")) : (file, null);
    }
}
