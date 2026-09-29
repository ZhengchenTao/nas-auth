using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using NasAuth.Data;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

/// <summary>
/// 登录会话的服务端作废（external-auth.md §十六）。
/// 登录 cookie 是 30 天滑动的自包含票据，服务端原本收不回来；现在票据里带登录时的
/// users.session_version，每个请求在 cookie 验证环节比对，对不上（或用户已删）就作废并清 cookie。
/// 退出其他设备 / 改密 / 管理员重置密码或强制下线 = 版本 +1。
/// </summary>
public static class SessionValidator
{
    public const string ClaimType = "nas_sv";

    /// <summary>票据里的版本与库里一致才算有效。老票据没有这个 claim 按 0 算（升级不掉线）。</summary>
    public static bool IsCurrent(ClaimsPrincipal? principal, UserRow? user)
    {
        if (user is null) return false;
        var raw = principal?.FindFirst(ClaimType)?.Value;
        var version = long.TryParse(raw, out var v) ? v : 0;
        return version == user.session_version;
    }

    public static async Task ValidateAsync(CookieValidatePrincipalContext ctx)
    {
        var uid = ctx.Principal?.Identity?.Name;
        var users = ctx.HttpContext.RequestServices.GetRequiredService<UserRepository>();
        var user = string.IsNullOrEmpty(uid) ? null : users.GetById(uid);
        if (IsCurrent(ctx.Principal, user)) return;

        ctx.RejectPrincipal();
        await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }
}
