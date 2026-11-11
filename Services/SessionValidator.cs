using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using NasAuth.Data;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

/// <summary>
/// 登录会话的服务端作废（external-auth.md §十六）。
/// 旧 cookie 按 users.session_version / session_epoch 校验后平滑纳入设备记录。
/// 新 cookie 逐次验证服务端 nas_sid；全局撤销同步使设备记录失效，退出其他设备保留当前记录。
/// </summary>
public static class SessionValidator
{
    public const string ClaimType = "nas_sv";
    public const string EpochClaimType = "nas_epoch";

    /// <summary>票据里的版本与库里一致才算有效。老票据没有这个 claim 按 0 算（升级不掉线）。</summary>
    public static bool IsCurrent(ClaimsPrincipal? principal, UserRow? user)
    {
        if (user is null || user.is_disabled != 0 || (principal?.FindFirst(EpochClaimType)?.Value ?? "") != user.session_epoch) return false;
        var raw = principal?.FindFirst(ClaimType)?.Value;
        var version = long.TryParse(raw, out var v) ? v : 0;
        return version == user.session_version;
    }

    public static async Task ValidateAsync(CookieValidatePrincipalContext ctx)
    {
        var uid = ctx.Principal?.Identity?.Name;
        var users = ctx.HttpContext.RequestServices.GetRequiredService<UserRepository>();
        var user = string.IsNullOrEmpty(uid) ? null : users.GetById(uid);
        var sessions = ctx.HttpContext.RequestServices.GetRequiredService<DeviceSessions>();
        var id = DeviceSessions.CurrentId(ctx.Principal);
        if (id is null && IsCurrent(ctx.Principal, user))
        {
            var cookie = ctx.Options.CookieManager.GetRequestCookie(ctx.HttpContext, ctx.Options.Cookie.Name!);
            id = sessions.AdoptLegacy(ctx.HttpContext, user!, cookie ?? "", ctx.Properties.ExpiresUtc);
            if (id is not null)
            {
                var principal = ctx.Principal!.Clone();
                ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(DeviceSessions.ClaimType, id));
                ctx.ReplacePrincipal(principal); ctx.ShouldRenew = true;
            }
        }
        if (id is not null && user is not null &&
            (ctx.Principal?.FindFirst(EpochClaimType)?.Value ?? "") == user.session_epoch &&
            sessions.Validate(id, user.user_id, ctx.HttpContext, touch: true)) return;

        ctx.RejectPrincipal();
        await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }
}
