using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.OAuth;
using NasAuth.Config;
using NasAuth.Data.Repositories;
using NasAuth.Pages;
using NasAuth.Services;

namespace NasAuth.Endpoints;

/// <summary>
/// 外部登录（外部认证设计 §五 / §六）。
/// 流程：/external/{provider}/start 发起 Challenge → 框架 handler 在 /signin/{provider}
/// 处理 IdP 回调（state + correlation cookie CSRF 防护由框架完成）并把外部身份
/// 写进短寿命 external cookie → /external/complete 读出来跑 §5.2 状态机。
/// 只有 active 才建立主会话（与密码登录成功后同一个 SignInCookie 路径）。
/// </summary>
public static class ExternalLoginEndpoints
{
    /// <summary>承接 IdP 回调结果的临时 cookie scheme，与主会话 cookie 分离。</summary>
    public const string ExternalScheme = "external";

    private const string ProviderKey = "provider";
    private const string ReturnUrlKey = "return_url";
    private const string ModeKey = "mode";
    private const string BindUserKey = "bind_user";
    public const string BindPromptKey = "prompt";
    public const string BindPrompt = "select_account";

    public static void MapExternalLoginEndpoints(this IEndpointRouteBuilder app)
    {
        // 发起外部登录。provider 未启用（凭证没配）→ 404。
        app.MapGet("/external/{provider}/start", (string provider, HttpContext ctx,
            ExternalProviderOptions providers) =>
        {
            var scheme = SchemeOf(provider);
            if (scheme is null || !providers.IsEnabled(provider))
                return Results.NotFound();

            var returnUrl = ReturnUrl.SafeLocal(ctx.Request.Query[ReturnUrlKey].ToString());

            // provider / return_url 走 AuthenticationProperties.Items：
            // 随 OAuth state 防篡改往返，不信任 complete 端的 query 参数。
            var props = new AuthenticationProperties
            {
                RedirectUri = "/external/complete",
                Items = { [ProviderKey] = provider, [ReturnUrlKey] = returnUrl },
            };
            // 一律强制 IdP 弹账号选择器（2026-09-30 起；此前只有「换个账号」入口的 select_account=1 才带，参数现保留兼容）。
            // 不带的话 Google / 微软会静默选浏览器里当前登着的那个账号：想换号的人换不掉；
            // 共用电脑上前一个人退出应用（nas-auth 也联动退出）后，下一个人点「通过 Google 继续」照样被静默登成前一个人。
            props.SetParameter(BindPromptKey, BindPrompt);
            return Results.Challenge(props, new[] { scheme });
        });

        // 自绑定（设计 §5.3 bootstrap）：已登录用户把外部身份直接绑到自己头上，不走审批。
        // 硬约束（§九）：必须已有活跃会话；绑定目标 user_id 取自会话并经 OAuth state
        // 防篡改往返，complete 端再与当时的会话二次核对。
        // 只收 POST（2026-09-29 安全修复）：原先是 GET，任何站点都能把已登录的管理员导航过来，
        // IdP 静默同意后就把浏览器里当前那个 Google / Microsoft 账号绑到管理员头上。
        // POST 受 CrossOriginGuard 保护；再加 prompt=select_account，每次绑定都弹账号选择器。
        app.MapPost("/external/{provider}/bind", (string provider, HttpContext ctx,
            ExternalProviderOptions providers) =>
        {
            var scheme = SchemeOf(provider);
            if (scheme is null || !providers.IsEnabled(provider))
                return Results.NotFound();

            var sessionUid = ctx.User?.Identity?.IsAuthenticated == true ? ctx.User.Identity.Name : null;
            if (string.IsNullOrEmpty(sessionUid))
                return Results.Redirect("/login?return_url=" + Uri.EscapeDataString("/account/security"));

            var props = new AuthenticationProperties
            {
                RedirectUri = "/external/complete",
                Items =
                {
                    [ProviderKey] = provider,
                    [ModeKey] = "bind",
                    [BindUserKey] = sessionUid,
                    [ReturnUrlKey] = "/account/security",
                },
            };
            // Google / MicrosoftAccount handler 都从 AuthenticationProperties.Parameters 取 "prompt" 拼进授权 URL
            props.SetParameter(BindPromptKey, BindPrompt);
            return Results.Challenge(props, new[] { scheme });
        });

        // IdP 回调完成后的落点：external cookie → 登录 §5.2 状态机 / 自绑定 §5.3。
        app.MapGet("/external/complete", async (HttpContext ctx,
            ExternalSignInService signIn, AuditLogger audit,
            ExternalProviderOptions providers, PasswordLoginGate passwordLogin,
            UserRepository users, ExternalIdentityRepository identities) =>
        {
            var auth = await ctx.AuthenticateAsync(ExternalScheme);
            if (!auth.Succeeded || auth.Principal is null)
                return ErrorPage(ctx, StatusCodes.Status400BadRequest,
                    "External sign-in failed",
                    "No external sign-in result found. Please start over from the sign-in page.");

            // 一次性消费，立刻清掉临时 cookie
            await ctx.SignOutAsync(ExternalScheme);

            auth.Properties!.Items.TryGetValue(ProviderKey, out var provider);
            auth.Properties.Items.TryGetValue(ReturnUrlKey, out var rawReturnUrl);
            if (provider is not "google" and not "microsoft")
                return ErrorPage(ctx, StatusCodes.Status400BadRequest,
                    "External sign-in failed", "Unknown provider.");
            var returnUrl = ReturnUrl.SafeLocal(rawReturnUrl);

            var subject = ExternalClaims.GetSubject(provider, auth.Principal);
            if (string.IsNullOrEmpty(subject))
            {
                audit.ExternalLogin(false, provider, "-", null, ctx.RemoteIp(), "no_subject_claim");
                return ErrorPage(ctx, StatusCodes.Status400BadRequest,
                    "External sign-in failed", "The identity provider did not return a stable subject.");
            }

            var email = ExternalClaims.GetEmail(auth.Principal);
            var displayName = ExternalClaims.GetDisplayName(auth.Principal);
            var avatar = ExternalClaims.GetAvatar(auth.Principal);

            // ---- 自绑定模式（§5.3）----
            auth.Properties.Items.TryGetValue(ModeKey, out var mode);
            if (mode == "bind")
            {
                auth.Properties.Items.TryGetValue(BindUserKey, out var bindUser);
                var sessionUid = ctx.User?.Identity?.IsAuthenticated == true ? ctx.User.Identity.Name : null;
                // 活跃会话仍在，且与发起绑定时是同一个人
                if (string.IsNullOrEmpty(sessionUid) || sessionUid != bindUser)
                {
                    audit.ExternalLogin(false, provider, subject, bindUser, ctx.RemoteIp(), "bind_session_mismatch");
                    return ErrorPage(ctx, StatusCodes.Status403Forbidden,
                        "Binding failed", "Your session changed during the binding flow. Please sign in and try again.");
                }

                var bindError = signIn.BindToUser(provider, subject, sessionUid, email, displayName);
                if (bindError is not null)
                {
                    audit.ExternalLogin(false, provider, subject, sessionUid, ctx.RemoteIp(), "bind_refused");
                    return ErrorPage(ctx, StatusCodes.Status409Conflict, "Binding failed", bindError);
                }

                // §十九：刷新该外部账号的名字 / 头像快照；用户自己还没设昵称 / 头像就用它补上
                identities.UpdateSnapshot(provider, subject, displayName, avatar);
                users.FillProfileIfEmpty(sessionUid, displayName, avatar);
                audit.ExternalLogin(true, provider, subject, sessionUid, ctx.RemoteIp(), "bind");
                // 绑定结果页二次展示绑到了哪个 user（§九）
                return Results.Content(
                    HtmlTemplates.ExternalBindResult(provider, email, sessionUid),
                    "text/html; charset=utf-8");
            }

            // ---- 登录模式（§5.2 状态机）----
            var result = signIn.Resolve(provider, subject, email, displayName,
                ExternalClaims.IsEmailVerified(provider, auth.Principal));
            // §十九：每次外部登录都刷新快照（待批的也存，审批通过时给新用户补昵称 / 头像）
            identities.UpdateSnapshot(provider, subject, displayName, avatar);
            switch (result.Status)
            {
                case ExternalSignInStatus.Active:
                case ExternalSignInStatus.ActiveByInvite:
                    users.FillProfileIfEmpty(result.User!.user_id, displayName, avatar);
                    await AuthorizationEndpoints.SignInCookie(ctx, result.User!.user_id);
                    audit.ExternalLogin(true, provider, subject, result.User.user_id, ctx.RemoteIp(),
                        result.Status == ExternalSignInStatus.ActiveByInvite ? "invite_redeemed" : null);
                    return Results.Redirect(DashboardSupport.LandingFor(returnUrl, result.User));

                case ExternalSignInStatus.PendingNew:
                case ExternalSignInStatus.PendingExisting:
                    audit.ExternalLogin(false, provider, subject, null, ctx.RemoteIp(),
                        result.Status == ExternalSignInStatus.PendingNew ? "pending_created" : "pending");
                    return Results.Content(
                        HtmlTemplates.ExternalPending(provider, email,
                            SwitchOptions(returnUrl, providers, passwordLogin)),
                        "text/html; charset=utf-8");

                case ExternalSignInStatus.Rejected:
                default:
                    audit.ExternalLogin(false, provider, subject, null, ctx.RemoteIp(),
                        result.Status == ExternalSignInStatus.OrphanedActive ? "orphaned_active" : "rejected");
                    return ErrorPage(ctx, StatusCodes.Status403Forbidden,
                        "Access denied", "This external account is not allowed to sign in.",
                        SwitchOptions(returnUrl, providers, passwordLogin));
            }
        });
    }

    /// <summary>
    /// §十九：在 IdP 回调建票据时把外部头像下载存好，文件名作为 claim 随外部登录 cookie 带到 /external/complete。
    /// 只存文件名不存图片本身：外部 cookie 有大小上限。下载失败不影响登录。
    /// </summary>
    public static async Task AttachAvatarAsync(OAuthCreatingTicketContext ctx, string url, string? bearerToken)
    {
        var sp = ctx.HttpContext.RequestServices;
        var http = sp.GetRequiredService<IHttpClientFactory>().CreateClient(ProfileService.HttpClientName);
        var file = await sp.GetRequiredService<ProfileService>().DownloadAsync(http, url, bearerToken, ctx.HttpContext.RequestAborted);
        if (file is not null) ctx.Identity?.AddClaim(new Claim(ExternalClaims.AvatarClaimType, file));
    }

    /// <summary>
    /// IdP 回调失败（用户取消授权、IdP 返回 error 参数、token 交换失败等）的兜底。
    /// 默认行为是 throw → 500 白页；这里改为渲染友好错误页并吞掉异常。
    /// 错误详情只进日志不上页面（避免把 IdP 原始 error_description 直接暴露给访客）。
    /// </summary>
    public static Task HandleRemoteFailure(Microsoft.AspNetCore.Authentication.RemoteFailureContext ctx)
    {
        var logger = ctx.HttpContext.RequestServices
            .GetRequiredService<ILoggerFactory>().CreateLogger("ExternalLogin");
        logger.LogWarning(ctx.Failure, "外部登录回调失败: {Message}", ctx.Failure?.Message);

        ctx.Response.StatusCode = StatusCodes.Status502BadGateway;
        ctx.Response.ContentType = "text/html; charset=utf-8";
        ctx.HandleResponse(); // 阻止异常继续抛成 500
        // 用户在 IdP 页取消 / 选错后返回，也给「换个账号」出口，并尽量回到原来的授权页
        string? returnUrl = null;
        ctx.Properties?.Items.TryGetValue(ReturnUrlKey, out returnUrl);
        var sp = ctx.HttpContext.RequestServices;
        return ctx.Response.WriteAsync(HtmlTemplates.ExternalError(
            "External sign-in failed",
            "The identity provider returned an error or the sign-in was cancelled. Please try again from the sign-in page.",
            SwitchOptions(ReturnUrl.SafeLocal(returnUrl), sp.GetRequiredService<ExternalProviderOptions>(),
                sp.GetRequiredService<PasswordLoginGate>())));
    }

    private static string? SchemeOf(string provider) => provider switch
    {
        "google" => GoogleDefaults.AuthenticationScheme,
        "microsoft" => MicrosoftAccountDefaults.AuthenticationScheme,
        _ => null,
    };

    private static IResult ErrorPage(HttpContext ctx, int statusCode, string title, string message,
        SwitchAccountOptions? switchOptions = null)
    {
        ctx.Response.StatusCode = statusCode;
        return Results.Content(HtmlTemplates.ExternalError(title, message, switchOptions), "text/html; charset=utf-8");
    }

    /// <summary>等待批准 / 被拒 / IdP 失败页上「换个账号」出口需要的信息（此时没有会话，全靠 return_url 回原流程）。</summary>
    private static SwitchAccountOptions SwitchOptions(string returnUrl, ExternalProviderOptions providers,
        PasswordLoginGate passwordLogin) =>
        new(returnUrl, providers.GoogleEnabled, providers.MicrosoftEnabled, passwordLogin.Enabled);
}
