using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using NasAuth.Config;
using NasAuth.Data.Repositories;
using NasAuth.Pages;
using NasAuth.Services;
using static NasAuth.Pages.I18n;

namespace NasAuth.Endpoints;

/// <summary>
/// forward-auth：给「自己不带登录」的站点在反向代理这一层挡门（external-auth.md §二十二）。
/// <para>四个端点，分落在两个域名上：</para>
/// <list type="bullet">
/// <item><c>GET /forward-auth/verify?aud=…</c> —— 只给反向代理调（Caddy <c>forward_auth</c> / nginx <c>auth_request</c>）。
/// 2xx = 放行；页面导航且没会话 = 302 去登录；其它 = 401。</item>
/// <item><c>GET /forward-auth/start</c> —— 在本服务自己的域名上，要求已登录（没登录走现有登录页再回来），
/// 查这个人能不能进这个站，能就带一次性票据跳回站点。</item>
/// <item><c>GET /.nas-auth/callback</c>、<c>GET /.nas-auth/logout</c> —— 落在<b>被保护站点</b>的域名上
/// （反向代理把 <c>/.nas-auth/*</c> 原样转给本服务），在那个域名上种 / 清站点 cookie。</item>
/// </list>
/// <para>
/// 「这是哪个站」：verify 只认 query 里的 <c>aud</c>，由运维写死在反向代理配置里；
/// <b>不读 <c>X-Forwarded-Host</c></b> —— 反向代理若信任上游代理，访客能自带这个头，
/// 拿着 A 站的 cookie 去 B 站时把自己说成 A 站。回调 / 退出按 <c>Host</c> 头找站点（反向代理按它路由，伪造不了）。
/// </para>
/// </summary>
public static class ForwardAuthEndpoints
{
    public const string UserHeader = "X-Auth-User";
    public const string EmailHeader = "X-Auth-Email";

    public static void MapForwardAuthEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/forward-auth/verify", Verify);
        app.MapGet("/forward-auth/start", Start).RequireAuthorization();
        app.MapGet(ForwardAuthService.PathPrefix + "/callback", Callback);
        app.MapGet(ForwardAuthService.PathPrefix + "/logout", Logout);
    }

    private static IResult Verify(HttpContext ctx, ForwardAuthService fa, ResourceCatalog catalog,
        UserRepository users, UserResourceRepository userResources, ExternalIdentityRepository identities,
        AuthOptions options)
    {
        // aud 不存在、或不是 forward-auth 资源：反向代理把 404 原样回给访客，等于不放行
        var site = catalog.FindForwardAuth(ctx.Request.Query["aud"].ToString());
        if (site is null) return Results.NotFound();

        var req = ctx.Request;
        if (fa.TryReadSession(req.Cookies[ForwardAuthService.SessionCookie], out var session) &&
            session.Aud == site.Aud &&
            users.GetById(session.UserId) is { } user &&
            user.session_version == session.SessionVersion &&   // 强制下线 / 改密 / 退出其他设备后立即失效
            IsAllowed(site, user.user_id, user.is_admin != 0, userResources))
        {
            // 身份头每次都回（没有邮箱回空串）：反向代理配了透传时，访客自带的同名头一定被这里的值盖掉
            var (email, _) = OidcEndpoints.ResolveProfile(identities, users, user.user_id);
            ctx.Response.Headers[UserHeader] = ForwardAuthService.HeaderValue(user.user_id);
            ctx.Response.Headers[EmailHeader] = ForwardAuthService.HeaderValue(email);
            return Results.StatusCode(StatusCodes.Status200OK);
        }

        // 没会话、过期、被作废、授权被撤：都当「没登录」。
        // 被撤授权的人也走跳转，到 /forward-auth/start 那边看带样式的 403 页（这里是站点的域名，引用不了本服务的样式）。
        if (!ForwardAuthService.IsPageNavigation(
                req.Headers["X-Forwarded-Method"].ToString(),
                req.Headers["Sec-Fetch-Mode"].ToString(),
                req.Headers.Accept.ToString()))
            return Results.Text("401 Unauthorized: sign-in required. Reload the page to sign in.",
                statusCode: StatusCodes.Status401Unauthorized);

        // 同一个浏览器并排开几个标签页时共用一个随机数：各自的回调都对得上，不会后开的把先开的顶掉
        var nonce = req.Cookies[ForwardAuthService.StateCookie];
        if (string.IsNullOrEmpty(nonce) || nonce.Length > 64) nonce = ForwardAuthService.NewNonce();
        ctx.Response.Cookies.Append(ForwardAuthService.StateCookie, nonce,
            SiteCookie(ForwardAuthService.StateLifetime));

        var state = fa.CreateState(site.Aud,
            ForwardAuthService.SafeReturnPath(req.Headers["X-Forwarded-Uri"].ToString()), nonce);
        return Results.Redirect(
            $"{options.Issuer.TrimEnd('/')}/forward-auth/start?aud={Uri.EscapeDataString(site.Aud)}&state={state}");
    }

    private static IResult Start(HttpContext ctx, ForwardAuthService fa, ResourceCatalog catalog,
        UserRepository users, UserResourceRepository userResources, AuditLogger audit)
    {
        var site = catalog.FindForwardAuth(ctx.Request.Query["aud"].ToString());
        if (site is null)
            return Page(HtmlTemplates.SimpleMessage(T("Unknown site"), T("This site is not registered here."), isError: true),
                StatusCodes.Status400BadRequest);

        var origin = ResourceCatalog.SiteOrigin(site);
        var rawState = ctx.Request.Query["state"].ToString();
        // state 过期（登录页上停太久）或被改过：回站点重新来一遍，那边会签一份新的
        if (!fa.TryReadState(rawState, out var state) || state.Aud != site.Aud)
            return Results.Redirect(origin + "/");

        var user = users.GetById(ctx.User.Identity!.Name!);
        if (user is null) return Results.Redirect(origin + "/"); // 会话校验刚过、人就被删了

        if (!IsAllowed(site, user.user_id, user.is_admin != 0, userResources))
        {
            audit.ForwardAuth(false, site.Aud, user.user_id, ctx.RemoteIp(), "access_denied_user_resource");
            // 换个账号 = 退出本服务后回到站点，站点再把人送回登录页
            var switchUrl = "/logout?post_logout_redirect_uri=" + Uri.EscapeDataString(origin + "/");
            return Page(HtmlTemplates.ForwardAuthDenied(site.DisplayName, user.user_id, switchUrl),
                StatusCodes.Status403Forbidden);
        }

        audit.ForwardAuth(true, site.Aud, user.user_id, ctx.RemoteIp());
        var ticket = fa.CreateTicket(site.Aud, user.user_id, user.session_version);
        // state 原样带回去，但重新编码：base64 解码会跳过空白，校验通过不代表串里没有不该进 Location 头的字符
        return Results.Redirect(
            $"{origin}{ForwardAuthService.PathPrefix}/callback?ticket={ticket}&state={Uri.EscapeDataString(rawState)}");
    }

    private static IResult Callback(HttpContext ctx, ForwardAuthService fa, ResourceCatalog catalog,
        UserRepository users, ILoggerFactory loggers)
    {
        var site = catalog.FindForwardAuthByHost(ctx.Request.Host);
        if (site is null) return Results.NotFound();

        // 失败一律停在一张说明页上、给一个「重试」链接，不自动跳回去：
        // 浏览器禁了 cookie 这类必然失败的情况，自动重试就是无限重定向
        IResult Fail(string reason)
        {
            loggers.CreateLogger("nas-auth.forward-auth").LogWarning(
                "forward-auth 回调被拒 aud={Aud} reason={Reason} ip={Ip}", site.Aud, reason, ctx.RemoteIp() ?? "-");
            return Page(HtmlTemplates.Bare(T("Sign-in could not be completed"),
                    T("The sign-in link has expired or was already used. Make sure cookies are enabled for this site, then try again."),
                    "/", T("Try again")),
                StatusCodes.Status400BadRequest);
        }

        var q = ctx.Request.Query;
        if (!fa.TryReadTicket(q["ticket"].ToString(), out var ticket) || ticket.Aud != site.Aud)
            return Fail("bad_ticket");
        if (!fa.TryReadState(q["state"].ToString(), out var state) || state.Aud != site.Aud)
            return Fail("bad_state");
        // 发起这次登录的必须是同一个浏览器：别人把自己的回调链接发来点，这里对不上
        if (!ForwardAuthService.NonceMatches(ctx.Request.Cookies[ForwardAuthService.StateCookie], state.Nonce))
            return Fail("state_cookie_mismatch");
        if (!fa.TryConsume(ticket)) return Fail("ticket_replayed");

        var user = users.GetById(ticket.UserId);
        if (user is null || user.session_version != ticket.SessionVersion) return Fail("session_revoked");

        var lifetime = TimeSpan.FromHours(site.ForwardAuth!.SessionHours);
        ctx.Response.Cookies.Append(ForwardAuthService.SessionCookie,
            fa.CreateSession(site.Aud, user.user_id, user.session_version, lifetime), SiteCookie(lifetime));
        // state cookie 不清，让它自己过期：并排开的其它标签页各有一张没用过的票据，还要靠它完成自己的回调。
        // 重放由「票据只能用一次」挡，不靠清这张 cookie。
        return Results.Redirect(ForwardAuthService.SafeReturnPath(state.ReturnPath));
    }

    /// <summary>
    /// 站点上的退出：清本站 cookie，再去本服务退出登录会话（不退的话下一次访问就静默登回来，等于没退）。
    /// 其它被保护站点的 cookie 不在这个域名上，清不到，留到各自到期。GET 即可：被人诱导退出没有危害。
    /// </summary>
    private static IResult Logout(HttpContext ctx, ResourceCatalog catalog, AuthOptions options)
    {
        var site = catalog.FindForwardAuthByHost(ctx.Request.Host);
        if (site is null) return Results.NotFound();

        ctx.Response.Cookies.Delete(ForwardAuthService.SessionCookie, SiteCookie(null));
        var back = Uri.EscapeDataString(ResourceCatalog.SiteOrigin(site) + "/");
        return Results.Redirect($"{options.Issuer.TrimEnd('/')}/logout?post_logout_redirect_uri={back}");
    }

    /// <summary>admin_only + user_resources，与 /authorize 的用户级授权检查同一套判据（§5.5）。</summary>
    private static bool IsAllowed(ResourceConfig site, string userId, bool isAdmin, UserResourceRepository userResources) =>
        site.AllowsUser(isAdmin) && userResources.IsAllowed(userId, site.Aud, Array.Empty<string>());

    /// <summary>
    /// 站点域名上的 cookie：<c>__Host-</c> 前缀要求 Secure + Path=/ + 不带 Domain（删除时也要带齐，否则浏览器不认）。
    /// SameSite 只能是 Lax：Strict 的 cookie 在「外站链接点进来 → 一串跳转」里全程不回传，登录完又被当成没登录。
    /// </summary>
    private static CookieOptions SiteCookie(TimeSpan? lifetime) => new()
    {
        Path = "/",
        Secure = true,
        HttpOnly = true,
        SameSite = SameSiteMode.Lax,
        MaxAge = lifetime,
    };

    private static IResult Page(string html, int statusCode) =>
        Results.Content(html, "text/html; charset=utf-8", statusCode: statusCode);
}
