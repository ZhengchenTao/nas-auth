using System.Text;
using NasAuth.Services;
using static NasAuth.Pages.I18n;
using static NasAuth.Pages.Ui;

namespace NasAuth.Pages;

/// <summary>
/// 登录 / 授权 / 改密等单卡片页。不引 Razor，避免 view engine 依赖。
/// 所有用户可控字段都走 HtmlEncode。样式是本地的 Basecoat + app.css（见 <see cref="Ui"/>），不依赖外部资源。
/// </summary>
public static class HtmlTemplates
{
    /// <param name="body">卡片内容：一个 &lt;header&gt; 加一个 &lt;section&gt;（见 <see cref="CardHeader"/>）。</param>
    /// <param name="footer">卡片下方的一行（语言切换），可空。</param>
    public static string Layout(string title, string body, string? footer = null)
    {
        return $@"<!doctype html>
<html lang=""{(IsZh ? "zh-CN" : "en")}"">
<head>
  <meta charset=""utf-8"">
  <meta name=""viewport"" content=""width=device-width,initial-scale=1"">
  <title>{Esc(title)}</title>
  {HeadAssets()}
</head>
<body class=""auth-page"">
  <main class=""auth-wrap"">
    <div class=""auth-brand"">{IconLogo}<span>nas-auth</span></div>
    <div class=""card auth-card"">
      {body}
    </div>
    {footer}
  </main>
</body>
</html>";
    }

    /// <summary>卡片头。title / subtitle 是已转义的 HTML。</summary>
    private static string CardHeader(string title, string? subtitle = null) =>
        $"<header><h2>{title}</h2>{(string.IsNullOrEmpty(subtitle) ? "" : $"<p>{subtitle}</p>")}</header>";

    /// <summary>Continue with Google / Microsoft 按钮组（设计 §5.1）。未启用的 provider 不渲染。</summary>
    private static void AppendProviderButtons(StringBuilder sb, string returnUrl,
        bool googleEnabled, bool microsoftEnabled)
    {
        if (!googleEnabled && !microsoftEnabled) return;
        var encoded = Uri.EscapeDataString(returnUrl);
        sb.Append("<div class='stack'>");
        if (googleEnabled)
            sb.Append($"<a class='btn block' data-variant='outline' href='/external/google/start?return_url={Esc(encoded)}'>{IconGoogle}{T("Continue with Google")}</a>");
        if (microsoftEnabled)
            sb.Append($"<a class='btn block' data-variant='outline' href='/external/microsoft/start?return_url={Esc(encoded)}'>{IconMicrosoft}{T("Continue with Microsoft")}</a>");
        sb.Append("</div>");
    }

    /// <summary>
    /// 「换个账号」出口（等待批准 / 被拒 / IdP 失败页）：外部按钮带 select_account=1 强制弹账号选择器，
    /// 否则 IdP 会静默选回刚才那个账号；再给一个回原流程（授权页或登录页）的入口，那里能用密码登录。
    /// </summary>
    private static string SwitchAccount(SwitchAccountOptions? o)
    {
        if (o is null) return "";
        var encoded = Esc(Uri.EscapeDataString(o.ReturnUrl));
        var sb = new StringBuilder($"<div class='sep'>{T("Use a different account")}</div><div class='stack'>");
        if (o.GoogleEnabled)
            sb.Append($"<a class='btn block' data-variant='outline' href='/external/google/start?return_url={encoded}&amp;select_account=1'>{IconGoogle}{T("Choose another Google account")}</a>");
        if (o.MicrosoftEnabled)
            sb.Append($"<a class='btn block' data-variant='outline' href='/external/microsoft/start?return_url={encoded}&amp;select_account=1'>{IconMicrosoft}{T("Choose another Microsoft account")}</a>");
        // 回原流程：return_url 是授权页就回授权页（那里有密码和其他登录方式），否则回登录页
        var back = o.ReturnUrl.StartsWith("/authorize", StringComparison.Ordinal)
            ? Esc(o.ReturnUrl)
            : $"/login?return_url={encoded}";
        sb.Append($"<a class='btn block' data-variant='ghost' href='{back}'>{(o.PasswordEnabled ? T("Back to sign-in (password)") : T("Back to sign-in"))}</a>");
        sb.Append("</div>");
        return sb.ToString();
    }

    /// <summary>
    /// 密码表单。fold = 有外部按钮或会话时折叠为次要入口（设计 §5.1）；
    /// 出错重渲染时保持展开，不然错误提示对着一个收起的表单。
    /// </summary>
    private static void AppendPasswordForm(StringBuilder sb, bool fold, bool open,
        string action, string hiddenInputs, string submitLabel)
    {
        if (fold)
            sb.Append($"<details class='password-login'{(open ? " open" : "")}><summary><span class='sep'>{T("Sign in with password")}</span></summary>");
        sb.Append($"<form class='form' method='post' action='{action}'>");
        sb.Append(hiddenInputs);
        sb.Append($"<div class='field'><label for='username'>{T("Username")}</label><input type='text' id='username' name='username' autocomplete='username' required></div>");
        sb.Append($"<div class='field'><label for='password'>{T("Password")}</label><input id='password' name='password' type='password' autocomplete='current-password' required></div>");
        sb.Append($"<button class='btn block' type='submit'>{submitLabel}</button>");
        sb.Append("</form>");
        if (fold) sb.Append("</details>");
    }

    public static string Authorize(
        string clientName,
        string resourceDisplayName,
        IEnumerable<string> scopes,
        IDictionary<string, string?> hiddenFields,
        string? error,
        string returnUrl = "/account",
        string? sessionUser = null,
        bool googleEnabled = false,
        bool microsoftEnabled = false,
        bool passwordEnabled = true,
        string? redirectUri = null,
        bool selfRegistered = false)
    {
        clientName = ClientDisplayName(clientName);
        var sb = new StringBuilder();
        sb.Append(CardHeader(
            T("<strong>{0}</strong> wants to access your <strong>{1}</strong>", Esc(clientName), Esc(resourceDisplayName)),
            T("Review the permissions below and sign in to authorize.")));
        sb.Append("<section>");

        // 防 consent 钓鱼：client_name 是 DCR 客户端自报的，谁都能叫 "Claude"；
        // 授权码最终送去哪由 redirect_uri 决定，把它的去向摆在最显眼处
        var target = RedirectTargetHtml(redirectUri);
        if (target != null)
            sb.Append($"<p class='consent-target'>{IconExternal}<span>{target}</span></p>");
        if (selfRegistered)
            // 包一层 <p>：Basecoat 的 .alert > section 是 grid，裸的行内元素会各占一行
            sb.Append($"<div class='alert consent-warn' role='note'>{IconAlert}<section><p>" +
                      $"<span class='badge warn'>{T("Unverified app")}</span> " +
                      T("The name <strong>{0}</strong> was supplied by the app itself and has not been verified. Only continue if you just started connecting this app yourself.", Esc(clientName)) +
                      "</p></section></div>");
        sb.Append("<div class='scopes'>");
        foreach (var s in scopes) sb.Append($"<span class='badge mono' data-variant='secondary'>{Esc(s)}</span>");
        sb.Append("</div>");
        if (!string.IsNullOrEmpty(error)) sb.Append(Alert(Esc(error), error: true));

        var hidden = new StringBuilder();
        foreach (var (k, v) in hiddenFields)
            hidden.Append($"<input type='hidden' name='{Esc(k)}' value='{Esc(v ?? "")}'>");

        var hasSession = !string.IsNullOrEmpty(sessionUser);
        var hasProviders = googleEnabled || microsoftEnabled;

        // 已有会话（密码或外部登录建立的）→ 一键授权，不再要密码
        if (hasSession)
        {
            sb.Append("<form method='post' action='/authorize'>");
            sb.Append(hidden);
            sb.Append("<input type='hidden' name='use_session' value='1'>");
            sb.Append($"<button class='btn block' type='submit'>{T("Authorize as {0}", Esc(sessionUser))}</button>");
            sb.Append("</form>");
            if (hasProviders) sb.Append($"<div class='sep'>{T("or use another account")}</div>");
        }

        AppendProviderButtons(sb, returnUrl, googleEnabled, microsoftEnabled);

        // 密码登录：开关关掉（设计 §十 二期）直接不渲染
        if (passwordEnabled)
            AppendPasswordForm(sb, fold: hasProviders || hasSession, open: !string.IsNullOrEmpty(error),
                "/authorize", hidden.ToString(), T("Authorize"));

        sb.Append("</section>");
        return Layout($"Authorize {clientName} to access {resourceDisplayName}", sb.ToString(), LangSwitcher());
    }

    /// <summary>
    /// consent 页「授权后跳到哪」一行（已转义的 HTML）。https 显示主机（+非默认端口），主机用 punycode 形式防同形字域名；
    /// 环回 http 说明是本机应用；其余 http 带上 scheme 以示未加密；私有 scheme 显示 scheme。
    /// 解析不了就原样显示整条 URI（宁可难看也不能不显示）；没有 redirectUri 返回 null。
    /// </summary>
    private static string? RedirectTargetHtml(string? redirectUri)
    {
        if (string.IsNullOrEmpty(redirectUri)) return null;
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var u) || (u.Scheme is "https" or "http" && string.IsNullOrEmpty(u.Host)))
            return T("After you authorize, you will be sent to <strong>{0}</strong>.", Esc(redirectUri));
        if (u.Scheme is "https" or "http")
        {
            if (u.Scheme == "http" && RedirectUriPolicy.IsLoopbackHost(u.Host))
                return T("After you authorize, you will be sent back to an app running on this computer (<strong>{0}</strong>).", Esc(u.Authority));
            string host;
            try { host = u.HostNameType == UriHostNameType.Dns ? u.IdnHost : u.Host; }
            catch { host = u.Host; } // InvariantGlobalization 下 IDN 映射万一不可用，退回原 host
            var shown = (u.Scheme == "http" ? "http://" : "") + host + (u.IsDefaultPort ? "" : $":{u.Port}");
            return T("After you authorize, you will be sent to <strong>{0}</strong>.", Esc(shown));
        }
        return T("After you authorize, you will be handed to the app that opens <strong>{0}</strong> links.", Esc(u.Scheme + ":"));
    }

    public static string Login(string? returnUrl, string? error, string? notice,
        bool googleEnabled = false, bool microsoftEnabled = false, bool passwordEnabled = true)
    {
        var target = string.IsNullOrEmpty(returnUrl) ? "/account" : returnUrl;
        var sb = new StringBuilder();
        sb.Append(CardHeader(T("Sign in to nas-auth"), T("One account for all your NAS apps")));
        sb.Append("<section>");
        if (!string.IsNullOrEmpty(notice)) sb.Append(Alert(Esc(notice), error: false));
        if (!string.IsNullOrEmpty(error)) sb.Append(Alert(Esc(error), error: true));

        AppendProviderButtons(sb, target, googleEnabled, microsoftEnabled);

        if (passwordEnabled)
            AppendPasswordForm(sb, fold: googleEnabled || microsoftEnabled, open: !string.IsNullOrEmpty(error),
                "/login", $"<input type='hidden' name='return_url' value='{Esc(target)}'>", T("Sign in"));

        sb.Append("</section>");
        return Layout("Sign in · nas-auth", sb.ToString(), LangSwitcher());
    }

    /// <summary>
    /// 语言切换：保留现有 query（consent 页参数不能丢），只改/加 lang。
    /// 点击由 theme.js 按 data-lang 事件委托处理（不写内联 onclick，CSP script-src 'self' 下可用）。
    /// </summary>
    public static string LangSwitcher()
    {
        var (code, label) = IsZh ? ("en", "English") : ("zh", "中文");
        return "<p class='auth-foot'>" +
               $"<a href='#' data-lang='{code}'>{label}</a></p>";
    }

    /// <summary>外部登录 pending 等待页（设计 §5.2）：不建会话，让用户等管理员批准。</summary>
    public static string ExternalPending(string provider, string? email, SwitchAccountOptions? switchOptions = null)
    {
        var who = string.IsNullOrEmpty(email) ? T("Your account") : $"<code>{Esc(email)}</code>";
        var body = CardHeader(T("Waiting for approval")) +
                   "<section>" +
                   Alert(T("{0} ({1}) has been registered and is awaiting administrator approval.", who, Esc(provider)), error: false) +
                   $"<p class='hint'>{T("You will be able to sign in once an administrator approves this account. Nothing else is required from you right now.")}</p>" +
                   SwitchAccount(switchOptions) +
                   "</section>";
        return Layout("Waiting for approval · nas-auth", body, LangSwitcher());
    }

    /// <summary>
    /// 自绑定结果页（设计 §5.3 / §九）：二次展示外部身份绑定到了哪个 user，
    /// 防止"以为绑给了 A 实际绑给了 B"的会话错位静默通过。
    /// </summary>
    public static string ExternalBindResult(string provider, string? email, string boundUserId)
    {
        var who = string.IsNullOrEmpty(email) ? Esc(provider) : $"{Esc(email)} ({Esc(provider)})";
        var body = CardHeader(T("Account bound")) +
                   "<section>" +
                   Alert(T("External account <code>{0}</code> is now bound to user <code>{1}</code>.", who, Esc(boundUserId)), error: false) +
                   $"<p class='hint'>{T("You can sign in with this external account from now on. If this is not the user you expected, unbind it immediately.")}</p>" +
                   $"<a class='btn block' data-variant='outline' href='/account/security'>{T("Sign-in & security")}</a>" +
                   "</section>";
        return Layout("Account bound · nas-auth", body);
    }

    /// <summary>外部登录失败 / 拒绝页。不暴露内部状态细节。</summary>
    public static string ExternalError(string title, string message, SwitchAccountOptions? switchOptions = null)
    {
        var body = CardHeader(Esc(T(title))) +
                   "<section>" +
                   Alert(Esc(T(message)), error: true) +
                   (switchOptions is null
                       ? $"<a class='btn block' data-variant='outline' href='/login'>{T("Back to sign-in")}</a>"
                       : SwitchAccount(switchOptions)) +
                   "</section>";
        return Layout($"{title} · nas-auth", body);
    }

    /// <summary>
    /// 首次登录 / admin 重置密码后强制改密页面。无需输入当前密码（cookie session 即为身份）。
    /// </summary>
    public static string ForceChangePassword(string username, string? error)
    {
        var sb = new StringBuilder();
        sb.Append(CardHeader(T("Please change your password"),
            T("Account <code>{0}</code> is currently using a temporary password. Please set a new one to continue.", Esc(username))));
        sb.Append("<section>");
        if (!string.IsNullOrEmpty(error)) sb.Append(Alert(Esc(T(error)), error: true));
        sb.Append("<form class='form' method='post' action='/account/force-change-password'>");
        sb.Append($"<div class='field'><label for='new_password'>{T("New password")}</label><input id='new_password' name='new_password' type='password' required minlength='8' autocomplete='new-password'></div>");
        sb.Append($"<div class='field'><label for='confirm_password'>{T("Confirm")}</label><input id='confirm_password' name='confirm_password' type='password' required minlength='8' autocomplete='new-password'></div>");
        sb.Append($"<button class='btn block' type='submit'>{T("Set password")}</button>");
        sb.Append("</form>");
        sb.Append("</section>");
        return Layout("Change password · nas-auth", sb.ToString());
    }

    public static string SimpleMessage(string title, string message, bool isError = false)
    {
        var body = CardHeader(Esc(title)) +
                   "<section>" +
                   Alert(Esc(message), isError) +
                   $"<a class='btn block' data-variant='outline' href='/account'>{T("Back to /account")}</a>" +
                   "</section>";
        return Layout(title, body);
    }
}

/// <summary>「换个账号」出口参数：回原流程的本地地址 + 哪些登录方式可用。</summary>
public record SwitchAccountOptions(string ReturnUrl, bool GoogleEnabled, bool MicrosoftEnabled, bool PasswordEnabled);

public record AccountAuthorizationView(
    string ClientId,
    string ClientName,
    string ResourceUrl,
    string ResourceDisplay,
    IReadOnlyList<string> Scopes,
    string LastUsedDisplay
);

public record UserAdminView(
    string UserId,
    string Username,
    bool IsAdmin,
    bool MustChangePassword,
    bool IsSelf,
    string CreatedAtDisplay,
    string? Email = null,
    bool AllowPasswordLogin = false,
    string? LockedUntilDisplay = null
);
