using System.Text;
using NasAuth.Data;
using NasAuth.Services;
using static NasAuth.Pages.I18n;
using static NasAuth.Pages.Ui;

namespace NasAuth.Pages;

public static partial class DashboardTemplates
{
    public static string ApplicationSetupSection(ApplicationSetupDraft draft)
    {
        var input = draft.Input;
        string Field(string name, string title, string value, string placeholder = "") =>
            $"<div class='field'><label for='setup-{name}'>{T(title)}</label><input id='setup-{name}' name='{name}' value='{Esc(value)}' placeholder='{Esc(placeholder)}' maxlength='2048'></div>";
        string Option(string value, string title, string selected) => $"<option value='{value}'{(selected == value ? " selected" : "")}>{T(title)}</option>";
        var form = "<form method='post' action='/admin/apps/new' class='form'><div class='form-grid application-setup-grid'>" +
            Field("id", "Application ID", input.Id, "example") + Field("name", "Application name", input.Name) +
            "<div class='field'><label for='setup-kind'>" + T("Connection type") + "</label><select id='setup-kind' name='kind'>" +
            Option("oidc", "OIDC sign-in", input.Kind) + Option("forward-auth", "Protected entry", input.Kind) + Option("mcp", "MCP access", input.Kind) + "</select></div>" +
            Field("url", "Resource address", input.Url, "https://app.example.com") + Field("scopes", "Scopes", input.Scopes, "openid profile email") +
            "<div class='field'><label for='setup-client-type'>" + T("OIDC client type") + "</label><select id='setup-client-type' name='client_type'>" +
            Option("confidential", "Server application with a secret", input.ClientType) + Option("public", "Public client with PKCE", input.ClientType) + "</select></div></div>" +
            $"<div class='field'><label for='setup-callbacks'>{T("OIDC callback URLs (one per line)")}</label><textarea id='setup-callbacks' name='callbacks' rows='3' maxlength='4096'>{Esc(input.Callbacks)}</textarea></div>" +
            $"<p class='hint'>{T("Leave scopes empty for the suggested defaults. Client type and callbacks apply to OIDC only.")}</p>" +
            $"<div class='form-foot'><button class='btn' type='submit'>{T("Generate configuration")}</button></div></form>";
        var html = Card(T("Connect an application"), T("Generate configuration for review. Deployment files remain the source of truth."), form);
        foreach (var error in draft.Errors) html += $"<p role='alert' class='hint'>{Esc(T(error))}</p>";
        if (draft.Resources.Length == 0) return html;
        html += Card("resources.json", T("Merge these entries into the existing array; do not replace the whole file."), Code(draft.Resources));
        if (draft.Clients != "[]") html += Card("clients.preset.json", T("Merge these entries into the existing array; do not replace the whole file."), Code(draft.Clients));
        html += Card(T("Configure the receiving application"), T("Use these values in the application or proxy. Auth does not assign application roles."), Code(draft.Receiver));
        if (draft.SecretEnvironment.Length > 0)
            html += Card(T("Client credential"), T("Generate a secret in your secret manager. Inject it into Auth using this environment variable and configure the same secret in the receiving application."), $"<code>{Esc(draft.SecretEnvironment)}</code>");
        if (input.Kind == "mcp") html += $"<p class='hint'>{T("Publish the protected resource metadata in your MCP service and validate issuer, audience, token type and scopes on every request.")}</p>";
        if (input.Kind == "forward-auth") html += $"<p class='hint'>{T("Configure the reverse proxy using the forward-auth integration guide, including trusted headers and sign-in routing. A verification URL alone does not protect an application.")}</p>";
        return html + Card(T("Validate and deploy"), T("Run the configuration check with the proposed files and required environment variables, then restart Auth and test the real sign-in flow."),
            Code("dotnet nas-auth.dll --check-config") + $"<p><a href='/admin/apps/diagnostics'>{T("Check configuration and access")}</a></p>");
    }

    private static string Code(string value) => $"<pre style='white-space:pre-wrap;overflow-wrap:anywhere'><code>{Esc(value)}</code></pre>";

    public static string CredentialLinksSection(UserRow user, IReadOnlyList<CredentialLinkRow> links)
    {
        if (user.allow_password_login == 0)
            return Card(T("Invitation and recovery"), T("Local password access is disabled for this account. Recover an external account through its identity provider."), "");
        var body = new StringBuilder($"<form method='post' action='/admin/users/credential-links/issue'>{Hidden("user_id", user.user_id)}");
        body.Append($"<label class='check-line'><input type='checkbox' name='verified' value='1' required>{T("I have verified the recipient's identity and will deliver the link through a trusted channel.")}</label>");
        body.Append($"<div class='form-foot'><button class='btn' data-variant='outline' type='submit'>{T("Issue or reissue a password link")}</button></div></form>");
        if (links.Count > 0)
        {
            body.Append($"<div class='table-container'><table class='table'><thead><tr><th>{T("Type")}</th><th>{T("Status")}</th><th>{T("Expires")}</th><th></th></tr></thead><tbody>");
            foreach (var link in links)
                body.Append($"<tr><td>{T(link.purpose)}</td><td>{T(link.state)}</td><td>{DateTimeOffset.FromUnixTimeSeconds(link.expires_at):yyyy-MM-dd HH:mm} UTC</td><td>" +
                    (link.state == "pending" ? $"<form method='post' action='/admin/users/credential-links/cancel'>{Hidden("user_id", user.user_id)}{Hidden("id", link.id)}<button class='btn' data-size='sm' data-variant='outline' type='submit'>{T("Revoke link")}</button></form>" : "") + "</td></tr>");
            body.Append("</tbody></table></div>");
        }
        return Card(T("Invitation and recovery"), T("Links expire and can be used once. Reissuing revokes previous links. Existing credentials change only after the recipient sets a password."), body.ToString());
    }

    public static string IssuedCredentialSection(IssuedCredentialLink link, string issuer)
    {
        var url = issuer.TrimEnd('/') + "/credential-link#token=" + link.Token;
        return Card(T("Password link created"), T("Copy this link now and deliver it to the verified recipient. It will not be shown again. No email has been sent."),
            $"<div class='field'><label for='issued-credential-link'>{T("One-time link")}</label><textarea id='issued-credential-link' rows='3' readonly autocomplete='off'>{Esc(url)}</textarea></div>" +
            $"<p>{T("Expires")}: {DateTimeOffset.FromUnixTimeSeconds(link.ExpiresAt):yyyy-MM-dd HH:mm} UTC</p>" +
            $"<a class='btn' data-variant='outline' href='{Esc(EditHref(link.UserId))}'>{T("Back to user")}</a>");
    }

    public static string CredentialEntryPage(string? error = null, bool complete = false, string token = "")
    {
        var title = T(complete ? "Password set" : "Set your password");
        var body = $"<header><h2>{title}</h2><p>{T(complete ? "Sign in with your new password. Previous Auth sessions and tokens have been revoked." : "Use the invitation or recovery link provided by your administrator.")}</p></header><section>";
        if (error is not null) body += $"<p role='alert'>{Esc(T(error))}</p>";
        if (complete) body += $"<a class='btn block' href='/login'>{T("Sign in")}</a>";
        else body += $"<form id='credential-link-form' method='post' action='/credential-link' class='form'><input type='hidden' name='token' value='{Esc(token)}'>" +
            $"<div class='field'><label for='link-password'>{T("New password")}</label><input id='link-password' name='new_password' type='password' minlength='8' maxlength='256' required autocomplete='new-password'></div>" +
            $"<div class='field'><label for='link-confirm'>{T("Confirm password")}</label><input id='link-confirm' name='confirm_password' type='password' minlength='8' maxlength='256' required autocomplete='new-password'></div>" +
            $"<button class='btn block' type='submit'>{T("Set password")}</button><p class='hint'>{T("If you reload this page, reopen the original link. Expired or revoked links must be reissued by an administrator.")}</p></form>";
        return HtmlTemplates.Layout(title, body + "</section>");
    }
}
