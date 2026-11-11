using System.Text;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Services;
using static NasAuth.Pages.I18n;
using static NasAuth.Pages.Ui;

namespace NasAuth.Pages;

public static partial class DashboardTemplates
{
    public static string DiagnosticsSection(IReadOnlyList<ResourceConfig> resources, string aud,
        string userId, ApplicationDiagnosis result, string issuer, string query = "", IReadOnlyList<UserRow>? candidates = null)
    {
        var form = new StringBuilder("<form method='get' action='/admin/apps/diagnostics' class='form'>");
        form.Append($"<div class='field'><label for='diagnostic-resource'>{T("Resource")}</label><select id='diagnostic-resource' name='aud'><option value=''>{T("Select a resource")}</option>");
        foreach (var r in resources)
            form.Append($"<option value='{Esc(r.Aud)}'{(r.Aud == aud ? " selected" : "")}>{Esc(r.App?.Name ?? r.DisplayName)} — {Esc(r.Aud)}</option>");
        form.Append($"</select></div><div class='field'><label for='diagnostic-user'>{T("Find accounts")}</label><input id='diagnostic-user' type='search' name='q' maxlength='128' value='{Esc(query)}' placeholder='{T("Name, username or email")}'></div>");
        form.Append($"<input type='hidden' name='user' value='{Esc(userId)}'><div class='form-foot'><button class='btn' data-variant='outline' type='submit'>{T("Check configuration and access")}</button></div></form>");
        if (candidates is not null)
        {
            form.Append($"<p class='hint'>{T("Select an account. Up to 25 active and 25 disabled matches are shown; narrow the search if needed.")}</p>");
            foreach (var candidate in candidates)
                form.Append($"<p><a href='/admin/apps/diagnostics?aud={Uri.EscapeDataString(aud)}&amp;user={Uri.EscapeDataString(candidate.user_id)}'>{Esc(candidate.display_name ?? candidate.username)} · {Esc(candidate.username)} · {Esc(candidate.user_id)}{(candidate.is_disabled != 0 ? " · " + T("Disabled") : "")}</a></p>");
            if (candidates.Count == 0) form.Append(Empty(T("No users found.")));
        }
        var actions = $"<a class='btn' data-variant='outline' data-size='sm' href='/admin/apps'>{T("Connected apps")}</a> <a class='btn' data-variant='outline' data-size='sm' href='/admin/users'>{T("Users")}</a>";
        var html = Card(T("Application diagnostics"), T("Read-only local checks. No permissions are changed and no external services are contacted."), form.ToString(), action: actions);
        html += Card(T("Configuration checks"), T("These checks describe the loaded configuration. Edit deployment files and restart to apply changes."),
            $"<dl class='kv'><dt>Issuer</dt><dd>{Esc(issuer)}</dd><dt>Discovery</dt><dd>{Esc(issuer.TrimEnd('/') + "/.well-known/openid-configuration")}</dd></dl>" + Checks(result.Configuration));
        if (!string.IsNullOrWhiteSpace(userId))
            html += Card(T("Access diagnosis"), T("Each resource capability is checked separately. An Auth grant does not grant application roles or end existing application sessions."), Checks(result.Access),
                action: $"<a class='btn' data-variant='outline' data-size='sm' href='{Esc(EditHref(userId))}'>{T("Manage")}</a>");
        return html;
    }

    private static string Checks(IReadOnlyList<DiagnosticCheck> checks)
    {
        if (checks.Count == 0) return $"<p class='hint'>{T("No local configuration issues found. This is not an end-to-end connection test.")}</p>";
        var body = new StringBuilder("<div class='table-container'><table class='table'><thead><tr>");
        body.Append($"<th>{T("Status")}</th><th>{T("Details")}</th></tr></thead><tbody>");
        foreach (var check in checks)
            body.Append($"<tr><td class='fit'><span class='badge' data-variant='{(check.Level == "error" ? "destructive" : "outline")}'>{Esc(T(check.Level))}</span></td><td class='wrap'>{Esc(T(check.Message))}{(check.Detail.Length > 0 ? "<span class='sub'>" + Esc(check.Detail) + "</span>" : "")}</td></tr>");
        return body.Append("</tbody></table></div>").ToString();
    }
}
