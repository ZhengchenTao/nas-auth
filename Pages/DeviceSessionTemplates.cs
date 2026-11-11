using System.Text;
using NasAuth.Services;
using static NasAuth.Pages.I18n;
using static NasAuth.Pages.Ui;

namespace NasAuth.Pages;

public static partial class DashboardTemplates
{
    private static string DeviceTime(long timestamp) => DateTimeOffset.FromUnixTimeSeconds(timestamp).ToLocalTime().ToString("yyyy-MM-dd HH:mm");
    public static string DeviceSessionsSection(IReadOnlyList<DeviceSessionRow> rows, string? currentId,
        DeviceSessions sessions, string userId, bool admin = false)
    {
        var body = new StringBuilder();
        if (rows.Count == 0) body.Append(Empty(T("Devices appear when their browser next uses Auth.")));
        else
        {
            body.Append($"<div class='table-container'><table class='table device-session-table'><thead><tr><th>{T("Device")}</th><th>{T("Last activity")}</th><th>{T("Expires")}</th><th></th></tr></thead><tbody>");
            foreach (var row in rows)
            {
                var active = sessions.Available(row);
                var state = row.revoked_at is not null ? "revoked" : active ? "active" : "expired";
                var label = row.name ?? T(row.browser) + " · " + T(row.platform);
                body.Append($"<tr data-session-id='{Esc(row.id)}' data-current='{(row.id == currentId ? "true" : "false")}' data-state='{state}'>" +
                    $"<td class='wrap'><strong>{Esc(label)}</strong> <span class='badge' data-variant='outline'>{T(row.id == currentId && active ? "This device" : state)}</span>" +
                    $"<span class='sub'>{Esc(T(row.browser))} · {Esc(T(row.platform))}<br>{T("Last browser IP")}: {Esc(row.last_ip.Length == 0 ? "—" : row.last_ip)}</span>");
                if (!admin && active)
                    body.Append($"<details><summary>{T("Rename device")}</summary><form method='post' action='/account/sessions/name'>{Hidden("id", row.id)}<div class='field'><input name='name' aria-label='{T("Device name")}' value='{Esc(label)}' maxlength='64' required></div><button class='btn' data-variant='outline' data-size='sm'>{T("Save")}</button></form></details>");
                body.Append($"</td><td data-label='{T("Last activity")}'>{DeviceTime(row.last_seen_at)}<span class='sub'>{T("First recorded")}: {DeviceTime(row.created_at)}</span></td>" +
                    $"<td data-label='{T("Expires")}'>{DeviceTime(sessions.EffectiveExpiry(row))}</td><td class='fit'>");
                if (active)
                    body.Append($"<form method='post' action='{(admin ? "/admin/users/sessions/revoke" : "/account/sessions/revoke")}' {Confirm(T("Sign out this device and revoke its linked Auth credentials?"))}>{Hidden("id", row.id)}" +
                        (admin ? Hidden("user_id", userId) : "") + $"<button class='btn' data-variant='outline' data-size='sm'>{T("Sign out device")}</button></form>");
                body.Append("</td></tr>");
            }
            body.Append("</tbody></table></div>");
        }
        body.Append($"<p class='hint'>{T("Up to 50 recent sessions are shown. Device names are inferred from the browser, not verified hardware identities. Activity can include linked application requests.")}</p>");
        body.Append($"<p class='hint'>{T("Signing out revokes this Auth session and its linked credentials. Older unlinked authorizations and application-owned sessions may remain; review Authorized apps when needed.")}</p>");
        if (!admin)
            body.Append($"<form method='post' action='/account/sessions/revoke-others' {Confirm(T("Sign out of all other devices?"))}><button class='btn' data-variant='outline'>{T("Sign out of all other devices")}</button></form>");
        return Card(T("Devices and sessions"), T("Recognize your devices, give them a name, and sign out a selected session without ending the others."), body.ToString());
    }
}
