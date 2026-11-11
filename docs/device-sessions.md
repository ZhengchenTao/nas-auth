# Device sessions

Open **Devices and sessions** (`/account/sessions`) from the personal sidebar or Sign-in & security.
The page shows up to 50 recent sessions, browser/OS, an optional user-defined name, first recorded
time, last activity, last browser IP, expiry and current-device status. Times use the deployment's
local time zone, matching the other account pages. Administrators see the same records on user pages
and can revoke one session there. Renaming is a personal action; every mutation requires CSRF validation.

A device entry describes an Auth session, not verified physical hardware. Browser profiles, private
windows and automation can be separate sessions. Full User-Agent strings are not stored and there
is no location/fingerprint service. IP and activity metadata belong to the account and its administrators.
Activity can include related application requests; token refresh does not replace the browser IP
with the receiving server's address. Activity writes are throttled to once a minute.

## Revocation

New Auth cookies have a server-owned `nas_sid`. Authorization codes and refresh tokens retain the
session ID, including refresh rotation; Auth-issued access tokens carry the same private claim.
New forward-auth tickets/site sessions carry it too. Revoking a device stops its Auth cookie,
unspent authorization codes, refresh tokens, local JWT validation and forward-auth access.
Other devices and resource grants remain unchanged. Logging out revokes the current device.

**Sign out other devices** keeps this exact session and its linked credentials. It also invalidates
old, not-yet-migrated cookies and unlinked legacy refresh/code credentials, so older integrations
may need to sign in again. Password changes, administrator sign-out, account disable/restoration
and recovery retain the existing global session-version/epoch protection and invalidate device rows.
Revoked cookie reuse during consent cannot create a replacement session without fresh authentication.

Auth cannot end an application's independent session or retroactively notify an offline JWT validator.
No downstream account is disabled when only one device is revoked: that would affect other devices.
Applications protected by forward-auth recheck the associated device on subsequent requests.

## Existing installations

Valid pre-upgrade Auth cookies migrate on their next authenticated request without a global sign-out.
Migration uses a one-way hash of the protected cookie to identify the same legacy ticket and renews
it with a session ID. Replaying the old cookie after revocation cannot create a different device.
The first-recorded timestamp is the migration time; it does not invent historical device information.

Old forward-auth credentials and OAuth authorizations that lack a session ID cannot reliably be
attributed to a browser. They keep their existing expiry/revocation behavior until a fresh browser
authorization, expiry or explicit revocation; refresh rotation alone cannot assign a legacy grant to a device. Use
Authorized apps or a deliberate global sign-out when those older authorizations must also end.

## Expiry and retention

```json
{
  "DeviceSessions": {
    "IdleHours": 720,
    "AbsoluteHours": 0
  }
}
```

The defaults preserve the existing 30-day sliding cookie policy. IdleHours accepts 1–8760;
AbsoluteHours accepts 0–8760, where 0 disables the absolute cap. Both limits also apply to linked
Auth credentials. Successful associated requests may extend idle expiry; the absolute limit never
extends. Missing, expired or revoked server records fail closed. Expired records are retained for
90 additional days; legacy tombstones are never removed before the original protected cookie expires.

## Deployment and rollback

The additive migration creates `device_sessions` and adds nullable `session_id` to authorization
codes and refresh tokens. Subjects, grants, signing keys and existing credentials remain intact.
Run preflight, back up the Auth data/key set consistently and verify multiple independent browsers.

**Do not downgrade to a build without device-session validation after enabling this feature.**
Older builds ignore `nas_sid` and could accept a cookie or token belonging to a revoked device.
The image label `io.nas-auth.device-sessions=1` identifies supporting builds. Retain this enforcement
in a compatible rollback or use a forward fix; do not restore an older live database to undo a UI change.

## 中文

个人中心新增「设备与会话」，可查看浏览器/系统、最近浏览器 IP、活动与到期时间，命名设备，
单独下线，或退出其他设备。管理员可在账号详情中下线指定会话。设备信息不等于物理硬件识别，
最近活动也可能来自关联应用；不存储完整 User-Agent，不调用定位或指纹服务。

新签发的 Auth cookie、forward-auth 凭据、授权码及 token 与设备绑定；单独下线保留其他设备。
旧 Auth cookie 首次使用时平滑纳入列表；没有设备标识的旧授权和应用自身会话仍有原有边界。
升级后不能直接回退到忽略设备标识的旧镜像，否则可能使已下线设备重新有效。
