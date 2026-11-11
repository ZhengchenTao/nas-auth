# Local password invitations and recovery

The local password account form can create an **expiring invitation link** instead of asking
the administrator to choose a password. The recipient opens the link and sets their own password.
Applications selected at creation retain the existing explicit grant semantics; the link itself
does not add grants, administrator privileges, external identity bindings or verified-email claims.
An invited identity is not a public registration: an administrator created it first.

On an existing user page, **Invitation and recovery** shows link status and expiry, provides
revocation and reissue, and requires the administrator to confirm they have verified the recipient.
Recovery is available only for active accounts explicitly enabled for local password access.
An external-only account should recover through its identity provider. This release does not send
email or expose a public “forgot password” lookup: deliver the link through a trusted channel
after identity verification. Existing external email prebindings remain a separate flow.

## Link and credential boundaries

- Invitation lifetime defaults to 72 hours (configurable 1–168); recovery defaults to 30 minutes
  (configurable 5–120). Set `CredentialLinks:InvitationHours` and `CredentialLinks:RecoveryMinutes`.
- Links contain 256 bits of randomness. Only their SHA-256 hash is persisted; the complete link
  appears once in the administrator's response and is never included in audit events.
- The secret is in the URL fragment. First-party page code removes it from the address bar and
  submits it in the form body. Responses are `no-store`, forms require antiforgery validation,
  and redemption shares the authentication rate limit. A GET never consumes a link.
- Reissue revokes prior pending links. Cancellation, expiry, deletion, disable/restore, password
  or email changes, local-password toggles, administrator-role changes and session-version changes
  invalidate the link. Links bind to the stable identity, not a reusable username.
- Redemption and password update are atomic. Concurrent redemption succeeds once. The existing
  password continues working until successful redemption, which clears lockout/forced-change state
  and invalidates Auth cookies, forward-auth sessions/tickets, locally verified access tokens,
  refresh tokens and authorization codes. The recipient then signs in normally; no automatic login.
- Offline JWT validators and application-owned sessions retain their documented revocation limits.
  Password recovery is not a claim of global logout from every connected application.

These controls follow the [OWASP recovery guidance](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).

## Upgrade and rollback

The migration adds `credential_links` and an invalidation trigger, preserving existing subjects,
grants and credentials. Back up SQLite and signing/cookie keys consistently before deployment.
Use a rollback version that already enforces account epochs (such as the prior unified release).
Never restore an old live database to undo a UI change. During rollback, newly issued links will
be unavailable until an invitation-aware version is running; credential changes already made stay
effective. Keep trigger/table compatibility when performing a later migration.

## 中文

在本地密码账号创建表单勾选「让接收人自行设置密码」，管理员即可交付一次性邀请链接。
账号详情显示到期、已使用、已撤销等状态，并支持撤销、重发；恢复前需核实接收人身份。
本轮使用管理员交付链接，不自动发邮件，不改变外部邮箱预绑定或 UAM 的恢复方式。

链接只存哈希，使用一次即失效；重发、改密、停用、身份恢复或相关账号状态变化会让旧链接失效。
成功设密后撤销旧 Auth 凭据，用户重新登录；应用内部的会话边界仍由各应用负责。
创建邀请、重发、撤销和兑换均留审计事件，事件中不含链接秘密。
