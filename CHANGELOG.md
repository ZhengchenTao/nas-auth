# Changelog

Changes below describe source behavior. They are not a claim that every deployment has upgraded. Pin an image digest or source revision; `latest` is not a rollback plan.

## Unreleased

### Unified releases and application diagnostics

- Test one runtime image with household and path-mounted team configurations before publishing. Record immutable release digests and support checked offline image export/import instead of rebuilding per deployment.
- Add administrator-only application configuration checks and searchable account access diagnosis, including partial scopes, direct/group grant sources and desired versus acknowledged account synchronization state.
- Preserve configuration-file ownership and existing UI components. Diagnostics are read-only and do not claim external connectivity, current downstream state or global session revocation.


### Team administration

- Search existing accounts by display name, username, stable ID or email; filter active users by Auth role and switch between active, disabled and deleted identities with state totals.
- Add bounded server-side pagination (25/50/100 rows), stable ordering, filter-preserving navigation and clear empty states. Disabled profiles remain searchable; deleted records search only the reserved ID.
- These changes require no schema migration or organization-specific settings. See [user management](docs/user-management.md).

### Application grants and account lifecycle

- Use the full resource catalog to assign application access during account creation and editing. Account sync shows applications with effective access or delivery history.
- Allow explicitly confirmed reuse of a deleted sign-in name for a new password account. Preserve the old subject, mint a new subject and downstream login, and require a separate application grant.

### User groups

- Use the dashboard outline button style for the New group link so its label stays readable in both themes.

- Manage flat user groups and grant application access to all members. Preview changes before saving and inspect direct and group grant sources on each user. Configured account provisioning follows effective access.

### Account provisioning

- Add optional, configured application account delivery with transactional SQLite change tracking, durable desired state, bounded retry backoff, sanitized audit results and administrator reconciliation.
- Select applications while creating directory, invitation or password accounts. Existing users can manage application access with one checkbox per configured app; advanced resource grants remain available.
- Keep stable issuer/subject identities and downstream business roles separate. The [receiver contract](docs/account-provisioning.md) requires revision ordering, revocation tombstones, safe first-sign-in races and preservation of local account holds.

### Security

- Bind forward-auth tickets and site sessions to the account session epoch as well as its version. Hard deletion, original-identity restoration and reauthorization must not revive an old site cookie or pending ticket. Existing cookies without an epoch remain valid only for accounts whose epoch is still empty.
- Gate Docker image publishing behind the full test suite. Add portable GitHub Linux/Windows tests and a runtime-image build without production credentials.

### Configuration

- Add optional `Jwt:AccessTokenLifetimeMinutes`, taking precedence over the legacy `AccessTokenLifetimeDays`. Existing deployments retain their configured day-based lifetime until explicitly changed. Reject non-positive or overflowing effective lifetimes at startup.
- Use the effective lifetime consistently for JWT expiration, token-response `expires_in` and key-management guidance. A shorter new lifetime does not shorten previously issued tokens.

### Existing capabilities documented

- Configurable OIDC/ticket upstreams, per-provider profiles, explicit identity approval/binding, administrator role management, disabling and original-identity recovery are implemented. Stronger local sign-in and complete expiring invitations are not yet implemented.
- Publish security reporting, contribution and [upgrade/backup/recovery guidance](docs/operations.md).

### Upgrade boundary

Read [operations](docs/operations.md) before changing images or restoring data. Once an account has been disabled or restored, a pre-lifecycle image cannot enforce the state or epoch. An image from before the forward-auth epoch fix does not fully enforce restoration boundaries.
