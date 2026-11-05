# Changelog

Changes below describe source behavior. They are not a claim that every deployment has upgraded. Pin an image digest or source revision; `latest` is not a rollback plan.

## Unreleased

### Security

- Bind forward-auth tickets and site sessions to the account session epoch as well as its version. Hard deletion, original-identity restoration and reauthorization must not revive an old site cookie or pending ticket. Existing cookies without an epoch remain valid only for accounts whose epoch is still empty.
- Gate Docker image publishing behind the full test suite. Add portable GitHub Linux/Windows tests and a runtime-image build without production credentials.

### Configuration

- Add optional `Jwt:AccessTokenLifetimeMinutes`, taking precedence over the legacy `AccessTokenLifetimeDays`. Existing deployments retain their configured day-based lifetime until explicitly changed. Reject non-positive or overflowing effective lifetimes at startup.
- Use the effective lifetime consistently for JWT expiration, token-response `expires_in` and key-management guidance. A shorter new lifetime does not shorten previously issued tokens.

### Existing capabilities documented

- Configurable OIDC/ticket upstreams, per-provider profiles, explicit identity approval/binding, administrator role management, disabling and original-identity recovery are implemented. Groups, stronger local sign-in and complete expiring invitations are not yet implemented.
- Publish security reporting, contribution and [upgrade/backup/recovery guidance](docs/operations.md).

### Upgrade boundary

Read [operations](docs/operations.md) before changing images or restoring data. Once an account has been disabled or restored, a pre-lifecycle image cannot enforce the state or epoch. An image from before the forward-auth epoch fix does not fully enforce restoration boundaries.
