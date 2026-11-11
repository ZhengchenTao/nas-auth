# Release, upgrade and recovery

## Release gates and versioning

GitHub CI tests the full suite on Windows/Linux and builds the Linux image. The Dockerfile independently runs the full suite before publishing runtime files, so the instance-specific Gitea build/push also inherits this gate. CI success is not protocol certification, a security audit, or a disaster-recovery drill. OpenID conformance testing and wider application/browser integration coverage remain follow-up work.

Pin deployments to a source revision or image digest. Record the current issuer, image and volume layout before upgrading. Main pushes build source; the Gitea workflow only deploys on explicit manual dispatch with `deploy=true`. GitHub CI never deploys or needs production secrets. A release should include a version tag, changelog, image/source reference and compatibility notes; no particular support lifetime is currently promised.

## Token lifetime

For a new small-team deployment, an example starting point is:

```json
{
  "Jwt": {
    "AccessTokenLifetimeMinutes": 15,
    "RefreshTokenLifetimeDays": 7,
    "AuthCodeLifetimeMinutes": 5
  }
}
```

The minute value takes precedence if supplied. Omitting it retains `AccessTokenLifetimeDays` (legacy default 30), preserving existing deployments. Both configuration styles require a positive effective duration that fits the token response's seconds value. Changing access-token lifetime affects newly issued tokens only. Keep previous signing keys until the longest outstanding historical token lifetime, plus any verifier clock skew, has elapsed.

Do not shorten an existing deployment's lifetime without checking its clients' refresh behavior. Offline JWT verification cannot observe a local disable immediately; application-owned sessions may outlive Auth sessions. Document these boundaries to operators.

## Before upgrading

1. Record the image digest/revision and current configuration. Read Unreleased/release notes and identify the oldest compatible rollback revision.
2. Make a consistent backup and confirm it can be opened in an isolated environment.
3. Verify a recovery-administrator login path without removing ordinary identity-provider configuration or weakening HTTPS.
4. Upgrade Auth alone. Check health, discovery/JWKS, existing-session compatibility, a fresh administrator login and the application's actual OIDC/forward-auth flow. Compare public JWKS if key rotation was not intended.

## Backup contents and consistency

Back up the entire Auth data volume: SQLite, RSA signing keys (current and previous), DataProtection key ring and avatars. Back up deployment/configuration files and references to secrets separately, using the deployment's secret manager. A database-only backup cannot restore the signing and cookie identities.

For the simplest portable backup, stop this Auth instance, snapshot/copy its data volume and configuration, then start the same image again. Keep the interruption scoped to this instance. For online backups use SQLite's backup API or a storage snapshot with documented consistency guarantees; copying just a live `auth.db` while ignoring WAL files is not a safe backup procedure.

Encrypt backups, restrict access and keep a second copy where the deployment's retention policy requires it. Never commit a backup or decrypted restore to this repository. Test backup failure handling; file existence alone does not demonstrate recoverability.

## Isolated restore drill

1. Restore a selected encrypted backup through the deployment's backup system into a new restricted directory. Verify its provenance and the recorded image/configuration revision.
2. Start a separate compatible Auth image with copies of the restored data/configuration. Bind only to loopback or an isolated test network, prevent production callback/proxy traffic, and do not mount live production volumes.
3. Preserve the backed-up issuer and keys for verification. Use isolated DNS/Host routing if a login flow is needed; do not change the production issuer or redirect existing production users to the drill.
4. Check SQLite integrity and schema, health/discovery and public JWKS against the backed-up reference. Verify a designated synthetic user's fresh login and the relevant lifecycle boundary in the isolated copy. Do not resume production integrations merely to make the drill appear successful.
5. Record the backup revision, checks, elapsed restore time and unresolved limitations without personal data or credentials. Stop the drill instance. Production recovery is a separate deliberate operation.

## Rollback boundaries

Device-aware versions add per-session revocation. Follow [device-session rollback limits](device-sessions.md#deployment-and-rollback):
an older image that ignores `nas_sid` can revive revoked sessions even if it still checks the account epoch.

The lifecycle migration adds `users.is_disabled` and `users.session_epoch` with backward-compatible defaults. Original subjects and issuer remain unchanged. Browser SSO cookies, forward-auth tickets/site cookies and locally validated access tokens check the current epoch; restoration assigns a new epoch. Missing epochs on older cookies are accepted only when the stored account epoch remains empty.

After any account is disabled/restored, do not roll back to an image that does not enforce that state and epoch on every applicable path. Downgrading could re-enable an old session despite a healthy process. A forward fix based on the compatible revision is safer. Do not overwrite a live database with an older backup to undo a cosmetic or configuration change: that can resurrect deleted users, credentials and permissions and discard newer audit events.

This guide defines the procedure. Each deployment must demonstrate its own backups and restore drill; it does not claim that a particular installation has done so.
