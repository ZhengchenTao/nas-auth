# Optional application account provisioning

Account provisioning creates an application's local account before the user's first sign-in.
Auth grants application access; the application still owns its roles, teams and data permissions.
The feature is disabled unless applications are explicitly configured. It is an outbound HTTP
contract, not a SCIM server and not an automatic importer of existing application accounts.

## Configuration

```json
{
  "Provisioning": {
    "Applications": {
      "example": {
        "Name": "Example application",
        "Endpoint": "https://adapter.example.test/accounts",
        "BearerEnvironment": "EXAMPLE_PROVISIONING_BEARER",
        "RequiredResources": { "example-web": ["openid", "profile"] }
      }
    }
  }
}
```

Supply a separate high-entropy bearer credential through the named environment variable.
HTTPS is required, except for explicit loopback HTTP adapters. Redirects and cookies are disabled.
An application may require several resources; **all** required scopes must be granted to enable
its account. New-user forms show one checkbox per configured application, including directory
and email-invitation creation. Existing resource grants remain the authority.

Installing a connector does not silently adopt existing accounts. Review exact identity matches,
then use **Synchronize / retry** on each user, or save reviewed grants. No personal deployment
configuration, downstream administrator credentials or company protocol belongs in this repository.

## Delivery contract

Auth POSTs a JSON object (receivers should accept case-insensitive property names):

```json
{
  "EventId": "b6a47af1ded04cf5a16129b038daf877",
  "Revision": 639000000000000000,
  "ApplicationId": "example",
  "Issuer": "https://auth.example.test",
  "Subject": "stable-user-id",
  "Username": "stable-user-id",
  "DisplayName": "Example User",
  "Email": "user@example.test",
  "Enabled": true
}
```

The identity key is the exact **Issuer + Subject**, never email, name or an upstream identity
provider's original subject. No password, administrator flag, role or permission assignment is sent.
Only return **200 or 204 after applying** the desired state. A queued 202 is not success.
Other responses are retried with exponential backoff, capped at one hour. The response body is
never stored or logged. An optional `X-Provisioning-Error` header may contain a short, non-sensitive
`[a-z0-9_]{1,64}` diagnostic code. Never put personal information or credentials there.

Receiver requirements:

`Revision` is a signed 64-bit integer; receivers must retain its exact precision.

- Authenticate a credential scoped to this operation; pin the expected issuer and application.
- Persist the last applied revision, including revocations for accounts that do not yet exist.
  Ignore older/equal revisions and retain that watermark when disabling/deleting an account.
- Serialize concurrent changes or use database uniqueness plus revision concurrency checks.
  Precreation and first sign-in must converge on one application identity.
- Preserve local roles and administrator decisions. Source re-enablement must not clear a local hold.
- Revoke the application's sessions when disabling access, without deleting repositories or business data.
- Ensure first-sign-in/session validation respects source revocations, including concurrent JIT creation.
- Reject ambiguous existing-account matches; never silently link by email or name.

## Reliability and operation

SQLite triggers enqueue account/profile/grant changes inside the same transaction as the change.
The resource editor replaces its whole submission atomically. A background worker captures the
latest desired state and delivers at least once; an application outage does not roll back Auth grants.
User details distinguish pending, synchronized and failed delivery, with explicit reconciliation/retry.
Unchanged desired state keeps its revision; a changed state supersedes earlier work. Delivery audits
record identifiers and sanitized outcome codes, not profiles or response bodies.

Source disable/delete/revoke emits a disable for previously managed accounts. Restoring an Auth
identity does not restore old resource grants. Provisioning status is the last captured delivery,
not a guarantee that a user has a business role or that an asynchronous revoke is instantaneous.

Run one Auth instance against this SQLite database. Revisions use UTC ticks with a persisted
per-account monotonic floor. A normal database restore is followed by explicit reconciliation;
issuer changes or clock rollback require receiver watermark review before resuming. Keep the
database and signing material in backups. Removing a connector stops delivery; it does not delete
downstream accounts. Disable/reconcile accounts before retiring an integration.
