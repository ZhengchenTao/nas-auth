# Product assessment and proposed roadmap

Assessment started 2026-11-05; implementation status updated 2026-11-06. Remaining recommendations are not release commitments.

## Positioning

A lightweight identity gateway for households and small teams: OIDC, forward-auth and OAuth for MCP, packaged as one process with SQLite. Preserve straightforward operation and explicit authorization. Organization-specific protocols and endpoints belong in adapters and deployment configuration.

## Current strengths and gaps

The product already supports external identity approval and binding, local passwords, per-user resource grants, audit logs, configurable external profiles, account disabling and explicit original-identity restoration. These capabilities need coherent onboarding, recovery and troubleshooting flows rather than more isolated forms.

Current source has a binary administrator flag and individual grants, rather than general user groups or delegated administrative roles. Invitation binding exists, but it is not a complete expiring invitation and credential-recovery experience. Local authentication has no passkey/MFA enrollment. Device-specific session inventory is absent. Local user management now supports bounded server-side search, role/lifecycle filters and pagination. Resource/client configuration remains oriented toward deployment files.

## Implemented in source as of 2026-11-06

- Lifecycle hardening covers restored identities, sessions and forward-auth epochs. Minute-based access-token lifetime configuration is available. Release gates, Windows/Linux CI, contribution/security policies and operations documentation are present.
- Optional durable application account provisioning includes application selection, delivery status, retry and reconciliation. Business permissions remain in each receiving app. The generic receiver contract stays independent of deployment adapters.
- Existing-account search supports display name, username, stable ID and email; role/lifecycle filters, state totals and 25/50/100-row pages cover daily team administration. See [user management](user-management.md).

These are source capabilities, not a statement that any particular installation has upgraded. Production integration checks, an isolated backup-restore drill and conformance assessment remain separate work. The legacy access-token default is still 30 days unless overridden.


## Priority 0: reliable lifecycle and releases

- Validate disabling, deletion and restoration across SSO cookies, forward-auth tickets and sessions, access tokens, refresh tokens, authorization codes and external sign-in. Old credentials must never regain validity after restoration and subsequent reauthorization.
- Support token lifetimes in minutes, document separate security profiles and explain local revocation versus offline token validation and application-owned sessions.
- Require fresh authentication for sensitive identity, credential and administrator changes; preserve recovery-administrator protections.
- Run the full test suite as a release gate. Add real-browser smoke checks and a small set of application integration checks. Evaluate the applicable OpenID Foundation conformance profiles; unit test counts do not imply certification.
- Publish versioned releases with migration and rollback compatibility notes. Provide a generic backup-and-restore procedure covering SQLite and signing/cookie keys, and an isolated restore drill.

## Priority 1: team administration

1. **Groups and permission explanation.** Add groups, group-to-application grants, explicit exception semantics and expiry. Show the source of every effective grant and preview affected users before a group change. Keep descriptive department attributes separate from authorization unless an administrator explicitly configures a trusted mapping.
2. **Onboarding and recovery.** Build on existing invitation binding: expiring single-use invitations, status, cancellation, reissue and a user-controlled initial credential step. Make password recovery optional when a verified delivery channel is configured; otherwise support an audited administrator-assisted recovery flow.
3. **Application onboarding and diagnostics.** Provide an OIDC/forward-auth/MCP setup wizard, exact callback URLs, configuration validation and a preview of a selected user's effective claims. Keep client/resource details behind the application-level view. Diagnose account pending, account disabled, grant missing, provider unavailable and browser lookup unavailable as distinct operator-visible states.
4. **Stronger local sign-in.** Prioritize passkeys and a usable recovery path. Evaluate TOTP compatibility based on demand. Make enforcement configurable for administrators and applications; do not assume every upstream provider has performed MFA.
5. **Sessions and temporary access.** Add named/device-specific sessions and individual revocation, configurable idle/absolute expiry, and expiring guest access. Document which connected applications can receive logout or provisioning updates.
6. **Scalable daily operation.** Add local-user search, pagination, filters and carefully previewed batch actions. Show pending onboarding and expiring permissions as actionable work, rather than presenting raw counters without next steps.

## Open-source usability and maintainability

- Reconcile English/Chinese documentation, supported features and example configurations. Offer household, external-IdP team and password-only examples without organization-specific identifiers.
- Provide portable CI and release instructions, SECURITY.md, CONTRIBUTING.md, issue templates and a compatibility policy.
- Keep a versioned adapter contract, bounded profile schemas, example adapter, mock provider and contract tests. Separate verified identity claims from informational browser-imported attributes.
- Add structured operational events, redacted audit export, readiness checks and optional metrics/webhooks with retries and deduplication. Notifications and external transmission remain opt-in per deployment.
- Define configuration ownership and validation before introducing editable configuration UI or hot reload; avoid two competing sources of truth.

## Defer until demonstrated demand

Multi-tenancy, a general workflow designer, arbitrary policy scripting, SAML, full LDAP directory hosting, broad SCIM provisioning and multi-node HA should follow concrete adoption requirements. A larger authentication feature surface also increases the compatibility and security maintenance burden.

## Suggested milestones and acceptance

1. **Reliable release:** lifecycle checks across every credential type, portable CI, truthful docs, versioned upgrade and recovery procedures.
2. **Usable team administration:** groups, effective-permission explanations, invitations and application onboarding. A new administrator can onboard and offboard a colleague without editing database rows or guessing claim mappings.
3. **Self-service and automation:** stronger local authentication, per-device sessions, optional notifications and a versioned administration API. An adopter can operate the deployment without assistance from its original author.

## Comparison references

- [Pocket ID introduction](https://pocket-id.org/docs/introduction): focused small-team/homelab positioning, passkeys and group-based client access.
- [Authelia access control](https://www.authelia.com/overview/authorization/access-control/): resource access policies and authentication requirements.
- [authentik policies](https://docs.goauthentik.io/customize/policies/): reusable policy checks and bindings.
- [OpenID Provider conformance testing](https://openid.net/certification/connect_op_testing/): protocol conformance test plans and certification requirements.
