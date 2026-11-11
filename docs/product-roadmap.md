# Product assessment and proposed roadmap

Assessment started 2026-11-05; implementation status updated 2026-11-12. Remaining recommendations are not release commitments.

## Positioning

A lightweight identity gateway for households and small teams: OIDC, forward-auth and OAuth for MCP, packaged as one process with SQLite. Preserve straightforward operation and explicit authorization. Organization-specific protocols and endpoints belong in adapters and deployment configuration.

## Current strengths and gaps

The product already supports external identity approval and binding, local passwords, per-user resource grants, audit logs, configurable external profiles, account disabling and explicit original-identity restoration. These capabilities need coherent onboarding, recovery and troubleshooting flows rather than more isolated forms.

Current source supports a binary administrator flag, individual grants and flat user groups with grant-source explanations and change previews. Local password invitations and administrator-assisted recovery now use expiring, revocable links; verified automatic delivery and external-provider recovery remain separate work. Local authentication has no passkey/MFA enrollment. Device sessions support inventory, names, individual revocation and configurable expiry. Local user management supports bounded server-side search, role/lifecycle filters and pagination. Resource/client configuration remains in deployment files, with a setup wizard and preflight command to prepare and validate changes.

## Implemented in source as of 2026-11-06

Additions on 2026-11-11: [unified release artifacts](unified-release.md), [application diagnostics](application-diagnostics.md),
[application setup and preflight](application-onboarding.md), and [local invitations/recovery](invitations-and-recovery.md).

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

1. **Group access.** Flat groups, application grants, grant sources and impact previews are available. Use real NAS and small-team deployments to validate the group workflow.
2. **Onboarding and recovery.** Local password invitations and audited administrator-assisted recovery are implemented with expiry, single use, status, cancellation and reissue. Optional verified delivery, self-service recovery requests and richer external-provider onboarding remain follow-up work.
3. **Application onboarding and diagnostics.** OIDC/forward-auth/MCP setup, callback/configuration checks and effective grant diagnosis are implemented. Effective claim preview and explicit external-provider/browser-lookup availability checks remain follow-up work. Keep deployment files authoritative.
4. **Stronger local sign-in.** Prioritize passkeys and a usable recovery path. Evaluate TOTP compatibility based on demand. Make enforcement configurable for administrators and applications; do not assume every upstream provider has performed MFA.
5. **Sessions and temporary access.** [Device session inventory, naming, revocation and configurable idle/absolute expiry](device-sessions.md) are implemented. Expiring guest grants and further application-specific logout integration remain follow-up work.
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
