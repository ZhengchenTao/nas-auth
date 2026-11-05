# Security policy

This is a small, actively evolving identity gateway. A passing test suite is not an independent security audit or OpenID certification.

## Reporting

Use private vulnerability reporting on the upstream GitHub repository when available. If that facility is unavailable, open an issue requesting a confidential reporting channel without including exploit details, personal data, credentials, tickets or tokens. Do not publish a working exploit in a normal issue before coordinated disclosure.

Provide the source revision/image digest, configuration with sensitive values removed, affected authentication path, expected behavior and a minimal reproduction using synthetic accounts. Retain sensitive evidence privately. Maintainer response times are best effort; there is no response-time SLA.

## Deployment and support boundary

Run a pinned revision behind HTTPS. Protect the database, RSA and DataProtection keys as credentials. The current main branch receives fixes; older revisions have no promised backport period. Review the changelog and migration notes before upgrading.

Disabling an Auth account does not delete connected application accounts. The gateway checks its own sessions and locally validated tokens. Offline JWT consumers and applications' own sessions have their own expiration and revocation behavior. Treat browser-imported directory attributes as informational rather than proof of ownership or permission.

Do not downgrade past a lifecycle/security boundary to work around a deployment failure. Prefer a compatible forward fix or isolate the deployment while investigating.
