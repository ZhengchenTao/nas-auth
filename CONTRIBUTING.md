# Contributing

Use a reproducible issue with the exact revision, platform, redacted configuration and a synthetic reproduction. Describe the user-facing problem and expected behavior before proposing an API or protocol extension. Security reports follow [SECURITY.md](SECURITY.md).

## Local checks

Install .NET 10 and run from the repository root:

```sh
dotnet test tests/nas-auth.Tests --artifacts-path ./artifacts
docker build -t nas-auth:check .
```

Tests use temporary SQLite databases and fake identity providers; no company directory or production credentials are required. Docker builds run the entire test suite before publishing runtime files. GitHub CI tests Linux and Windows; runtime images target Linux.

For a fix, include a failing regression that covers the actual boundary. For lifecycle changes cover existing cookies, forward-auth tickets/sessions, access and refresh tokens, authorization codes, grants, restoration and migration. Presentation-only changes need visual checks and existing relevant template checks rather than tests that mirror CSS.

Preserve default behavior unless an intentional migration is documented. Never change an existing subject or issuer implicitly. Keep organization-specific protocols, identifiers, URLs, credentials and deployment details out of generic implementation and examples. Add both English and Simplified Chinese UI text, appropriate configuration documentation and an Unreleased changelog entry.

Use the existing source layout and styles; avoid new runtime dependencies or general-purpose extension mechanisms without a concrete need. Do not commit generated build output, databases, keys or real identity data. A pull request should explain behavior, compatibility and validation, including anything not yet validated.
