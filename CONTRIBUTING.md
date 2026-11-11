# Contributing

Use a reproducible issue with the exact revision, platform, redacted configuration and a synthetic reproduction. Describe the user-facing problem and expected behavior before proposing an API or protocol extension. Security reports follow [SECURITY.md](SECURITY.md).

## Local checks

Install .NET 10 and run from the repository root:

```sh
dotnet test tests/nas-auth.Tests --artifacts-path ./artifacts
docker build -t nas-auth:check .
```

Tests use temporary SQLite databases and fake identity providers; no company directory or production credentials are required. Docker builds run the entire test suite before publishing runtime files. GitHub CI tests Linux and Windows; runtime images target Linux.

For UI changes, review screenshots in light and dark themes at desktop, 390px and 320px widths.
Include account/security/devices, applications/setup/diagnostics, the user directory, another user's
details (destructive controls are hidden for yourself), and credential-link error/success pages.
Check primary links as well as buttons, hover/focus/busy states, long unbroken names and URLs,
and sidebar resize/Escape behavior without reloading. Measure rendered foreground/background
contrast; a page with no horizontal scrollbar can still clip content inside a card. Use synthetic
accounts and avoid capturing live credential links. Keep screenshots out of the source tree.

For a fix, include a failing regression that covers the actual boundary. For lifecycle changes cover existing cookies, forward-auth tickets/sessions, access and refresh tokens, authorization codes, grants, restoration and migration. Presentation-only changes need visual checks and existing relevant template checks rather than tests that mirror CSS.

Preserve default behavior unless an intentional migration is documented. Never change an existing subject or issuer implicitly. Keep organization-specific protocols, identifiers, URLs, credentials and deployment details out of generic implementation and examples. Add both English and Simplified Chinese UI text, appropriate configuration documentation and an Unreleased changelog entry.

Use the existing source layout and styles; avoid new runtime dependencies or general-purpose extension mechanisms without a concrete need. Do not commit generated build output, databases, keys or real identity data. A pull request should explain behavior, compatibility and validation, including anything not yet validated.
