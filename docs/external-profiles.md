# Configurable external profiles and account creation

External identity binding always uses `(provider, subject)`. Display attributes, directory results and email addresses do not replace that key. Features below are disabled when not configured; ordinary Google/Microsoft and root-path deployments retain their existing sign-in behavior.

## Provider-specific fields

Configure `ExternalProfiles:Providers:<provider-id>`. Its ID must match the configured sign-in provider. Each provider has its own fields and browser lookup capability. For example:

```json
{
  "ExternalProfiles": {
    "Providers": {
      "staff": {
        "DisplayName": "Employee directory",
        "SubjectField": "employee_id",
        "UsernameField": "username",
        "NameField": "name",
        "EmailField": "email",
        "BrowserLookupUrl": "https://directory.example.test/lookup.html",
        "AllowAdminCreate": true,
        "AllowSelfRefresh": true,
        "AutoRefreshAfterLogin": true,
        "Fields": {
          "employee_id": { "Label": "Employee ID", "BrowserImport": true },
          "username": { "Label": "Username", "BrowserImport": true },
          "name": { "Label": "Full name", "BrowserImport": true },
          "email": { "Label": "Work email", "Type": "email", "BrowserImport": true },
          "department": { "Label": "Department", "BrowserImport": true }
        }
      }
    }
  }
}
```

`Order` controls field placement; `Detail=true` folds technical attributes into identity details. Empty values are omitted, and the configured name field becomes the card heading. `Visible` defaults to true; hidden fields can still be imported if explicitly allowed. `BrowserImport` defaults to false. Optional `SourceClaim` maps a claim from the authenticated identity to a stored field on sign-in. A personal deployment can configure only name/email or omit this section entirely. Attributes are bounded, rendered as escaped text, and shown only to the owner and administrators. They do not enter downstream tokens automatically or assert `email_verified`.

## Two browser workflows

* After external sign-in, an opted-in provider opens a self-profile lookup. Only the authenticated user's already bound subject can be updated. A browser-supplied profile cannot change their primary downstream email, binding or privileges. Failure or timeout continues the original sign-in destination.
* An administrator searches the directory, explicitly selects a person, and confirms creation or profile import. New accounts have no usable password, no administrator role and no application grants. The generated username must be valid, unused and never retired; conflicts require the existing approval flow. Existing subjects cannot be overwritten. Administrators may explicitly adopt the imported email as the primary account email.

Browser results are client-supplied informational data, not a signed directory assertion. The backend enforces actor/target ownership, field allowlists, exact subjects, CSRF and size/type limits. The audit records the actor, target, mode and field names, not the complete profile. Private provider adapters own endpoint URLs, response mapping and any directory-specific authentication.

## Lookup bridge protocol

The configured helper must use a distinct approved HTTPS origin. A separate same-site hostname is preferred. A different port isolates DOM access but shares host cookies; such deployments require HttpOnly authentication/CSRF cookies, strict cross-origin write rejection, a static helper without backend credentials, and exact message validation. Never allow third-party directory JSONP globally in the auth page's script policy.

The parent creates a sandboxed iframe with a UUID `request` and exact parent origin in the fragment. The helper validates its allowed parent and sends `{type:"directory-ready",request}`. The parent checks the helper's origin, window source and request ID before sending `{type:"directory-query",request,keyword}`. The helper returns `{type:"directory-result",request,status:"ok",rows:[{...normalized fields...}]}` or an error status. Both sides reject unknown/expired requests. Only declared fields reach the save form. The helper must not forward directory cookies to the auth backend.

## A single account email

When a public auth site queries an intranet directory, newer browsers may require Local Network Access permission. Set `BrowserLookupNeedsLocalNetwork=true` only for providers that need it. This delegates the ability to request that permission to the exact helper origin; it does not grant browser permission or enable loopback access. The user must allow the site prompt. Keep browser protections enabled and do not extract directory cookies.

The default external-account form asks for one email and creates a one-time verified-email invitation. The separate password-account form asks for username/password/email. Directory-enabled deployments show personnel search instead of the email invitation form. Existing user IDs never change.

The account editor uses its account email to enable a pending first binding, without a second email input. Historical pending aliases remain visible/removable. Updating the primary email moves its matching unconsumed invitation atomically, preserves unrelated legacy aliases, and rolls back on conflicts. It does not change existing external identity bindings. Account creation and its invitation are also atomic.

## Releases

Pushing source to `main` builds/publishes an image. Deployment requires an explicit manual workflow dispatch with `deploy=true`; source integration does not implicitly restart a configured runtime. Validate the default configuration and each configured deployment separately.
