# External sign-in and path-mounted forward-auth

This note supplements [external-auth.md](external-auth.md) with the current generic ticket-provider contract, `PathBase` deployment, and Nginx `auth_request` configuration.

## Mount nas-auth under `/auth`

`Auth:PathBase` defaults to empty, which preserves existing root-path deployments. To mount the service under `/auth`, set:

```dotenv
Auth__PathBase=/auth
Auth__Issuer=https://auth.example.test/auth
```

The public login page, OIDC endpoints, static assets, and external identity callbacks use `/auth/...`. The reverse proxy must preserve that prefix when forwarding to nas-auth. The service strips `/auth` before endpoint routing.

Forward-auth callbacks and logout are different: the browser visits `/.nas-auth/*` on the protected site's hostname. When nas-auth uses `PathBase=/auth`, proxy those site paths to nas-auth's `/auth/.nas-auth/*`. Do not put `auth_request` on this callback/logout location. With an empty `PathBase`, keep the existing root-path behavior.

## Multiple applications on one host

Forward-auth `resource_url` values may include path prefixes. These entries can share a hostname:

```json
[
  { "aud": "tools", "resource_url": "https://portal.example.test/tools/", "display_name": "Tools", "forward_auth": {} },
  { "aud": "tools-admin", "resource_url": "https://portal.example.test/tools/admin/", "display_name": "Tools admin", "forward_auth": {} }
]
```

The longest matching prefix wins, so `/tools/admin/...` selects `tools-admin`. Each application has its own grant and its own host-only cookie name derived from `aud`.

## Nginx `auth_request`

The fixed `aud` belongs in each internal verify location. The request's `Host`, `Cookie`, `Accept`, `Origin`, `Sec-Fetch-*`, original method, and original URI must reach nas-auth. `response=auth_request` makes a browser navigation without a session return `401`, `X-Auth-Redirect`, and a state `Set-Cookie`. Nginx does not automatically forward response headers from an auth subrequest, so capture the redirect and cookie with `auth_request_set`. API requests get a 401 with no redirect header, and a denied user gets 403. Upstream errors fail closed.

This example assumes HTTPS on the default port, one protected hostname, and upstream apps that expect their public path prefix to be stripped. Adjust `proxy_pass` paths if an app expects the prefix. In the auth virtual host, preserve `/auth/` when proxying nas-auth.

```nginx
server {
    listen 443 ssl;
    server_name auth.example.test;

    # Default external-provider callbacks carry state/code/ticket query values.
    location ^~ /auth/signin/ {
        access_log off;
        proxy_pass http://nas_auth:8080/auth/signin/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /auth/ {
        proxy_pass http://nas_auth:8080/auth/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

```nginx
server {
    listen 443 ssl;
    server_name portal.example.test;

    # Browser callback/logout routes on the protected hostname. No auth_request here.
    location ^~ /.nas-auth/ {
        access_log off;
        proxy_pass http://nas_auth:8080/auth/.nas-auth/;
        proxy_set_header Host portal.example.test;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location = /tools {
        return 308 /tools/;
    }
    location = /tools/admin {
        return 308 /tools/admin/;
    }

    # The more specific application has its own fixed audience.
    location ^~ /tools/admin/ {
        auth_request /_nas_auth_verify_tools_admin;
        auth_request_set $nas_auth_redirect $upstream_http_x_auth_redirect;
        auth_request_set $nas_auth_state_cookie $upstream_http_set_cookie;
        auth_request_set $nas_auth_user $upstream_http_x_auth_user;
        auth_request_set $nas_auth_email $upstream_http_x_auth_email;
        error_page 401 = @nas_auth_401;

        proxy_set_header Host $host;
        proxy_set_header X-Auth-User $nas_auth_user;
        proxy_set_header X-Auth-Email $nas_auth_email;
        add_header Cache-Control "private, no-cache" always;
        proxy_pass http://tools_admin/;
    }

    location ^~ /tools/ {
        auth_request /_nas_auth_verify_tools;
        auth_request_set $nas_auth_redirect $upstream_http_x_auth_redirect;
        auth_request_set $nas_auth_state_cookie $upstream_http_set_cookie;
        auth_request_set $nas_auth_user $upstream_http_x_auth_user;
        auth_request_set $nas_auth_email $upstream_http_x_auth_email;
        error_page 401 = @nas_auth_401;

        proxy_set_header Host $host;
        proxy_set_header X-Auth-User $nas_auth_user;
        proxy_set_header X-Auth-Email $nas_auth_email;
        add_header Cache-Control "private, no-cache" always;
        proxy_pass http://tools_site/;
    }

    # Internal subrequests. Keep each aud fixed here; never accept it from visitors.
    location = /_nas_auth_verify_tools_admin {
        internal;
        proxy_pass http://nas_auth:8080/auth/forward-auth/verify?aud=tools-admin&response=auth_request;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Host portal.example.test;
        proxy_set_header Cookie $http_cookie;
        proxy_set_header Accept $http_accept;
        proxy_set_header Origin $http_origin;
        proxy_set_header Sec-Fetch-Site $http_sec_fetch_site;
        proxy_set_header Sec-Fetch-Mode $http_sec_fetch_mode;
        proxy_set_header Sec-Fetch-Dest $http_sec_fetch_dest;
        proxy_set_header Sec-Fetch-User $http_sec_fetch_user;
        proxy_set_header X-Forwarded-Method $request_method;
        proxy_set_header X-Forwarded-Uri $request_uri;
    }

    location = /_nas_auth_verify_tools {
        internal;
        proxy_pass http://nas_auth:8080/auth/forward-auth/verify?aud=tools&response=auth_request;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Host portal.example.test;
        proxy_set_header Cookie $http_cookie;
        proxy_set_header Accept $http_accept;
        proxy_set_header Origin $http_origin;
        proxy_set_header Sec-Fetch-Site $http_sec_fetch_site;
        proxy_set_header Sec-Fetch-Mode $http_sec_fetch_mode;
        proxy_set_header Sec-Fetch-Dest $http_sec_fetch_dest;
        proxy_set_header Sec-Fetch-User $http_sec_fetch_user;
        proxy_set_header X-Forwarded-Method $request_method;
        proxy_set_header X-Forwarded-Uri $request_uri;
    }

    # Only browser navigations carry X-Auth-Redirect. APIs remain plain 401s.
    location @nas_auth_401 {
        if ($nas_auth_redirect = "") { return 401; }
        add_header Set-Cookie $nas_auth_state_cookie always;
        add_header Cache-Control "no-store" always;
        return 302 $nas_auth_redirect;
    }
}
```

The proxy overwrites any visitor-supplied `X-Auth-User` and `X-Auth-Email` headers. Pass identity headers only if the application needs them. Protected responses should not enter a shared cache. Nginx's `auth_request` module allows 2xx, rejects 401/403, and treats other subrequest statuses as errors; `auth_request_set` reads response values such as `$upstream_http_set_cookie` after the subrequest completes ([official module documentation](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)).

## Generic ticket login provider

`ExternalProviders:TicketProviders` is a generic integration point. Provider-specific login protocol details belong in a separately configured private adapter, not in the public repository. A provider is registered and shown only when `Enabled=true` and the login URL, validation URL, and shared token are all present. A disabled provider has no authentication handler on its callback path.

The login URL must be an HTTPS URL with no embedded credentials. The validation URL must use HTTPS, except that HTTP is allowed for a loopback-only local adapter. Inject the adapter token from a deployment secret store; do not commit it in `appsettings`, compose files, or logs.

NAS sends one POST to the validation URL only after receiving the login callback with a ticket:

```http
Authorization: Bearer <configured shared token>
Content-Type: application/json
```

```json
{ "ticket": "<callback ticket>", "client_ip": "<RemoteIpAddress or null>" }
```

Only a 2xx response with a bounded JSON body is accepted:

```json
{ "subject": "<stable immutable account id>", "display_name": "<optional>", "email": "<optional>" }
```

`subject` is required and must be stable. `display_name` and `email` may be omitted or null. The configured `SubjectClaim`, `NameClaim`, and `EmailClaim` choose the internal claim names. The contract has no `email_verified` field, so email cannot redeem a pre-bound email invite or automatically claim an existing account. An unknown identity enters `/admin/approvals`; an administrator checks the pending provider, subject, and display details, then explicitly binds it to an existing local account (including an administrator) or creates a user. This does not import old debug identities or replace an existing binding by email.

Non-2xx, timeout, connection failure, non-JSON, oversized or malformed responses, missing subject, and replayed tickets all fail authentication. The validation request disables HTTP redirects and times out after 10 seconds. The NAS handler never logs the ticket or token. Reverse-proxy access logs must also suppress query strings on callback URLs; the Nginx example disables access logging on the default callback locations. The process-local replay cache keeps only a provider-namespaced SHA-256 digest, has a 10,000-entry limit, and removes expired entries before accepting new ones. When full it fails closed and logs a warning; it does not grow without bound. Restart clears the replay cache, so the adapter must still make tickets short-lived and one-time.

Ticket settings use `ExternalProviders:TicketProviders:<index>:`: `Id`, `DisplayName`, `Enabled`, `LoginUrl`, `ValidationUrl`, `ValidationToken`, `CallbackPath` (default `/signin/{id}`), `ReturnUrlParameter` (default `return_url`), `StateParameter`, `TicketParameter`, `LoginParameters`, `SubjectClaim`, `NameClaim`, and `EmailClaim`. Public examples use `.example.test`; real login domains, query values, and tokens belong only in private deployment configuration. With no explicit provider list and an empty `Auth:PathBase`, the existing Google/Microsoft environment-variable behavior and root-path deployment remain available.
