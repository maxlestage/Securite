---
title: Authentication
summary: Bearer tokens, API keys, HTTP Basic or your own validator such as JWT, with secrets stored as SHA-256 digests and compared in constant time.
category: access
order: 3
---

`Auth` puts a credential check in front of your routes. It supports the schemes most services need (bearer tokens, API keys in a custom header, HTTP Basic) and lets you plug your own validation logic, for example JWT verification. Secrets are kept as SHA-256 digests and compared in constant time against every configured credential, and the authenticated identity is handed to your handlers.

## Threats mitigated

- **A01:2021 Broken Access Control**: admin panels, internal APIs and metrics endpoints left reachable without credentials.
- **A07:2021 Identification and Authentication Failures**: token comparisons that leak through timing (CWE-208), credentials checked inconsistently from one handler to the next.
- **A02:2021 Cryptographic Failures**: plain-text secrets lying in configuration files; with `token_sha256` your configuration only holds a digest.

## How it works

1. **Path selection.** A request is protected when its path matches one of the `protect` prefixes (every path if none is configured) and none of the `public` prefixes. Prefixes match on segment boundaries: `/api` covers `/api` and `/api/orders`, not `/apiary`.
2. **Preflights.** `OPTIONS` requests go through by default, because browsers never attach credentials to CORS preflights.
3. **Extraction.** The credential is read according to the scheme: `Authorization: Bearer …`, a custom header, or `Authorization: Basic …`.
4. **Verification.** The presented secret is hashed with SHA-256 and compared with every configured digest using a constant-time equality, without early exit. Neither the length nor the position of the matching credential can be inferred from response times.
5. **Outcome.** On success, a `Principal` is inserted into the request extensions. On failure, the request is rejected with `401 Unauthorized`, code `unauthorized`, message `Authentication required.` and a `WWW-Authenticate` challenge.

The guard runs late in the pipeline, after rate limiting, the bot blocker, the WAF and CSRF checks, so brute-force attempts are throttled before any credential is checked.

## Quick start

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let token = std::env::var("API_TOKEN").expect("API_TOKEN must be set");

let app: Router = Router::new()
    .route("/api/health", get(|| async { "ok" }))
    .route("/api/orders", get(|| async { "[]" }))
    .layer(
        ShieldBuilder::recommended()
            .guard(
                Auth::bearer()
                    .token("ci-pipeline", &token)
                    .protect(["/api"])
                    .public(["/api/health"]),
            )
            .build(),
    );
```

```bash
curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/api/orders
```

## Schemes

### Bearer tokens

`Auth::bearer()` reads `Authorization: Bearer <token>` (the scheme name is case-insensitive). Register as many tokens as you need, each with a label that becomes the principal name: it tells you which client called.

### API keys

```rust
use securite::prelude::*;

let partner_key = std::env::var("PARTNER_ACME_KEY").expect("PARTNER_ACME_KEY must be set");
let auth = Auth::api_key("x-api-key").token("partner-acme", &partner_key);
```

The header value is compared exactly as received.

### HTTP Basic

```rust
use securite::prelude::*;

let password = std::env::var("ADMIN_PASSWORD").expect("ADMIN_PASSWORD must be set");
let auth = Auth::basic("Admin area").user("admin", &password);
```

The digest of `user:password` is stored, and the principal name is the user name. Basic credentials travel with every request: only use them over HTTPS.

### Custom validation

`Auth::custom` hands the bearer token and the request head to your function, which returns the principal name when the token is valid. A complete JWT example follows below.

## Configuration

| Method | Default | Description |
|---|---|---|
| `Auth::bearer()` | — | `Authorization: Bearer <token>`. |
| `Auth::api_key(header)` | — | Key in a custom header; panics if the header name is invalid. |
| `Auth::basic(realm)` | — | HTTP Basic authentication with the given realm. |
| `Auth::custom(f)` | — | Bearer token checked by `Fn(&str, &request::Parts) -> Option<String>`. |
| `.token(label, secret)` | none | Accepted token or API key; panics if the secret is shorter than 8 bytes. |
| `.token_sha256(label, hex)` | none | Accepted token given by its SHA-256 hex digest; panics unless it is 64 hex characters. |
| `.user(user, password)` | none | Basic auth user; panics if the user name contains `:`. |
| `.realm(realm)` | `restricted` | Realm advertised in `WWW-Authenticate` (quotes and backslashes are removed). |
| `.protect(prefixes)` | every path | Only these path prefixes require credentials. |
| `.public(prefixes)` | none | Path prefixes that never require credentials; they win over `protect`. |
| `.protect_options()` | `OPTIONS` allowed | Also requires credentials on `OPTIONS` requests. |

## Keeping secrets out of your configuration

With `token_sha256`, only the digest of a token is stored in your configuration or environment. Compute it with:

```bash
# printf %s does not append a newline (echo would, and the digest would change).
printf %s "s3cr3t-token-from-vault" | sha256sum
# 316c2c9705150d9a064339f9af33986ffd585a65b1d3ff481c5a9941d45abe1f  -
```

```rust
use securite::prelude::*;

let auth = Auth::bearer()
    .token_sha256("deploy-bot", "316c2c9705150d9a064339f9af33986ffd585a65b1d3ff481c5a9941d45abe1f")
    .protect(["/deploy"]);
```

Basic credentials are verified as the digest of `user:password`, so `token_sha256` also works with `Auth::basic`; the label then becomes the principal name:

```bash
printf %s "admin:correct horse battery staple" | sha256sum
# 1ced36b78267abc485730b6921c0fe42edac8704d5fabe97bf6bb09b46b4164a  -
```

```rust
use securite::prelude::*;

let auth = Auth::basic("Admin area")
    .token_sha256("admin", "1ced36b78267abc485730b6921c0fe42edac8704d5fabe97bf6bb09b46b4164a")
    .protect(["/admin"]);
```

> **Tip:** Generate tokens with a cryptographically secure generator, for example `openssl rand -hex 32`. A plain SHA-256 digest is fine for such high-entropy tokens, but it would not protect a short human password from offline cracking: keep Basic passwords long and random.

## The `Principal` extension

```rust
use axum::{routing::get, Extension, Router};
use securite::prelude::*;

async fn whoami(Extension(principal): Extension<Principal>) -> String {
    // name: the credential label (or the Basic user name)
    // scheme: "bearer", "api_key", "basic" or "custom"
    format!("authenticated as {} via {}", principal.name, principal.scheme)
}

let token = std::env::var("API_TOKEN").expect("API_TOKEN must be set");
let app: Router = Router::new()
    .route("/api/whoami", get(whoami))
    .layer(Shield::builder().guard(Auth::bearer().token("ci-pipeline", &token)).build());
```

`Principal` is only inserted on protected paths. Extracting it from a public route makes axum answer `500 Internal Server Error` because the extension is missing.

## The `WWW-Authenticate` challenge

Every `401` carries a challenge that tells the client which scheme to use:

```text
Bearer realm="restricted"
ApiKey realm="restricted", header="x-api-key"
Basic realm="Admin area", charset="UTF-8"
```

`Auth::custom` sends a `Bearer` challenge. With Basic, browsers display their native login dialog.

## OPTIONS requests

CORS preflights never carry credentials, so `Auth` lets `OPTIONS` through by default. When a `Cors` guard is configured, it answers preflights before `Auth` even runs. If your API is never called from a browser, `.protect_options()` closes this door too.

## Plugging JWT validation

`Auth::custom` accepts any synchronous function. Here with the `jsonwebtoken` crate:

```rust
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use securite::prelude::*;
use serde::Deserialize;

#[derive(Clone, Deserialize)]
struct Claims {
    sub: String,
}

let key = DecodingKey::from_secret(
    std::env::var("JWT_SECRET").expect("JWT_SECRET must be set").as_bytes(),
);
let mut validation = Validation::new(Algorithm::HS256);
validation.set_audience(&["orders-api"]);
validation.set_issuer(&["https://auth.example.com"]);

let auth = Auth::custom(move |token, _req| {
    // Signature, expiry, audience and issuer are checked by `decode`.
    decode::<Claims>(token, &key, &validation)
        .ok()
        .map(|data| data.claims.sub)
})
.protect(["/api"])
.public(["/api/health"]);
```

The validator runs on the request path: keep it CPU-only (signature checks, in-memory lookups). Load signing keys or JWKS at startup and refresh them in a background task rather than fetching them per request. The second argument gives access to the request head, for example to read a tenant header.

## Several schemes in one application

A `Shield` holds one guard per name, so a second `Auth` would replace the first. Use standalone layers on separate routers instead, with `route_layer` so that unknown URLs still answer `404`:

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let admin_password = std::env::var("ADMIN_PASSWORD").expect("ADMIN_PASSWORD must be set");
let partner_key = std::env::var("PARTNER_ACME_KEY").expect("PARTNER_ACME_KEY must be set");

let admin = Router::new()
    .route("/admin/dashboard", get(|| async { "admin" }))
    .route_layer(Auth::basic("Admin area").user("admin", &admin_password));

let partners = Router::new()
    .route("/partners/orders", get(|| async { "[]" }))
    .route_layer(Auth::api_key("x-api-key").token("partner-acme", &partner_key));

let app: Router = Router::new()
    .route("/", get(|| async { "public home" }))
    .merge(admin)
    .merge(partners)
    .layer(Shield::recommended());
```

## Pitfalls and tips

- Serve authenticated routes over HTTPS only (`HttpsRedirect` and HSTS), otherwise tokens and Basic passwords travel in clear text.
- Rotate tokens without downtime: add the new token under a new label, deploy, migrate clients, then remove the old one.
- `401` is a default strike status of `AutoBan`: with [auto-ban](/docs/auto-ban) enabled, clients that keep guessing credentials are banned automatically. Add a strict `RateLimit` on login-like endpoints as well.
- `.public` always wins over `.protect`: double-check that a public prefix does not accidentally cover a sensitive sub-path.
- With `Auth::custom`, constant-time comparison is your validator's responsibility; signature verification libraries already take care of it.

## Related pages

- [IP filter](/docs/ip-filter)
- [Auto-ban](/docs/auto-ban)
- [Rate limiting](/docs/rate-limit)
- [HTTPS redirect](/docs/https-redirect)
- [CORS](/docs/cors)
- [Webhook signatures](/docs/webhook-signatures)
- [Security events and statistics](/docs/events-stats)
