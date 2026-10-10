---
title: CORS
summary: Strict, allow-list based Cross-Origin Resource Sharing that never reflects arbitrary origins and refuses insecure combinations at startup.
category: browser
order: 2
---

`Cors` answers preflight requests and adds `Access-Control-*` headers for the origins you list, and only for those. Its defaults are deliberately closed: no origin is allowed until you name one.

## The threat

The same-origin policy prevents a page on `evil.example` from reading your API's responses. CORS is how you poke controlled holes in that policy, and a misconfiguration turns it off entirely:

- **Origin reflection**: echoing any `Origin` together with `Access-Control-Allow-Credentials: true` lets every website read your users' authenticated data.
- **The `null` origin**: sandboxed iframes and `file://` pages send `Origin: null`; trusting it is equivalent to trusting anyone.
- **Sloppy matching**: suffix or regex checks that accept `app.example.com.evil.com` or `evilexample.com`.

These are classic OWASP Top 10 2021 A05 Security Misconfiguration and A01 Broken Access Control issues, covered by the OWASP Web Security Testing Guide (WSTG-CLNT-07).

## How it works

`Cors` runs at priority 90, before rate limiting, CSRF and authentication, so preflights carrying no credentials are answered first.

- **No `Origin` header** (same-origin navigation, curl, server-to-server): the request is not touched.
- **Preflight** (`OPTIONS` with `Access-Control-Request-Method`): the origin, the method and every requested header are checked. On success the shield answers `204 No Content` itself, with `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, `Access-Control-Max-Age` and `Access-Control-Allow-Origin`. On failure it answers `403` with the code `cors_rejected`, and the event is logged.
- **Actual request from an allowed origin**: the response gets `Access-Control-Allow-Origin` (the exact origin, or `*` for `allow_any_origin()` without credentials), plus `Access-Control-Allow-Credentials` and `Access-Control-Expose-Headers` when configured.
- **Actual request from another origin**: no CORS header is added, so the browser hides the response from the calling script.
- Every response carries `Vary: Origin`, so caches never serve one origin's answer to another.

Origins are compared case-insensitively, with any trailing slash ignored. `https://*.example.com` matches subdomains at any depth but not `example.com` itself; scheme and port must match exactly. `null` is only accepted when listed explicitly. Passing `"*"` to `allow_origin` panics (use `allow_any_origin()`), and so does combining `allow_any_origin()` with `allow_credentials(true)`.

## Quick start

```rust
use std::time::Duration;

use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    let cors = Cors::new()
        .allow_origin("https://app.example.com")
        .allow_credentials(true)
        .max_age(Duration::from_secs(3600));

    Router::new()
        .route("/api/me", get(|| async { "{}" }))
        .layer(Shield::builder().guard(cors).build())
}
```

## Configuration

| Method | Default | Description |
|---|---|---|
| `Cors::new()` | no origin | Starts with common methods and headers, but no allowed origin. |
| `allow_origin(&str)` | — | Allows one origin (`https://app.example.com`) or a wildcard pattern (`https://*.example.com`). |
| `allow_origins(iter)` | — | Allows several origins. |
| `allow_any_origin()` | off | Sends `Access-Control-Allow-Origin: *`. Public, unauthenticated APIs only. |
| `allow_methods(iter of Method)` | `GET, HEAD, POST, PUT, PATCH, DELETE` | **Replaces** the allowed methods. |
| `allow_headers(iter)` | `accept, accept-language, content-language, content-type, authorization, x-requested-with, x-csrf-token, x-request-id` | **Replaces** the allowed request headers. |
| `expose_headers(iter)` | none | **Replaces** the response headers readable by scripts. |
| `allow_credentials(bool)` | `false` | Allows cookies and `Authorization` on cross-origin requests. |
| `max_age(Duration)` | 600 seconds | How long browsers may cache a preflight. |
| `allow_private_network(bool)` | `false` | Answers Private Network Access preflights with `Access-Control-Allow-Private-Network: true`. |

The guard is named `cors`. No preset includes it, because only you know your origins.

## Examples

### Front-end on another subdomain, with cookies

A single-page app on `app.example.com` calls `api.example.com` with a session cookie. Its `POST` requests are cross-origin, so CSRF protection must trust that origin too:

```rust
use std::time::Duration;

use axum::{Router, routing::{get, post}};
use securite::prelude::*;

pub fn api() -> Router {
    let shield = ShieldBuilder::recommended()
        .guard(
            Cors::new()
                .allow_origin("https://app.example.com")
                .allow_credentials(true)
                .expose_headers(["x-request-id", "ratelimit-remaining"])
                .max_age(Duration::from_secs(3600)),
        )
        // Replaces the preset's CSRF guard: the SPA is a trusted cross-origin caller.
        .guard(Csrf::new().trusted_origin("https://app.example.com"))
        .build();

    Router::new()
        .route("/me", get(|| async { "{}" }))
        .route("/orders", post(|| async { "created" }))
        .layer(shield)
}
```

### Public read-only API

```rust
use axum::http::Method;
use securite::prelude::*;

pub fn public_cors() -> Cors {
    Cors::new()
        .allow_any_origin()
        .allow_methods([Method::GET, Method::HEAD])
        .allow_headers(["accept", "content-type"])
}
```

### Subdomains, preview deployments and custom headers

```rust
use securite::prelude::*;

pub fn cors(dev: bool) -> Cors {
    let cors = Cors::new()
        .allow_origins(["https://example.com", "https://*.example.com"])
        .allow_headers(["content-type", "authorization", "x-api-key"]);
    if dev { cors.allow_origin("http://localhost:5173") } else { cors }
}
```

### Checking a preflight with curl

```bash
curl -i -X OPTIONS https://api.example.com/orders \
  -H "Origin: https://app.example.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type"
```

```text
HTTP/2 204
access-control-allow-methods: GET, HEAD, POST, PUT, PATCH, DELETE
access-control-max-age: 3600
access-control-allow-headers: accept, accept-language, content-language, content-type, authorization, x-requested-with, x-csrf-token, x-request-id
access-control-allow-origin: https://app.example.com
access-control-allow-credentials: true
vary: origin
```

## Standalone layer

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/api/items", get(|| async { "[]" }))
        .layer(Cors::new().allow_origin("https://app.example.com"))
}
```

With axum, the last `.layer()` call is the outermost one. When you stack standalone layers, add `Cors` after any authentication layer so that preflights, which never carry credentials, are answered before they reach it. Inside a single `Shield` this order is automatic.

## Pitfalls and tips

> **Warning:** CORS is not access control. A "simple" request from a disallowed origin still reaches your handler; the browser only hides the response. Protect state-changing endpoints with [CSRF protection](/docs/csrf) and a JSON-only [Content-Type allow-list](/docs/content-type).

- `allow_methods`, `allow_headers` and `expose_headers` replace their defaults. Adding `x-api-key` alone would drop `content-type` and `authorization`.
- Never list `null`. It is sent by sandboxed iframes and local files that any attacker can create.
- A wildcard covers every current and future subdomain, including one taken over through a dangling DNS record. Prefer an exact list for credentialed APIs.
- `https://app.example.com` and `https://app.example.com:8443` are different origins.
- Browsers cap `max_age` (Chromium at two hours), so larger values have no effect.
- Keep development origins such as `http://localhost:5173` out of the production configuration.
- Scripts can only read CORS-safelisted response headers. Expose `x-request-id` or rate-limit headers if your front-end needs them.

> **Tip:** if your CDN caches API responses, make sure it honours `Vary: Origin`.

## Related pages

- [CSRF protection](/docs/csrf)
- [Content-Type allow-list](/docs/content-type)
- [Security headers](/docs/security-headers)
- [Cookie hardening](/docs/cookies)
- [Authentication](/docs/auth)
