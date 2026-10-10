---
title: Quick start
summary: Protect an axum application with Shield::recommended(), check the headers it adds, watch it block an SQL injection, then tailor the preset.
category: start
order: 3
---

In five minutes you will put an axum application behind the recommended shield, see what changes on the wire and adjust the preset to your needs.

## Create the project

```bash
cargo new secure-app
cd secure-app
cargo add securite axum
cargo add tokio --features macros,rt-multi-thread,net
```

## Add the shield

Replace `src/main.rs` with:

```rust
use std::net::SocketAddr;

use axum::{Router, routing::get};
use securite::prelude::*;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(|| async { "Hello, secure world!" }))
        // Security headers, WAF, rate limiting, CSRF, request ids …
        .layer(Shield::recommended());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on http://{}", listener.local_addr().unwrap());
    axum::serve(
        listener,
        // Gives the shield the real client IP.
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
```

Two details matter. `.layer()` comes after the routes, because axum only wraps the routes registered before it. `into_make_service_with_connect_info` exposes the TCP peer address, which per-IP guards need (see [Installation](/docs/installation)).

## Run it

```bash
cargo run
```

## A normal request

```bash
curl -i http://127.0.0.1:3000/
```

```text
HTTP/1.1 200 OK
content-type: text/plain; charset=utf-8
content-length: 20
x-request-id: 3f6c2a1e-8b4d-4e7a-9c15-2d0f6b8a7e43
ratelimit-limit: 100
ratelimit-remaining: 99
ratelimit-reset: 1
strict-transport-security: max-age=63072000; includeSubDomains
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: accelerometer=(), autoplay=(), camera=(), …
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
origin-agent-cluster: ?1
x-dns-prefetch-control: off
x-download-options: noopen
x-permitted-cross-domain-policies: none
x-xss-protection: 0
content-security-policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests

Hello, secure world!
```

Your handler did not change, yet the response is now hardened:

| Header | Added by | Protection |
|---|---|---|
| `x-request-id` | `request_id` | Correlates the response with logs and security events |
| `ratelimit-*` | `rate_limit` | Tells clients their remaining budget (20 req/s, burst 100) |
| `content-security-policy` | `security_headers` | Blocks injected scripts, plugins and framing (XSS, clickjacking) |
| `strict-transport-security` | `security_headers` | Forces HTTPS for two years, including sub-domains |
| `cross-origin-*` | `security_headers` | Isolates your origin from cross-origin documents |

Headers that reveal your stack, such as `Server` or `X-Powered-By`, are removed.

## A blocked attack

Now send a classic SQL injection in the query string:

```bash
curl -i "http://127.0.0.1:3000/?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"
```

```text
HTTP/1.1 403 Forbidden
content-type: application/problem+json
cache-control: no-store
x-request-id: 9a1d4c7b-2e3f-4a5b-8c6d-0e1f2a3b4c5d
ratelimit-limit: 100
ratelimit-remaining: 99
ratelimit-reset: 1
x-content-type-options: nosniff
x-frame-options: DENY
…
```

The body follows RFC 9457 (formatted here for readability):

```json
{
  "type": "about:blank",
  "title": "Forbidden",
  "status": 403,
  "code": "waf_blocked",
  "detail": "Request blocked by the web application firewall.",
  "request_id": "9a1d4c7b-2e3f-4a5b-8c6d-0e1f2a3b4c5d"
}
```

The handler never ran. The client gets a stable `code` and the `request_id`, but nothing about the rules that matched: those details only go to your logs. Rejections are marked `no-store` and still receive every security header.

### See it in your logs

Blocked requests are written with `tracing` under the `securite` target. Add a subscriber (`cargo add tracing-subscriber`) and call `tracing_subscriber::fmt::init();` at the top of `main`:

```text
WARN securite: request blocked guard="waf" code="waf_blocked" status=403 ip=Some(127.0.0.1) method=GET path="/" request_id="9a1d4c7b-2e3f-4a5b-8c6d-0e1f2a3b4c5d" details="score=… rules=[…] categories=sqli"
```

## Customize the preset

`ShieldBuilder::recommended()` returns the same preset as a builder. `.guard()` adds a guard, or replaces the guard with the same name; `.without()` removes one:

```rust
use std::time::Duration;

use axum::http::Method;
use axum::{Router, routing::get};
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    // Same name as the preset's limiter ("rate_limit"): it replaces it.
    .guard(
        RateLimit::new(Quota::per_second(20).burst(100))
            .route_methods("/login", [Method::POST], Quota::per_minute(5))
            .skip_paths(["/health"]),
    )
    // Not in the preset: it is added.
    .guard(AutoBan::new().max_strikes(10).ban_for(Duration::from_secs(600)))
    // Token-authenticated API without cookies: CSRF protection is not needed.
    .without("csrf")
    .build();

println!("{:?}", shield.guard_names());
// ["request_id", "ban", "hygiene", "method", "body_limit", "rate_limit",
//  "bot_blocker", "waf", "security_headers", "cookies"]

let app: Router = Router::new()
    .route("/", get(|| async { "Hello, secure world!" }))
    .route("/health", get(|| async { "ok" }))
    .layer(shield);
```

> **Warning:** Only remove `csrf` when no state-changing endpoint relies on cookies or other ambient credentials. Browsers attach cookies to cross-site requests; CSRF protection is what stops another site from using them.

> **Tip:** `CookieHardening` adds `Secure` to every cookie. Browsers accept secure cookies on `http://localhost`, but on another plain-HTTP development host use `CookieHardening::new().insecure_dev()`, and never in production.

## Next steps

- [Shield and presets](/docs/shield-presets): what each preset contains and in which order guards run.
- [Client IP](/docs/client-ip): mandatory reading before deploying behind a proxy.
- [Monitor mode](/docs/monitor-mode): roll out the WAF or a stricter CSP without breaking production.
