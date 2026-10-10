---
title: Host filter
summary: An allow-list for the Host header that stops Host header poisoning and DNS-rebinding attacks.
category: access
order: 2
---

`HostFilter` only lets through requests addressed to your own domain names. Anything else (a forged `Host`, a raw IP address, a domain that merely resolves to your server) is refused before it reaches your code.

## The threat

The `Host` header is chosen by the client, yet many applications trust it:

- **Password-reset and link poisoning**: an application that builds absolute URLs from `Host` ("click here to reset your password") sends victims a link to the attacker's domain, together with a valid reset token.
- **Web cache poisoning**: a cache that ignores `Host` in its key can store a response generated for a forged host and serve it to everyone.
- **DNS rebinding**: a malicious page re-points its own domain to `127.0.0.1` or an internal address. The victim's browser then talks to your local or internal service as if it were same-origin with the attacker's page, sending `Host: attacker.example`.
- **Scanners and misrouting**: bots that sweep IP ranges send the raw IP address as host.

OWASP lists Host header injection in its Web Security Testing Guide (WSTG-INPV-17); it typically ends up under A05 Security Misconfiguration.

## How it works

The guard runs at priority 70, after the protocol hygiene checks and right before the HTTPS redirect (75). It takes the host from the request URI (absolute-form requests and HTTP/2 `:authority`) or, failing that, from the `Host` header. Before comparison the value is lowercased, its port is stripped and a trailing dot is removed. Each rule is either an exact name or a `*.example.com` pattern.

- Allowed host: the request continues.
- Unknown host: `421 Misdirected Request`, code `invalid_host`; the rejected value is recorded in the event details, never sent back.
- No host at all: `400 Bad Request`, code `missing_host`.

Requests carrying several `Host` headers are already rejected by the `Hygiene` guard of the presets.

| Rule | Matches | Does not match |
|---|---|---|
| `example.com` | `example.com`, `EXAMPLE.com:443`, `example.com.` | `www.example.com`, `example.com.evil.com` |
| `*.example.com` | `api.example.com`, `a.b.example.com` | `example.com`, `evilexample.com` |
| `localhost` (via `allow_localhost`) | `localhost:3000` | `localhost.example.com` |

## Quick start

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    let shield = Shield::builder()
        .guard(HostFilter::new(["example.com", "*.example.com"]))
        .build();

    Router::new()
        .route("/", get(|| async { "hello" }))
        .layer(shield)
}
```

The guard is named `host`. No preset includes it, because only you know your domains.

## Configuration

| Method | Default | Description |
|---|---|---|
| `HostFilter::new(hosts)` | — | Allowed host names, port-insensitive. `*.example.com` matches every subdomain but not `example.com` itself. |
| `allow(hosts)` | — | Adds more allowed hosts. |
| `allow_localhost()` | off | Also accepts `localhost`, `127.0.0.1` and `[::1]`. |
| `monitor()` | enforce | Logs and reports violations without blocking. |
| `is_allowed(&str)` | — | Tells whether a host, with or without port, is allowed. |

## Examples

### Production and local development

```rust
use securite::prelude::*;

pub fn hosts(dev: bool) -> HostFilter {
    let hosts = HostFilter::new(["example.com", "*.example.com"]);
    if dev { hosts.allow_localhost() } else { hosts }
}
```

### A local tool protected against DNS rebinding

Development dashboards, desktop-app back-ends and admin tools bound to `127.0.0.1` are the favourite targets of DNS rebinding:

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn local_admin() -> Router {
    Router::new()
        .route("/", get(|| async { "local admin" }))
        .layer(HostFilter::new(["localhost", "127.0.0.1", "[::1]"]))
}
```

### Rolling out in monitor mode

Before enforcing, find out which hosts your real traffic uses:

```rust
use securite::prelude::*;

pub fn shield() -> Shield {
    Shield::builder()
        .guard(HostFilter::new(["example.com", "*.example.com"]).monitor())
        .on_event(|e| {
            if e.guard == "host" {
                eprintln!("unexpected host on {}: {:?}", e.path, e.details);
            }
        })
        .build()
}
```

### Health checks addressed by IP

Load balancers and Kubernetes probes often use the instance IP as host. With axum, routes added after `.layer()` are not wrapped by it:

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "hello" }))
        .layer(Shield::builder().guard(HostFilter::new(["example.com"])).build())
        // Not behind the shield: probes using the pod IP as host still succeed.
        .route("/healthz", get(|| async { "ok" }))
}
```

## Standalone layer

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(SecurityHeaders::strict())
        .layer(HostFilter::new(["example.com"])) // outermost: runs first
}
```

## Pitfalls and tips

> **Tip:** inside one `Shield`, `HostFilter` runs before [HttpsRedirect](/docs/https-redirect), which builds its `Location` from the `Host` header: add both to the same shield and only validated hosts are ever redirected. With standalone layers, put `HostFilter` outside `HttpsRedirect`.

- A wildcard does not include the apex: list both `example.com` and `*.example.com`.
- Rules ignore the port; the filter cannot distinguish `example.com:8080` from `example.com`.
- `X-Forwarded-Host` is not checked. If your framework builds URLs from it, make sure your proxy overwrites it.
- Never build absolute URLs from request headers in the first place; use a configured base URL. The filter is a safety net, not a substitute.
- Health checks by IP get `421`: exempt them as shown above or allow the address explicitly.

> **Tip:** `421 Misdirected Request` is the status HTTP/2 clients expect when a connection is reused for a host it does not serve; well-behaved clients retry on a fresh connection.

## Related pages

- [HTTPS redirect](/docs/https-redirect)
- [CSRF protection](/docs/csrf)
- [CORS](/docs/cors)
- [Security headers](/docs/security-headers)
- [HTTP hygiene](/docs/hygiene)
- [Monitor mode](/docs/monitor-mode)
