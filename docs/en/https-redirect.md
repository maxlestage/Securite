---
title: HTTPS redirect
summary: Redirects plain-HTTP requests to HTTPS with a 308, and understands TLS-terminating proxies such as Heroku, Render, AWS ALB or Cloudflare.
category: browser
order: 4
---

`HttpsRedirect` sends every plain-HTTP request to its `https://` equivalent with `308 Permanent Redirect`. It reads the original scheme from the request URI or from the headers set by your TLS-terminating proxy, and leaves local development alone.

## The threat

Over plain HTTP, anyone on the network path (public Wi-Fi, a compromised router, an ISP) can read and modify traffic: credentials, session cookies, pages and downloads. An active attacker can also keep a victim on HTTP indefinitely ("SSL stripping"). This is OWASP Top 10 2021 A02 Cryptographic Failures; the OWASP Transport Layer Security and HTTP Strict Transport Security cheat sheets, and WSTG-CONF-07, cover it.

A redirect alone is not enough, because the first request is still sent in clear text. The robust setup is:

1. `HttpsRedirect` moves visitors who arrive over HTTP to HTTPS;
2. [HSTS](/docs/security-headers), sent on HTTPS responses, makes the browser use HTTPS directly for the following visits;
3. optionally, HSTS preloading removes even the very first HTTP request.

## How it works

The guard runs at priority 75, after the ban, IP filter, hygiene and method checks and right after `HostFilter` (70): when both are in the same shield, the redirect is only built from a validated host. It still runs before rate limiting and the WAF. It determines the scheme in this order:

1. the scheme of the request URI, if the request uses an absolute URI;
2. if `trust_forwarded_proto` is enabled (the default), the right-most value of `X-Forwarded-Proto`, the one set by the closest proxy, which is the same trust model as `ClientIpSource::XForwardedFor`;
3. otherwise the `proto=` parameter of the standard `Forwarded` header;
4. if none is available, the scheme is unknown and **nothing happens**, which keeps local development working.

When the request is plain HTTP and its path is not exempt, the shield answers `308 Permanent Redirect` with `Location: https://<host><path>?<query>`. The host comes from the URI or the `Host` header, without its port. Unlike `301` and `302`, a `308` keeps the method and the body. The redirect is a benign short-circuit: empty body, not logged as an attack, not counted as blocked. A missing or malformed host yields `400 Bad Request` with the code `https_required`.

`/.well-known/acme-challenge/` is exempt by default so that Let's Encrypt HTTP-01 validation keeps working.

## Quick start

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    let shield = Shield::builder()
        .guard(HttpsRedirect::new())
        .guard(SecurityHeaders::new()) // HSTS for the following visits
        .build();

    Router::new()
        .route("/", get(|| async { "secure" }))
        .layer(shield)
}
```

`Shield::strict()` already includes `HttpsRedirect::new()`. The guard is named `https_redirect`.

## Configuration

| Method | Default | Description |
|---|---|---|
| `HttpsRedirect::new()` | trusts forwarded headers, exempts ACME | Recommended setup. |
| `trust_forwarded_proto(bool)` | `true` | Reads `X-Forwarded-Proto` (right-most value) and `Forwarded`. When `false`, only an absolute request URI can reveal the scheme. |
| `exempt(prefix)` | `/.well-known/acme-challenge/` | Adds a path prefix that is never redirected. Can be called several times. |

Prefixes match on segment boundaries: `/health` matches `/health` and `/health/live`, but not `/healthz`. A missing leading slash is added for you.

## Examples

### Behind a PaaS or a load balancer

Heroku, Render, Fly.io, AWS ALB and Cloudflare terminate TLS and set `X-Forwarded-Proto`. Health checks often use plain HTTP, so exempt them:

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    let shield = Shield::builder()
        .client_ip(ClientIpSource::heroku())
        .guard(HttpsRedirect::new().exempt("/health"))
        .guard(SecurityHeaders::new())
        .build();

    Router::new()
        .route("/", get(|| async { "secure" }))
        .route("/health", get(|| async { "ok" }))
        .layer(shield)
}
```

### Checking the redirect with curl

```bash
curl -i http://127.0.0.1:3000/path?x=1 \
  -H "Host: example.com" \
  -H "X-Forwarded-Proto: http"
```

```text
HTTP/1.1 308 Permanent Redirect
location: https://example.com/path?x=1
```

### Terminating TLS in your own process

If the application serves HTTPS itself and listens on port 80 only to redirect, requests on that listener carry no scheme information. Mark them as plain HTTP before the shield runs, and add `HostFilter` to the same shield so that the host is validated before the redirect:

```rust
use axum::{Router, extract::Request, http::{HeaderValue, StatusCode}, middleware::map_request};
use securite::prelude::*;

async fn mark_plain_http(mut req: Request) -> Request {
    req.headers_mut()
        .insert("x-forwarded-proto", HeaderValue::from_static("http"));
    req
}

// Served on port 80 only; the real application listens on 443.
pub fn port_80_app() -> Router {
    let shield = Shield::builder()
        .guard(HostFilter::new(["example.com", "www.example.com"])) // priority 70
        .guard(HttpsRedirect::new()) // priority 75: only sees allowed hosts
        .build();

    Router::new()
        .fallback(|| async { StatusCode::NOT_FOUND }) // reached by exempt paths only
        .layer(shield)
        .layer(map_request(mark_plain_http)) // outermost: runs first
}
```

## Standalone layer

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(HttpsRedirect::new())
}
```

## Pitfalls and tips

> **Tip:** the `Location` is built from the `Host` header, and a `308` can be cached. Add [HostFilter](/docs/host-filter) to the same `Shield`: it runs at priority 70, before `HttpsRedirect` (75), so a forged host is refused with `421` instead of being redirected. With standalone layers, put `HostFilter` outside `HttpsRedirect`.

- **No scheme, no redirect**: if neither the URI nor a proxy header reveals the scheme, the guard does nothing. Check in staging with the curl command above.
- **Trust the proxy, not the client**: `X-Forwarded-Proto` is only reliable when your proxy sets it. The guard reads the right-most value, written by the proxy closest to your application, so a value the client wrote to its left is ignored. With `trust_forwarded_proto(false)`, a server behind no proxy only redirects absolute-URI requests.
- **Chained proxies**: when several proxies append to `X-Forwarded-Proto`, the right-most value only describes the last hop. If that hop is plain HTTP, every request is redirected: make the proxy closest to your application forward the client's scheme instead of appending its own.
- **Ports**: the redirect always targets the default HTTPS port, 443.
- **APIs**: a client that follows the redirect has already sent its token in clear text. For pure APIs, prefer not to listen on HTTP at all.
- **Health checks**: load balancers that probe over HTTP would receive a `308` and mark the instance unhealthy; exempt their path.

> **Tip:** combine the redirect with HSTS from [SecurityHeaders](/docs/security-headers) and secure cookies from [CookieHardening](/docs/cookies): together they keep sessions off plain HTTP.

## Related pages

- [Security headers](/docs/security-headers)
- [Host filter](/docs/host-filter)
- [Cookie hardening](/docs/cookies)
- [Client IP](/docs/client-ip)
