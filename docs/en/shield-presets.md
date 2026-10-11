---
title: Shield and presets
summary: What Shield::recommended(), strict() and api() contain, how to customise them with ShieldBuilder, and the exact order in which guards run.
category: start
order: 4
---

A `Shield` is an immutable, cheaply clonable pipeline of guards. You get one from a preset or from `ShieldBuilder`, then add it to your app with `app.middleware()` (or to a tower service with `.layer()`). `Shield::recommended()` is simply `ShieldBuilder::recommended().build()`, and the same goes for `strict()` and `api()`.

## The three presets

### Shield::recommended()

Sensible protection for web applications and APIs served to browsers. Ten guards:

| Guard | Name | Settings |
|---|---|---|
| `RequestId::new()` | `request_id` | `x-request-id`, reuses safe incoming ids |
| `Hygiene::new()` | `hygiene` | URI 8 KiB, 100 headers, 32 KiB of headers, 256 query parameters, no dot segments or bad encoding |
| `MethodFilter::new()` | `method` | `GET HEAD POST PUT PATCH DELETE OPTIONS`, method-override headers refused |
| `BodyLimit::new(2 * 1024 * 1024)` | `body_limit` | Based on `Content-Length` |
| `RateLimit::new(Quota::per_second(20).burst(100))` | `rate_limit` | 20 req/s per IP, burst 100, IPv6 grouped by /64 |
| `BotBlocker::new()` | `bot_blocker` | Built-in list of scanners (sqlmap, nikto, nuclei …) |
| `Waf::new()` | `waf` | Paranoia `Low`, threshold 5, headers inspected |
| `Csrf::new()` | `csrf` | Fetch Metadata and `Origin` checks, no token |
| `SecurityHeaders::new()` | `security_headers` | Strict same-origin CSP, HSTS two years with sub-domains, `nosniff`, `DENY` … |
| `CookieHardening::new()` | `cookies` | `Secure; HttpOnly; SameSite=Lax` |

### Shield::strict()

Everything in `recommended()`, with tighter limits and four extra guards:

| Guard | Name | Change |
|---|---|---|
| `HttpsRedirect::new()` | `https_redirect` | Added: `308` to HTTPS, trusts `X-Forwarded-Proto`, ACME challenges exempt |
| `AutoBan::new()` | `ban` | Added: 20 strikes within a minute (requests blocked by another guard, `401`, `403` or `429` responses) trigger a 15 min ban, doubling up to 24 h |
| `BodyLimit::new(1024 * 1024)` | `body_limit` | Lowered from 2 MiB |
| `RateLimit::new(Quota::per_second(10).burst(40))` | `rate_limit` | 10 req/s per IP, burst 40 |
| `ConcurrencyLimit::per_ip(32)` | `concurrency` | Added: 32 in-flight requests per IP |
| `Waf::new().paranoia(Paranoia::Medium)` | `waf` | Paranoia `Medium` |
| `ContentTypeGuard::new()` | `content_type` | Added: JSON, `application/*+json`, URL-encoded and multipart forms |
| `SecurityHeaders::strict()` | `security_headers` | Adds `Cross-Origin-Embedder-Policy: require-corp` and `Referrer-Policy: no-referrer` (no HSTS `preload`) |
| `CookieHardening::new().same_site(SameSite::Strict)` | `cookies` | `SameSite=Strict` |

> **Tip:** no preset sends the HSTS `preload` directive, which signals consent to inclusion in browser preload lists. Once every sub-domain serves HTTPS, opt in with `.hsts(Some(Hsts { preload: true, ..Hsts::default() }))` on `SecurityHeaders` (import `securite::headers::Hsts`), see [Security headers](/docs/security-headers).

### Shield::api()

Tuned for JSON APIs authenticated with tokens rather than cookies, so it contains no CSRF guard:

| Guard | Name | Settings |
|---|---|---|
| `RequestId`, `Hygiene`, `MethodFilter` | `request_id`, `hygiene`, `method` | As in `recommended()` |
| `BodyLimit::new(1024 * 1024)` | `body_limit` | 1 MiB |
| `RateLimit::new(Quota::per_second(20).burst(50))` | `rate_limit` | 20 req/s per IP, burst 50 |
| `BotBlocker::new()`, `Waf::new()` | `bot_blocker`, `waf` | As in `recommended()` |
| `ContentTypeGuard::json()` | `content_type` | `application/json` and `application/*+json` only |
| `SecurityHeaders::api()` | `security_headers` | CSP `default-src 'none'`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` |
| `CookieHardening::new()` | `cookies` | `Secure; HttpOnly; SameSite=Lax` |

## The builder

`Shield::builder()` starts from an empty pipeline; `ShieldBuilder::recommended()`, `strict()` and `api()` start from a preset.

| Method | Effect | Default |
|---|---|---|
| `.guard(g)` | Adds a guard; a guard with the same `name()` is replaced | — |
| `.without(name)` | Removes the guard with that name | — |
| `.client_ip(source)` | Where the client IP comes from, see [Client IP](/docs/client-ip) | `ClientIpSource::Peer` |
| `.error_format(format)` | How rejections are rendered, see [Error format](/docs/error-format) | `ErrorFormat::ProblemJson` |
| `.on_event(f)` | Callback for every block or monitored violation | None |
| `.log_events(bool)` | Writes events with `tracing` (target `securite`) | `true` |
| `.build()` | Sorts guards by priority and returns the `Shield` | — |

```rust
use securite::prelude::*;

let shield = ShieldBuilder::strict()
    // Behind Heroku's router.
    .client_ip(ClientIpSource::heroku())
    // Not in the preset: added.
    .guard(Cors::new().allow_origin("https://app.example.com"))
    // Same name as the preset's guard: replaced.
    .guard(BodyLimit::new(10 * 1024 * 1024))
    // Removed by name.
    .without("concurrency")
    .error_format(ErrorFormat::PlainText)
    .on_event(|e| {
        if e.enforced {
            eprintln!("[security] {} blocked {} {}", e.guard, e.method, e.path);
        }
    })
    .build();

assert_eq!(
    shield.guard_names(),
    [
        "request_id", "ban", "hygiene", "method", "https_redirect", "body_limit",
        "cors", "rate_limit", "bot_blocker", "waf", "csrf", "content_type",
        "security_headers", "cookies",
    ]
);
```

Because `.guard()` replaces by name, configuring a preset never produces duplicates: there is always at most one `rate_limit`, one `waf`, and so on.

## Execution order

`build()` sorts guards by priority, lower first; guards with equal priority keep their insertion order. The constants live in `securite::priority`:

| Constant | Value | Guard | Name |
|---|---|---|---|
| `REQUEST_ID` | 10 | `RequestId` | `request_id` |
| `BAN` | 30 | `AutoBan` | `ban` |
| `IP_FILTER` | 40 | `IpFilter` | `ip_filter` |
| `HYGIENE` | 50 | `Hygiene` | `hygiene` |
| `METHOD` | 60 | `MethodFilter` | `method` |
| `HOST` | 70 | `HostFilter` | `host` |
| `HTTPS_REDIRECT` | 75 | `HttpsRedirect` | `https_redirect` |
| `BODY_LIMIT` | 80 | `BodyLimit` | `body_limit` |
| `CORS` | 90 | `Cors` | `cors` |
| `RATE_LIMIT` | 100 | `RateLimit` | `rate_limit` |
| `CONCURRENCY` | 105 | `ConcurrencyLimit` | `concurrency` |
| `USER_AGENT` | 110 | `BotBlocker` | `bot_blocker` |
| `WAF` | 120 | `Waf` | `waf` |
| `CSRF` | 130 | `Csrf` | `csrf` |
| `AUTH` | 140 | `Auth` | `auth` |
| `CONTENT_TYPE` | 150 | `ContentTypeGuard` | `content_type` |
| `CUSTOM` | 500 | Your own guards (default) | Your choice |
| `HEADERS` | 900 | `SecurityHeaders` | `security_headers` |
| `COOKIES` | 910 | `CookieHardening` | `cookies` |

The order is deliberate. The request id comes first so that every event carries one. Banned and filtered IPs are dropped before any real work, cheap protocol checks run before the WAF, the HTTPS redirect follows the host filter so that its `Location` is built from a validated host, and rate limiting cuts floods before the more expensive inspection. Response decoration follows the same order, so security headers and cookie hardening act last on the final response. `shield.guard_names()` returns the names in execution order.

## Standalone guards

Every guard converts into a `Shield` (and implements `tower::Layer`), so a single protection can be used on its own:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(SecurityHeaders::strict()));
app.middleware(Shield::from(RateLimit::per_minute(120)));
app.get("/", |_req: Request| async { "ok" });

let waf_only = Shield::from(Waf::new());
```

> **Warning:** Each standalone guard is an independent one-guard shield: it uses the default error format and keeps its own statistics. It resolves the client IP from the TCP peer address, unless an outer shield already did: behind a proxy, make `Shield::builder().client_ip(ClientIpSource::heroku()).build()` (or your platform's source) the first middleware, see [Client IP](/docs/client-ip). Shields do not decorate each other's rejections either: the first middleware added is the outermost, so the `429` responses above carry no security headers. Prefer a single `Shield` built with `.guard()`.

## Inspecting a shield

`shield.stats()` returns a `StatsSnapshot` with `total`, `blocked`, `monitored` and per-guard counters, plus `allowed()` and `to_json()`. A `Shield` is an `Arc` internally: clone it freely to share it between your router and a metrics endpoint. See [Events and stats](/docs/events-stats).
