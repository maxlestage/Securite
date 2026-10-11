---
title: Error responses
summary: Choose how blocked requests are answered, from RFC 9457 problem+json to plain text, empty bodies or your own renderer, without leaking internals.
category: integrity
order: 4
---

When a guard rejects a request, the shield builds the response itself: your handlers never run. `ErrorFormat` decides what that response looks like. Whatever the format, rejections share the same hardening: a short generic message, no internal details, `Cache-Control: no-store`, and the same security headers as your normal responses.

## Why it matters

- **A05:2021 Security Misconfiguration** and **CWE-209** (error messages containing sensitive information): verbose errors that reveal rule ids, versions or stack traces help an attacker tune payloads until one gets through. Securite only sends a generic message; rule ids and matched values stay in the audit trail.
- Consistent, machine-readable errors let API clients distinguish a rate limit from a WAF block or an authentication failure without parsing text.

## The formats

| Variant | `Content-Type` | Body |
|---|---|---|
| `ErrorFormat::ProblemJson` (default) | `application/problem+json` | RFC 9457 problem details |
| `ErrorFormat::PlainText` | `text/plain; charset=utf-8` | `403 Forbidden: <message>` |
| `ErrorFormat::Empty` | none | empty |
| `ErrorFormat::custom(f)` | yours | whatever your closure returns |

Select one on the builder; the default is `ProblemJson`:

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .error_format(ErrorFormat::PlainText)
    .build();
```

| Method | Default | Description |
|---|---|---|
| `ShieldBuilder::error_format(ErrorFormat)` | `ErrorFormat::ProblemJson` | How rejections are rendered. |
| `ErrorFormat::custom(f)` | — | Builds `ErrorFormat::Custom` from a `Fn(&Rejection, &Context) -> Response<Bytes>` closure. |

### ProblemJson

The default format follows RFC 9457 (Problem Details for HTTP APIs), with two extension members: `code`, the machine-readable rejection code, and `request_id`, present when a `RequestId` guard runs.

```text
HTTP/1.1 403 Forbidden
content-type: application/problem+json
cache-control: no-store
x-request-id: 3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44
x-content-type-options: nosniff
```

```json
{
  "type": "about:blank",
  "title": "Forbidden",
  "status": 403,
  "code": "waf_blocked",
  "detail": "Request blocked by the web application firewall.",
  "request_id": "3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44"
}
```

The body is sent on a single line; `<` and `>` are escaped as `\u003c` and `\u003e`.

### PlainText

```text
403 Forbidden: Request blocked by the web application firewall.
```

Handy for small services and command-line clients.

### Empty

Only the status code and headers, no body. Use it when you prefer to reveal as little as possible, or when a CDN or reverse proxy renders its own error pages.

### Custom

Your closure receives the `Rejection` and the request `Context`, and returns an `http::Response<bytes::Bytes>` (`http` is re-exported as `securite::http`; add the `bytes` crate to your dependencies or use Vitesse's re-export `vitesse::Bytes`). A branded HTML page for a website:

```rust
use bytes::Bytes;
use http::{header, Response};
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .error_format(ErrorFormat::custom(|rejection, ctx| {
        let body = format!(
            "<!doctype html><title>{status}</title><h1>{status}</h1><p>{message}</p><p>Reference: {id}</p>",
            status = rejection.status(),
            message = rejection.message(),
            id = ctx.request_id().unwrap_or("n/a"),
        );
        Response::builder()
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Bytes::from(body))
            .unwrap()
    }))
    .build();
```

Or the error envelope your API clients already know, built with `serde_json` so that every value is escaped correctly:

```rust
use bytes::Bytes;
use http::{header, Response};
use securite::prelude::*;

let shield = ShieldBuilder::api()
    .error_format(ErrorFormat::custom(|rejection, ctx| {
        let body = serde_json::json!({
            "error": {
                "code": rejection.code(),
                "message": rejection.message(),
                "request_id": ctx.request_id(),
            }
        });
        Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Bytes::from(body.to_string()))
            .unwrap()
    }))
    .build();
```

`Rejection` exposes `status()`, `code()`, `message()`, `details()`, `headers()` and `is_benign()`. `Context` exposes `client_ip()`, `method()`, `uri()`, `path()`, `request_id()`, `rejected_by()`, `started()` and `csp_nonce()`.

> **Warning:** Never copy `rejection.details()` into the response. Details hold rule ids, matched patterns and IP addresses meant for your audit trail only.

## What every rejection gets

After rendering, whatever the format:

1. The status is set to the rejection's status, even if your custom response used another one.
2. `Cache-Control: no-store` is set, so that no browser or shared cache stores an error page.
3. Headers carried by the rejection are appended: `Retry-After` for rate limits and bans, `WWW-Authenticate` for authentication, `Allow` for forbidden methods.
4. Every guard decorates the response as usual: security headers, `X-Request-Id`, `RateLimit-*` headers, CORS headers, hardened cookies.

Common rejection codes:

| Guard | Status | `code` |
|---|---|---|
| `waf` | 403 | `waf_blocked` |
| `bot_blocker` | 403 | `bot_blocked` |
| `auth` | 401 | `unauthorized` |
| `rate_limit` | 429 | `rate_limited` |
| `ban` | 403 | `banned` |
| `csrf` | 403 | `csrf_rejected`, `csrf_token_invalid` |
| `body_limit` | 413 | `body_too_large` |
| `method` | 405 | `method_not_allowed` |
| `content_type` | 415 | `unsupported_media_type` |
| `ip_filter` | 403 | `ip_blocked` |
| `host` | 421 | `invalid_host` |

## Benign responses

Some short-circuits are not attacks: a CORS preflight answered with `204 No Content` (`cors_preflight`) or a plain HTTP request redirected with `308 Permanent Redirect` (`https_redirect`). They are created with `Rejection::respond(status, code)` and always have an empty body, whatever the format; your custom closure is not called. They do not get `Cache-Control: no-store`, are not logged or counted as blocked, and do not trigger `on_event`.

## Rejections from your own guards

A custom guard returns `Rejection::new(status, code, message)`. The message is sent to clients, so keep it generic and never include user input or secrets. Put diagnostics in `.with_details(…)`, and extra response headers in `.with_header(name, value)`.

## Standalone guards

A guard used on its own (`app.middleware(Shield::from(Waf::new()))`) builds an internal shield with the default format, so its rejections are always problem+json. The same is true for `SignatureLayer`. To choose the format, register your guards in a `Shield` built with `error_format`.

## Pitfalls and tips

- Your custom closure runs on every rejection, possibly during an attack: keep it fast, allocation-light and free of I/O.
- Escape everything you interpolate. Built-in messages are static, but messages from your own guards may not be.
- If your front end displays errors, show the `request_id`: it lets your support team find the exact event in the logs.
- `ErrorFormat::Empty` makes debugging harder for legitimate clients. Prefer `ProblemJson` for APIs and a custom HTML page for websites.

## Related pages

- [Custom guards](/docs/custom-guards)
- [Security events and statistics](/docs/events-stats)
- [Request IDs](/docs/request-id)
- [Shield and presets](/docs/shield-presets)
