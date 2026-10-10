---
title: Method filter
summary: Allow only the HTTP methods your application uses, refuse TRACE, CONNECT and WebDAV verbs, and block method-override headers.
category: traffic
order: 6
---

`MethodFilter` is a global allow-list of HTTP methods. Requests using any other method are refused with `405 Method Not Allowed` and an `Allow` header, before routing, rate limiting or the WAF spend any time on them. It also rejects method-override headers by default.

## What it protects against

* **Cross-Site Tracing (XST)**: `TRACE` echoes the request back, including cookies and authorization headers, which can defeat `HttpOnly` protections when a proxy or framework implements it.
* **Proxy abuse**: `CONNECT` turns a misconfigured server or proxy into an open tunnel.
* **Unexpected attack surface**: WebDAV verbs (`PROPFIND`, `MKCOL`, `COPY`, `MOVE`, `LOCK` …) and custom methods reach code paths nobody tested, and are a favourite of scanners.
* **Access-control bypass through method override**: headers such as `X-HTTP-Method-Override: DELETE` let a `POST` be treated as another method by frameworks or proxies that honour them, slipping past rules written for the real method (OWASP A01:2021, Broken Access Control).

## How it works

```text
request ----> method in allow-list?
                no  -> 405 method_not_allowed + Allow: GET, HEAD, POST, ...
                yes -> override header present and not allowed?
                         yes -> 400 method_override
                         no  -> next guard
```

* The default allow-list is `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`.
* The `Allow` header value is computed once, when the filter is built.
* The blocked override headers are `X-HTTP-Method-Override`, `X-HTTP-Method` and `X-Method-Override`, whatever their value.
* The guard runs at priority 60, after `Hygiene` and before `HostFilter`, `BodyLimit`, CORS and rate limiting.

## Quick start

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(Shield::builder().guard(MethodFilter::new()).build());
```

`MethodFilter::new()` is already part of the `recommended`, `strict` and `api` presets.

## Configuration

| Method | Default | Description |
|---|---|---|
| `MethodFilter::new()` | – | `GET HEAD POST PUT PATCH DELETE OPTIONS`, override headers blocked. |
| `MethodFilter::only(methods)` | – | Exactly these methods (replaces the default list). Panics on an empty list. |
| `MethodFilter::read_only()` | – | `GET HEAD OPTIONS` only. |
| `.allow_method_override()` | blocked | Accept method-override headers (legacy clients). |

## Examples

### A read-only site

A documentation site, a status page or a public mirror never needs writes:

```rust
use securite::prelude::*;

let shield = Shield::builder()
    .guard(MethodFilter::read_only())
    .build();
```

### An exact list with a custom method

`only` replaces the defaults, so list everything you need, including custom verbs such as a cache `PURGE`:

```rust
use axum::http::Method;
use securite::prelude::*;

let purge = Method::from_bytes(b"PURGE").expect("valid method");
let filter = MethodFilter::only([
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::OPTIONS,
    purge,
]);
```

### Legacy clients that need method override

Some old HTML forms and SOAP-era clients can only send `GET` and `POST`. If your framework relies on override headers, re-enable them explicitly:

```rust
use securite::prelude::*;

let filter = MethodFilter::new().allow_method_override();
```

## Standalone layer

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(MethodFilter::read_only());
```

## Response headers

A refused method gets an `Allow` header listing the accepted methods, as required by RFC 9110:

```text
HTTP/1.1 405 Method Not Allowed
allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Method Not Allowed","status":405,"code":"method_not_allowed","detail":"Method not allowed."}
```

An override header gets `400 Bad Request` with the code `method_override`. The refused method is written to the audit details of the security event (`method=TRACE`), never to the client.

## Pitfalls and tips

* **Keep `OPTIONS` if you use CORS**: browsers send preflights with `OPTIONS`, and the method filter runs before the CORS guard. Without it, every cross-origin preflight fails with `405`.
* **Keep `HEAD` next to `GET`**: uptime monitors, crawlers and link checkers rely on it, and axum answers `HEAD` for every `GET` route.
* `MethodFilter` is global. Per-route method restrictions remain your router's job (axum answers `405` for a known path with an unrouted method).
* Method names are case-sensitive: `get` is not `GET`, and is refused.

> **Tip:** the security event of a refused method carries the method name. A spike of `TRACE`, `PROPFIND` or `DEBUG` usually means a scanner is crawling your site; [auto-ban](/docs/auto-ban) in the same shield counts every refused method as a strike and can stop it.

## Related pages

* [HTTP hygiene](/docs/hygiene)
* [Body limit](/docs/body-limit)
* [Auto-ban](/docs/auto-ban)
* [CORS](/docs/cors)
