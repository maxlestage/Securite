---
title: Request IDs
summary: Gives every request a unique, validated identifier that reaches your handlers, your logs, every security event and every error response.
category: integrity
order: 1
---

When a customer reports "the site said Forbidden", you need to find that exact request among millions of log lines. `RequestId` assigns every request an identifier, passes it to your handlers, echoes it in the response and attaches it to every security event and error body, so a single value ties together what the client saw, what the shield decided and what your application logged.

## Why it matters

- **A09:2021 Security Logging and Monitoring Failures**: without a correlation identifier, incidents cannot be reconstructed and alerts cannot be linked to application logs.
- **Log injection (CWE-117)**: identifiers supplied by clients are reused only when they are short and made of safe characters, so nobody can forge log lines or inject markup into your dashboards through this header.

## How it works

1. The guard runs first in the pipeline, so every later decision can reference the identifier.
2. If the request already carries the header (by default `X-Request-Id`) with a valid value, that value is kept. Valid means 1 to 128 characters among `A-Z`, `a-z`, `0-9`, `-`, `_`, `.` and `:`.
3. Otherwise a new identifier is generated in UUID v4 format, for example `3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44`.
4. The header is (re)written in the request, and a `RequestIdValue` is inserted into the request extensions.
5. The identifier is echoed in the response header, including on rejections, and added to `SecurityEvent::request_id`, to the `securite` tracing logs and to the `request_id` field of problem+json error bodies.

## Quick start

`RequestId::new()` is part of every preset. In a custom shield:

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "home" }))
    .layer(Shield::builder().guard(RequestId::new()).build());
```

```bash
curl -i https://example.com/
# HTTP/2 200
# x-request-id: 3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44
```

## Configuration

| Method | Default | Description |
|---|---|---|
| `RequestId::new()` | `x-request-id`, safe incoming ids reused | Creates the guard (`RequestId::default()` is equivalent). |
| `.header(name)` | `x-request-id` | Custom header name such as `x-correlation-id`; panics if the name is invalid. |
| `.always_generate()` | off | Ignores incoming identifiers and always generates a fresh one. |
| `RequestId::generate()` | — | Returns a new identifier in UUID v4 format (`String`). |

## Reading the ID in handlers

```rust
use axum::{routing::post, Extension, Router};
use securite::prelude::*;

async fn create_order(Extension(id): Extension<RequestIdValue>) -> String {
    tracing::info!(request_id = id.as_str(), "creating order");
    format!("order accepted, reference {}", id.as_str())
}

let app: Router = Router::new()
    .route("/orders", post(create_order))
    .layer(Shield::builder().guard(RequestId::new()).build());
```

`RequestIdValue` wraps the `HeaderValue` (`id.0`), which you can copy as-is into the headers of outgoing requests to propagate the identifier to downstream services.

## Adding the ID to every log line

With `tower-http`, open a span per request that carries the identifier. The trace layer must sit below the shield so that the extension is already present:

```rust
use axum::{body::Body, http::Request, routing::get, Router};
use securite::prelude::*;
use tower_http::trace::TraceLayer;

let app: Router = Router::new()
    .route("/", get(|| async { "home" }))
    .layer(TraceLayer::new_for_http().make_span_with(|req: &Request<Body>| {
        let id = req
            .extensions()
            .get::<RequestIdValue>()
            .map(|id| id.as_str().to_owned())
            .unwrap_or_default();
        tracing::info_span!("http", method = %req.method(), path = req.uri().path(), request_id = %id)
    }))
    // Added last, so it runs first.
    .layer(Shield::recommended());
```

## Behind a proxy or a platform

Heroku's router, many load balancers and Nginx (`proxy_set_header X-Request-Id $request_id;`) already set a request identifier. `RequestId::new()` reuses it when it is valid, so the same value appears in your platform logs and in your application logs. If your organisation uses another convention, change the header name:

```rust
use securite::prelude::*;

let request_id = RequestId::new().header("x-correlation-id");
```

If the application is reachable directly by clients, they can choose their own identifier. Validation makes that harmless for your logs, but a client could reuse another request's identifier to muddy an investigation. Use `.always_generate()` when no trusted proxy sets the header:

```rust
use securite::prelude::*;

let request_id = RequestId::new().always_generate();
```

## Standalone layer

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "home" }))
    .layer(RequestId::new());
```

> **Warning:** A standalone `RequestId` layer has its own internal shield. Another `Shield` in the same stack will not know the identifier: its events and problem+json bodies will not contain it. Register `RequestId` in the same shield as your other guards, as the presets do.

## Pitfalls and tips

- Identifiers are random but produced by a fast, non-cryptographic generator. They are correlation identifiers, not secrets: never use them as session tokens, nonces or authorisation keys.
- The identifier is returned on blocked requests too. Show it on your error pages so that users can quote it to your support team.
- Keep the header name consistent across services so that a single search in your log platform follows a request end to end.

## Related pages

- [Security events and statistics](/docs/events-stats)
- [Error responses](/docs/error-format)
- [Client IP](/docs/client-ip)
