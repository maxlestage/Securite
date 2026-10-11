---
title: Body limit
summary: Reject oversized request bodies before your handler runs, with per-route limits, and enforce the limit on chunked streams too.
category: traffic
order: 4
---

Securite gives you two complementary tools against oversized request bodies. `BodyLimit` is a guard that rejects requests whose declared `Content-Length` is too large, before any byte of the body is read. The streaming limit, which also covers chunked uploads that declare no length, is the server's: Vitesse's `app.body_limit`, or the `BodyLimitLayer` tower layer in other services.

## What it protects against

Accepting arbitrarily large bodies is one of the cheapest denial-of-service attacks: a few clients uploading gigabytes can fill your memory or disk, saturate your bandwidth and keep workers busy parsing (OWASP API4:2023, Unrestricted Resource Consumption). JSON and form parsers are especially exposed, because they usually buffer the whole body in memory before parsing it.

## How it works

```text
request head ----> BodyLimit (guard, priority 80)
                     Content-Length present?
                       invalid           -> 400 bad_content_length
                       > limit for path  -> 413 body_too_large
                     no Content-Length, Transfer-Encoding set,
                     POST/PUT/PATCH and require_content_length(true)
                                         -> 411 length_required
body stream -----> Vitesse: app.body_limit (1 MiB by default)
                   tower services: BodyLimitLayer (Limited body)
                     more than max bytes read -> 413
```

* `BodyLimit` only looks at headers: rejection costs nothing and happens before your handler, the WAF or authentication run.
* Route limits match path prefixes on segment boundaries; the **longest matching prefix wins**, the default limit applies elsewhere.
* A chunked body has no `Content-Length`, so `BodyLimit` cannot judge its size. Either refuse such bodies with `require_content_length(true)` or rely on the streaming limit: Vitesse's `app.body_limit(bytes)` (1 MiB by default) stops reading past the limit and answers `413 Payload Too Large`; in tower services, `BodyLimitLayer` wraps the body in `http_body_util::Limited` the same way.

## Quick start

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let shield = Shield::builder()
    // 1 MiB for every request body.
    .guard(BodyLimit::new(1024 * 1024))
    .build();

let mut app = App::new();
app.middleware(shield);
app.post("/comments", |req: Request| async move {
    let body = req.text().await?;
    Ok::<_, Error>(format!("{} bytes", body.len()))
});
```

The presets already include a body limit: 2 MiB for `Shield::recommended()`, 1 MiB for `Shield::strict()` and `Shield::api()`.

## Configuration

### BodyLimit (guard)

| Method | Default | Description |
|---|---|---|
| `BodyLimit::new(max_bytes)` | – | Default maximum body size in bytes (`u64`). |
| `.route(prefix, max_bytes)` | none | Different limit for a path prefix (longest prefix wins). |
| `.require_content_length(bool)` | `false` | Reject `POST`, `PUT` and `PATCH` bodies sent with `Transfer-Encoding` and no `Content-Length` (`411`). |
| `.limit_for(path)` | – | Returns the limit that applies to `path`. |

### BodyLimitLayer (streaming)

| Method | Default | Description |
|---|---|---|
| `BodyLimitLayer::new(max_bytes)` | – | Maximum number of body bytes your service can read (`usize`). |

`BodyLimitLayer` is a plain tower layer for services without Vitesse (which has `app.body_limit`), not a guard: it cannot be registered with `Shield::builder().guard()`, and overflows are not reported as security events.

## Examples

### Small API bodies, large uploads

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let shield = Shield::builder()
    .guard(
        BodyLimit::new(256 * 1024)                    // 256 KiB everywhere...
            .route("/upload", 50 * 1024 * 1024)       // ...50 MiB for uploads...
            .route("/upload/avatar", 2 * 1024 * 1024) // ...but 2 MiB for avatars
            .require_content_length(true),
    )
    .build();

async fn upload(req: Request) -> Result<String, Error> {
    let body = req.bytes().await?;
    Ok(format!("{} bytes", body.len()))
}

let mut app = App::new();
// Vitesse's own limit (1 MiB by default) must be raised as well.
app.body_limit(50 * 1024 * 1024);
app.middleware(shield);
app.post("/upload/files", upload);
app.post("/upload/avatar", upload);
```

### Chunked uploads

When clients legitimately stream bodies without `Content-Length` (HTTP/2 clients, chunked encoders), keep `require_content_length(false)` and add the streaming layer as a backstop:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
// Hard cap on what the handler can ever read, chunked or not.
app.body_limit(1024 * 1024);
// Fast path: honest Content-Length values are rejected before any read.
app.middleware(Shield::builder().guard(BodyLimit::new(1024 * 1024)).build());
app.post("/ingest", |req: Request| async move {
    let body = req.bytes().await?;
    Ok::<_, Error>(format!("{} bytes", body.len()))
});
```

## Standalone guard

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(BodyLimit::new(64 * 1024)));
app.post("/comments", |req: Request| async move { req.text().await });
```

## Response headers

`BodyLimit` adds no specific header. Rejections use the shield's error format (`application/problem+json` and `Cache-Control: no-store` by default):

| Status | Code | When |
|---|---|---|
| `413 Payload Too Large` | `body_too_large` | `Content-Length` above the limit for the path. The message includes the limit. |
| `400 Bad Request` | `bad_content_length` | `Content-Length` is not a number. |
| `411 Length Required` | `length_required` | Chunked `POST`/`PUT`/`PATCH` with `require_content_length(true)`. |

```text
HTTP/1.1 413 Payload Too Large
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Payload Too Large","status":413,"code":"body_too_large","detail":"Request body too large (max 262144 bytes)."}
```

Overflows detected while streaming are answered by the server: Vitesse sends its `413` error (customisable with `app.on_error`); a tower service answers with its own error for `BodyLimitLayer`.

## Pitfalls and tips

* **Two limits apply with Vitesse**: `req.bytes()`, `req.text()`, `req.json()` and `req.form()` stop at the server's own limit, 1 MiB by default. Raise it with `app.body_limit` for upload routes, or uploads above 1 MiB fail even when Securite allows them.
* **`BodyLimit` alone does not cover chunked bodies**: use `require_content_length(true)` or the streaming limit (`app.body_limit`, `BodyLimitLayer`).
* `require_content_length(true)` can break HTTP/2 clients and streaming uploads that legitimately omit `Content-Length`. Test your clients before enabling it.
* Route prefixes are compared on segment boundaries: `/upload` covers `/upload/files` but not `/uploads`.
* Multipart uploads count the whole encoded body, boundaries and headers included: leave some margin above the largest file you accept.

> **Tip:** keep the default limit small and grant large limits only on the routes that need them. Most JSON APIs never need more than a few hundred kilobytes.

## Related pages

* [HTTP hygiene](/docs/hygiene)
* [Rate limiting](/docs/rate-limit)
* [Concurrency limit](/docs/concurrency-limit)
* [Method filter](/docs/method-filter)
