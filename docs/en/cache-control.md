---
title: Cache-Control
summary: Sets the Cache-Control header of successful GET responses by path prefix and by content type, with presets for fingerprinted assets and personal data.
category: everyday
order: 3
---

`Cache-Control` tells browsers, CDNs and proxies how long they may keep a response. Getting it right makes repeat visits instant; getting it wrong serves stale pages or someone else's data. `CacheControl` sets it in one place, by path and by content type, instead of in every handler.

## How it works

For every `GET` or `HEAD` request answered with a `2xx` status, a `304` or a permanent redirect (`301`, `308`):

1. If the handler already set `Cache-Control`, it is kept (unless `.overwrite(true)`).
2. Otherwise the value of the **longest matching path prefix** is used (`/assets` covers `/assets/app.js`, not `/assetsx`),
3. else the first matching **content type prefix** (`image/` covers `image/png`),
4. else the **fallback**, if any.

Errors (`4xx`, `5xx`), temporary redirects (`302`, `303`, `307`, which must not be cached for as long as the page) and writes (`POST`, `PUT`…) are left alone.

> **Warning:** Static files served by Vitesse (`app.static_dir`, `ServeDir`) always carry their own `Cache-Control` (`public, max-age=0` unless `ServeDir::max_age(…)` says otherwise), which wins by default. Set the value there, or add `.overwrite(true)` so that your rules replace it.

## Quick start

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(
    CacheControl::new()
        .fallback(CacheControl::NO_CACHE)
        .route("/assets", CacheControl::IMMUTABLE)
        .route("/account", CacheControl::NO_STORE)
        .content_type("image/", "public, max-age=86400"),
);
```

## Configuration

| Method | Description |
|---|---|
| `CacheControl::new()` | No rule: responses are left alone until you add one. |
| `.route(prefix, value)` | Value for a path prefix; the longest prefix wins. |
| `.content_type(prefix, value)` | Value for a content type prefix (`image/`, `text/css`, `application/json`). |
| `.fallback(value)` | Value when nothing else matches. |
| `.overwrite(true)` | Replace a value set by the handler (default: keep it). |

Every method panics at startup if the value is not a valid header value.

## Presets

| Constant | Value | Use it for |
|---|---|---|
| `CacheControl::IMMUTABLE` | `public, max-age=31536000, immutable` | Fingerprinted files (`app.3f9a.js`) whose name changes with their content. |
| `CacheControl::NO_CACHE` | `no-cache` | HTML and API answers: stored, but revalidated every time (pair it with [ETag](/docs/etag)). |
| `CacheControl::NO_STORE` | `no-store` | Personal or sensitive data, never written to disk. |

## Pitfalls and tips

- `immutable` is only correct when the URL changes with the content. A plain `/style.css` with `IMMUTABLE` stays stale for a year in your visitors' browsers.
- Pages that depend on the logged-in user must not be `public`: use `private` or `no-store`, otherwise a CDN may serve one user's page to another.
- Securite's `SecurityHeaders::api()` already sends `no-store` on API responses; since the handler's value is kept, `CacheControl` doesn't fight it.

## Related pages

- [ETag and 304](/docs/etag)
- [Response cache](/docs/response-cache)
