---
title: Pratique, everyday middlewares
summary: The sibling crate of Securite: thirteen Vitesse middlewares for caching, logs, metrics, URLs, health checks, maintenance, languages and API deprecation.
category: everyday
order: 1
---

Securite protects your application. **Pratique** takes care of everything else a production service needs and that has nothing to do with security: `304` answers, cache headers, access logs, Prometheus metrics, health checks, maintenance mode, redirects, languages… Each middleware is one line, and they all live in the same repository as Securite.

## Add the crate

```bash
cargo add pratique --git https://github.com/maxlestage/Securite
```

```toml
[dependencies]
pratique = { git = "https://github.com/maxlestage/Securite" }
vitesse = { git = "https://github.com/maxlestage/Vitesse" }
```

Pratique depends on Vitesse only, has no unsafe code (`#![forbid(unsafe_code)]`) and supports Rust 1.85 and later.

## Quick start

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

fn main() -> std::io::Result<()> {
    let mut app = App::new();
    app.middleware(AccessLog::json().skip("/health"));
    app.middleware(Metrics::new());
    app.middleware(Health::new().version(env!("CARGO_PKG_VERSION")));
    app.middleware(ResponseTime::new());
    app.middleware(TrailingSlash::trim());
    app.middleware(ETag::new());
    app.middleware(CacheControl::new().fallback(CacheControl::NO_CACHE));
    app.middleware(Locale::new(["en", "fr", "es"]));
    app.get("/", |_req: Request| async { "Hello!" });
    app.run(3000)
}
```

## The middlewares

| Family | Middleware | What it does |
|---|---|---|
| Caching | [`ETag`](/docs/etag) | `ETag` from the body, `304 Not Modified` on `If-None-Match` |
| | [`CacheControl`](/docs/cache-control) | `Cache-Control` by path prefix and content type |
| | [`ResponseCache`](/docs/response-cache) | Cache of whole `GET` responses, in memory or shared in Redis, one entry per language and variant |
| Observability | [`AccessLog`](/docs/access-log) | One line per request, JSON or Apache combined |
| | [`Metrics`](/docs/metrics) | Prometheus `/metrics`: counts, latency histogram, in-flight requests |
| | [`ResponseTime`](/docs/response-time) | `X-Response-Time` and `Server-Timing` |
| URLs | [`TrailingSlash`](/docs/trailing-slash) | One address per page, with or without the final `/` |
| | [`Redirects`](/docs/redirects) | Moved pages, renamed sections, canonical domain |
| Operations | [`Health`](/docs/health) | `/health` probe with named checks |
| | [`Maintenance`](/docs/maintenance) | `503` and `Retry-After`, switched on and off at runtime |
| Responses & APIs | [`SetHeaders`](/docs/set-headers) | Add, replace or remove headers on every response |
| | [`Locale`](/docs/locale) | Language from `?lang=`, a cookie or `Accept-Language` |
| | [`Deprecation`](/docs/deprecation) | `Deprecation`, `Sunset` and `Link` headers |

## Order of the middlewares

Vitesse runs middlewares in the order they are added: the first one added is the outermost, it sees the request first and the response last. A good order:

1. **Observers**: `AccessLog`, `Metrics`, `ResponseTime`, so they measure everything, including the answers of the other middlewares.
2. **Securite's `Shield`**, so that `/metrics` and the rest are protected.
3. **Middlewares that answer by themselves**: `Health`, `Maintenance`, `Redirects`, `TrailingSlash`.
4. **Middlewares that work on your routes' responses**: `Locale`, `ETag`, `CacheControl`, `ResponseCache`, `SetHeaders`, `Deprecation`.

```rust
use pratique::prelude::*;
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(AccessLog::json().skip("/health"));
app.middleware(Metrics::new());
app.middleware(Shield::recommended());
app.middleware(Health::new());
app.middleware(Redirects::new().prefix("/blog", "/articles"));
app.middleware(ETag::new());
```

> **Tip:** A middleware can also be attached to a single route with `handler.with(middleware)`, or to a `Router` mounted on a prefix with `router.middleware(…)`.

## Related pages

- [Installation of Securite](/docs/installation)
- [Shield presets](/docs/shield-presets)
