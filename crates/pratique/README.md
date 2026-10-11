# Pratique

![MSRV 1.85](https://img.shields.io/badge/MSRV-1.85-blue)
![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success)

**Everyday middlewares for [Vitesse](https://maxlestage.github.io/Vitesse/) that have
nothing to do with security**: caching, observability, URLs, operations and
internationalisation. The security side lives in its sibling crate, `securite`.

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

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
```

## Middlewares

| Category | Middleware | What it does |
|---|---|---|
| Caching | `ETag` | `ETag` computed from the body, `304 Not Modified` on `If-None-Match` |
| | `CacheControl` | `Cache-Control` by path prefix and content type (`IMMUTABLE`, `NO_CACHE`, `NO_STORE` presets) |
| | `ResponseCache` | In-memory cache of whole `GET` responses: TTL, size limits, `X-Cache` / `Age`, purge handle |
| Observability | `AccessLog` | One line per request, JSON or Apache "combined", to stdout or any sink |
| | `Metrics` | Prometheus `GET /metrics`: requests by method and status class, latency histogram, in-flight, uptime |
| | `ResponseTime` | `X-Response-Time: 1.234ms` and `Server-Timing: app;dur=1.234` |
| URLs | `TrailingSlash` | `/about/` → `/about` (or the reverse), by `308` redirect or in-place rewrite |
| | `Redirects` | Exact paths (`308` / `307` / any `3xx`), whole sections by prefix, canonical domain |
| Operations | `Health` | `GET /health` with named checks, `application/health+json`, `503` when a check fails |
| | `Maintenance` | `503` + `Retry-After` (HTML, JSON or text), switched on and off at runtime, open paths |
| Responses & API | `SetHeaders` | Add (if missing), replace, append or remove headers on every response |
| | `Locale` | Language from `?lang=`, a `lang` cookie or `Accept-Language`; `req.get::<Lang>()` |
| | `Deprecation` | `Deprecation` (RFC 9745), `Sunset` (RFC 8594) and `Link` headers on old endpoints |

## Examples

### Caching

```rust
use pratique::prelude::*;
use std::time::Duration;

app.middleware(ETag::new()); // 304s for free on every JSON / HTML answer
app.middleware(
    CacheControl::new()
        .fallback(CacheControl::NO_CACHE)
        .route("/assets", CacheControl::IMMUTABLE)
        .content_type("image/", "public, max-age=86400"),
);

let cache = ResponseCache::new(Duration::from_secs(30)).only("/api/catalog");
let purge = cache.handle(); // purge.invalidate("/api/catalog") after an update
app.middleware(cache);
```

`ResponseCache` only keeps shareable answers: status `200`, known size, no
`Set-Cookie`, `Vary`, `Content-Encoding` or `Cache-Control: private / no-store /
no-cache`; requests with `Authorization` or `Cookie` always reach the handler.

### Operations

```rust
use pratique::prelude::*;
use std::time::Duration;

let maintenance = Maintenance::new()
    .allow("/health")
    .retry_after(Duration::from_secs(600))
    .html("<h1>Back in a few minutes</h1>");
let switch = maintenance.switch(); // switch.on() / switch.off() from anywhere
app.middleware(maintenance);

app.middleware(Health::new().check("database", move || db_ok()));
```

### Observability

```rust
use pratique::prelude::*;

let metrics = Metrics::new();          // GET /metrics, Prometheus text format
let numbers = metrics.handle();        // numbers.total(), numbers.by_class(5) …
// 203.0.113.9 - - [11/Oct/2026:08:49:37 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8.9"
app.middleware(AccessLog::combined().ip_from_header("x-forwarded-for")); // behind Heroku, Nginx…
app.middleware(metrics);
```

The metrics endpoint is public by default: add Securite's `Shield` (an `Auth` or
`IpFilter` guard) before it in production.

### URLs and APIs

```rust
use pratique::prelude::*;
use std::time::{Duration, UNIX_EPOCH};

app.middleware(
    Redirects::new()
        .host("www.example.com", "https://example.com")
        .permanent("/old-pricing", "/pricing")
        .prefix("/blog", "/articles"),
);
app.middleware(TrailingSlash::trim());

let since = UNIX_EPOCH + Duration::from_secs(1_767_225_600);
app.middleware(
    Deprecation::since(since)
        .sunset(since + Duration::from_secs(365 * 86_400))
        .link("https://example.com/docs/v2")
        .only("/api/v1"),
);
```

The full guide, one page per middleware in English, French and Spanish, is in the
`docs` folder of the repository (category `everyday`), published on the website.

## Order

Vitesse runs middlewares in the order they are added, the first one being the
outermost. Put the observers first (`AccessLog`, `Metrics`), then the ones that
answer by themselves (`Health`, `Maintenance`, `Redirects`, `TrailingSlash`), then
the ones that work on your routes' responses (`ETag`, `CacheControl`,
`ResponseCache`).

## License

Proprietary software by Maxime Nathan Lestage, like the rest of this repository:
see [`LICENSE`](../../LICENSE).
