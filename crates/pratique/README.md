# Pratique

![MSRV 1.85](https://img.shields.io/badge/MSRV-1.85-blue)
![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success)

**Everyday middlewares for [Vitesse](https://vitesse-f16135654c3d.herokuapp.com/) that have
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
| | `ResponseCache` | Cache of whole `GET` responses, in memory or shared by every instance in Redis: one entry per language and `Vary` variant, `X-Cache` / `Age`, `304` on hits, purge handle |
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
let purge = cache.handle(); // purge.invalidate("/api/catalog").await after an update
app.middleware(cache);
```

`ResponseCache` only keeps shareable answers: status `200`, known size, no
`Set-Cookie`, no `Vary: *`, no `Cache-Control: private / no-store / no-cache`
(`max-age` / `s-maxage` shorten the TTL). Requests with credentials
(`Authorization`, `Cookie`, `X-Api-Key` …) always reach the handler. Each language
chosen by `Locale` and each variant named by `Vary` gets its own entry.

With several instances, share one cache in Redis or Valkey (feature `redis`, or
`redis-tls` for `rediss://`):

```rust
let store = RedisStore::open(&std::env::var("REDIS_URL").unwrap())?.prefix("shop:cache:");
app.middleware(ResponseCache::new(Duration::from_secs(60)).store(store));
```

The connection opens on first use (one per worker thread), every operation gives up
after 250 ms, and after a failure Redis is left alone for a second: when it is down
or silent, requests are simply served by the handler, without waiting.

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

## Cargo features

| Feature | Gives |
|---|---|
| `redis` | `RedisStore`, a response cache shared through Redis / Valkey (Rust 1.88+, like the `redis` crate) |
| `redis-tls` | `rediss://` addresses for it (rustls + ring) |

Without features, Pratique only depends on Vitesse and supports Rust 1.85.

## Order

Vitesse runs middlewares in the order they are added, the first one being the
outermost:

1. the observers (`AccessLog`, `Metrics`, `ResponseTime`);
2. Securite's `Shield` (and CORS), so that `/metrics` and cached pages are protected;
3. the ones that answer by themselves (`Health`, `Maintenance`, `Redirects`,
   `TrailingSlash`);
4. `Locale`, then `ResponseCache` (one entry per language);
5. the ones that shape your routes' responses (`CacheControl`, `ETag`,
   `SetHeaders`, `Deprecation`): inside the cache, stored responses carry their
   headers and a `Cache-Control: private` keeps a page out of it.

## License

Proprietary software by Maxime Nathan Lestage, like the rest of this repository:
see [`LICENSE`](../../LICENSE).
