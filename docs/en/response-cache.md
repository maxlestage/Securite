---
title: Response cache
summary: Keeps whole GET responses in memory or in Redis and answers identical requests without running the handler, with one entry per language and per Vary variant, shared by every instance of the app.
category: everyday
order: 4
---

Some endpoints are expensive and change rarely: a product catalogue, a public dashboard, a rendered home page. `ResponseCache` stores their responses for a fixed time (TTL) and answers the next identical requests itself, without calling your handler or your database. The responses live in the memory of the process by default, or in Redis so that every instance of the app shares one cache.

## What is cached

A request is looked up in the cache when it is a `GET` or a `HEAD`, carries **no credentials** (`Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key`, plus the headers you add with `.bypass_header(…)`) and its path is under one of the `.only(…)` prefixes (every path by default).

A response is stored only when it can be shared:

- status `200 OK`, complete body of known size, at most `max_body` bytes;
- no `Set-Cookie`, no `Vary: *`;
- no `Cache-Control: private`, `no-store` or `no-cache`.

It is stored for the cache's TTL, or less when the response says so: `Cache-Control: max-age=10` (or `s-maxage`) keeps it 10 seconds, `max-age=0` not at all.

## One entry per variant

The key of an entry is the path **and** the query string (`/products?page=2` is not `/products`), plus:

- **the language chosen by [Locale](/docs/locale)**, when `Locale` is added before the cache: the French and the English pages are two entries, and every `Accept-Language` that negotiates French (`fr`, `fr-CA`, `de, fr;q=0.8`…) shares the French one;
- **the headers named by the response's `Vary`**: with `Vary: Accept-Encoding`, clients asking for Brotli and clients asking for gzip get their own entry.

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Locale::new(["en", "fr", "es"])); // before the cache
app.middleware(ResponseCache::new(Duration::from_secs(60)));
app.get("/", |req: Request| async move {
    match req.get::<Lang>().map(Lang::as_str) {
        Some("fr") => "Bonjour",
        Some("es") => "Hola",
        _ => "Hello",
    }
});
```

Answers carry `X-Cache: MISS` (computed by the handler) or `X-Cache: HIT` (served from the cache, with an `Age` header in seconds). A hit answers `304 Not Modified` itself when the request's `If-None-Match` matches the stored `ETag`. A request with `Cache-Control: no-cache` skips the lookup and refreshes the entry.

## Quick start

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(ResponseCache::new(Duration::from_secs(30)).only("/api/catalog"));
app.get("/api/catalog", |_req: Request| async { Json(json!({ "products": [] })) });
```

## Configuration

| Method | Default | Description |
|---|---|---|
| `ResponseCache::new(ttl)` | — | How long a response stays fresh. |
| `.store(store)` | `MemoryStore` of 1 000 entries | Where the responses live: `MemoryStore`, `RedisStore` or your own `CacheStore`. |
| `.only(prefix)` | every path | Restrict the cache to path prefixes (can be called several times). |
| `.bypass_header(name)` | — | One more credential header whose requests always reach the handler. |
| `.max_body(bytes)` | `1 MiB` | Largest body stored. |
| `.on_error(f)` | — | Called when the store fails (the request is then served by the handler). |
| `.handle()` | — | A `CacheHandle` to purge the cache and read its counters. |

## Sharing the cache with Redis

With several instances behind a load balancer (dynos, pods, servers), each `MemoryStore` is a separate cache: a page is computed once per instance, and a purge only reaches one of them. A `RedisStore` (feature `redis`) puts the entries in Redis or Valkey, so every instance reads what any other one computed, and purges reach them all.

```toml
[dependencies]
pratique = { git = "https://github.com/maxlestage/Securite", features = ["redis-tls"] }
```

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

fn main() -> std::io::Result<()> {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into());
    let store = RedisStore::open(&url).expect("invalid REDIS_URL").prefix("shop:cache:");
    let mut app = App::new();
    app.middleware(
        ResponseCache::new(Duration::from_secs(60))
            .store(store)
            .on_error(|e| eprintln!("response cache: {e}")),
    );
    app.get("/", |_req: Request| async { "home" });
    app.run(3000)
}
```

| Feature | Gives |
|---|---|
| `redis` | `RedisStore` for `redis://` addresses. |
| `redis-tls` | `rediss://` addresses too (rustls). Add `#insecure` to the address for a self-signed certificate, as Heroku Data for Redis uses. |

How the store behaves:

- **Lazy connection**: `RedisStore::open` only checks the address. The connection is opened by the first request, from the app's runtime, and reopened automatically after a failure.
- **Timeouts**: every command times out after 250 ms (`.timeout(…)`). When Redis is slow or down, requests are served by the handler instead of waiting: the cache can be lost, the site stays up. Failures are counted (`handle.errors()`) and passed to `.on_error`.
- **Expiry**: entries are written with `PX`, so Redis drops them by itself.
- **Isolation**: every key starts with the prefix (`pratique:cache:` by default). Give each app its own prefix when they share a Redis.
- **Purges** use `SCAN` and `UNLINK`, never `KEYS`, so they don't block Redis.

The `redis` features need Rust 1.88 or later (like the `redis` crate); without them, Pratique supports Rust 1.85.

## Purging after an update

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

let cache = ResponseCache::new(Duration::from_secs(300)).only("/api/catalog");
let purge = cache.handle();

let mut app = App::new();
app.middleware(cache);
app.post("/admin/products", move |_req: Request| {
    let purge = purge.clone();
    async move {
        // … save the product …
        // Every query string, every variant, and the paths below it.
        if let Err(e) = purge.invalidate("/api/catalog").await {
            eprintln!("purge failed: {e}");
        }
        "saved"
    }
});
```

| `CacheHandle` method | Description |
|---|---|
| `invalidate(path).await` | Forgets `path` and below it (`/api/catalog` covers `/api/catalog?page=2` and `/api/catalog/42`, not `/api/catalogs`). |
| `clear().await` | Forgets everything (only the keys of this cache's prefix with Redis). |
| `hits()`, `misses()`, `errors()` | Counters of this process. |

To inspect a `MemoryStore`, keep it in an `Arc`: `let store = Arc::new(MemoryStore::new()); ResponseCache::new(ttl).store(store.clone())`, then `store.len()`.

## Your own store

`CacheStore` has four methods (`get`, `set` with a TTL, `remove_prefixes`, `clear`), each returning a future: implement it for Memcached, a database or a test double. A store that returns an error is treated as a miss.

## Pitfalls and tips

- Only cache public responses. The credential headers are bypassed, but a response that depends on something else (an IP, a session passed in the query string) must be kept out with `.only(…)`, or say `Cache-Control: private`.
- Add [Locale](/docs/locale) **before** the cache: added after it, `Locale` still works, but the raw `Accept-Language` becomes part of the key, which splits the cache into many entries.
- Headers that belong to one exchange (`X-Request-Id`, `X-Response-Time`, `Server-Timing`, `Date`, `Age`) are not stored; with [ETag](/docs/etag) (before or after the cache), hits are answered with `304` when the client already has the page.
- Many concurrent misses for the same key all reach the handler until the first answer is stored.

## Related pages

- [ETag and 304](/docs/etag)
- [Cache-Control](/docs/cache-control)
- [Language negotiation](/docs/locale)
