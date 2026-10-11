---
title: Response cache
summary: Keeps whole GET responses in memory for a while and answers identical requests without running the handler, with size limits, X-Cache and Age headers and a purge handle.
category: everyday
order: 4
---

Some endpoints are expensive and change rarely: a product catalogue, a public dashboard, a rendered home page. `ResponseCache` stores their responses in memory for a fixed time (TTL) and answers the next identical requests itself, without calling your handler or your database.

## What is cached

A request is looked up in the cache when it is a `GET` or a `HEAD`, has **no** `Authorization` and **no** `Cookie` header, and its path is under one of the `.only(…)` prefixes (every path by default). The key is the path **and** the query string: `/products?page=2` is not `/products`.

A response is stored only when it can be shared:

- status `200 OK`, complete body of known size, at most `max_body` bytes;
- no `Set-Cookie`, no `Vary`, no `Content-Encoding`;
- no `Cache-Control: private`, `no-store` or `no-cache`.

Answers carry `X-Cache: MISS` (computed by the handler) or `X-Cache: HIT` (served from memory, with an `Age` header in seconds). A request with `Cache-Control: no-cache` skips the lookup and refreshes the entry.

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
| `.only(prefix)` | every path | Restrict the cache to path prefixes (can be called several times). |
| `.max_entries(n)` | `1000` | Maximum number of stored responses; expired ones are evicted first, then the oldest. |
| `.max_body(bytes)` | `1 MiB` | Largest body stored. |
| `.handle()` | — | A `CacheHandle` to inspect or purge the cache while the app runs. |

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
        purge.invalidate("/api/catalog"); // every query string, and below
        "saved"
    }
});
```

`CacheHandle` also has `clear()`, `len()` and `is_empty()`.

## Pitfalls and tips

- The cache lives in the memory of each process: two instances behind a load balancer have two caches. Keep TTLs short, or purge every instance.
- Responses that depend on something other than the path and the query (a header, the language) must say so with `Vary`, which disables caching for them. With [Locale](/docs/locale), cache only language-independent endpoints, or add the language to the query string.
- Put the cache after a compression middleware so that it stores the original bytes.
- Many concurrent misses for the same key all reach the handler once each until the first answer is stored.

## Related pages

- [ETag and 304](/docs/etag)
- [Cache-Control](/docs/cache-control)
