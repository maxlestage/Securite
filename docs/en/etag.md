---
title: ETag and 304 Not Modified
summary: Gives every GET response an ETag computed from its body and answers 304 Not Modified, without a body, when the client already has it.
category: everyday
order: 2
---

A browser or an API client that already downloaded a page can ask "has it changed?" by sending back the `ETag` it received in an `If-None-Match` header. `ETag` computes that tag for you from the body of every `GET` and `HEAD` response, and answers `304 Not Modified` with an empty body when nothing changed: the bytes never travel twice.

## How it works

1. Only `GET` and `HEAD` requests, and `200 OK` responses, are concerned.
2. If the response already has an `ETag` (static files served by Vitesse), it is kept.
3. Otherwise, when the body is complete and of known size (text, HTML, JSON…) and not bigger than the limit (4 MiB by default), it is hashed and the response gets `ETag: "<length>-<hash>"`. Streams and larger bodies pass through untouched.
4. If the request's `If-None-Match` lists that tag (or `*`), the status becomes `304 Not Modified` and the body is dropped. The other headers (`ETag`, `Cache-Control`, `Vary`…) stay.

The hash (64-bit FNV-1a) is stable across restarts and servers: every instance behind a load balancer produces the same tag for the same body.

## Quick start

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(ETag::new());
app.get("/api/products", |_req: Request| async { Json(json!([{ "id": 1 }])) });
```

```bash
curl -i https://example.com/api/products
# HTTP/1.1 200 OK
# etag: "a-1f3c9b2e8d7a6c54"

curl -i https://example.com/api/products -H 'If-None-Match: "a-1f3c9b2e8d7a6c54"'
# HTTP/1.1 304 Not Modified
```

## Configuration

| Method | Default | Description |
|---|---|---|
| `ETag::new()` | strong tags, 4 MiB | Creates the middleware (`ETag::default()` is equivalent). |
| `.max_size(bytes)` | `4 * 1024 * 1024` | Largest body hashed. Bigger bodies get no tag. |
| `.weak(true)` | `false` | Weak tags (`W/"…"`), for when a later middleware may change the bytes but not the meaning. |

## With Cache-Control

`ETag` decides whether the bytes must be sent again; `Cache-Control` decides whether the client asks at all. `Cache-Control: no-cache` means "always ask, then reuse if unchanged", the perfect partner of `ETag`:

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(ETag::new());
app.middleware(CacheControl::new().fallback(CacheControl::NO_CACHE));
```

## Pitfalls and tips

- The body has to be computed to be hashed: a `304` saves bandwidth and client time, not server work. To save server work too, add a [ResponseCache](/docs/response-cache).
- Comparison is weak, as RFC 9110 requires for `If-None-Match`: `W/"x"` matches `"x"`.
- With Vitesse's `middleware::compress()`, use `.weak(true)`: the same tag then covers the compressed and the uncompressed versions, as RFC 9110 allows for weak tags only.

## Related pages

- [Cache-Control](/docs/cache-control)
- [Response cache](/docs/response-cache)
