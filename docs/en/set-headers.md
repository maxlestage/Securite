---
title: Response headers
summary: Adds, replaces, appends or removes headers on every response, including the ones built by Vitesse itself such as 404s.
category: everyday
order: 12
---

Some headers belong on every response: a `Server` or `X-Powered-By` value, a default `Content-Language`, a `Link` preload, a `Timing-Allow-Origin`… and some should never leave the server, like a debug header set by a library. `SetHeaders` handles them in one place.

## Operations

| Method | Effect |
|---|---|
| `.set(name, value)` | Sets the header, replacing what the handler set. |
| `.if_missing(name, value)` | Adds the header only when the response doesn't have it. |
| `.append(name, value)` | Adds one more value, keeping the existing ones (`Link`, `Vary`…). |
| `.remove(name)` | Removes the header. |

Operations run in the order given, on every response: those of your handlers, of Vitesse (`404`, `405`) and of the middlewares added after `SetHeaders`. Invalid names or values make the method panic at startup, never at request time.

## Quick start

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(
    SetHeaders::new()
        .set("x-powered-by", "Vitesse")
        .if_missing("content-language", "en")
        .append("link", "</app.css>; rel=preload; as=style")
        .remove("x-debug"),
);
```

## Pitfalls and tips

- For security headers (CSP, HSTS, `X-Frame-Options`…), use Securite's [security headers](/docs/security-headers): they come with safe defaults and per-request nonces.
- `X-Powered-By` tells the world which stack you run. It is harmless with a maintained stack, but you can just as well `.remove("x-powered-by")`.
- To edit headers of a single route, wrap its handler: `handler.with(SetHeaders::new()…)`.

## Related pages

- [Cache-Control](/docs/cache-control)
- [Security headers](/docs/security-headers)
