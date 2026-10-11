---
title: Redirects
summary: Sends old addresses to new ones before the routes run, for single pages, whole sections and an entire domain, with the right 3xx status and the query string kept.
category: everyday
order: 9
---

Pages move, sections get renamed, `www.` gets dropped. Every old address still has links and search rankings pointing at it. `Redirects` keeps them alive with one table of rules instead of a route per old address.

## Rules

| Method | Example | Status |
|---|---|---|
| `.permanent(from, to)` | `/old-pricing` → `/pricing` | `308 Permanent Redirect` |
| `.temporary(from, to)` | `/sale` → `/products?promo=autumn` | `307 Temporary Redirect` |
| `.exact(from, to, status)` | any `3xx` (`301`, `302`, `303`…) | as given; panics if not a redirection |
| `.prefix(from, to)` | `/blog/2024/hello` → `/articles/2024/hello` | `308` |
| `.host(host, origin)` | `www.example.com/x` → `https://example.com/x` | `308` |

Rules are checked in this order: host, exact path, then the longest matching prefix. A prefix covers whole segments: `/blog` covers `/blog` and `/blog/x`, not `/blogger`. The query string of the request is appended, unless the target has its own.

`308` and `307` keep the method and the body: a form posted to an old address still arrives as a `POST`.

## Quick start

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(
    Redirects::new()
        .host("www.example.com", "https://example.com")
        .permanent("/old-pricing", "/pricing")
        .prefix("/blog", "/articles")
        .temporary("/sale", "/products?promo=autumn"),
);
```

```bash
curl -i "https://example.com/blog/2024/hello?utm_source=mail"
# HTTP/1.1 308 Permanent Redirect
# location: /articles/2024/hello?utm_source=mail
```

## Canonical domain

`.host(host, origin)` redirects every request whose `Host` (without port, case-insensitive) is `host` to the same path on `origin`. Only the hosts you list are redirected, so `localhost` and preview domains keep working.

```rust
use pratique::prelude::*;

let canonical = Redirects::new()
    .host("www.example.com", "https://example.com")
    .host("example.fr", "https://example.com/fr");
```

> **Tip:** To force HTTPS on every host, use Securite's [HTTPS redirect](/docs/https-redirect), which understands proxies.

## Pitfalls and tips

- Browsers remember permanent redirects for a long time. Test with `.temporary(…)` first, then switch to `.permanent(…)`.
- Targets are your own configuration, never taken from the request, so the middleware cannot become an open redirect.
- Avoid chains (`/a` → `/b` → `/c`): point every old address straight at the final one.

## Related pages

- [Trailing slash](/docs/trailing-slash)
- [HTTPS redirect](/docs/https-redirect)
