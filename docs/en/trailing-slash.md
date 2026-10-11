---
title: Trailing slash
summary: Gives every page a single address by removing or adding the final slash, with a 308 redirect that search engines follow or by rewriting the request in place.
category: everyday
order: 8
---

`/about` and `/about/` are two different addresses for search engines, caches and analytics. `TrailingSlash` picks one style for the whole application.

## Styles

| Constructor | Effect |
|---|---|
| `TrailingSlash::trim()` | `/about/` → `/about` (`/` itself is left alone; `/about///` → `/about`). |
| `TrailingSlash::append()` | `/about` → `/about/`, except paths whose last segment looks like a file (`/app.js`). |

`.except(prefix)` leaves a part of the site alone (can be called several times).

By default the client gets a **`308 Permanent Redirect`** to the normalised address: search engines merge both URLs, and the method and body of a `POST` are kept. The query string follows.

With `.rewrite()`, there is no redirect: the request is rewritten in place and your routes see the normalised path while the browser keeps its address.

## Quick start

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(TrailingSlash::trim());
app.get("/about", |_req: Request| async { "about" });
```

```bash
curl -i "https://example.com/about/?ref=mail"
# HTTP/1.1 308 Permanent Redirect
# location: /about?ref=mail
```

## Rewriting instead of redirecting

```rust
use pratique::prelude::*;

let slash = TrailingSlash::trim().rewrite(); // `/about/` answers like `/about`
```

## Pitfalls and tips

- Add it before your routes and before middlewares that look at the path (`CacheControl`, `ResponseCache`).
- A path starting with several slashes or a backslash is never turned into a protocol-relative address (`//evil.example`, `/\evil.example`): the redirect always stays on your site.
- The query string is kept exactly as sent; characters that are not allowed in an address (`"`, `<`, spaces…) are percent-encoded in the `Location`.
- Vitesse's static directories (`app.static_dir`, `ServeDir`) redirect a folder to its address **with** a final slash (`/docs` → `/docs/`) to serve its `index.html`. With `trim()`, exclude them, or the two redirects loop:

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(TrailingSlash::trim().except("/site"));
app.static_dir("/site", "./public");
```

## Related pages

- [Redirects](/docs/redirects)
