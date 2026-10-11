---
title: API deprecation
summary: Announces that endpoints are deprecated, when they will stop working and where to read about the migration, with the standard Deprecation, Sunset and Link headers.
category: everyday
order: 14
---

When `/api/v1` is replaced by `/api/v2`, its clients need to know, ideally from the API itself rather than from an email nobody reads. `Deprecation` adds the standard headers that API gateways, SDKs and monitoring tools understand:

```text
deprecation: @1767225600
sunset: Fri, 01 Jan 2027 00:00:00 GMT
link: <https://example.com/docs/v2>; rel="deprecation"; type="text/html"
```

| Header | Standard | Meaning |
|---|---|---|
| `Deprecation` | RFC 9745 | Since when the resource is deprecated (Unix time). |
| `Sunset` | RFC 8594 | When it will stop working (HTTP date). |
| `Link` with `rel="deprecation"` | RFC 9745 | Page describing the deprecation and the migration. |

## Quick start

```rust
use pratique::prelude::*;
use std::time::{Duration, UNIX_EPOCH};
use vitesse::prelude::*;

let since = UNIX_EPOCH + Duration::from_secs(1_767_225_600); // 2026-01-01
let mut app = App::new();
app.middleware(
    Deprecation::since(since)
        .sunset(since + Duration::from_secs(365 * 86_400))
        .link("https://example.com/docs/v2")
        .only("/api/v1"),
);
```

## Configuration

| Method | Description |
|---|---|
| `Deprecation::since(time)` | Deprecated since `time` (`SystemTime`). |
| `.sunset(time)` | Stops working at `time`. |
| `.link(url)` | Migration page; panics if the URL contains characters not allowed in a header. |
| `.only(prefix)` | Only responses under a path prefix (can be called several times). Default: every response. |

Several deprecations with different dates? Add several middlewares, each with its `.only(…)`, or attach one to the `Router` of the old version.

## After the sunset

`Deprecation` only informs. When the date has passed, remove the routes, or answer `410 Gone` and keep the headers so that clients understand why:

```rust
use vitesse::prelude::*;

let mut app = App::new();
app.all("/api/v1/*rest", |_req: Request| async {
    res::status(410).json(json!({ "error": "gone", "see": "https://example.com/docs/v2" }))
});
```

## Pitfalls and tips

- Announce the sunset date early (months for public APIs) and watch who still calls the old version, for example with [access logs](/docs/access-log) filtered on `/api/v1`.
- The headers are informative: browsers ignore them, API tooling and gateways surface them.

## Related pages

- [Access logs](/docs/access-log)
- [Redirects](/docs/redirects)
