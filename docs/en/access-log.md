---
title: Access logs
summary: Writes one line per request, as JSON for log pipelines or in the Apache combined format for classic analyzers, to standard output or any sink, with the real client address behind a proxy.
category: everyday
order: 5
---

Vitesse's `middleware::logger()` prints colourful lines for humans. `AccessLog` writes lines for machines: Loki, Elasticsearch, CloudWatch, Datadog, GoAccess or AWStats read them without any parsing rule.

## Formats

**JSON lines** (`AccessLog::json()`), one object per request; absent fields are left out:

```json
{"time":"2026-10-11T08:49:37.042Z","ip":"203.0.113.9","method":"GET","path":"/search?q=shoes","version":"HTTP/1.1","referer":"https://example.com/","user_agent":"Mozilla/5.0","request_id":"3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44","status":200,"bytes":5120,"duration_ms":1.842}
```

**Apache / Nginx combined** (`AccessLog::combined()`):

```text
203.0.113.9 - - [11/Oct/2026:08:49:37 +0000] "GET /search?q=shoes HTTP/1.1" 200 5120 "https://example.com/" "Mozilla/5.0"
```

| Field | Content |
|---|---|
| `time` | When the request arrived, UTC, RFC 3339 with milliseconds. |
| `ip` | Client address (see below). |
| `method`, `path`, `version` | Request line; `path` includes the query string. |
| `status`, `bytes` | Status and body size of the response (`bytes` is absent for streamed bodies). |
| `duration_ms` | Time to produce the response head. |
| `referer`, `user_agent` | Request headers. |
| `request_id` | `X-Request-Id` of the request, or of the response (Securite's `RequestId`). |

## Quick start

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(AccessLog::json().skip("/health").skip("/metrics"));
app.get("/", |_req: Request| async { "home" });
```

## Configuration

| Method | Description |
|---|---|
| `AccessLog::json()` | JSON lines on standard output. |
| `AccessLog::combined()` | Combined lines on standard output. |
| `.to(sink)` | Send each line (without the newline) to a closure: a file, a channel, `tracing`… |
| `.skip(prefix)` | Don't log requests under a path prefix (health checks, metrics). Can be called several times. |
| `.ip_from_header(name)` | Read the client address from a header written by your reverse proxy. |

```rust
use pratique::prelude::*;

let log = AccessLog::json().to(|line| tracing::info!(target: "access", "{line}"));
```

## Behind a reverse proxy

Behind Heroku, Render, Fly.io, Nginx or Cloudflare, the connection comes from the proxy, so the logged address would be the proxy's. Tell `AccessLog` which header the proxy writes:

```rust
use pratique::prelude::*;

let log = AccessLog::combined().ip_from_header("x-forwarded-for"); // Heroku, Nginx, Render…
let log = AccessLog::combined().ip_from_header("cf-connecting-ip"); // Cloudflare
```

The **last** address of the header is used: the one appended by the proxy in front of your app, which a client cannot forge (anything a client sends itself sits before it). Without the header, or with an invalid value, the peer address is logged.

## Pitfalls and tips

- Logging is synchronous. Standard output is fine on every platform; for a slow destination, make the sink push into a channel read by a background task.
- Every quoted field of the combined format escapes `"`, `\` and control characters, and JSON strings are escaped: a crafted `User-Agent` cannot forge a log line.
- Access logs contain IP addresses, which are personal data under the GDPR: set a retention period.

## Related pages

- [Prometheus metrics](/docs/metrics)
- [Request IDs](/docs/request-id)
- [Client IP](/docs/client-ip)
