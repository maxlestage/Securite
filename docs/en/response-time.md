---
title: Response time
summary: Adds X-Response-Time and Server-Timing headers with the time spent producing each response, visible in the browser's developer tools.
category: everyday
order: 7
---

`ResponseTime` measures how long the rest of the chain took to produce the response head and writes it in two headers:

```text
x-response-time: 1.842ms
server-timing: app;dur=1.842
```

`Server-Timing` is shown by browsers in their developer tools (Network tab, then Timing), next to DNS, TLS and download times, which makes it easy to tell a slow server from a slow network.

## Quick start

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(ResponseTime::new());
app.get("/", |_req: Request| async { "home" });
```

## Configuration

| Method | Default | Description |
|---|---|---|
| `ResponseTime::new()` | both headers, 3 decimals | Creates the middleware. |
| `.header(Some(name))` / `.header(None)` | `x-response-time` | Another header name, or no such header. |
| `.server_timing(Some(metric))` / `.server_timing(None)` | `app` | Metric name in `Server-Timing`, or none. |
| `.digits(n)` | `3` | Decimals of the milliseconds. |

```rust
use pratique::prelude::*;

// Only Server-Timing, named "backend", in whole milliseconds.
let timing = ResponseTime::new().header(None).server_timing(Some("backend")).digits(0);
```

## Pitfalls and tips

- The time covers what comes after the middleware in the chain: add it first to include every other middleware.
- `Server-Timing` is appended, so handlers can add their own metrics (`db;dur=4.2`) next to it.
- Timings tell how busy your server is. For a public service you may prefer to send `Server-Timing` only to your staff, or to use [Prometheus metrics](/docs/metrics) instead.

## Related pages

- [Prometheus metrics](/docs/metrics)
- [Access logs](/docs/access-log)
