---
title: Prometheus metrics
summary: Counts every request and serves request counts by method and status class, a latency histogram, in-flight requests and uptime at /metrics, in the Prometheus text format.
category: everyday
order: 6
---

`Metrics` gives your application the four numbers every dashboard starts with (traffic, errors, latency, saturation) and serves them at `GET /metrics` in the Prometheus text format, read by Prometheus, Grafana Agent, VictoriaMetrics, Datadog or the OpenTelemetry collector.

## What is measured

```text
# TYPE http_requests_total counter
http_requests_total{method="GET",status="2xx"} 1027
http_requests_total{method="POST",status="4xx"} 3
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{le="0.001"} 812
http_request_duration_seconds_bucket{le="0.005"} 1001
…
http_request_duration_seconds_bucket{le="+Inf"} 1030
http_request_duration_seconds_sum 1.734
http_request_duration_seconds_count 1030
# TYPE http_requests_in_flight gauge
http_requests_in_flight 2
# TYPE process_uptime_seconds gauge
process_uptime_seconds 86400
```

| Metric | Type | Labels |
|---|---|---|
| `http_requests_total` | counter | `method` (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `OTHER`), `status` (`1xx` … `5xx`) |
| `http_request_duration_seconds` | histogram | buckets from 1 ms to 10 s |
| `http_requests_in_flight` | gauge | — |
| `process_uptime_seconds` | gauge | — |

The labels form a fixed set of at most 40 series: the path is deliberately **not** a label, so an attacker or a crawler cannot create millions of series. Counting costs a few atomic additions per request, without locks.

## Quick start

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Metrics::new());
app.get("/", |_req: Request| async { "home" });
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: my-app
    static_configs:
      - targets: ["my-app:3000"]
```

## Configuration

| Method | Default | Description |
|---|---|---|
| `Metrics::new()` | `/metrics`, prefix `http` | Creates the middleware. |
| `.path(path)` | `/metrics` | Path of the endpoint. |
| `.prefix(prefix)` | `http` | Prefix of the metric names, e.g. `shop_http`; panics if invalid. |
| `.handle()` | — | A `MetricsHandle` to read the numbers from your code. |

```rust
use pratique::prelude::*;

let metrics = Metrics::new();
let numbers = metrics.handle();
// later: numbers.total(), numbers.by_class(5), numbers.in_flight(), numbers.render()
```

## Keep the endpoint private

Anyone who can reach `/metrics` sees your traffic. Add it after Securite's `Shield` with an `Auth` or an `IpFilter` guard:

```rust
use pratique::prelude::*;
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(
    Shield::builder()
        .guard(Auth::bearer().token("prometheus", "long-random-token").protect(["/metrics"]))
        .build(),
);
app.middleware(Metrics::new());
```

## Pitfalls and tips

- The endpoint doesn't count itself, so scrapes don't skew the numbers.
- Durations stop when the response head is ready, not when a streamed body ends.
- Add `Metrics` early (first or right after `AccessLog`) so that the answers of the other middlewares (redirects, `304`, maintenance) are counted too.
- Each process has its own counters; Prometheus adds the instances up.

## Related pages

- [Access logs](/docs/access-log)
- [Health checks](/docs/health)
- [Authentication](/docs/auth)
