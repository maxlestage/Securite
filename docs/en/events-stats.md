---
title: Security events and statistics
summary: Every block or monitor-mode finding becomes a structured security event for your logs, metrics, SIEM or alerting, and live counters can be exposed as JSON.
category: integrity
order: 3
---

Blocking attacks is only half of the job: you also need to know what is being blocked, by which guard, from where, and whether a new rule is hurting real users. Every time a guard rejects a request, or would have rejected it in monitor mode, the shield emits a `SecurityEvent`, writes it to `tracing` and updates live counters that you can read at any time.

## Why it matters

**A09:2021 Security Logging and Monitoring Failures** lists the absence of logs for security-relevant events, of alerting thresholds and of real-time detection among the most common weaknesses. The events below give you a structured, low-cardinality audit trail out of the box, and the hook lets you route it wherever your team already looks.

## The `SecurityEvent`

| Field | Type | Description |
|---|---|---|
| `guard` | `&'static str` | Name of the guard: `waf`, `rate_limit`, `auth`, `bot_blocker`… |
| `code` | `&'static str` | Machine-readable rejection code: `waf_blocked`, `rate_limited`… |
| `status` | `StatusCode` | Status returned (or that would have been returned in monitor mode). |
| `enforced` | `bool` | `false` when the guard runs in monitor mode. |
| `client_ip` | `Option<IpAddr>` | Resolved client IP address, if known. |
| `method` | `&Method` | Request method. |
| `path` | `&str` | Request path, without the query string. |
| `request_id` | `Option<&str>` | Request identifier, when a `RequestId` guard runs. |
| `message` | `&str` | Message sent to the client. |
| `details` | `Option<&str>` | Audit-only details, such as `score=8 rules=[143, 100] categories=sqli`. |

An event is emitted for every rejection by a guard of the shield, in enforce or monitor mode. No event is emitted for allowed requests, for benign short-circuits (CORS preflight answers, HTTPS redirects), for `SignatureLayer` rejections (they are only written to `tracing`), or for `Waf::inspect_text` calls made in your handlers.

## Built-in tracing output

By default, events are written with `tracing` under the `securite` target:

- `WARN` with the message `request blocked` for enforced rejections;
- `INFO` with the message `violation (monitor mode)` for monitor-mode findings.

Each line carries the fields `guard`, `code`, `status`, `ip`, `method`, `path`, `request_id` and `details`. `AutoBan` also logs `client banned` at `WARN`, and `SignatureLayer` logs `webhook signature rejected`.

```rust
// Requires tracing-subscriber with the "env-filter" feature.
tracing_subscriber::fmt()
    .with_env_filter("info,securite=info")
    .init();
```

```text
2026-10-10T08:12:44.913245Z  WARN securite: request blocked guard="waf" code="waf_blocked" status=403 ip=Some(203.0.113.7) method=GET path="/search" request_id="3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44" details="score=8 rules=[143, 100] categories=sqli"
```

```bash
# Blocked requests only
RUST_LOG=info,securite=warn ./my-service
# Blocked requests and monitor-mode findings
RUST_LOG=info,securite=info ./my-service
```

Call `.log_events(false)` on the builder if you prefer to handle events only through your hook.

## The `on_event` hook

`ShieldBuilder::on_event` registers a function called synchronously for every event. Plug your metrics, SIEM or alerting there.

### Metrics counter

With the `metrics` crate (Prometheus, StatsD, OpenTelemetry exporters…):

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .on_event(|e| {
        metrics::counter!(
            "securite_events_total",
            "guard" => e.guard,
            "code" => e.code,
            "enforced" => if e.enforced { "true" } else { "false" }
        )
        .increment(1);
    })
    .build();
```

### Alerting

The hook runs on the request path: never block in it. Copy what you need into an owned value and hand it to a background task through a channel:

```rust
use std::net::IpAddr;

use securite::prelude::*;
use tokio::sync::mpsc;

#[derive(Debug)]
struct Alert {
    guard: &'static str,
    code: &'static str,
    ip: Option<IpAddr>,
    path: String,
    request_id: Option<String>,
    details: Option<String>,
}

let (tx, mut rx) = mpsc::channel::<Alert>(1024);

tokio::spawn(async move {
    while let Some(alert) = rx.recv().await {
        // Post to Slack, PagerDuty or your SIEM here.
        eprintln!("security alert: {alert:?}");
    }
});

let shield = ShieldBuilder::recommended()
    .on_event(move |e| {
        if e.enforced && matches!(e.guard, "waf" | "auth" | "ban") {
            // try_send never blocks: alerts are dropped if the queue is full.
            let _ = tx.try_send(Alert {
                guard: e.guard,
                code: e.code,
                ip: e.client_ip,
                path: e.path.to_owned(),
                request_id: e.request_id.map(str::to_owned),
                details: e.details.map(str::to_owned),
            });
        }
    })
    .build();
```

## Live statistics

`Shield::stats()` returns a `StatsSnapshot`, a point-in-time copy of lock-free counters:

| Item | Type | Description |
|---|---|---|
| `total` | `u64` | Requests seen by the shield. |
| `blocked` | `u64` | Requests rejected by an enforcing guard. |
| `monitored` | `u64` | Violations reported by guards in monitor mode. |
| `by_guard` | `Vec<(&'static str, u64)>` | Violations per guard (blocked and monitored), in execution order. |
| `allowed()` | `u64` | `total` minus `blocked`. |
| `to_json()` | `String` | The snapshot as a compact JSON object. |

### Exposing an admin endpoint

Keep a clone of the shield (it is an `Arc`) and serve the snapshot behind authentication:

```rust
use axum::{extract::State, http::header, response::IntoResponse, routing::get, Router};
use securite::prelude::*;

async fn security_stats(State(shield): State<Shield>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        shield.stats().to_json(),
    )
}

let admin_token = std::env::var("ADMIN_TOKEN").expect("ADMIN_TOKEN must be set");
let shield = ShieldBuilder::recommended()
    .guard(Auth::bearer().token("ops", &admin_token).protect(["/admin"]))
    .build();

let app: Router = Router::new()
    .route("/admin/security/stats", get(security_stats))
    .with_state(shield.clone())
    .layer(shield);
```

```json
{
  "total": 15230,
  "allowed": 15102,
  "blocked": 128,
  "monitored": 0,
  "by_guard": {
    "request_id": 0,
    "hygiene": 4,
    "method": 2,
    "body_limit": 0,
    "rate_limit": 61,
    "bot_blocker": 17,
    "waf": 39,
    "csrf": 1,
    "auth": 4,
    "security_headers": 0,
    "cookies": 0
  }
}
```

`to_json()` returns the same object on a single line.

## Pitfalls and tips

- Counters live in memory, per shield and per process: they restart from zero on every deployment and are not shared between instances. Use the hook and your metrics backend for fleet-wide, long-term figures.
- A standalone guard layer builds its own internal shield, whose statistics you cannot read. Build a `Shield`, keep a clone, and register your guards in it.
- `total` also counts benign short-circuits such as CORS preflights and HTTPS redirects; they are part of `allowed()`.
- Never use the client IP address or the path as metric labels: their cardinality is unbounded and attackers control it. Keep `guard`, `code` and `enforced`.
- Protect the statistics endpoint: it tells an attacker which guards are active and which of their attempts succeed.
- `details` are written for your eyes only. They are never sent to clients, so do not copy them into responses.

## Related pages

- [Monitor mode](/docs/monitor-mode)
- [Request IDs](/docs/request-id)
- [Error responses](/docs/error-format)
- [Web application firewall](/docs/waf)
- [Authentication](/docs/auth)
