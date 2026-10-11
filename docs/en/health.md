---
title: Health checks
summary: Answers GET /health for load balancers, Kubernetes and uptime monitors, in the application/health+json format, with named checks that turn the answer into a 503.
category: everyday
order: 10
---

Load balancers, orchestrators (Kubernetes, Nomad, Fly.io, Heroku…) and uptime monitors regularly ask "are you alive?". `Health` answers that question itself, before your routes, so the probes never reach your handlers or your logs.

## The answer

```json
{"status":"pass","uptime":3600,"version":"1.4.0","checks":{"database":{"status":"pass"},"cache":{"status":"pass"}}}
```

- `200 OK` with `"status":"pass"` when every check passes;
- `503 Service Unavailable` with `"status":"fail"` as soon as one fails, so the load balancer stops sending traffic to this instance.

The content type is `application/health+json` and the answer is never cached (`Cache-Control: no-store`). Only `GET` and `HEAD` on the exact path are answered; everything else goes to your routes.

## Quick start

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Health::new().version(env!("CARGO_PKG_VERSION")));
```

```bash
curl -i https://example.com/health
# HTTP/1.1 200 OK
# content-type: application/health+json
#
# {"status":"pass","uptime":42,"version":"1.4.0"}
```

## Configuration

| Method | Default | Description |
|---|---|---|
| `Health::new()` | `/health`, no check | Creates the middleware. |
| `.path(path)` | `/health` | Another path (`/healthz`, `/_health`…). |
| `.version(v)` | none | Version shown in the answer. |
| `.check(name, f)` | none | Named check; `f() == false` fails the probe. |

## Checks

Checks run on every probe, synchronously: keep them cheap. The usual pattern is a flag that a background task keeps up to date:

```rust
use pratique::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use vitesse::prelude::*;

async fn ping_database() -> bool {
    true // e.g. `SELECT 1` with a short timeout
}

let db_up = Arc::new(AtomicBool::new(true));

let flag = db_up.clone();
vitesse::tokio::spawn(async move {
    loop {
        let ok = ping_database().await;
        flag.store(ok, Ordering::Relaxed);
        vitesse::tokio::time::sleep(Duration::from_secs(5)).await;
    }
});

let mut app = App::new();
app.middleware(Health::new().check("database", move || db_up.load(Ordering::Relaxed)));
```

## Liveness and readiness

Kubernetes distinguishes "restart me" (liveness) from "don't send me traffic yet" (readiness). Use two instances on two paths:

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Health::new().path("/livez"));
app.middleware(Health::new().path("/readyz").check("database", || true));
```

## Pitfalls and tips

- Add `Health` before Securite's `Shield` if your platform probes without a `Host` header or from an address your rules would block, and before [Maintenance](/docs/maintenance) (or `allow` its path) so that probes keep working during maintenance.
- Skip the path in your [access logs](/docs/access-log): `.skip("/health")`.
- Don't make liveness depend on the database: a database outage would restart every instance in a loop.

## Related pages

- [Maintenance mode](/docs/maintenance)
- [Prometheus metrics](/docs/metrics)
