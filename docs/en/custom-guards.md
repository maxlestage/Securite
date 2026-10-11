---
title: Custom guards
summary: Write your own security rules by implementing the Guard trait, reject requests with structured errors and register them in any shield.
category: start
order: 6
---

Built-in guards cover generic threats; your application has its own rules: a maintenance window, a partner network, a business-hours restriction. Implement the `Guard` trait and your rule gets everything the built-in ones have: ordering, structured errors, events, statistics and monitor mode.

## The Guard trait

```rust
pub trait Guard: Send + Sync + 'static {
    /// Stable, machine readable name (logs, events, stats, `without`).
    fn name(&self) -> &'static str;

    /// Execution order, lower runs first. Default: `priority::CUSTOM` (500).
    fn priority(&self) -> u16 { priority::CUSTOM }

    /// `Mode::Enforce` (default) or `Mode::Monitor`.
    fn mode(&self) -> Mode { Mode::Enforce }

    /// Inspect (and possibly modify) the request head. `Err` stops the pipeline.
    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        Ok(())
    }

    /// Decorate the response head (handler responses and rejections alike).
    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {}
}
```

Only `name()` is required. The `request` and `response` modules come from the `http` crate, which Securite re-exports: `use securite::http::{request::Parts, StatusCode};` works without adding `http` to your dependencies.

| Method | Role |
|---|---|
| `name` | Identifies the guard; `.guard()` replaces any guard with the same name |
| `priority` | Position in the pipeline, see the constants in [Shield and presets](/docs/shield-presets) |
| `mode` | Return `Mode::Monitor` to report violations without blocking |
| `on_request` | Inspect the method, URI, headers and extensions; return `Err(Rejection)` to block |
| `on_response` | Add or remove response headers; called for every response |

## Rejections

| API | Effect |
|---|---|
| `Rejection::new(status, code, message)` | Blocking rejection: logged, counted, rendered with the shield's error format |
| `Rejection::respond(status, code)` | Benign short-circuit (redirect, preflight): empty body, not logged, not counted |
| `.with_header(name, value)` | Adds a response header such as `Retry-After` or `WWW-Authenticate` |
| `.with_details(text)` | Audit-only details, written to events and logs, never sent to the client |

`code` is a short, stable identifier such as `maintenance`, used in the problem+json body, events and statistics. `message` is shown to the client: keep it generic and put matched values in `details`.

## The request context

`Context` is shared by every guard for the duration of a request:

| Method | Description |
|---|---|
| `client_ip()` | Resolved client address, `Option<IpAddr>` (see [Client IP](/docs/client-ip)) |
| `method()`, `uri()`, `path()` | Request line as received by the shield |
| `request_id()` | Id assigned by `RequestId`, which runs first |
| `rejected_by()` | Name of the guard that rejected the request, useful in `on_response` |
| `blocked()` | Whether a guard blocked the request; benign short-circuits such as CORS preflights or HTTPS redirects do not count |
| `started()` | `Instant` at which the shield started processing |
| `csp_nonce()` | Per-request CSP nonce, when enabled |
| `add_set_cookie(value)` | Appends a `Set-Cookie` header to the final response |
| `hold(value)` | Keeps a value alive until the response head is produced, then drops it |
| `extensions()`, `extensions_mut()` | Typed storage private to guards |
| `Context::new(method, uri, client_ip)` | Builds a context outside any shield, to unit-test a guard |

## Example: maintenance mode

This guard answers `503 Service Unavailable` while maintenance is on, except for the staff network and the health check, and can be toggled at runtime:

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use securite::http::header::{HeaderValue, RETRY_AFTER};
use securite::http::{StatusCode, request, response};
use securite::prelude::*;
use securite::priority;

/// Marker stored in the context when staff bypass maintenance.
#[derive(Clone)]
struct StaffBypass;

/// Answers `503` to everyone but staff while maintenance is on.
#[derive(Clone)]
pub struct Maintenance {
    enabled: Arc<AtomicBool>,
    staff: IpSet,
}

impl Maintenance {
    pub fn new(staff: IpSet) -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(false)),
            staff,
        }
    }

    /// Shared by every clone: flip it from an admin endpoint or a signal handler.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }
}

impl Guard for Maintenance {
    fn name(&self) -> &'static str {
        "maintenance"
    }

    // Right after the request id, before bans, rate limiting and the WAF.
    fn priority(&self) -> u16 {
        priority::REQUEST_ID + 5
    }

    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        if !self.enabled.load(Ordering::Relaxed) || req.uri.path() == "/health" {
            return Ok(());
        }
        if ctx.client_ip().is_some_and(|ip| self.staff.contains(ip)) {
            ctx.extensions_mut().insert(StaffBypass);
            return Ok(());
        }
        Err(Rejection::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "maintenance",
            "The service is under maintenance, please retry in a few minutes.",
        )
        .with_header(RETRY_AFTER, HeaderValue::from_static("600"))
        .with_details(format!("path={}", req.uri.path())))
    }

    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {
        if ctx.extensions().get::<StaffBypass>().is_some() {
            res.headers
                .insert("x-maintenance-bypass", HeaderValue::from_static("staff"));
        }
    }
}
```

### Register it

Keep a clone of the guard: all clones share the same flag.

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let maintenance = Maintenance::new(
    IpSet::parse(["10.0.0.0/8", "192.0.2.0/24"]).expect("valid networks"),
);

let shield = ShieldBuilder::recommended()
    .guard(maintenance.clone())
    .build();

let mut app = App::new();
app.middleware(shield);
app.get("/", |_req: Request| async { "Hello, secure world!" });
app.get("/health", |_req: Request| async { "ok" });

// Later, from wherever you kept the clone:
maintenance.set_enabled(true);
```

Visitors then receive a problem+json body with `"code":"maintenance"` and a `Retry-After` header, and every refusal appears in your logs and statistics. If you would rather keep maintenance out of the security audit trail, use `Rejection::respond(StatusCode::SERVICE_UNAVAILABLE, "maintenance")`, which is silent and has an empty body.

## Holding resources

`ctx.hold` ties a value to the lifetime of the request: it is dropped when the response head is produced or the request is cancelled. The concurrency limiter releases its permits this way. Here it measures slow responses:

```rust
use std::time::{Duration, Instant};

use securite::http::request;
use securite::{Context, Guard, Rejection};

/// Logs requests whose response head took more than one second.
struct SlowRequests;

struct Timer {
    path: String,
    started: Instant,
}

impl Drop for Timer {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        if elapsed > Duration::from_secs(1) {
            eprintln!("slow request: {} took {:?}", self.path, elapsed);
        }
    }
}

impl Guard for SlowRequests {
    fn name(&self) -> &'static str {
        "slow_requests"
    }

    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        ctx.hold(Timer {
            path: req.uri.path().to_owned(),
            started: Instant::now(),
        });
        Ok(())
    }
}
```

## Testing a guard

A guard is a plain struct: call `on_request` directly with request parts and a context built by `Context::new`, no server needed. In the file that defines `Maintenance`:

```rust
#[cfg(test)]
mod tests {
    use securite::http::{Method, Request, StatusCode, Uri};
    use securite::prelude::*;

    use super::Maintenance;

    #[test]
    fn maintenance_blocks_visitors_but_not_staff() {
        let guard = Maintenance::new(IpSet::parse(["10.0.0.0/8"]).unwrap());
        guard.set_enabled(true);
        let (mut req, ()) = Request::get("/orders").body(()).unwrap().into_parts();

        // A visitor gets a 503.
        let visitor = Some("203.0.113.7".parse().unwrap());
        let mut ctx = Context::new(Method::GET, Uri::from_static("/orders"), visitor);
        let rejection = guard.on_request(&mut req, &mut ctx).unwrap_err();
        assert_eq!(rejection.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(rejection.code(), "maintenance");

        // Staff go through.
        let staff = Some("10.1.2.3".parse().unwrap());
        let mut ctx = Context::new(Method::GET, Uri::from_static("/orders"), staff);
        assert!(guard.on_request(&mut req, &mut ctx).is_ok());
    }
}
```

## Rules of thumb

- **Stay synchronous and fast.** Guards run on every request and cannot `.await`. Never do blocking I/O; refresh shared state in the background instead (an `Arc<RwLock<…>>` or an atomic, as above).
- **Choose a unique name.** `.guard()` replaces a guard with the same name: calling yours `waf` would silently remove the built-in WAF.
- **Do not assume `on_request` ran.** `on_response` is called for every response, including rejections issued by guards that run before yours. Check `ctx.rejected_by()` or `ctx.blocked()` when it matters.
- **Pass data to handlers through the request.** Insert it into `req.extensions` and read it in handlers with `req.get::<T>()`; `ctx.extensions_mut()` is private to guards. Values stored in either must implement `Clone + Send + Sync`.
- **Keep secrets out of messages.** The message reaches the client; `with_details` stays in your logs.
- **Roll out gradually.** Return `Mode::Monitor` from `mode()` to observe a new rule before enforcing it, see [Monitor mode](/docs/monitor-mode).
