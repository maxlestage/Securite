---
title: Maintenance mode
summary: Answers every request with 503 Service Unavailable and Retry-After while a switch is on, as HTML, JSON or text, and keeps chosen paths open.
category: everyday
order: 11
---

During a database migration or an incident, it is better to say "back in ten minutes" than to serve errors. `Maintenance` does that with a switch you flip while the application runs, without a redeploy.

## How it works

While the switch is on, every request outside the allowed paths is answered with:

- `503 Service Unavailable`, the status search engines understand as "temporary, come back later";
- `Retry-After: <seconds>` when configured;
- `Cache-Control: no-store`, so nobody caches the maintenance page;
- an HTML page for browsers (if you gave one and the request accepts `text/html`), JSON `{"error":"maintenance","message":"…"}` for clients that accept JSON, plain text otherwise.

The switch is an atomic flag: checking it costs nothing when maintenance is off.

## Quick start

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

let maintenance = Maintenance::new()
    .allow("/health")
    .allow("/admin")
    .retry_after(Duration::from_secs(600))
    .html("<!doctype html><title>Maintenance</title><h1>Back in a few minutes</h1>");
let switch = maintenance.switch();

let mut app = App::new();
app.middleware(maintenance);
app.post("/admin/maintenance", move |req: Request| {
    let switch = switch.clone();
    async move {
        switch.set(req.query("on").as_deref() == Some("1"));
        format!("maintenance: {}", switch.is_on())
    }
});
```

> **Warning:** Protect the route that flips the switch, for example with Securite's [authentication](/docs/auth).

## Configuration

| Method | Default | Description |
|---|---|---|
| `Maintenance::new()` | off | Creates the middleware. |
| `.enabled(true)` | `false` | Start in maintenance (e.g. from an environment variable). |
| `.switch()` | — | The `MaintenanceSwitch`, to keep before handing the middleware to the app. |
| `.allow(prefix)` | none | Path prefix still served. Can be called several times. |
| `.retry_after(duration)` | none | `Retry-After`, in whole seconds. |
| `.message(text)` | a generic sentence | Text of the text and JSON answers. |
| `.html(page)` | none | Page shown to browsers. |

`MaintenanceSwitch` is cheap to clone and has `on()`, `off()`, `set(bool)` and `is_on()`.

## Starting from the environment

```rust
use pratique::prelude::*;

let maintenance = Maintenance::new()
    .enabled(std::env::var("MAINTENANCE").as_deref() == Ok("1"))
    .allow("/health");
```

## Pitfalls and tips

- Allow your health check path, or your orchestrator will think the instances are dead and restart them.
- Each process has its own switch: with several instances, flip each one (or read a shared flag in a background task and call `set`).
- Keep the HTML page self-contained (inline styles, no external assets): your static files may be unavailable too.

## Related pages

- [Health checks](/docs/health)
- [Authentication](/docs/auth)
