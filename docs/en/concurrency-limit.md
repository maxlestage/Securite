---
title: Concurrency limit
summary: Cap the number of requests a single client can have in flight at the same time, to stop slow or expensive request floods.
category: traffic
order: 2
---

`ConcurrencyLimit` limits how many requests one client IP can have **in flight simultaneously**. Rate limiting counts requests over time; this guard counts requests that are being processed right now.

## What it protects against

A client sending a modest number of *slow* or *expensive* requests can stay under any per-second quota and still tie up your resources: report exports, search queries, image processing, endpoints that hold a database connection for seconds. With enough parallel requests, one client exhausts your worker pool, your database pool or your memory, and everybody else waits. This is an application-level denial of service (OWASP API4:2023, Unrestricted Resource Consumption).

Capping in-flight requests per client keeps one client's share of your capacity bounded, whatever the cost of each request.

## How it works

```text
ConcurrencyLimit::per_ip(2), one client IP

t0  request A arrives     in flight 1/2   accepted
t1  request B arrives     in flight 2/2   accepted
t2  request C arrives     in flight 2/2   429 too_many_concurrent
t3  response head of A    in flight 1/2   permit released
t4  request D arrives     in flight 2/2   accepted
```

* The guard keeps a counter per client IP (IPv6 grouped by `/64`) in a sharded, bounded store: 64 mutex-protected shards, keys dispatched with randomly keyed SipHash.
* When a request is accepted, an RAII permit is stored in the request context. It is released when the **response head** is produced, or when the request is cancelled (client disconnect, timeout): a dropped connection never leaks a permit.
* Counters drop to zero and are removed as soon as a client has nothing in flight, so memory follows the number of *active* clients.
* The store tracks at most 500,000 clients. When it is full, new clients are rejected (fail closed).
* Requests whose client IP is unknown are not limited.

## Quick start

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let shield = Shield::builder()
    // At most 16 simultaneous requests per client IP.
    .guard(ConcurrencyLimit::per_ip(16))
    .build();

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(shield);
```

Serve the app with `into_make_service_with_connect_info::<SocketAddr>()` so the guard sees the client address.

## Configuration

| Method | Default | Description |
|---|---|---|
| `ConcurrencyLimit::per_ip(max)` | – | At most `max` in-flight requests per client IP (minimum 1). |
| `.monitor()` | enforce | Report violations without blocking. |
| `.in_flight(ip)` | – | Number of requests currently in flight for `ip`. |

Fixed behaviour: IPv6 grouping by `/64`, at most 500,000 tracked clients.

## Examples

### Protect only an expensive endpoint

Concurrency limits work best where requests are costly. Apply the guard as a layer on a sub-router:

```rust
use axum::{routing::{get, post}, Router};
use securite::prelude::*;

// At most 2 report exports at a time per client.
let reports = Router::new()
    .route("/reports/export", post(|| async { "export queued" }))
    .layer(ConcurrencyLimit::per_ip(2));

let app: Router = Router::new()
    .route("/", get(|| async { "home" }))
    .merge(reports)
    .layer(Shield::recommended());
```

### Behind a reverse proxy

A standalone layer resolves the client IP from the TCP peer address, unless an outer shield already did: it then reuses that shield's `ClientIp`. Behind a proxy, configure the source once, on the outermost shield:

```rust
use axum::{routing::{get, post}, Router};
use securite::prelude::*;

let reports = Router::new()
    .route("/reports/export", post(|| async { "export queued" }))
    .layer(ConcurrencyLimit::per_ip(2));

let app: Router = Router::new()
    .route("/", get(|| async { "home" }))
    .merge(reports)
    // Outermost: the inner ConcurrencyLimit reuses the client IP it resolves.
    .layer(
        ShieldBuilder::recommended()
            .client_ip(ClientIpSource::cloudflare())
            .build(),
    );
```

### Inspecting live usage

Clones share their counters, which is handy for a debug or metrics endpoint:

```rust
use securite::prelude::*;

let limit = ConcurrencyLimit::per_ip(8);
let handle = limit.clone(); // give `limit` to the shield, keep `handle`

let busy = handle.in_flight("203.0.113.7".parse().unwrap());
println!("203.0.113.7 has {busy} requests in flight");
```

## Standalone layer

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/search", get(|| async { "results" }))
    .layer(ConcurrencyLimit::per_ip(4));
```

## Response headers

A rejected request gets `429 Too Many Requests` with the code `too_many_concurrent`, rendered as `application/problem+json` with `Cache-Control: no-store`. No `Retry-After` is sent: the right moment to retry depends on when the client's other requests finish.

```text
HTTP/1.1 429 Too Many Requests
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Too Many Requests","status":429,"code":"too_many_concurrent","detail":"Too many concurrent requests."}
```

## Pitfalls and tips

* **Streaming responses** (downloads, Server-Sent Events, WebSocket upgrades) release their permit as soon as the response head is sent: the time spent streaming the body is not counted.
* **HTTP/2 multiplexing**: a browser loading a page can fire dozens of requests at once over one connection. Leave headroom above your typical page fan-out, or scope the limit to API or expensive routes as shown above.
* **Shared addresses**: offices, mobile carriers and corporate NATs put many users behind one IP. Prefer generous limits on public pages.
* **Unknown IPs pass through**: forget `with_connect_info` and the guard does nothing; the shield only logs a warning once, under the `securite` target.
* `ConcurrencyLimit` complements, but does not replace, a global cap on your server: it bounds each client's share, not the total.

> **Tip:** use `ConcurrencyLimit` together with [rate limiting](/docs/rate-limit). The rate limit bounds how often a client may call you, the concurrency limit bounds how much of your capacity it can hold at once.

## Related pages

* [Rate limiting](/docs/rate-limit)
* [Auto-ban](/docs/auto-ban)
* [Body limit](/docs/body-limit)
* [Client IP behind a proxy](/docs/client-ip)
