---
title: Rate limiting
summary: Exact GCRA rate limiting per IP, API key, route or custom key, with standard RateLimit headers and a memory-bounded, fail-closed store.
category: traffic
order: 1
---

`RateLimit` caps how many requests a client can send over time: per client IP by default, with optional per-route rules and API-key or custom keys. Excess traffic gets `429 Too Many Requests` with a `Retry-After` header.

## What it protects against

* **Brute force and credential stuffing** on login, password reset or OTP endpoints (OWASP A07:2021, Identification and Authentication Failures).
* **Application-level DoS and scraping**: one client hammering expensive endpoints (OWASP API4:2023, Unrestricted Resource Consumption).
* **Abuse of costly side effects**: e-mails, SMS or paid third-party API calls.

It runs inside your process, so it does not stop a volumetric DDoS: keep a CDN or load balancer in front for that.

## How it works

### GCRA in one picture

The limiter uses GCRA (Generic Cell Rate Algorithm) and stores a single `u64` per client: the *theoretical arrival time* (TAT). A quota defines an emission interval `T` and a tolerance `tau = T x (burst - 1)`.

```text
Quota::per_second(10).burst(3)
  T   = 1 s / 10        = 100 ms
  tau = T x (burst - 1) = 200 ms

time     request  TAT - now          verdict                  new TAT
0 ms     #1       0                  ok   (remaining 2)       100
0 ms     #2       100                ok   (remaining 1)       200
0 ms     #3       200                ok   (remaining 0)       300
0 ms     #4       300  > tau         429, retry in 100 ms     300
100 ms   #5       200 <= tau         ok                       400
```

For each request, `tat = max(TAT, now)`. If `tat - now > tau` the request is too early: it is rejected with `Retry-After = tat - now - tau`, rounded up to a whole second. Otherwise the TAT moves to `tat + T`. This behaves like a token bucket of capacity `burst` refilled every `T`, without background timers and without the boundary bursts of fixed windows.

### A bounded, sharded store

* Each rule has its own store of 64 mutex-protected shards, so different clients rarely contend.
* Keys are dispatched with randomly keyed SipHash: crafted colliding keys (HashDoS) are not possible.
* An entry expires once its bucket is full again; expired entries are swept every 4,096 operations on a shard and whenever a shard is full.
* Each rule tracks at most `max_entries` keys (1,000,000 by default, about 50 MB worst case). When a shard is full of live clients, **new** clients get `429` (fail closed) while known clients keep their buckets: rotating keys cannot exhaust your memory.
* IPv6 clients are grouped by `/64`, the block ISPs usually hand to each subscriber, so rotating addresses does not escape the limit.

## Quick start

```rust
use securite::prelude::*;
use vitesse::prelude::*;

fn main() -> std::io::Result<()> {
    let shield = Shield::builder()
        // 10 requests per second per client IP, bursts of up to 30.
        .guard(RateLimit::per_second(10).burst(30))
        .build();

    let mut app = App::new();
    // The shield reads the peer address of each connection itself.
    app.middleware(shield);
    app.get("/", |_req: Request| async { "hello" });
    app.run(3000)
}
```

## Configuration

### Quota

| Method | Default | Description |
|---|---|---|
| `Quota::new(n, period)` | burst = `n` | `n` requests per `period`. Panics if `n == 0` or `period` is zero. |
| `Quota::per_second(n)`, `Quota::per_minute(n)`, `Quota::per_hour(n)` | burst = `n` | Shortcuts for common periods. |
| `.burst(b)` | `n` | Bucket capacity: requests allowed at once (minimum 1). |
| `.burst_size()`, `.replenish_interval()` | – | Return the capacity and `T = period / n`. |

### RateLimit

| Method | Default | Description |
|---|---|---|
| `RateLimit::new(quota)` | – | One global rule, keyed by client IP. |
| `RateLimit::per_second(n)`, `RateLimit::per_minute(n)`, `RateLimit::per_hour(n)` | burst = `n` | Shortcuts for `RateLimit::new(Quota::per_second(n))`, `per_minute` and `per_hour`. |
| `.burst(n)` | quota burst | Burst of the global rule. |
| `.key(key)` | `RateLimitKey::Ip` | What the global rule counts by. |
| `.route(prefix, quota)` | – | Extra per-IP rule for a path prefix. |
| `.route_keyed(prefix, quota, key)` | – | Extra rule for a path prefix with any key. |
| `.route_methods(prefix, methods, quota)` | – | Extra per-IP rule for some methods on a path prefix. |
| `.headers(style)` | `HeaderStyle::Standard` | Which rate-limit headers are sent. |
| `.ipv6_prefix(bits)` | `64` | IPv6 grouping prefix (clamped to 128). |
| `.skip_paths(prefixes)` | none | Path prefixes never rate limited. |
| `.max_entries(n)` | `1_000_000` | Tracked keys per rule, split over 64 shards (at least 16 per shard). |
| `.monitor()` | enforce | Report violations without blocking. |

The global rule applies to every path except `skip_paths`. Every matching rule must pass; rules are checked in declaration order and the first failure answers `429`. Prefixes match on segment boundaries: `/api` matches `/api/users`, not `/apiary`.

### Keys

| Variant | Counts requests by |
|---|---|
| `RateLimitKey::Ip` | Client IP, IPv6 masked to `ipv6_prefix`. Default. |
| `RateLimitKey::Header(name)` | Value of a header; falls back to the IP when the header is missing, empty or longer than 256 bytes. |
| `RateLimitKey::Global` | One bucket shared by everybody (throughput cap). |
| `RateLimitKey::custom(f)` | Your closure `Fn(&Parts, &Context) -> Option<String>`. Returning `None` skips the rule for that request. |

`RateLimitKey::custom(f)` builds the `RateLimitKey::Custom(Arc<KeyFn>)` variant for you.

## Examples

### Login and password reset

```rust
use securite::http::Method;
use securite::prelude::*;

let limiter = RateLimit::new(Quota::per_second(20).burst(50))
    // 5 login attempts per minute and per IP, POST only.
    .route_methods("/login", [Method::POST], Quota::per_minute(5))
    // Reset e-mails are expensive and easy to abuse.
    .route("/password-reset", Quota::per_hour(10))
    // Never throttle load balancer probes.
    .skip_paths(["/health", "/ready"]);
```

`Quota::per_minute(5)` allows 5 attempts at once, then one every 12 seconds.

### API keys and global caps

```rust
use securite::http::HeaderName;
use securite::prelude::*;

let limiter = RateLimit::per_second(50)
    // Each API key gets its own bucket on /api.
    .route_keyed(
        "/api",
        Quota::per_minute(600).burst(100),
        RateLimitKey::Header(HeaderName::from_static("x-api-key")),
    )
    // Protect a fragile upstream: 200 searches per second for all clients combined.
    .route_keyed("/search", Quota::per_second(200), RateLimitKey::Global);
```

> **Warning:** header values are chosen by the client, and `Auth` runs after `RateLimit`. An attacker who sends a new random key on each request gets a fresh bucket each time. Keep the global per-IP rule so these requests are still limited per IP.

### Custom key

```rust
use securite::prelude::*;

let internal = IpSet::private_networks();
// Count by IP, but never limit internal callers.
let key = RateLimitKey::custom(move |_req, ctx| {
    let ip = ctx.client_ip()?;
    (!internal.contains(ip)).then(|| ip.to_string())
});

let limiter = RateLimit::per_second(10).key(key);
```

Custom keys receive the raw client IP: apply your own IPv6 grouping if you build keys from it.

### Monitor mode first

```rust
use securite::prelude::*;

let shield = Shield::builder()
    .guard(RateLimit::per_second(5).monitor())
    .on_event(|e| {
        if e.guard == "rate_limit" {
            eprintln!("would throttle {:?} on {}", e.client_ip, e.path);
        }
    })
    .build();
```

Watch who would have been throttled for a few days, then drop `.monitor()`.

## Standalone guard

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(RateLimit::per_minute(120)));
app.get("/", |_req: Request| async { "hello" });

// Or replace the limiter of a preset (guards with the same name are replaced).
let shield = ShieldBuilder::recommended()
    .guard(RateLimit::per_minute(600))
    .build();
```

Clones of a `RateLimit` share their counters, so the same limiter applied to several routes counts them together.

## Response headers

Successful responses carry the state of the most restrictive matching rule. With `HeaderStyle::Standard` (IETF draft):

```text
ratelimit-limit: 30
ratelimit-remaining: 29
ratelimit-reset: 1
```

`HeaderStyle::Legacy` sends `x-ratelimit-*` instead; `HeaderStyle::None` only keeps `Retry-After` on rejections. `HeaderStyle` is part of the prelude. A rejection looks like this:

```text
HTTP/1.1 429 Too Many Requests
content-type: application/problem+json
cache-control: no-store
retry-after: 12
ratelimit-limit: 5
ratelimit-remaining: 0
ratelimit-reset: 12

{"type":"about:blank","title":"Too Many Requests","status":429,"code":"rate_limited","detail":"Too many requests, slow down."}
```

## Pitfalls and tips

* **Unknown client IP**: without `into_make_service_with_connect_info::<SocketAddr>()`, IP-keyed rules cannot see the client and *all* requests share one bucket. The shield then logs a warning once, under the `securite` target.
* **Behind a proxy**, configure `ShieldBuilder::client_ip`, otherwise every client is the proxy. With standalone layers, make `Shield::builder().client_ip(ClientIpSource::heroku()).build()` (or your platform's source) the outermost layer: the inner layers reuse the address it resolved, see [Client IP](/docs/client-ip).
* **One limiter per shield**: a second `RateLimit` passed to `.guard()` replaces the first. Add rules with `.route*()` instead.
* **State is per process**: with N replicas the effective limit is N times higher.
* Rules checked before the failing one have already consumed a token.
* `RateLimit` runs after `AutoBan`, `IpFilter`, `Hygiene`, `MethodFilter` and `BodyLimit`, before the WAF, CSRF and `Auth`.

> **Tip:** combine with [auto-ban](/docs/auto-ban): every `429` counts as a strike, so clients that keep hitting the limit end up banned.

## Related pages

* [Auto-ban](/docs/auto-ban)
* [Concurrency limit](/docs/concurrency-limit)
* [IP filter](/docs/ip-filter)
* [Client IP behind a proxy](/docs/client-ip)
