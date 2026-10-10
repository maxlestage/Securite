---
title: Auto-ban
summary: fail2ban-style automatic banning of clients that keep failing authentication, tripping the WAF or hitting rate limits, with escalating ban durations.
category: traffic
order: 3
---

`AutoBan` watches the outcome of every request. Every request blocked by another guard of the same shield, and every response with a *strike status*, adds a strike to the client; too many strikes in a short window get the client banned, and repeat offenders are banned for longer and longer.

## What it protects against

* **Brute force and credential stuffing** (OWASP A07:2021): a stream of `401` from your login endpoint.
* **Vulnerability scanners and fuzzers**: a burst of WAF, hygiene or bot-blocker rejections, or of unknown URLs (`404`, if you count them).
* **Persistent abusers**: clients that keep hitting the rate limit (`429`) instead of backing off.

Each guard rejects individual requests; `AutoBan` turns a *pattern* of rejections into a ban, so the attacker stops reaching your application at all.

## How it works

* After each response, the guard adds a strike when another guard of the same shield blocked the request, whatever the status: WAF, rate limit, hygiene `400`, method filter `405`, body limit `413`, host filter `421`, content type `415`, bot blocker, CSRF, IP filter, `Auth` or one of your own guards. It also adds one when the final status is a *strike status*, by default `401`, `403` and `429`, which covers your own handlers, for example failed logins. Benign short-circuits (CORS preflights, HTTPS redirects) never count, and neither do violations reported in monitor mode.
* Strikes are counted in a window that opens with the first strike. When `max_strikes` is reached within `window`, the client is banned; if the window has elapsed, the count restarts.
* The ban check runs at priority 30, right after request IDs: a banned client is rejected before any other work, with `403 Forbidden`, code `banned` and a `Retry-After` header.
* Bans escalate: each new ban doubles the previous duration, up to `max_ban`.

```text
AutoBan::new(): 20 strikes in 60 s, ban_for 15 min, max_ban 24 h

1st ban   15 min x 1    = 15 min
2nd ban   15 min x 2    = 30 min
3rd ban   15 min x 4    =  1 h
4th ban   15 min x 8    =  2 h
5th ban   15 min x 16   =  4 h
6th ban   15 min x 32   =  8 h
7th ban   15 min x 64   = 16 h
8th ban   15 min x 128  = 32 h -> capped at 24 h
```

State lives in a sharded, bounded in-memory store (64 shards, randomly keyed SipHash, at most 500,000 clients). IPv6 clients are grouped by `/64`, so an attacker cannot escape a ban by moving to the next address of their prefix. A client that was never banned is forgotten once it has been quiet for `window`. A client banned at least once keeps its record, ban count included, until it has been quiet for `max(window, max_ban)`, which is how returning offenders get longer bans.

## Quick start

```rust
use std::time::Duration;

use axum::{routing::get, Router};
use securite::prelude::*;

let shield = Shield::builder()
    .guard(
        AutoBan::new()
            .max_strikes(10)
            .window(Duration::from_secs(60))
            .ban_for(Duration::from_secs(15 * 60)),
    )
    .build();

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(shield);
```

## Configuration

| Method | Default | Description |
|---|---|---|
| `AutoBan::new()` | – | 20 strikes per minute, 15 minute ban, doubling up to 24 hours. |
| `.max_strikes(n)` | `20` | Strikes before a ban (minimum 1). |
| `.window(duration)` | 60 s | Window in which strikes are counted. |
| `.ban_for(duration)` | 15 min | Duration of the first ban. |
| `.max_ban(duration)` | 24 h | Upper bound for escalating bans. |
| `.count_status(code)` | – | Adds a strike status (e.g. `404`, `400`). |
| `.statuses(codes)` | `401, 403, 429` | Replaces the list of strike statuses. Requests blocked by another guard count in any case. |
| `.never_ban(networks)` | none | IPs or CIDRs that never collect strikes. Panics on an invalid network. |
| `.ignore_paths(prefixes)` | none | Requests on these path prefixes never count as strikes, blocked or not. |
| `.monitor()` | enforce | Record and report bans, but let banned clients through. |

All clones of an `AutoBan` share the same state. Keep one clone to manage bans at runtime:

| Method | Description |
|---|---|
| `.ban(ip, duration)` | Bans a client manually (counts for escalation). |
| `.unban(ip)` | Lifts the ban and forgets the client's history. |
| `.is_banned(ip)` | Whether the client is currently banned. |
| `.banned()` | Every banned client with the remaining ban time, as `Vec<(IpAddr, Duration)>`. |

## Examples

### Login protection in depth

```rust
use std::time::Duration;

use axum::http::Method;
use securite::prelude::*;

let shield = Shield::builder()
    .guard(
        RateLimit::per_second(20)
            .route_methods("/login", [Method::POST], Quota::per_minute(5)),
    )
    .guard(
        AutoBan::new()
            .max_strikes(10)
            .window(Duration::from_secs(5 * 60))
            .ban_for(Duration::from_secs(30 * 60))
            .max_ban(Duration::from_secs(7 * 24 * 3600))
            .count_status(404) // scanners probe unknown URLs
            .never_ban(["10.0.0.0/8", "192.0.2.10"]) // internal network, uptime monitor
            .ignore_paths(["/api/session"]), // SPA "am I logged in?" probe answers 401
    )
    .build();
```

Failed logins produce `401`, then `429` once the login quota is exhausted; both are strikes, so a password-guessing client is banned for 30 minutes after 10 failures in 5 minutes.

### Admin endpoints to manage bans

```rust
use std::net::IpAddr;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use securite::prelude::*;

async fn list_bans(State(ban): State<AutoBan>) -> String {
    ban.banned()
        .into_iter()
        .map(|(ip, left)| format!("{ip}\t{}s\n", left.as_secs()))
        .collect()
}

async fn ban_ip(State(ban): State<AutoBan>, Path(ip): Path<IpAddr>) -> StatusCode {
    ban.ban(ip, Duration::from_secs(24 * 3600));
    StatusCode::NO_CONTENT
}

async fn unban_ip(State(ban): State<AutoBan>, Path(ip): Path<IpAddr>) -> StatusCode {
    ban.unban(ip);
    StatusCode::NO_CONTENT
}

fn app() -> Router {
    let ban = AutoBan::new();
    let shield = Shield::builder()
        // Only the internal network may reach /admin.
        .guard(IpFilter::new().allow_private().only_paths(["/admin"]))
        .guard(ban.clone())
        .build();

    Router::new()
        .route("/admin/bans", get(list_bans))
        .route("/admin/bans/{ip}", post(ban_ip).delete(unban_ip))
        .with_state(ban)
        .layer(shield)
}
```

## Standalone layer

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(RateLimit::per_second(10))
    .layer(AutoBan::new()); // outermost: sees the 429s of the inner layer
```

With axum the last `.layer()` call is the outermost one. Put `AutoBan` outside the layers whose rejections should count, so it also blocks banned clients before they reach them. Across separate layers only strike statuses count: a `413` from a standalone `BodyLimit` is not a strike unless you add it with `count_status(413)`. Inside a single `Shield`, every block counts.

## Response headers

```text
HTTP/1.1 403 Forbidden
content-type: application/problem+json
cache-control: no-store
retry-after: 840

{"type":"about:blank","title":"Forbidden","status":403,"code":"banned","detail":"Your address is temporarily banned."}
```

`Retry-After` is the remaining ban time in seconds. The ban rejection itself never counts as a strike.

## Pitfalls and tips

* **Shared addresses**: one abuser behind a corporate NAT or a carrier-grade NAT can get everyone behind it banned. Use `never_ban` for partners and offices you know.
* **Behind a proxy**, configure `ShieldBuilder::client_ip`; otherwise the first ban locks out the proxy, and therefore everybody. With standalone layers, make `Shield::builder().client_ip(ClientIpSource::heroku()).build()` (or your platform's source) the outermost layer, see [Client IP](/docs/client-ip).
* **Count `404` with care**: broken links, old bookmarks and crawlers produce `404` too. Raise `max_strikes` if you add it.
* **Manual bans ignore `never_ban`**, and `unban` resets the escalation history.
* `banned()` reports IPv6 clients by their `/64` network address.
* State is per process and lost on restart. With several replicas each instance bans independently.
* In monitor mode, bans are still recorded and logged (`client banned`), and requests from banned clients are reported instead of blocked.

> **Warning:** protect the endpoints that call `ban` and `unban` (IP filter, `Auth`): anyone who can reach them can lock users out or unban themselves.

## Related pages

* [Rate limiting](/docs/rate-limit)
* [IP filter](/docs/ip-filter)
* [Concurrency limit](/docs/concurrency-limit)
* [Web application firewall](/docs/waf)
