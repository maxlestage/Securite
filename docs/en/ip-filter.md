---
title: IP filter
summary: CIDR allow and deny lists for IPv4 and IPv6, scoped to paths if needed, with O(log n) lookups and lists you can update at runtime.
category: access
order: 1
---

`IpFilter` decides from the client address whether a request may go further. Use it to keep admin panels on the internal network, to block known-bad networks from a threat-intelligence feed, or to lock a partner API down to its customers' ranges.

## What it protects against

* **Exposed back-offices** (OWASP A01:2021, Broken Access Control): admin panels, metrics and internal tools reachable from the Internet. An allow-list adds a network barrier on top of authentication.
* **Known malicious sources**: scanners, botnets, abusive hosting ranges, Tor exits or regions you do not serve, listed as CIDR blocks.
* **Incident response**: block an attacking network in seconds, without a redeploy.

## How it works

### Decision rules

```text
only_paths set and path not matched -> pass (filter not applied)
client IP in deny-list              -> 403 ip_blocked   (deny always wins)
allow-list empty                    -> pass
client IP in allow-list             -> pass
otherwise                           -> 403 ip_blocked
```

| Allow-list | Client | Result |
|---|---|---|
| empty | in deny-list | blocked |
| empty | not listed | allowed |
| empty | unknown IP | allowed |
| not empty | in deny-list | blocked |
| not empty | in allow-list | allowed |
| not empty | not listed | blocked |
| not empty | unknown IP | blocked (fail closed) |

### IpSet: sorted ranges, binary search

Lists are stored as an `IpSet`. Every IP or CIDR becomes a `[start, end]` range in a single 128-bit space: IPv4 lives in the IPv4-mapped block `::ffff:0:0/96`, and IPv4-mapped client addresses (`::ffff:203.0.113.9`) are converted to IPv4 first. Ranges are sorted and overlapping or adjacent ranges are merged, so a lookup is one binary search: `O(log n)`, whether the list holds ten entries or a hundred thousand.

Accepted syntax: `"192.0.2.7"` (single host), `"10.0.0.0/8"`, `"2001:db8::/32"`. Host bits after the prefix are ignored (`10.1.2.3/8` means `10.0.0.0/8`).

### Runtime updates

The lists sit behind a read-write lock shared by every clone of the filter. Requests take the read lock for a binary search. `replace_deny_list` and `replace_allow_list` receive a set built beforehand, so the write lock is only held for a swap; `deny_now` and `allow_now` merge their network into the list under the lock. Builder methods (`allow`, `deny`, `try_allow`, `try_deny`, `allow_private`) are copy-on-write: the filter they return gets its own lists, and clones made earlier are left unchanged. Finish the configuration first, then keep a clone as a handle and give the other one to the shield.

## Quick start

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let shield = Shield::builder()
    .guard(IpFilter::new().deny(["203.0.113.0/24", "2001:db8:bad::/48"]))
    .build();

let mut app = App::new();
app.middleware(shield);
app.get("/", |_req: Request| async { "hello" });
```

## Configuration

| Method | Default | Description |
|---|---|---|
| `IpFilter::new()` | – | Empty filter: everybody passes. |
| `.allow(networks)` | empty | Adds IPs or CIDRs to the allow-list. Panics on invalid input. |
| `.deny(networks)` | empty | Adds IPs or CIDRs to the deny-list. Panics on invalid input. |
| `.try_allow(networks)` | – | Fallible `allow`, returns `Result<IpFilter, InvalidNetwork>`. |
| `.try_deny(networks)` | – | Fallible `deny`. |
| `.allow_private()` | – | Adds private, loopback, link-local and CGNAT ranges to the allow-list. |
| `.only_paths(prefixes)` | all paths | Applies the filter to these path prefixes only. |
| `.monitor()` | enforce | Report violations without blocking. |
| `.deny_now(network)` | – | Adds one network to the deny-list at runtime (`Result`), for every clone. |
| `.allow_now(network)` | – | Adds one network to the allow-list at runtime (`Result`), for every clone. |
| `.replace_deny_list(set)` | – | Replaces the whole deny-list. |
| `.replace_allow_list(set)` | – | Replaces the whole allow-list. |
| `.is_allowed(Option<IpAddr>)` | – | Evaluates the lists for an address. |

`IpSet` can be built with `IpSet::parse(items)`, with `str::parse` on a comma or whitespace separated list, or with `IpSet::private_networks()` (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `100.64.0.0/10`, `::1/128`, `fc00::/7`, `fe80::/10`). It offers `contains(ip)`, `len()` and `is_empty()`. Since IPv4 lives in the IPv4-mapped range, a set containing `::/0` contains every IPv4 address too. Parsing errors are `securite::ip_filter::InvalidNetwork`, also exported by the prelude.

## Examples

### Admin panel restricted to the office and the VPN

```rust
use securite::prelude::*;

let shield = Shield::builder()
    .client_ip(ClientIpSource::cloudflare())
    .guard(
        IpFilter::new()
            .allow_private() // VPN and internal tools
            .allow(["198.51.100.10", "2001:db8:abcd::/48"]) // office
            .only_paths(["/admin", "/metrics"]),
    )
    .build();
```

Everybody can reach the public site; only the listed networks reach `/admin` and `/metrics`.

### Block a network during an incident

```rust
use securite::prelude::*;
use vitesse::prelude::*;

async fn block(req: Request) -> Result<StatusCode, Error> {
    // The network to block is the body of the request, e.g. "203.0.113.0/24".
    let cidr = req.text().await?;
    Ok(match req.state::<IpFilter>().deny_now(cidr.trim()) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::BAD_REQUEST,
    })
}

fn app() -> App {
    let filter = IpFilter::new();
    let admin = IpFilter::new().allow_private().only_paths(["/admin"]);
    let mut app = App::new();
    app.state(filter.clone());
    // Both guards are named "ip_filter": the second would replace the first in
    // one shield, so each one gets its own middleware.
    app.middleware(Shield::builder().guard(filter).build());
    app.middleware(Shield::from(admin));
    app.post("/admin/block", block);
    app
}
```

### Refresh a deny-list from a feed

```rust
use std::time::Duration;

use securite::prelude::*;

async fn load_blocklist() -> std::io::Result<String> {
    tokio::fs::read_to_string("/etc/myapp/blocklist.txt").await
}

fn spawn_refresher(filter: IpFilter) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(600));
        loop {
            every.tick().await;
            let Ok(text) = load_blocklist().await else { continue };
            let entries = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'));
            match IpSet::parse(entries) {
                Ok(set) => filter.replace_deny_list(set),
                Err(e) => eprintln!("blocklist ignored: {e}"),
            }
        }
    });
}
```

Call `spawn_refresher(filter.clone())` and give `filter` to the shield. An invalid file is ignored and the previous list stays active.

## Standalone guard

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(IpFilter::new().allow_private()));
app.get("/metrics", |_req: Request| async { "up 1" });
```

## Response headers

`IpFilter` adds no specific header. Blocked clients get a deliberately terse answer; the client address is only written to the audit details of the security event (`ip=203.0.113.9`).

```text
HTTP/1.1 403 Forbidden
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Forbidden","status":403,"code":"ip_blocked","detail":"Access denied."}
```

## Pitfalls and tips

* **Behind a proxy, configure `ShieldBuilder::client_ip`**. Otherwise every request comes from the proxy: with `allow_private()` your admin panel is open to the whole Internet, and a deny rule can block everybody. With standalone layers, make `Shield::builder().client_ip(ClientIpSource::heroku()).build()` (or your platform's source) the outermost layer, see [Client IP](/docs/client-ip).
* **`::/0` also matches every IPv4 address**, because IPv4 is mapped into the IPv6 space. `0.0.0.0/0` matches IPv4 only.
* **Builder methods are copy-on-write**: calling `.allow()`, `.deny()`, `try_allow`, `try_deny` or `allow_private()` on a clone returns a filter with its own lists and never changes the original. Only `deny_now`, `allow_now`, `replace_deny_list` and `replace_allow_list` act on the live lists shared by every clone, so take your handle after the last builder call.
* Only one `IpFilter` per shield: guards are identified by name, so a second one replaces the first. Use separate layers as shown above.
* There is no "remove" for a single entry: rebuild the list and call `replace_deny_list` or `replace_allow_list`.
* `IpFilter` runs at priority 40, right after `AutoBan`, so blocked clients cost almost nothing.

> **Tip:** an IP allow-list is a second barrier, not authentication. Keep [authentication](/docs/auth) on admin routes as well.

## Related pages

* [Auto-ban](/docs/auto-ban)
* [Rate limiting](/docs/rate-limit)
* [Client IP behind a proxy](/docs/client-ip)
* [Authentication](/docs/auth)
