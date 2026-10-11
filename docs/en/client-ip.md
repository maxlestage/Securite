---
title: Client IP
summary: How the shield finds the real client address behind proxies and CDNs, why it reads X-Forwarded-For from the right, and how to use the address in handlers.
category: start
order: 5
---

Rate limiting, concurrency limits, auto-ban, IP filtering and the audit trail all depend on knowing who the client is. Getting it wrong is costly in both directions: trust the wrong header and attackers pick their own IP to dodge bans; ignore the proxy and every visitor shares the proxy's address and its rate limit.

## Sources

The shield resolves the address once per request, using the `ClientIpSource` set with `ShieldBuilder::client_ip`:

| Variant | Reads | Use it when |
|---|---|---|
| `Peer` (default) | The TCP peer address | The app is exposed directly, with no proxy |
| `XForwardedFor { trusted_hops }` | Right-most `X-Forwarded-For` entry, skipping `trusted_hops` extra proxies | Proxies that append to `X-Forwarded-For` |
| `Forwarded { trusted_hops }` | Right-most `for=` of the RFC 7239 `Forwarded` header | Proxies that emit the standard header |
| `Header(name)` | A single-IP header set by your edge | CDNs such as Cloudflare or Akamai |

### Helpers

| Helper | Equivalent | Platform |
|---|---|---|
| `ClientIpSource::heroku()` | `XForwardedFor { trusted_hops: 0 }` | Heroku, Render, AWS ALB, a single Nginx |
| `ClientIpSource::cloudflare()` | `Header("cf-connecting-ip")` | Cloudflare |
| `ClientIpSource::fly()` | `Header("fly-client-ip")` | Fly.io |
| `ClientIpSource::x_real_ip()` | `Header("x-real-ip")` | Nginx with `proxy_set_header X-Real-IP $remote_addr;` |

```rust
use securite::prelude::*;

// Heroku router, or any single proxy appending to X-Forwarded-For.
let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::heroku())
    .build();

// A CDN and a load balancer, both appending to X-Forwarded-For.
let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::XForwardedFor { trusted_hops: 1 })
    .build();

// Akamai, or any edge that sets a single-IP header.
// (securite::http re-exports the http crate.)
let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::Header(
        securite::http::HeaderName::from_static("true-client-ip"),
    ))
    .build();
```

## Why the right-most X-Forwarded-For entry

Each proxy *appends* the address it received the connection from. Everything to the left was already in the request when it reached your proxy, and therefore may have been written by the client. Suppose a visitor at `203.0.113.50` sends a forged header:

```text
X-Forwarded-For: 6.6.6.6                  ← sent by the client (forged)
X-Forwarded-For: 6.6.6.6, 203.0.113.50    ← after your proxy appended the peer
```

The left-most value, `6.6.6.6`, is attacker-controlled; the right-most, `203.0.113.50`, was written by infrastructure you trust. `ClientIpSource::heroku()` therefore resolves `203.0.113.50`. Libraries that take the left-most value let anyone evade bans and rate limits with a single header.

### trusted_hops

With several proxies in a chain, each appends one entry. `trusted_hops` is the number of *additional* trusted proxies to skip from the right:

| `X-Forwarded-For` | `trusted_hops` | Resolved address |
|---|---|---|
| `6.6.6.6, 1.2.3.4, 5.6.7.8` | `0` | `5.6.7.8` |
| `6.6.6.6, 1.2.3.4, 5.6.7.8` | `1` | `1.2.3.4` |
| `6.6.6.6, 1.2.3.4, 5.6.7.8` | `5` | Too few entries: TCP peer |

Several header lines count as one comma-separated list. Entries may carry a port (`1.2.3.4:5678`, `[2001:db8::1]:443`), and IPv4-mapped IPv6 addresses such as `::ffff:1.2.3.4` are normalised to IPv4. `Forwarded` works the same way: from `for=192.0.2.43, for="[2001:db8:cafe::17]:4711"`, `Forwarded { trusted_hops: 0 }` resolves `2001:db8:cafe::17`.

## Spoofing risks

> **Warning:** Only trust a forwarding header when your application is reachable **exclusively** through the proxy that sets it. If the origin is also reachable directly (a public IP, a `*.herokuapp.com` URL bypassing your CDN), an attacker can send the header themselves and pick any address. Lock the origin down with a firewall, a private network or your CDN's authenticated origin pulls.

Single-IP headers such as `CF-Connecting-IP` are the most exposed: they are taken verbatim, so they are only safe when every request goes through the edge that overwrites them.

## IPv6 grouping

ISPs usually hand each customer a whole IPv6 `/64`, that is 2^64 addresses. Counting each address separately would let one attacker rotate through billions of identities. The rate limiter, the concurrency limit and auto-ban therefore group IPv6 clients by `/64`; IPv4 addresses are used as they are. The rate limiter lets you change the prefix:

```rust
use securite::prelude::*;

// Some ISPs delegate a /56 per customer.
let limiter = RateLimit::per_second(20).burst(100).ipv6_prefix(56);
```

The `securite::ip::mask` function applies the same grouping in your own code.

## Using the address in handlers

The shield inserts a `ClientIp` extension into every request whose address it resolved. It holds the full address, not the `/64` group:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

async fn whoami(req: Request) -> String {
    match req.get::<ClientIp>() {
        Some(ClientIp(ip)) => format!("your address: {ip}"),
        None => "unknown address".to_owned(),
    }
}

let mut app = App::new();
app.middleware(Shield::recommended());
app.get("/whoami", whoami);
```

In a [custom guard](/docs/custom-guards), read it with `ctx.client_ip()`.

## Stacked shields and standalone layers

When a request already carries a `ClientIp` extension, set by an outer shield, the shield reuses that address instead of resolving it again. Inner shields and standalone guards therefore agree with the outermost one. To use standalone guards behind a proxy, add a shield without guards that only resolves the address, as the first middleware:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
// Outermost (first middleware added): resolves the client IP once,
// and the middlewares added after it reuse its `ClientIp`.
app.middleware(Shield::builder().client_ip(ClientIpSource::heroku()).build());
app.middleware(Shield::from(AutoBan::new()));
app.middleware(Shield::from(RateLimit::per_minute(120)));
app.get("/", |_req: Request| async { "hello" });
```

> **Warning:** only the outermost shield's `client_ip` setting counts. If it keeps the default `Peer` source, every inner shield reuses the proxy address it resolved, whatever its own setting: configure the source on the outermost shield.

## Fallbacks

When the configured header is missing, malformed or has too few entries, the shield falls back to the TCP peer address. The peer is the address of the connection, which Vitesse gives the shield; in a tower service it is looked up in a `PeerAddr` extension, then in a raw `SocketAddr` extension.

When no address can be found at all (a tower service without `PeerAddr`), the shield logs a warning once (target `securite`) recommending a `PeerAddr` extension, and guards degrade as follows:

| Guard | Behaviour without a client IP |
|---|---|
| `RateLimit` (per IP) | All such requests share one global bucket |
| `AutoBan`, `ConcurrencyLimit` | Skipped |
| `IpFilter` | Denied if an allow-list is configured, allowed otherwise |
| Security events | `client_ip` is `None` |

> **Tip:** Add the `whoami` handler above during deployment and call it through your real infrastructure. If it prints a proxy address or `unknown address`, fix the source before going live.
