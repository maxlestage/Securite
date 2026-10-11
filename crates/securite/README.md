# securite

[![crates.io](https://img.shields.io/crates/v/securite.svg)](https://crates.io/crates/securite)
[![docs.rs](https://img.shields.io/docsrs/securite)](https://docs.rs/securite)
![MSRV 1.85](https://img.shields.io/badge/MSRV-1.85-blue)
![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success)
[![License: proprietary](https://img.shields.io/badge/license-proprietary-2a2a2e.svg)](#license)

**Fast, easy, batteries-included security middlewares for Rust web services.**

`securite` plugs into any [tower](https://docs.rs/tower) stack — axum, hyper,
tonic, Loco, Leptos / Dioxus fullstack, Poem, Salvo… — and protects it with a
single layer, the `Shield`, or with individual middlewares.

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app = Router::new()
    .route("/", get(|| async { "Hello, secure world!" }))
    // Security headers, WAF, rate limiting, CSRF, request ids…
    .layer(Shield::recommended());
```

```console
$ curl -i "http://localhost:3000/?q=1'%20UNION%20SELECT%20password%20FROM%20users--"
HTTP/1.1 403 Forbidden
content-type: application/problem+json
x-request-id: 6f1c…

{"type":"about:blank","title":"Forbidden","status":403,"code":"waf_blocked",
 "detail":"Request blocked by the web application firewall.","request_id":"6f1c…"}
```

## Middlewares

| Category | Middleware | Protects against |
|---|---|---|
| Browser hardening | `SecurityHeaders` | XSS, clickjacking, MIME sniffing, Spectre (CSP with nonces & hashes, HSTS, COOP/CORP/COEP, Permissions-Policy…) |
| | `Cors` | Cross-origin data theft (strict allow-lists, unsafe configs refused at startup) |
| | `CookieHardening` | Session theft (adds `Secure`, `HttpOnly`, `SameSite` to every cookie) |
| | `HttpsRedirect` | Downgrade / sniffing (proxy-aware 308 redirect) |
| Traffic control | `RateLimit` | Brute force, scraping, DoS (GCRA, per IP / key / route) |
| | `ConcurrencyLimit` | Resource exhaustion (in-flight requests per IP) |
| | `AutoBan` | Persistent attackers (fail2ban-like, escalating bans) |
| | `BodyLimit`, `BodyLimitLayer` | Memory exhaustion (oversized bodies) |
| | `Hygiene` | Request smuggling, path traversal, oversized headers / URIs |
| | `MethodFilter` | Cross-site tracing, method-override bypasses |
| Access control | `IpFilter` | Unwanted networks (CIDR allow / deny lists, runtime updates, O(log n)) |
| | `HostFilter` | Host header poisoning, DNS rebinding |
| | `Auth` | Unauthenticated access (Bearer / API key / Basic / custom, constant time) |
| | `Csrf` | Cross-site request forgery (Fetch Metadata + signed double-submit tokens) |
| | `ContentTypeGuard` | Content-type confusion |
| Threat detection | `Waf` | SQLi, XSS, RCE, path traversal, Log4Shell, SSRF, NoSQLi, SSTI, scanners (anomaly scoring, ~400 signatures) |
| | `BotBlocker` | sqlmap, nikto, nuclei and 30+ attack tools |
| Integrity & tracing | `RequestId` | Untraceable incidents, log injection |
| | `SignatureLayer` | Forged webhooks (GitHub, Stripe, Slack, Shopify, custom HMAC, replay protection) |
| | Events & stats | Blind spots (`tracing` audit trail, SIEM hook, live counters) |

## Presets

```rust
use securite::prelude::*;

Shield::recommended(); // web apps and APIs
Shield::strict();      // + HTTPS redirect, auto-ban, per-IP concurrency, paranoia 2…
Shield::api();         // JSON only, locked CSP, no CSRF

// Customise any preset: a guard with the same name replaces the preset one.
let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::heroku())          // behind a proxy
    .guard(RateLimit::per_second(50).route("/login", Quota::per_minute(5)))
    .guard(Auth::bearer().token("ci", "s3cr3t-token").protect(["/admin"]))
    .without("csrf")
    .on_event(|e| tracing::warn!(guard = e.guard, ip = ?e.client_ip, "blocked"))
    .build();
```

Every middleware is also a standalone tower layer:

```rust
let app = router
    .layer(SecurityHeaders::strict())
    .layer(RateLimit::per_minute(600))
    .layer(Waf::new().monitor()); // log only, never block
```

## Performance

Measured with criterion (`cargo bench -p securite`) on a realistic request
(7 headers, query string), Linux x86_64, release build:

| | time |
|---|---|
| Full `recommended` pipeline (10 guards) | ≈ 6.1 µs (≈ 5.4 µs over the bare handler) |
| WAF inspection (≈ 400 signatures, one Aho-Corasick DFA pass) | ≈ 1.9 µs |
| IP lookup in 10 000 CIDR ranges | ≈ 3.4 ns |

Guards are synchronous and only look at the request head; shared state lives
in sharded, bounded, HashDoS-resistant maps. `#![forbid(unsafe_code)]`.

## Documentation

* Full guides (English, Français, Español): 
* API reference: <https://docs.rs/securite>
* Examples: `examples/`

## Client IP

IP-aware guards need the real client address:

* axum: serve with `app.into_make_service_with_connect_info::<SocketAddr>()`;
* hyper: insert `securite::PeerAddr(addr)` in the request extensions;
* behind a proxy: `.client_ip(ClientIpSource::heroku())`, `cloudflare()`, `fly()`,
  `x_real_ip()` or `XForwardedFor { trusted_hops }`.

## Minimum supported Rust version

Rust **1.85** (edition 2024).

## License

securite is proprietary software: © 2026 Maxime Nathan Lestage, all rights
reserved. It is not open source. The source code is published on crates.io
and GitHub so that it can be read, audited and built, and you may use it
freely as a dependency of your own programs, commercial ones included.
Modifying it or redistributing its source needs the author's written
permission. Full terms: [LICENSE](LICENSE).

Contributions (code, documentation, ideas) are welcome and become part of
the project under the same terms: by submitting one, you assign its rights
to the author, as the license states.

## Credits

Designed and developed by Maxime Nathan Lestage,
as part of one family of Rust projects: [Active](https://maxlestage.github.io/Active/), [Vitesse](https://maxlestage.github.io/Vitesse/), [Securite](https://maxlestage.github.io/Securite/), [Memoire](https://maxlestage.github.io/Memoire/), [Paquets](https://maxlestage.github.io/Paquets/) and [FerroSwift](https://maxlestage.github.io/FerroSwift/).
