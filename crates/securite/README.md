[![Securite: armor your Rust APIs against XSS, SQL injection and bots](https://raw.githubusercontent.com/maxlestage/Securite/master/site/static/og-image.jpg)](https://securite-2db4c1994be7.herokuapp.com/)

# Securite

[![crates.io](https://img.shields.io/crates/v/securite.svg)](https://crates.io/crates/securite)
[![docs.rs](https://img.shields.io/docsrs/securite)](https://docs.rs/securite)
![MSRV 1.85](https://img.shields.io/badge/MSRV-1.85-blue)
![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success)
[![License: proprietary](https://img.shields.io/badge/license-proprietary-2a2a2e.svg)](#license)

**Fast, easy, batteries-included security middlewares for Rust web services.**

`securite` protects a [Vitesse](https://vitesse-f16135654c3d.herokuapp.com/) application
with one line, and any [tower](https://docs.rs/tower) stack — hyper, tonic, Poem,
Salvo… — with a single layer, the `Shield`, or with individual middlewares.

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
// Security headers, WAF, rate limiting, CSRF, request ids…
app.middleware(Shield::recommended());
app.get("/", |_req: Request| async { "Hello, secure world!" });
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
| | `Auth` | Unauthenticated access (Bearer / API key / Basic / JWT with JWKS / custom, constant time) |
| | `AccessControl` | Broken access control by URL (Symfony-style `access_control`, role hierarchy, encoding-proof paths) |
| | `Sessions` | Session fixation and hijacking (server-side sessions, id rotation on login, idle and absolute timeouts) |
| | `Csrf` | Cross-site request forgery (Fetch Metadata + signed double-submit tokens) |
| | `ContentTypeGuard` | Content-type confusion |
| | `SignedUrls` | Tampered or expired links (Laravel-style signed URLs) |
| Threat detection | `Waf` | SQLi, XSS, RCE, path traversal, Log4Shell, SSRF, NoSQLi, SSTI, scanners (anomaly scoring, ~400 signatures) |
| | `BotBlocker` | sqlmap, nikto, nuclei and 30+ attack tools |
| Integrity & tracing | `RequestId` | Untraceable incidents, log injection |
| | `SignatureLayer` | Forged webhooks (GitHub, Stripe, Slack, Shopify, custom HMAC, replay protection) |
| | Events & stats | Blind spots (`tracing` audit trail, SIEM hook, live counters) |
| | `ClearSiteData` | Data left behind after logout (cache, cookies, storage) |

### Building blocks for your handlers

| Module | Protects against |
|---|---|
| `password::PasswordHasher` | Password cracking (Argon2id with OWASP parameters, rehash on login, pepper, anti user enumeration) |
| `throttle::LoginThrottle` | Password guessing, credential stuffing, 2FA brute force (lockout per account, IP or both) |
| `authz::Gate` | Broken access control (Laravel gates & policies, Symfony voters, deny by default) |
| `signing::Signer` | Tampered tokens and links (HMAC-SHA256, expiry, purposes, key rotation) |
| `totp::Totp` | Password-only logins (RFC 6238 two-factor codes, replay protection, recovery codes) |
| `jwt::JwtValidator` | Forged or confused JWTs (algorithm allow-list, no `none`, `exp`/`nbf`/`iss`/`aud`, JWKS rotation; feature `jwt`) |
| `crypt::Encrypter` | Readable or swapped secrets (XChaCha20-Poly1305, key rotation, encrypted cookies bound to their name) |
| `session::SessionManager` | Session fixation, stale sessions (logout with `Clear-Site-Data`), e-mail verification links with `Signer` |
| `password_policy::PasswordPolicy` | Weak and breached passwords (NIST SP 800-63B, Have I Been Pwned k-anonymity) |
| `counter::CounterStore` | Limits multiplied by the number of instances (shared counters for `LoginThrottle`, fail closed) |
| `report::parse_csp_reports` | Blind CSP roll-outs (report collector, `Reporting-Endpoints`; feature `reports`) |
| `security_txt::SecurityTxt` | Researchers who cannot reach you (RFC 9116) |

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

Every middleware also works on its own, as a one-guard shield:

```rust
app.middleware(Shield::from(SecurityHeaders::strict()));
app.middleware(Shield::from(RateLimit::per_minute(600)));
app.middleware(Shield::from(Waf::new().monitor())); // log only, never block
```

With tower, a guard is a layer by itself: `ServiceBuilder::new().layer(Waf::new())`.

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

* Vitesse: nothing to do, the shield reads the peer address of the connection;
* hyper: insert `securite::PeerAddr(addr)` in the request extensions;
* behind a proxy: `.client_ip(ClientIpSource::heroku())`, `cloudflare()`, `fly()`,
  `x_real_ip()` or `XForwardedFor { trusted_hops }`, plus
  `.trusted_proxies(["10.0.0.0/8"])` so the header is only believed from your proxies.

## Minimum supported Rust version

Rust **1.85** (edition 2024).

## License

Securite is proprietary software: © 2026 Maxime Nathan Lestage, all rights
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
as part of one family of Rust projects: [Active](https://active-c1883a966650.herokuapp.com/), [Vitesse](https://vitesse-f16135654c3d.herokuapp.com/), [Securite](https://securite-2db4c1994be7.herokuapp.com/), [Memoire](https://memoire-7f4525f1fdaf.herokuapp.com/) and [Paquets](https://paquets-90dfc06b6fea.herokuapp.com/).
