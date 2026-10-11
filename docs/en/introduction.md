---
title: Introduction
summary: Securite protects Vitesse applications, and any tower or hyper service, with a single middleware, the Shield, that runs fast security guards on every request and hardens every response.
category: start
order: 1
---

`securite` is a security toolkit for Rust web services, written for Vitesse and for the tower ecosystem. It bundles the protections every internet-facing application needs (security headers, rate limiting, a web application firewall, CSRF and CORS, IP filtering, automatic banning, authentication, webhook signatures) behind one layer that you add in a single line.

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::recommended());
app.get("/", |_req: Request| async { "Hello, secure world!" });
```

## Why Securite

No single control stops every attack. Securite applies **defense in depth**: several independent, inexpensive checks, each closing a different class of weakness, so that a gap in one layer is covered by the next. A request that slips under the rate limit still meets the WAF; a script injected despite the WAF is still neutralised by the Content-Security-Policy.

The defaults follow OWASP guidance (Secure Headers Project, Core Rule Set, CSRF and session management cheat sheets) and are meant for production as they are. You opt out of a protection explicitly; you never have to remember to opt in.

| OWASP Top 10 (2021) | Controls in Securite |
|---|---|
| A01 Broken Access Control | IP filter, host filter, authentication, CSRF, CORS |
| A03 Injection | WAF, hygiene, content-type allow-list, CSP |
| A05 Security Misconfiguration | Security headers, cookie hardening, method filter, HTTPS redirect |
| A07 Identification and Authentication Failures | Per-route rate limits, auto-ban, constant-time credential checks |
| A08 Software and Data Integrity Failures | Webhook signature verification |
| A09 Security Logging and Monitoring Failures | Security events, live stats, request ids |
| A10 Server-Side Request Forgery | WAF SSRF signatures |

## The Shield concept

`Shield` is the heart of the crate: a single tower layer that runs a pipeline of **guards**.

```text
request ─► request_id ─► hygiene ─► … ─► rate_limit ─► waf ─► csrf ─► handler
                 │ first rejection stops the pipeline             │
                 ▼                                                ▼
        rejection (problem+json)                         handler response
                 └───────────────────────┬────────────────────────┘
                                         ▼
           on_response: security headers, rate-limit headers, CORS,
                        hardened cookies, x-request-id …
```

### A pipeline of synchronous guards

Each guard inspects the request head (method, URI, headers, extensions) and either lets it through or rejects it. Guards are synchronous and never buffer the body, which keeps them extremely fast. They run in ascending priority order, so cheap checks such as bans and protocol hygiene happen before the WAF. The first rejection wins: your handler is never called and the client receives a structured error.

### Response decoration

Once a response exists, whether it comes from your handler or from a rejection, every guard can decorate its head. This is why error responses also carry security headers, rate-limit headers and the request id.

### Shared context and events

Guards share a per-request context (client IP, request id, CSP nonce…). Every violation produces a security event, written with `tracing` and passed to your own hook. The [Shield and presets](/docs/shield-presets) page details the execution order.

## Middlewares

### Browser hardening

| Middleware | What it does |
|---|---|
| [Security headers](/docs/security-headers) | CSP with nonces, HSTS, COOP, CORP, COEP, Permissions-Policy; strips fingerprinting headers |
| [CORS](/docs/cors) | Strict, allow-list based cross-origin resource sharing |
| [Cookies](/docs/cookies) | Adds `Secure`, `HttpOnly` and `SameSite` to every `Set-Cookie` |
| [HTTPS redirect](/docs/https-redirect) | Proxy-aware redirection from HTTP to HTTPS |

### Traffic control

| Middleware | What it does |
|---|---|
| [Rate limiting](/docs/rate-limit) | GCRA limiter per IP, header, route or globally |
| [Concurrency limit](/docs/concurrency-limit) | Caps simultaneous requests per client |
| [Auto-ban](/docs/auto-ban) | fail2ban-like banning of clients that keep failing |
| [Body limit](/docs/body-limit) | Rejects oversized bodies before your handler reads them |
| [Hygiene](/docs/hygiene) | Request smuggling, path traversal and protocol sanity checks |
| [Method filter](/docs/method-filter) | Allowed HTTP methods; blocks method-override headers |

### Access control

| Middleware | What it does |
|---|---|
| [IP filter](/docs/ip-filter) | CIDR allow and deny lists, updatable at runtime |
| [Host filter](/docs/host-filter) | `Host` allow-list against DNS rebinding and host header attacks |
| [Authentication](/docs/auth) | Bearer token, API key and Basic auth with constant-time checks |
| [CSRF](/docs/csrf) | Fetch Metadata verification and optional signed double-submit tokens |
| [Content type](/docs/content-type) | Allow-list of request media types |

### Threat detection

| Middleware | What it does |
|---|---|
| [WAF](/docs/waf) | Anomaly-scoring firewall: SQLi, XSS, traversal, RCE, Log4Shell, SSRF … |
| [Bot blocker](/docs/bot-blocker) | Blocks well-known scanners and attack tools |

### Integrity and tracing

| Middleware | What it does |
|---|---|
| [Request ID](/docs/request-id) | Validated request ids for logs, handlers and responses |
| [Webhook signatures](/docs/webhook-signatures) | HMAC verification for GitHub, Stripe, Slack, Shopify … |
| [Events and stats](/docs/events-stats) | Audit trail, `tracing` integration and live counters |
| [Error format](/docs/error-format) | RFC 9457 problem+json, plain text, empty or custom error bodies |

## Performance

Security that slows an application down ends up disabled, so Securite is built for speed. Measured with criterion (`cargo bench -p securite`):

| Benchmark | Time |
|---|---|
| Full recommended pipeline, realistic browser request | ~6 µs |
| WAF inspection of a request | ~2 µs |
| IP set lookup among 10,000 ranges | ~3.4 ns |

All WAF signatures are compiled into a single Aho-Corasick automaton, so the cost does not grow with the number of rules. The crate is `#![forbid(unsafe_code)]`, and stateful guards keep their data in sharded, bounded maps with randomly keyed hashing: attacker-controlled keys can neither exhaust memory nor trigger hash flooding.

## Compatibility

`Shield` is a Vitesse middleware and implements `tower::Layer`, so it plugs into anything that accepts tower layers:

| Stack | Integration |
|---|---|
| Vitesse | `app.middleware(shield)`; the shield reads the address of each connection itself |
| hyper 1 | Wrap your service with `tower::ServiceBuilder` and insert `PeerAddr` |
| tonic | `Server::builder().layer(shield)` |
| tower | `ServiceBuilder::new().layer(shield)` |

Every guard is also a standalone middleware, for example `app.middleware(Shield::from(Waf::new()))`. Continue with [Installation](/docs/installation), then the [Quick start](/docs/quick-start).
