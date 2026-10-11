# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **New crate `pratique`** (`crates/pratique`): everyday Vitesse middlewares that
  have nothing to do with security. Caching: `ETag` (body hash, `304 Not
  Modified`), `CacheControl` (by path prefix and content type), `ResponseCache`
  (in-memory cache of shareable `GET` responses, with a purge handle).
  Observability: `AccessLog` (JSON lines or Apache combined), `Metrics`
  (Prometheus `/metrics`: requests by method and status class, latency histogram,
  in-flight requests), `ResponseTime` (`X-Response-Time`, `Server-Timing`). URLs:
  `TrailingSlash` (redirect or rewrite), `Redirects` (exact paths, prefixes,
  canonical host). Operations: `Health` (`/health` with named checks,
  `application/health+json`), `Maintenance` (`503` + `Retry-After`, runtime
  switch). Responses and APIs: `SetHeaders`, `Locale` (`?lang=`, cookie,
  `Accept-Language`, `req.get::<Lang>()`), `Deprecation` (`Deprecation`, `Sunset`,
  `Link` headers).
- `AccessLog::ip_from_header(name)`: behind a reverse proxy, logs the client
  address that the proxy appended to `X-Forwarded-For` (or `CF-Connecting-IP` …)
  instead of the proxy's own address.
- Website: a new documentation category, "Pratique", with an overview and one page
  per middleware of the `pratique` crate, in English, French and Spanish.

### Changed

- **Vitesse instead of axum.** The `Shield` and the `SignatureLayer` are
  [Vitesse](https://maxlestage.github.io/Vitesse/) middlewares
  (`app.middleware(Shield::recommended())`, feature `vitesse`, enabled by
  default): the guards receive the peer address of the connection, and what they
  add to the request (`ClientIp`, `RequestIdValue`, `CspNonce`, `CsrfToken`,
  `Principal`) is read by handlers with `req.get::<T>()`. The `axum` feature and
  dependency are removed: the shield no longer reads axum's `ConnectInfo`; the
  `tower::Layer` implementation stays for hyper, tonic and `ServiceBuilder`
  (insert a `PeerAddr`). The examples (`vitesse_basic`, `vitesse_advanced`), the
  integration tests and the documentation use Vitesse; the website's own server
  runs on Vitesse too.
- License: Securite is proprietary software by Maxime Nathan Lestage, all rights
  reserved (see `LICENSE`); it is free to use as a dependency, commercially too,
  but not to modify or redistribute. The MIT/Apache-2.0 dual license is withdrawn.
- Credits: Maxime Nathan Lestage is named as the author in the crate metadata, the
  README and the website's footer, which now links the six projects of the
  ecosystem.
- `securite::VERSION`, the version of the crate.
- Website rewritten with [Active](https://maxlestage.github.io/Active/) instead of
  Yew and Trunk: the web server (protected by Securite itself) renders every page
  with complete SEO tags (canonical address, `hreflang` alternates, Open Graph,
  JSON-LD, sitemap) under `/{fr,en,es}/…`, and only the interactive parts
  (typewriter, middleware filter, code tabs, live attack playground, live shield
  statistics, documentation search) are WebAssembly islands; the animations run in a
  small Rust motion module. The documentation is compiled into the server. Addresses
  of the previous version (`/docs/…`, `/playground`) are redirected.
- The website is an installable Progressive Web App: web app manifest, icons and an
  offline service worker (the playground API always goes to the network).
- GitHub Pages: `securite-server export` writes the static copy (strict CSP `<meta>`
  tag with the hashes of the inline scripts and style, manifest, service worker,
  sitemap); CI, the Dockerfile and the Pages workflow build the browser bundle with
  `cargo` and the prebuilt `wasm-bindgen` instead of Trunk.

## [0.1.0] — 2026-10-10

### Added

- `Shield`: one tower layer running a pipeline of guards in priority order,
  with `recommended`, `strict` and `api` presets, client IP resolution
  (peer, `X-Forwarded-For`, `Forwarded`, single headers), RFC 9457 errors,
  `tracing` audit events, an `on_event` hook and live statistics.
- Browser hardening: `SecurityHeaders` (CSP builder with nonces and inline
  hashes, HSTS, COOP/COEP/CORP, Permissions-Policy…), `Cors`,
  `CookieHardening`, `HttpsRedirect`.
- Traffic control: GCRA `RateLimit`, `ConcurrencyLimit`, `AutoBan`,
  `BodyLimit` / `BodyLimitLayer`, `Hygiene`, `MethodFilter`.
- Access control: `IpFilter` / `IpSet`, `HostFilter`, `Auth`, `Csrf`,
  `ContentTypeGuard`.
- Threat detection: `Waf` (≈ 400 signatures, anomaly scoring, paranoia
  levels, evasion-resistant normalisation) and `BotBlocker`.
- Integrity: `RequestId`, `SignatureLayer` (GitHub, Stripe, Slack, Shopify,
  custom HMAC with replay protection).
- Website (Yew + WebAssembly, FR/EN/ES), documentation, Heroku deployment
  (Deploy button, GitHub Actions), CI with auto-merge into master.
