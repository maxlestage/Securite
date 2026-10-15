# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-15

### Added

- `securite::jwt` (new feature `jwt`): `JwtValidator` and `Auth::jwt`, JSON Web
  Token validation through the `jsonwebtoken` crate (RustCrypto backend). HMAC
  secrets, RSA / EC / Ed25519 PEM keys or a JWKS; algorithm allow-list checked
  against the key family (no RS256 → HS256 confusion, never `none`); `exp`
  required, `nbf` checked, `iss` / `aud` required once configured, 30 s leeway;
  keys chosen by `kid`, symmetric and encryption keys of a JWKS ignored,
  `set_jwks` for runtime key rotation shared by every clone; roles read from a
  claim (array, space separated `scope`, dotted paths such as Keycloak's
  `realm_access.roles`). On success the request gets a `Principal` (scheme `jwt`),
  the `JwtClaims` and the `Roles`; failures answer `401` with
  `WWW-Authenticate: Bearer error="invalid_token"`.
- `securite::crypt` (new default feature `crypt`): `Encrypter`, Laravel's `Crypt`
  with XChaCha20-Poly1305 (RustCrypto `chacha20poly1305`): random 192-bit nonces,
  versioned tokens carrying a key id, key rotation (`fallback_key`), purposes and
  contexts authenticated as associated data, optional expiry, `generate_key`, and
  encrypted cookies bound to their name (`encrypt_cookie`, `read_cookie`).
- `securite::access`: `Roles` (request extension), `RoleHierarchy` (Symfony's
  `role_hierarchy`, cycle safe) and the `AccessControl` guard (Symfony's
  `access_control`): ordered rules by path prefix and method, `Public`,
  `Authenticated`, `AnyRole`, `AllRoles`, `Deny`, `deny_unmatched` /
  `authenticate_unmatched`; `401` for anonymous requests, `403` otherwise; paths
  are canonicalised (percent-decoding, `\`, `;params`, `//`, dot segments, case)
  so encoding tricks do not bypass rules. New priorities `priority::SESSIONS` (138)
  and `priority::ACCESS_CONTROL` (145). `Auth::grant` gives roles to a credential.
- `authz::RoleVoter` and `Gate::roles`: `ROLE_*` abilities decided by the user's
  roles through a `RoleHierarchy`.
- `securite::session`: `SessionManager`, `SessionStore` (with
  `MemorySessionStore`) and the `Sessions` guard: 256-bit ids stored as SHA-256
  digests only, `login` / `regenerate` rotate the id (session fixation), idle (30
  min) and absolute (12 h) timeouts enforced server side, `__Host-` cookie with
  `Secure; HttpOnly; SameSite=Lax`, `logout` with an expired cookie and
  `Clear-Site-Data`.
- `securite::clear_site_data::ClearSiteData`: adds `Clear-Site-Data` to the
  successful responses of logout paths. New priority `priority::CLEAR_SITE_DATA`.
- `Signer::email_verification_url` / `verify_email_url` (links bound to the user
  *and* the current address, Laravel's `MustVerifyEmail`) and
  `Signer::sign_cookie` / `unsign_cookie` (signed cookies bound to their name).
- `securite::password_policy`: `PasswordPolicy` after NIST SP 800-63B (length
  12..128 characters by default, no composition rules, common passwords,
  context words such as the user name or e-mail, repetitive and sequential
  passwords, custom blocklist) and `hibp::RangeQuery`, Have I Been Pwned's
  k-anonymity range API without an HTTP client dependency.
- `securite::counter`: `CounterStore` (fixed-window counters shared by every
  instance, e.g. in Redis) with `MemoryCounterStore`, and
  `LoginThrottle::with_store`; keys are hashed and a store outage locks the key
  (fail closed).
- `securite::report` (new feature `reports`): `parse_csp_reports`, a defensive
  parser of CSP violation reports in both the `report-uri` and the Reporting API
  formats (size and count limits, truncated and control-free fields, extension
  noise filter, `tracing` output), and `SecurityHeaders::reporting_endpoint`
  (`Reporting-Endpoints`).
- `securite::security_txt::SecurityTxt`: RFC 9116 `security.txt` builder that
  refuses missing contacts, bad expiries, `http://` links and field injection.
- Documentation: new pages "JWT", "Encryption", "Access control", "Sessions",
  "Password policy", "Shared counters", "CSP reports" and "security.txt", in
  English, French and Spanish.

- `securite::password` (feature `password`, on by default): `PasswordHasher`,
  Argon2id password hashing through the RustCrypto `argon2` crate with the OWASP
  parameters (`m = 19 MiB, t = 2, p = 1`), PHC strings with a 16-byte random salt,
  `check` that hands back an upgraded hash when the stored one is weaker
  (`PasswordCheck::ValidNeedsRehash`), `verify_dummy` against account enumeration
  through timing, an optional pepper, a 1024-byte password limit and a cap on the
  costs a stored hash may request.
- `securite::throttle::LoginThrottle`: Laravel-style brute-force protection called
  from handlers. Failures are counted per key (account + IP, account, IP), the key
  is locked once the limit is reached until its window ends, `attempt` does not
  even run the verification of a locked key, keys are kept as SHA-256 digests in a
  bounded map that fails closed when full.
- `securite::authz::Gate`: authorization with Laravel's abilities, policies and
  `before` hooks and Symfony's voters and decision strategies (affirmative,
  consensus, unanimous). Deny by default: undefined abilities, resources of another
  type and all-abstain decisions are refused; `Forbidden::into_rejection` gives a
  `403` problem response that does not leak the ability.
- `securite::signing`: `Signer`, HMAC-SHA256 tokens and URLs with optional expiry,
  purposes, key rotation (`fallback_key`) and constant-time checks, and the
  `SignedUrls` guard (Laravel's `signed` middleware): requests on the protected
  prefixes need a URL signed with `Signer::sign_url`, else `403`
  `invalid_signature` / `expired_signature`. New priority `priority::SIGNED_URL`.
- `securite::totp`: RFC 6238 one-time passwords for two-factor authentication
  (SHA-1/256/512, 6 to 8 digits, clock skew), `verify_once` against code replay,
  `otpauth://` provisioning URIs, base32 secrets and `recovery_codes`.
- `ShieldBuilder::trusted_proxies` / `try_trusted_proxies` and
  `ClientIpSource::resolve_trusted`: forwarding headers are only believed when the
  TCP peer is a trusted proxy, and `X-Forwarded-For` / `Forwarded` are walked from
  the right past every trusted proxy (Express' `trust proxy`, Laravel's
  `TrustProxies`).
- Documentation: new pages "Password hashing", "Login throttling",
  "Authorization", "Two-factor authentication" and "Signed URLs and tokens", and a
  "Trusted proxies" section in "Client IP", in English, French and Spanish.
- Automatic releases: once CI is green on `master`, a version of `securite` without
  a tag gets its tag (`v0.1.0` for 0.1.0), its GitHub release (notes taken from its
  section of this changelog) and its publication on crates.io. Releasing a version
  is now: bump it, write its section here, push. Without the `CARGO_REGISTRY_TOKEN`
  secret, or while `vitesse` is not on crates.io, the publication is postponed
  (run *Publish crate* by hand later).
- Website: a card for shared links. Every page, the root included, has a share
  image (1200×630) with its size and description, shown large by WhatsApp,
  iMessage, LinkedIn, X or Slack.
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
- `ResponseCache` stores: `MemoryStore` (default) and, with the new `redis` /
  `redis-tls` features, `RedisStore`, a cache shared by every instance of the app
  (lazy connection, 250 ms timeouts, a down Redis means a miss, `SCAN`-based purges
  that reach every instance). Custom backends implement `CacheStore`.
- `ResponseCache` keeps one entry per variant: per language chosen by `Locale`, and
  per value of the headers named by `Vary` (only `Vary: *` is refused). `max-age` /
  `s-maxage` shorten the TTL, hits answer `304` on a matching `If-None-Match`, and
  `CacheHandle` counts hits, misses and store errors; `invalidate` and `clear` are
  now `async` and also reach a shared store.
- Website: a new documentation category, "Pratique", with an overview and one page
  per middleware of the `pratique` crate, in English, French and Spanish.

### Fixed

Found by reviewing every middleware of `pratique` before its first release:

- `ResponseCache`: a request whose target `http::Uri` rejects (`/x?a=<b>`) was
  stored under `/`, so `GET /` could be answered with another page; with `Locale`
  added before it, one language could be served to visitors of another; requests
  authenticated with `X-Api-Key` were cached like public ones.
- `Redirects`: `.prefix("/old", "/")` sent `/old//evil.example` to
  `//evil.example`, another site; a prefix whose target is under its source looped.
- `TrailingSlash`, `Redirects` and `AccessLog` lost or replaced query strings that
  `http::Uri` rejects; `TrailingSlash` could turn `/\evil.example/` into a
  protocol-relative address and redirected `OPTIONS *`; `.except(prefix)` avoids
  a redirect loop with Vitesse's static directories.
- `ResponseCache`, after a second review of its own: the site (`Host`,
  `Forwarded`, `X-Forwarded-Host`, `X-Forwarded-Proto`) and the CORS `Origin` are
  part of the key, so one domain's page is never served to another; responses
  with a CSP nonce, an invalid `max-age` or a request `Cache-Control: no-store`
  are not cached; a purge is not undone by a request already in flight; huge TTLs
  are capped instead of panicking; header lists that don't fit the stored format
  are not truncated; `MemoryStore` evicts in `O(log n)` and has a byte budget
  (`max_bytes`, 64 MiB). `RedisStore`: one connection per worker thread (a
  blocked core no longer holds up the others), one timeout per operation
  connection included, and a cooldown after a failure, so a silent or
  unreachable Redis costs at most one timeout per second instead of seconds per
  request; `clear` no longer removes the keys of a prefix that starts the same
  way.
- `Locale` adds `Vary: Cookie` when the cookie chooses the language, honours `Q=`
  and never picks a language refused with `q=0` through a regional variant; `Vary`
  values are merged into one line.
- `CacheControl` no longer gives temporary redirects (`302`, `303`, `307`) the
  cache lifetime of a page; `ETag` reads every `If-None-Match` line; `Health`
  follows the `application/health+json` format (checks as lists, `uptime` check)
  and, like `Metrics`, answers `HEAD` and a final `/`; `Metrics` sums durations in
  nanoseconds; `AccessLog` logs no body bytes for `HEAD`, `204` and `304`.

### Changed

- Links to the websites of Active, Vitesse, Securite, Memoire and Paquets (READMEs,
  documentation, doc comments, the crates' `homepage`, `app.json` and the website's
  footer) now point to their Heroku deployments instead of GitHub Pages. The static
  copy on GitHub Pages is still exported as before.
- The website is no longer published on GitHub Pages (the `pages.yml` workflow is
  removed): it is served by Heroku only, and GitHub only hosts the code. The
  "Deploy to GitHub Pages" documentation page is removed in the three languages
  (and from the website's footer, which links the Docker page instead); the
  READMEs, `CONTRIBUTING.md`, the Docker and CI pages and the website's texts no
  longer mention a Pages deployment. `securite-server export` still writes the
  static copy, and the CI still checks it.
- The ecosystem is now five projects: FerroSwift and Solidify are no longer listed
  in the READMEs, the website's footer or the publication order.
- Heroku builds the website with the
  [emk/rust buildpack](https://elements.heroku.com/buildpacks/emk/heroku-buildpack-rust)
  on the `heroku-26` stack by default: `RustConfig` (the Rust version, and
  `RUST_SKIP_BUILD=1` so that `heroku-build.sh` does the build instead),
  `heroku-build.sh` (`cargo build --release --locked -p securite-server`, then the
  WebAssembly islands, into `site/pkg`) and a `Procfile`; the Deploy button (`app.json`) uses it too. The
  *Deploy to Heroku* workflow takes a new optional repository variable,
  `HEROKU_BUILD`: `buildpack` (default) moves the app off the container stack and
  sets its buildpack, `docker` keeps building the `Dockerfile` with `heroku.yml`
  on the container stack. The Heroku guide, the READMEs and the Docker page
  describe both ways, and the Heroku CLI setup.
- **Vitesse instead of axum.** The `Shield` and the `SignatureLayer` are
  [Vitesse](https://vitesse-f16135654c3d.herokuapp.com/) middlewares
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
  README and the website's footer, which now links the seven projects of the
  ecosystem.
- Credits: Solidify joins the projects linked by the README, the license and the
  website's footer.
- `securite::VERSION`, the version of the crate.
- Website rewritten with [Active](https://active-c1883a966650.herokuapp.com/) instead of
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
