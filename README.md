<div align="center">

[![Securite: armor your Rust APIs against XSS, SQL injection and bots](https://raw.githubusercontent.com/maxlestage/Securite/master/site/static/og-image.jpg)](https://maxlestage.github.io/Securite/)

# 🛡️ Securite

**Fast, easy, batteries-included security middlewares for Rust.**

[![crates.io](https://img.shields.io/crates/v/securite.svg)](https://crates.io/crates/securite)
[![docs.rs](https://img.shields.io/docsrs/securite)](https://docs.rs/securite)
![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success)

**English** · [Français](README.fr.md) · [Español](README.es.md)

</div>

---

This repository contains:

| Folder | What |
|---|---|
| [`crates/securite`](crates/securite) | The **`securite` crate** (ready for crates.io): 19 security middlewares for Vitesse, and for tower / hyper / tonic |
| [`crates/pratique`](crates/pratique) | The **`pratique` crate**: 13 everyday Vitesse middlewares that have nothing to do with security (ETag, Cache-Control, response cache, access logs, Prometheus metrics, response time, trailing slash, redirects, health checks, maintenance mode, headers, locale, API deprecation) |
| [`site`](site) | The **website**, written with [Active](https://maxlestage.github.io/Active/): pages rendered on the server with complete SEO, WebAssembly islands, animated, FR / EN / ES, documentation hub by category, live attack playground, installable PWA that works offline |
| [`server`](server) | The Vitesse server that renders and hosts the website and its playground API — protected by `securite` itself |
| [`docs`](docs) | The **documentation** (47 pages × 3 languages), compiled into the website |
| [`RustConfig`](RustConfig), [`Procfile`](Procfile), [`heroku-build.sh`](heroku-build.sh), [`app.json`](app.json) | **One-tap Heroku deployment** with the Rust buildpack (`emk/rust`) |
| [`Dockerfile`](Dockerfile), [`heroku.yml`](heroku.yml) | Container image (Docker, or Heroku's container stack) |
| [`.github/workflows`](.github/workflows) | CI, **auto-merge into master**, Heroku deploy, crates.io publishing |

## The crate in 10 seconds

```bash
cargo add securite --git https://github.com/maxlestage/Securite
```

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::recommended()); // headers, WAF, rate limit, CSRF, request ids…
app.get("/", |_req: Request| async { "Hello, secure world!" });
```

| Category | Middlewares |
|---|---|
| Browser hardening | `SecurityHeaders` (CSP nonces & hashes, HSTS, COOP/CORP/COEP…), `Cors`, `CookieHardening`, `HttpsRedirect` |
| Traffic control | `RateLimit` (GCRA), `ConcurrencyLimit`, `AutoBan`, `BodyLimit`, `Hygiene`, `MethodFilter` |
| Access control | `IpFilter`, `HostFilter`, `Auth`, `Csrf`, `ContentTypeGuard` |
| Threat detection | `Waf` (SQLi, XSS, RCE, Log4Shell, SSRF, NoSQLi, SSTI, scanners), `BotBlocker` |
| Integrity & tracing | `RequestId`, `SignatureLayer` (GitHub / Stripe / Slack / Shopify webhooks), events & stats |

≈ 6 µs for the whole recommended pipeline · `#![forbid(unsafe_code)]` · MSRV 1.85.
Read the [crate README](crates/securite/README.md) and the [documentation](docs/en/introduction.md).

## Deploy from your phone (no computer needed)

**Option A — one tap.** Open `https://heroku.com/deploy?template=https://github.com/maxlestage/Securite` on your phone, pick an app name, tap *Deploy app*. Heroku compiles the site with the
[emk/rust buildpack](https://elements.heroku.com/buildpacks/emk/heroku-buildpack-rust)
on the `heroku-24` stack, as `RustConfig` and `Procfile` say (≈ 10–15 min the
first time), and starts it.

**Option B — automatic deploys on every merge.**

1. Heroku (mobile browser) → *Account settings* → *API Key* → *Reveal* → copy.
2. GitHub (mobile browser) → this repository → *Settings* → *Secrets and
   variables* → *Actions* → add `HEROKU_API_KEY` and `HEROKU_APP_NAME`.
3. Done: every push merged into `master` is deployed by
   [`deploy.yml`](.github/workflows/deploy.yml) (the app is created if needed).
   You can also run it by hand: GitHub app → *Actions* → *Deploy to Heroku* →
   *Run workflow*. It uses the buildpack too; set the repository variable
   `HEROKU_BUILD` to `docker` to build the `Dockerfile` (`heroku.yml`) instead.

From a computer: `heroku create --stack heroku-24 --buildpack emk/rust`, then
`git push heroku master:main`.

Full guide: [docs/en/heroku-from-phone.md](docs/en/heroku-from-phone.md).

## GitHub Pages (free static hosting)

[`pages.yml`](.github/workflows/pages.yml) publishes the website on
**https://maxlestage.github.io/Securite/** after every merge into `master`,
as static files exported by the server (`securite-server export`), with a
strict CSP as a `<meta>` tag (inline scripts allowed by hash), a web app
manifest and an offline service worker.
One-time setup from a phone: repository → *Settings* → *Pages* → *Source*:
**GitHub Actions**, then *Actions* → *Deploy to GitHub Pages* → *Run workflow*.
The live attack playground needs the server (Heroku or Docker).
Guide: [docs/en/github-pages.md](docs/en/github-pages.md).

## Always merged into master

Every branch pushed to GitHub runs the CI (fmt, clippy, tests, docs, MSRV,
WebAssembly bundle, static export) and is **merged into `master` automatically when green**
([`auto-merge.yml`](.github/workflows/auto-merge.yml)), which then triggers
the Heroku deployment. Dependabot pull requests are merged the same way as
soon as their CI is green ([`dependabot-auto-merge.yml`](.github/workflows/dependabot-auto-merge.yml)).
Name a branch `wip/...` to opt out.

## Publish the crate on crates.io (from your phone)

1. crates.io → *Account settings* → *API Tokens* → new token (publish scope).
2. GitHub → *Settings* → *Secrets and variables* → *Actions* → add
   `CARGO_REGISTRY_TOKEN`.
3. Bump the version in `crates/securite/Cargo.toml`, write its section in
   `CHANGELOG.md` and push. Once the CI of `master` is green, *Publish crate*
   tags the version (`v0.1.0`), creates the GitHub release with that section
   as notes and publishes the crate. Without the secret, or while `vitesse` is
   not on crates.io, the publication waits: later, GitHub app → *Actions* →
   *Publish crate* → *Run workflow* (uncheck *dry run*).

## Local development

```bash
# crate, website and server
cargo test --workspace

# website: the browser bundle (needs: rustup target add wasm32-unknown-unknown;
# cargo install wasm-bindgen-cli --version 0.2.129), then the server
cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release
wasm-bindgen --target web --no-typescript --out-dir site/pkg target/wasm32-unknown-unknown/wasm-release/securite_site.wasm
cargo run -p securite-server   # http://localhost:8080

# the static copy for GitHub Pages
BASE_PATH=/Securite cargo run -p securite-server -- export dist
```

## License

Securite is proprietary software: © 2026 Maxime Nathan Lestage, all rights
reserved. It is not open source. The source code is published on crates.io
and GitHub so that it can be read, audited and built, and you may use it
freely as a dependency of your own programs, commercial ones included.
Modifying it or redistributing its source needs the author's written
permission. Full terms: [LICENSE](LICENSE).
Security issues: see [SECURITY.md](SECURITY.md).

Contributions (code, documentation, ideas) are welcome and become part of
the project under the same terms: by submitting one, you assign its rights
to the author, as the license states.

## Credits

Designed and developed by Maxime Nathan Lestage,
as part of one family of Rust projects: [Active](https://maxlestage.github.io/Active/), [Vitesse](https://maxlestage.github.io/Vitesse/), [Securite](https://maxlestage.github.io/Securite/), [Memoire](https://maxlestage.github.io/Memoire/), [Paquets](https://maxlestage.github.io/Paquets/), [FerroSwift](https://maxlestage.github.io/FerroSwift/) and [Solidify](https://maxlestage.github.io/Solidify/).
