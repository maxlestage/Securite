<div align="center">

# 🛡️ securite

**Fast, easy, batteries-included security middlewares for Rust.**

[![CI](https://github.com/maxlestage/Securite/actions/workflows/ci.yml/badge.svg)](https://github.com/maxlestage/Securite/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/securite.svg)](https://crates.io/crates/securite)
[![docs.rs](https://img.shields.io/docsrs/securite)](https://docs.rs/securite)
![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success)

**English** · [Français](README.fr.md) · [Español](README.es.md)

[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://www.heroku.com/deploy?template=https://github.com/maxlestage/Securite)

</div>

---

This repository contains:

| Folder | What |
|---|---|
| [`crates/securite`](crates/securite) | The **`securite` crate** (ready for crates.io): 19 security middlewares for tower / axum / hyper / tonic |
| [`site`](site) | The **website**: Yew + WebAssembly, animated, FR / EN / ES, documentation hub by category, live attack playground |
| [`server`](server) | The axum server hosting the website — protected by `securite` itself |
| [`docs`](docs) | The **documentation** (32 pages × 3 languages), compiled into the website |
| [`Dockerfile`](Dockerfile), [`heroku.yml`](heroku.yml), [`app.json`](app.json) | Container image and **one-tap Heroku deployment** |
| [`.github/workflows`](.github/workflows) | CI, **auto-merge into master**, Heroku deploy, crates.io publishing |

## The crate in 10 seconds

```bash
cargo add securite
```

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app = Router::new()
    .route("/", get(|| async { "Hello, secure world!" }))
    .layer(Shield::recommended()); // headers, WAF, rate limit, CSRF, request ids…
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

**Option A — one tap.** Press the *Deploy to Heroku* button above, pick an app
name, tap *Deploy app*. Heroku builds the Docker image from `heroku.yml`
(≈ 10–15 min the first time) and starts the site.

**Option B — automatic deploys on every merge.**

1. Heroku (mobile browser) → *Account settings* → *API Key* → *Reveal* → copy.
2. GitHub (mobile browser) → this repository → *Settings* → *Secrets and
   variables* → *Actions* → add `HEROKU_API_KEY` and `HEROKU_APP_NAME`.
3. Done: every push merged into `master` is deployed by
   [`deploy.yml`](.github/workflows/deploy.yml) (the app is created if needed).
   You can also run it by hand: GitHub app → *Actions* → *Deploy to Heroku* →
   *Run workflow*.

Full guide: [docs/en/heroku-from-phone.md](docs/en/heroku-from-phone.md).

## Always merged into master

Every branch pushed to GitHub runs the CI (fmt, clippy, tests, docs, MSRV,
WebAssembly build) and is **merged into `master` automatically when green**
([`auto-merge.yml`](.github/workflows/auto-merge.yml)), which then triggers
the Heroku deployment. Name a branch `wip/...` to opt out.

## Publish the crate on crates.io (from your phone)

1. crates.io → *Account settings* → *API Tokens* → new token (publish scope).
2. GitHub → *Settings* → *Secrets and variables* → *Actions* → add
   `CARGO_REGISTRY_TOKEN`.
3. GitHub app → *Actions* → *Publish crate* → *Run workflow* (uncheck
   *dry run*), or push a tag `v0.1.0`.

## Local development

```bash
# crate
cargo test --workspace

# website (needs: rustup target add wasm32-unknown-unknown; cargo install trunk wasm-bindgen-cli)
cd site && trunk build --release && cd ..
DIST_DIR=site/dist cargo run -p securite-server   # http://localhost:8080

# or with hot reload: run the server, then `trunk serve` in site/ (http://localhost:8081)
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
Security issues: see [SECURITY.md](SECURITY.md).
