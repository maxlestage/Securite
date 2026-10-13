---
title: Docker image
summary: How the multi-stage Dockerfile builds the website and its server, how to run the image locally or on any container platform, and how to develop without Docker.
category: deploy
order: 3
---

The `Dockerfile` at the repository root builds this website: pages rendered on the server with [Active](https://active-c1883a966650.herokuapp.com/) and WebAssembly islands, served by a Vitesse server that protects itself with `securite`. Heroku builds the site with the Rust buildpack by default, and builds this same image for you when the deploy workflow's `HEROKU_BUILD` repository variable is `docker` (see [Deploy to Heroku from your phone](/docs/heroku-from-phone)); the commands on this page need a computer or a cloud shell.

## The two stages

### build

Based on `rust:1-slim-bookworm` with the `wasm32-unknown-unknown` target.

* Installs wasm-bindgen `0.2.129` (build arg `WASM_BINDGEN_VERSION`) from its prebuilt GitHub release binary. If the download fails, it falls back to `cargo install --locked` of the same version, which is slower.
* Copies the workspace manifests and `crates/`, with placeholder sources for `server/` and `site/`, and runs `cargo fetch --locked`: the dependency layer stays cached until `Cargo.lock` changes.
* Copies `server/`, `site/` and `docs/` (the site's `build.rs` compiles these pages into the server), then builds the browser bundle (`cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release`, then `wasm-bindgen --target web --no-typescript --out-dir site/pkg …`) and the server (`cargo build --release --locked -p securite-server`). The release profile uses thin LTO, one codegen unit and stripped symbols; the `wasm-release` profile optimizes the bundle for size.

### runtime

Based on `debian:bookworm-slim`, it only contains `/app/securite-server`, the static files in `/app/site/static` (style sheet, icons) and the browser bundle in `/app/site/pkg`. It runs as the non-root system user `app` (uid `10001`, no home, `nologin` shell), sets `SITE_DIR=/app/site`, `RUST_LOG=info` and `PORT=8080`, and exposes port 8080.

`.dockerignore` keeps the build context small: `.git`, `.github`, `target`, `site/pkg`, `dist` and Markdown files are left out, except `docs/**/*.md` and `crates/securite/README.md`.

> **Warning:** the wasm-bindgen CLI must match the `wasm-bindgen` crate exactly. To upgrade, change `0.2.129` in `site/Cargo.toml` and in the `WASM_BINDGEN_VERSION` argument of the `Dockerfile`, then run `cargo update -p wasm-bindgen`: the workflows read the version from `Cargo.lock`.

## Build and run

```bash
docker build -t securite-site .
docker run -p 8080:8080 -e SECURITE_ENV=development securite-site
```

Then open `http://localhost:8080`. Development mode keeps plain HTTP usable: production mode sends HSTS and `upgrade-insecure-requests`, which break `http://localhost`.

> **Tip:** the downloaded wasm-bindgen binary is built for x86_64. If the `wasm-bindgen --version` step fails on an ARM machine, add `--platform linux/amd64` to `docker build`.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | Listening port on `0.0.0.0`. Heroku, Render and Railway set it. |
| `SITE_DIR` | `/app/site` in the image, the `site/` folder otherwise | Holds `static/` and `pkg/`. Without `pkg/`, the server logs a warning: the pages work, without their animations and islands. |
| `BASE_PATH` | empty | Path the site lives under behind a proxy, for example `/securite`: every link starts with it. |
| `SITE_URL` | taken from each request | Public address, for canonical URLs, `sitemap.xml` and Open Graph. |
| `SECURITE_ENV` | `production` when `DYNO` is set, else `development` | `production` enables the HTTPS redirect (except `/api/health`), HSTS, `upgrade-insecure-requests` and `ClientIpSource::heroku()`. Any other value means development, with `ClientIpSource::Peer`. |
| `RUST_LOG` | `info` | `tracing` filter; security events use the `securite` target. |

## What the server runs

Every page is rendered on the server with Active, in English, French and Spanish: `/` redirects to `/en/`, `/fr/` or `/es/` according to `Accept-Language`, then come `/{lang}/`, `/{lang}/docs/`, `/{lang}/docs/{slug}/` and `/{lang}/playground/`; the addresses of the previous version (`/docs/waf`, `/playground`) are redirected. `/manifest.webmanifest` and `/sw.js` make the site an installable app that works offline, `/sitemap.xml` and `/robots.txt` help search engines, `/static/` and `/pkg/` serve the files (cached for a year when versioned). `/api/health` answers `ok`, `/api/stats` returns the shield counters as JSON, and `/api/demo` echoes the playground payload when the WAF lets it through.

| Guard | Setting |
|---|---|
| `MethodFilter` | `GET`, `HEAD` and `OPTIONS` only |
| `BodyLimit` | 16 KiB |
| `RateLimit` | 30 requests per second per IP, burst 150; `/api/demo` 60 per minute, burst 20 |
| `ConcurrencyLimit` | 64 requests in flight per IP |
| `AutoBan` | 30 strikes, `/api/demo` ignored |
| `SecurityHeaders` | Strict CSP: the inline scripts (WebAssembly loader, service worker registration) and the inline style of Active allowed by hash, `'wasm-unsafe-eval'`, `worker-src` and `manifest-src` limited to `'self'`; COEP `require-corp`, HSTS in production |
| `HttpsRedirect` | Production only, `/api/health` exempt |
| `RequestId`, `Hygiene`, `BotBlocker`, `Waf`, `Csrf`, `CookieHardening` | Defaults |

## Running it anywhere

The image listens on `$PORT` and logs to stdout, so any container platform works. Behind HTTPS, set `SECURITE_ENV=production` and make sure the client IP source matches the proxy, see [Client IP](/docs/client-ip). The website uses `ClientIpSource::heroku()` in production; for another proxy, change the `.client_ip(...)` call in `server/src/app.rs`.

| Platform | Deployment | Client IP source |
|---|---|---|
| Fly.io | `fly launch` detects the `Dockerfile`; keep `internal_port = 8080` | `ClientIpSource::fly()` |
| Render | Web Service with the Docker runtime; Render sets `PORT` | `ClientIpSource::heroku()` |
| Railway | Deploy from the GitHub repository; Railway sets `PORT` | `ClientIpSource::x_real_ip()` |
| Kubernetes | Deployment, Service and Ingress | `XForwardedFor { trusted_hops }`, one hop per extra proxy |

On Kubernetes, the image already fits a restricted security context:

```yaml
containers:
  - name: securite-site
    image: registry.example.com/securite-site:latest
    ports:
      - containerPort: 8080
    env:
      - name: SECURITE_ENV
        value: production
    readinessProbe:
      httpGet:
        path: /api/health
        port: 8080
    securityContext:
      runAsNonRoot: true
      runAsUser: 10001
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
```

> **Tip:** before going live, send an attack from the playground through the real proxy and read the `ip=` field of the `request blocked` log line: it must show your own address, not the proxy's.

## Local development without Docker

Install the tools once:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --locked --version 0.2.129
```

Build the browser bundle, then run the server as in production, with every header of the shield:

```bash
# From the repository root
cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release
wasm-bindgen --target web --no-typescript --out-dir site/pkg target/wasm32-unknown-unknown/wasm-release/securite_site.wasm
cargo run -p securite-server   # http://localhost:8080
```

The pages, the texts and the documentation are compiled into the server: after a change, run `cargo run -p securite-server` again. Rebuild the bundle only when the islands or the page motion change (`site/src/islands.rs`, `site/src/client/`).

The static copy published on GitHub Pages comes from the same code (see [Deploy to GitHub Pages](/docs/github-pages)):

```bash
BASE_PATH=/Securite SITE_URL=https://maxlestage.github.io/Securite cargo run -p securite-server -- export dist
```

## Related pages

* [Deploy to Heroku from your phone](/docs/heroku-from-phone)
* [Client IP](/docs/client-ip)
* [Security headers](/docs/security-headers)
* [CI and auto-merge](/docs/ci-auto-merge)
