---
title: Docker image
summary: How the multi-stage Dockerfile builds the website and its server, how to run the image locally or on any container platform, and how to develop without Docker.
category: deploy
order: 2
---

The `Dockerfile` at the repository root builds this website: a Yew + WebAssembly front-end served by an axum server that protects itself with `securite`. Heroku builds the same image for you (see [Deploy to Heroku from your phone](/docs/heroku-from-phone)); the commands on this page need a computer or a cloud shell.

## The three stages

### site

Based on `rust:1-slim-bookworm` with the `wasm32-unknown-unknown` target.

* Installs Trunk `0.21.14` and wasm-bindgen `0.2.129` (build args `TRUNK_VERSION` and `WASM_BINDGEN_VERSION`) from their prebuilt GitHub release binaries. If a download fails, it falls back to `cargo install --locked` of the same version, which is slower.
* Copies `site/Cargo.toml` and `site/Cargo.lock` alone and runs `cargo fetch --locked` against a placeholder `main.rs`, so the dependency layer stays cached until the lockfile changes.
* Copies `docs/` (the site's `build.rs` compiles these pages) and `site/`, then runs `trunk build --release --offline`: everything was fetched earlier, so no network is needed.

### server

Based on `rust:1-slim-bookworm`, it copies the workspace (`Cargo.toml`, `Cargo.lock`, `crates/`, `server/`) and runs `cargo build --release --locked -p securite-server`. The release profile uses thin LTO, one codegen unit and stripped symbols.

### runtime

Based on `debian:bookworm-slim`, it only contains `/app/securite-server` and the static files in `/app/dist`. It runs as the non-root system user `app` (uid `10001`, no home, `nologin` shell), sets `DIST_DIR=/app/dist`, `RUST_LOG=info` and `PORT=8080`, and exposes port 8080.

`.dockerignore` keeps the build context small: `.git`, `.github`, `target`, `site/target`, `site/dist` and Markdown files are left out, except `docs/**/*.md` and `crates/securite/README.md`.

> **Warning:** the wasm-bindgen CLI must match the `wasm-bindgen` crate exactly. To upgrade, change `0.2.129` in four places at once: `site/Cargo.toml`, `[tools]` in `site/Trunk.toml`, the `WASM_BINDGEN_VERSION` argument and the `site` job of `ci.yml`.

## Build and run

```bash
docker build -t securite-site .
docker run -p 8080:8080 -e SECURITE_ENV=development securite-site
```

Then open `http://localhost:8080`. Development mode keeps plain HTTP usable: production mode sends HSTS and `upgrade-insecure-requests`, which break `http://localhost`.

> **Tip:** the downloaded Trunk and wasm-bindgen binaries are built for x86_64. If the `trunk --version` step fails on an ARM machine, add `--platform linux/amd64` to `docker build`.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | Listening port on `0.0.0.0`. Heroku, Render and Railway set it. |
| `DIST_DIR` | `/app/dist` in the image, `dist` otherwise | Output of `trunk build`. Without `index.html`, the server logs a warning and serves a placeholder page. |
| `SECURITE_ENV` | `production` when `DYNO` is set, else `development` | `production` enables the HTTPS redirect (except `/api/health`), HSTS, `upgrade-insecure-requests` and `ClientIpSource::heroku()`. Any other value means development, with `ClientIpSource::Peer`. |
| `RUST_LOG` | `info` | `tracing` filter; security events use the `securite` target. |

## What the server runs

`/api/health` answers `ok`, `/api/stats` returns the shield counters as JSON, and `/api/demo` echoes the playground payload when the WAF lets it through. Every other path serves a static file or falls back to `index.html`.

| Guard | Setting |
|---|---|
| `MethodFilter` | `GET`, `HEAD` and `OPTIONS` only |
| `BodyLimit` | 16 KiB |
| `RateLimit` | 30 requests per second per IP, burst 150; `/api/demo` 60 per minute, burst 20 |
| `ConcurrencyLimit` | 64 requests in flight per IP |
| `AutoBan` | 30 strikes, `/api/demo` ignored |
| `SecurityHeaders` | Strict CSP allowing Trunk's inline script by hash plus `'wasm-unsafe-eval'`, COEP `require-corp`, HSTS in production |
| `HttpsRedirect` | Production only, `/api/health` exempt |
| `RequestId`, `Hygiene`, `BotBlocker`, `Waf`, `Csrf`, `CookieHardening` | Defaults |

## Running it anywhere

The image listens on `$PORT` and logs to stdout, so any container platform works. Behind HTTPS, set `SECURITE_ENV=production` and make sure the client IP source matches the proxy, see [Client IP](/docs/client-ip). The website uses `ClientIpSource::heroku()` in production; for another proxy, change the `.client_ip(...)` call in `server/src/main.rs`.

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
cargo install trunk --locked --version 0.21.14
cargo install wasm-bindgen-cli --locked --version 0.2.129
```

To run the site as in production, with every header of the shield:

```bash
# From the repository root
(cd site && trunk build --release)
DIST_DIR=site/dist cargo run -p securite-server
```

For live reload, keep the server running for the API and start Trunk in `site/`:

```bash
# Terminal 1, repository root: API on http://localhost:8080
DIST_DIR=site/dist cargo run -p securite-server

# Terminal 2: site with live reload on http://127.0.0.1:8081
cd site
trunk serve
```

`site/Trunk.toml` proxies `/api/` to `http://127.0.0.1:8080/api/`, so the playground and the counters keep working. Pages served by `trunk serve` do not carry the shield headers: check those on port 8080.

## Related pages

* [Deploy to Heroku from your phone](/docs/heroku-from-phone)
* [Client IP](/docs/client-ip)
* [Security headers](/docs/security-headers)
* [CI and auto-merge](/docs/ci-auto-merge)
