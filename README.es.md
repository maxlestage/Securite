<div align="center">

# 🛡️ securite

**Middlewares de seguridad nativos para Rust: rápidos, fáciles y completos.**

[![CI](https://github.com/maxlestage/Securite/actions/workflows/ci.yml/badge.svg)](https://github.com/maxlestage/Securite/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/securite.svg)](https://crates.io/crates/securite)
[![docs.rs](https://img.shields.io/docsrs/securite)](https://docs.rs/securite)
![unsafe prohibido](https://img.shields.io/badge/unsafe-prohibido-success)

[English](README.md) · [Français](README.fr.md) · **Español**

[![Desplegar en Heroku](https://www.herokucdn.com/deploy/button.svg)](https://www.heroku.com/deploy?template=https://github.com/maxlestage/Securite)

</div>

---

Este repositorio contiene:

| Carpeta | Contenido |
|---|---|
| [`crates/securite`](crates/securite) | La **crate `securite`** (lista para crates.io): 19 middlewares de seguridad para tower / axum / hyper / tonic |
| [`site`](site) | El **sitio web**: Yew + WebAssembly, animado, FR / EN / ES, documentación por categorías, playground de ataques en directo |
| [`server`](server) | El servidor axum que aloja el sitio — protegido por el propio `securite` |
| [`docs`](docs) | La **documentación** (32 páginas × 3 idiomas), compilada en el sitio |
| [`Dockerfile`](Dockerfile), [`heroku.yml`](heroku.yml), [`app.json`](app.json) | Imagen de contenedor y **despliegue en Heroku con un toque** |
| [`.github/workflows`](.github/workflows) | CI, **merge automático en master**, despliegue en Heroku, publicación en crates.io |

## La crate en 10 segundos

```bash
cargo add securite
```

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app = Router::new()
    .route("/", get(|| async { "¡Hola, mundo seguro!" }))
    .layer(Shield::recommended()); // cabeceras, WAF, rate limit, CSRF, request ids…
```

| Categoría | Middlewares |
|---|---|
| Protección del navegador | `SecurityHeaders` (CSP con nonces y hashes, HSTS, COOP/CORP/COEP…), `Cors`, `CookieHardening`, `HttpsRedirect` |
| Control de tráfico | `RateLimit` (GCRA), `ConcurrencyLimit`, `AutoBan`, `BodyLimit`, `Hygiene`, `MethodFilter` |
| Control de acceso | `IpFilter`, `HostFilter`, `Auth`, `Csrf`, `ContentTypeGuard` |
| Detección de amenazas | `Waf` (SQLi, XSS, RCE, Log4Shell, SSRF, NoSQLi, SSTI, escáneres), `BotBlocker` |
| Integridad y trazabilidad | `RequestId`, `SignatureLayer` (webhooks de GitHub / Stripe / Slack / Shopify), eventos y estadísticas |

≈ 6 µs para todo el pipeline recomendado · `#![forbid(unsafe_code)]` · MSRV 1.85.
Lee el [README de la crate](crates/securite/README.md) y la [documentación](docs/es/introduction.md).

## Despliega desde tu móvil (sin ordenador)

**Opción A — con un toque.** Pulsa el botón *Deploy to Heroku* de arriba,
elige un nombre de aplicación y pulsa *Deploy app*. Heroku construye la imagen
Docker a partir de `heroku.yml` (≈ 10–15 min la primera vez) y arranca el
sitio.

**Opción B — despliegue automático en cada merge.**

1. Heroku (navegador móvil) → *Account settings* → *API Key* → *Reveal* → copiar.
2. GitHub (navegador móvil) → este repositorio → *Settings* → *Secrets and
   variables* → *Actions* → añadir `HEROKU_API_KEY` y `HEROKU_APP_NAME`.
3. Listo: cada push fusionado en `master` se despliega con
   [`deploy.yml`](.github/workflows/deploy.yml) (la aplicación se crea si
   hace falta). Lanzamiento manual: app de GitHub → *Actions* → *Deploy to
   Heroku* → *Run workflow*.

Guía completa: [docs/es/heroku-from-phone.md](docs/es/heroku-from-phone.md).

## Siempre fusionado en master

Cada rama enviada a GitHub ejecuta la CI (fmt, clippy, tests, docs, MSRV,
build WebAssembly) y se **fusiona automáticamente en `master` si todo está en
verde** ([`auto-merge.yml`](.github/workflows/auto-merge.yml)), lo que
dispara el despliegue en Heroku. Las pull requests de Dependabot se fusionan
igual en cuanto su CI está en verde
([`dependabot-auto-merge.yml`](.github/workflows/dependabot-auto-merge.yml)).
Llama a una rama `wip/...` para excluirla.

## Publicar la crate en crates.io (desde el móvil)

1. crates.io → *Account settings* → *API Tokens* → nuevo token (permiso de publicación).
2. GitHub → *Settings* → *Secrets and variables* → *Actions* → añadir
   `CARGO_REGISTRY_TOKEN`.
3. App de GitHub → *Actions* → *Publish crate* → *Run workflow* (desmarca
   *dry run*), o envía un tag `v0.1.0`.

## Desarrollo local

```bash
# crate
cargo test --workspace

# sitio (requisitos: rustup target add wasm32-unknown-unknown; cargo install trunk wasm-bindgen-cli)
cd site && trunk build --release && cd ..
DIST_DIR=site/dist cargo run -p securite-server   # http://localhost:8080

# o con recarga en caliente: arranca el servidor y luego `trunk serve` en site/ (http://localhost:8081)
```

## Licencia

Doble licencia [MIT](LICENSE-MIT) o [Apache-2.0](LICENSE-APACHE).
Para reportar una vulnerabilidad: ver [SECURITY.md](SECURITY.md).
