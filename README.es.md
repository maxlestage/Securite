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
| [`site`](site) | El **sitio web**, escrito con [active](https://github.com/maxlestage/Active): páginas renderizadas en el servidor con SEO completo, islas WebAssembly, animado, FR / EN / ES, documentación por categorías, playground de ataques en directo, PWA instalable que funciona sin conexión |
| [`server`](server) | El servidor axum que renderiza y aloja el sitio y la API del playground — protegido por el propio `securite` |
| [`docs`](docs) | La **documentación** (33 páginas × 3 idiomas), compilada en el sitio |
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

## GitHub Pages (alojamiento estático gratuito)

[`pages.yml`](.github/workflows/pages.yml) publica el sitio en
**https://maxlestage.github.io/Securite/** tras cada fusión en `master`,
como archivos estáticos exportados por el servidor (`securite-server export`),
con una CSP estricta como etiqueta `<meta>` (scripts inline permitidos por
hash), un manifiesto de aplicación web y un service worker sin conexión.
Configuración única desde el móvil: repositorio → *Settings* → *Pages* →
*Source*: **GitHub Actions**, y luego *Actions* → *Deploy to GitHub Pages* →
*Run workflow*. El playground de ataques en directo necesita el
servidor (Heroku o Docker). Guía: [docs/es/github-pages.md](docs/es/github-pages.md).

## Siempre fusionado en master

Cada rama enviada a GitHub ejecuta la CI (fmt, clippy, tests, docs, MSRV,
bundle WebAssembly, exportación estática) y se **fusiona automáticamente en `master` si todo está en
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
# crate, sitio y servidor
cargo test --workspace

# sitio: el bundle del navegador (requisitos: rustup target add wasm32-unknown-unknown;
# cargo install wasm-bindgen-cli --version 0.2.129) y luego el servidor
cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release
wasm-bindgen --target web --no-typescript --out-dir site/pkg target/wasm32-unknown-unknown/wasm-release/securite_site.wasm
cargo run -p securite-server   # http://localhost:8080

# la copia estática para GitHub Pages
BASE_PATH=/Securite cargo run -p securite-server -- export dist
```

## Licencia

Doble licencia [MIT](LICENSE-MIT) o [Apache-2.0](LICENSE-APACHE).
Para reportar una vulnerabilidad: ver [SECURITY.md](SECURITY.md).
