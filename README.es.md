<div align="center">

[![Securite: protege tus API Rust contra el XSS, la inyección SQL y los bots](https://raw.githubusercontent.com/maxlestage/Securite/master/site/static/og-image.jpg)](https://maxlestage.github.io/Securite/)

# 🛡️ Securite

**Middlewares de seguridad nativos para Rust: rápidos, fáciles y completos.**

[![crates.io](https://img.shields.io/crates/v/securite.svg)](https://crates.io/crates/securite)
[![docs.rs](https://img.shields.io/docsrs/securite)](https://docs.rs/securite)
![unsafe prohibido](https://img.shields.io/badge/unsafe-prohibido-success)

[English](README.md) · [Français](README.fr.md) · **Español**

</div>

---

Este repositorio contiene:

| Carpeta | Contenido |
|---|---|
| [`crates/securite`](crates/securite) | La **crate `securite`** (lista para crates.io): 19 middlewares de seguridad para Vitesse, y para tower / hyper / tonic |
| [`crates/pratique`](crates/pratique) | La **crate `pratique`**: 13 middlewares cotidianos para Vitesse que no tienen nada que ver con la seguridad (ETag, Cache-Control, caché de respuestas, access logs, métricas Prometheus, tiempo de respuesta, barra final, redirecciones, health checks, modo mantenimiento, cabeceras, idioma, deprecación de API) |
| [`site`](site) | El **sitio web**, escrito con [Active](https://maxlestage.github.io/Active/): páginas renderizadas en el servidor con SEO completo, islas WebAssembly, animado, FR / EN / ES, documentación por categorías, playground de ataques en directo, PWA instalable que funciona sin conexión |
| [`server`](server) | El servidor Vitesse que renderiza y aloja el sitio y la API del playground — protegido por el propio `securite` |
| [`docs`](docs) | La **documentación** (47 páginas × 3 idiomas), compilada en el sitio |
| [`RustConfig`](RustConfig), [`Procfile`](Procfile), [`heroku-build.sh`](heroku-build.sh), [`app.json`](app.json) | **Despliegue en Heroku con un toque** con el buildpack de Rust (`emk/rust`) |
| [`Dockerfile`](Dockerfile), [`heroku.yml`](heroku.yml) | Imagen de contenedor (Docker, o el stack container de Heroku) |
| [`.github/workflows`](.github/workflows) | CI, **merge automático en master**, despliegue en Heroku, publicación en crates.io |

## La crate en 10 segundos

```bash
cargo add securite --git https://github.com/maxlestage/Securite
```

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::recommended()); // cabeceras, WAF, rate limit, CSRF, request ids…
app.get("/", |_req: Request| async { "Hello, secure world!" });
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

**Opción A — con un toque.** Abre `https://heroku.com/deploy?template=https://github.com/maxlestage/Securite` en tu móvil, elige un nombre de aplicación y pulsa *Deploy app*. Heroku compila el sitio con el
[buildpack emk/rust](https://elements.heroku.com/buildpacks/emk/heroku-buildpack-rust)
sobre el stack `heroku-24`, según indican `RustConfig` y `Procfile`
(≈ 10–15 min la primera vez), y lo arranca.

**Opción B — despliegue automático en cada merge.**

1. Heroku (navegador móvil) → *Account settings* → *API Key* → *Reveal* → copiar.
2. GitHub (navegador móvil) → este repositorio → *Settings* → *Secrets and
   variables* → *Actions* → añadir `HEROKU_API_KEY` y `HEROKU_APP_NAME`.
3. Listo: cada push fusionado en `master` se despliega con
   [`deploy.yml`](.github/workflows/deploy.yml) (la aplicación se crea si
   hace falta). Lanzamiento manual: app de GitHub → *Actions* → *Deploy to
   Heroku* → *Run workflow*. También usa el buildpack; da el valor `docker` a la
   variable de repositorio `HEROKU_BUILD` para construir en su lugar el
   `Dockerfile` (`heroku.yml`).

Desde un ordenador: `heroku create --stack heroku-24 --buildpack emk/rust` y
luego `git push heroku master:main`.

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
3. Cambia la versión en `crates/securite/Cargo.toml`, escribe su sección en
   `CHANGELOG.md` y envía los cambios. Cuando la CI de `master` está en verde,
   *Publish crate* pone el tag de la versión (`v0.1.0`), crea la release de
   GitHub con esa sección como notas y publica la crate. Sin el secreto, o
   mientras `vitesse` no esté en crates.io, la publicación espera: más tarde,
   app de GitHub → *Actions* → *Publish crate* → *Run workflow* (desmarca
   *dry run*).

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

Securite es software propietario: © 2026 Maxime Nathan Lestage, todos los
derechos reservados. No es software de código abierto. El código fuente se
publica en crates.io y GitHub para que pueda leerse, auditarse y compilarse,
y puedes usarlo libremente como dependencia de tus propios programas, también
comerciales. Modificarlo o redistribuir su código fuente requiere el permiso
escrito del autor. Condiciones completas: [LICENSE](LICENSE).
Para reportar una vulnerabilidad: ver [SECURITY.md](SECURITY.md).

Las contribuciones (código, documentación, ideas) son bienvenidas y pasan a
formar parte del proyecto en los mismos términos: al enviar una, cedes sus
derechos al autor, como indica la licencia.

## Créditos

Diseñado y desarrollado por Maxime Nathan Lestage,
dentro de una misma familia de proyectos Rust: [Active](https://maxlestage.github.io/Active/), [Vitesse](https://maxlestage.github.io/Vitesse/), [Securite](https://maxlestage.github.io/Securite/), [Memoire](https://maxlestage.github.io/Memoire/), [Paquets](https://maxlestage.github.io/Paquets/), [FerroSwift](https://maxlestage.github.io/FerroSwift/) y [Solidify](https://maxlestage.github.io/Solidify/).
