---
title: Imagen Docker
summary: Cómo el Dockerfile multietapa construye el sitio y su servidor, cómo ejecutar la imagen en local o en cualquier plataforma de contenedores, y cómo desarrollar sin Docker.
category: deploy
order: 3
---

El `Dockerfile` de la raíz del repositorio construye este sitio: páginas renderizadas en el servidor con [Active](https://maxlestage.github.io/Active/) e islas WebAssembly, servidas por un servidor Vitesse que se protege a sí mismo con `securite`. Heroku construye el sitio con el buildpack de Rust por defecto, y construye esta misma imagen por usted cuando la variable de repositorio `HEROKU_BUILD` del workflow de despliegue vale `docker` (vea [Desplegar en Heroku desde el móvil](/docs/heroku-from-phone)); los comandos de esta página necesitan un ordenador o una terminal en la nube.

## Las dos etapas

### build

Basada en `rust:1-slim-bookworm` con el target `wasm32-unknown-unknown`.

* Instala wasm-bindgen `0.2.129` (argumento de build `WASM_BINDGEN_VERSION`) a partir del binario precompilado publicado en GitHub. Si la descarga falla, recurre a `cargo install --locked` de la misma versión, que es más lento.
* Copia los manifiestos del workspace y `crates/`, con fuentes provisionales para `server/` y `site/`, y ejecuta `cargo fetch --locked`: la capa de dependencias queda en caché mientras `Cargo.lock` no cambie.
* Copia `server/`, `site/` y `docs/` (el `build.rs` del sitio compila estas páginas dentro del servidor), y luego construye el bundle del navegador (`cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release` y después `wasm-bindgen --target web --no-typescript --out-dir site/pkg …`) y el servidor (`cargo build --release --locked -p securite-server`). El perfil release usa LTO «thin», una sola unidad de generación de código y símbolos eliminados; el perfil `wasm-release` optimiza el bundle para el tamaño.

### runtime

Basada en `debian:bookworm-slim`, solo contiene `/app/securite-server`, los archivos estáticos de `/app/site/static` (hoja de estilos, iconos) y el bundle del navegador en `/app/site/pkg`. Se ejecuta con el usuario de sistema no root `app` (uid `10001`, sin directorio personal, shell `nologin`), define `SITE_DIR=/app/site`, `RUST_LOG=info` y `PORT=8080`, y expone el puerto 8080.

`.dockerignore` reduce el contexto de build: se excluyen `.git`, `.github`, `target`, `site/pkg`, `dist` y los archivos Markdown, salvo `docs/**/*.md` y `crates/securite/README.md`.

> **Atención:** la CLI de wasm-bindgen debe coincidir exactamente con el crate `wasm-bindgen`. Para actualizarla, cambie `0.2.129` en `site/Cargo.toml` y en el argumento `WASM_BINDGEN_VERSION` del `Dockerfile`, y luego ejecute `cargo update -p wasm-bindgen`: los workflows leen la versión en `Cargo.lock`.

## Construir y ejecutar

```bash
docker build -t securite-site .
docker run -p 8080:8080 -e SECURITE_ENV=development securite-site
```

Después abra `http://localhost:8080`. El modo desarrollo permite seguir en HTTP simple: el modo producción envía HSTS y `upgrade-insecure-requests`, que rompen `http://localhost`.

> **Consejo:** el binario de wasm-bindgen descargado está compilado para x86_64. Si el paso `wasm-bindgen --version` falla en una máquina ARM, añada `--platform linux/amd64` a `docker build`.

## Variables de entorno

| Variable | Valor por defecto | Función |
|---|---|---|
| `PORT` | `8080` | Puerto de escucha en `0.0.0.0`. Heroku, Render y Railway lo definen. |
| `SITE_DIR` | `/app/site` en la imagen, la carpeta `site/` en otro caso | Contiene `static/` y `pkg/`. Sin `pkg/`, el servidor registra un aviso: las páginas funcionan, sin sus animaciones ni sus islas. |
| `BASE_PATH` | vacío | Ruta bajo la que vive el sitio detrás de un proxy, por ejemplo `/securite`: todos los enlaces empiezan por ella. |
| `SITE_URL` | deducida de cada petición | Dirección pública, para las URL canónicas, `sitemap.xml` y Open Graph. |
| `SECURITE_ENV` | `production` si `DYNO` está definida, si no `development` | `production` activa la redirección a HTTPS (salvo `/api/health`), HSTS, `upgrade-insecure-requests` y `ClientIpSource::heroku()`. Cualquier otro valor significa desarrollo, con `ClientIpSource::Peer`. |
| `RUST_LOG` | `info` | Filtro de `tracing`; los eventos de seguridad usan el target `securite`. |

## Qué ejecuta el servidor

Cada página se renderiza en el servidor con Active, en español, inglés y francés: `/` redirige a `/es/`, `/en/` o `/fr/` según `Accept-Language`, y luego vienen `/{lang}/`, `/{lang}/docs/`, `/{lang}/docs/{slug}/` y `/{lang}/playground/`; las direcciones de la versión anterior (`/docs/waf`, `/playground`) se redirigen. `/manifest.webmanifest` y `/sw.js` hacen del sitio una aplicación instalable que funciona sin conexión, `/sitemap.xml` y `/robots.txt` ayudan a los buscadores, `/static/` y `/pkg/` sirven los archivos (en caché durante un año cuando llevan versión). `/api/health` responde `ok`, `/api/stats` devuelve los contadores del escudo en JSON y `/api/demo` devuelve la carga del playground cuando el WAF la deja pasar.

| Guarda | Configuración |
|---|---|
| `MethodFilter` | Solo `GET`, `HEAD` y `OPTIONS` |
| `BodyLimit` | 16 KiB |
| `RateLimit` | 30 peticiones por segundo y por IP, ráfaga de 150; `/api/demo` 60 por minuto, ráfaga de 20 |
| `ConcurrencyLimit` | 64 peticiones simultáneas por IP |
| `AutoBan` | 30 penalizaciones, `/api/demo` ignorada |
| `SecurityHeaders` | CSP estricta: los scripts inline (cargador WebAssembly, registro del service worker) y el estilo inline de Active permitidos por hash, `'wasm-unsafe-eval'`, `worker-src` y `manifest-src` limitados a `'self'`; COEP `require-corp`, HSTS en producción |
| `HttpsRedirect` | Solo en producción, `/api/health` exenta |
| `RequestId`, `Hygiene`, `BotBlocker`, `Waf`, `Csrf`, `CookieHardening` | Valores por defecto |

## Ejecutarla en cualquier sitio

La imagen escucha en `$PORT` y registra en la salida estándar, así que sirve cualquier plataforma de contenedores. Detrás de HTTPS, defina `SECURITE_ENV=production` y asegúrese de que la fuente de IP del cliente corresponde al proxy, vea [IP del cliente](/docs/client-ip). El sitio usa `ClientIpSource::heroku()` en producción; para otro proxy, cambie la llamada `.client_ip(...)` en `server/src/app.rs`.

| Plataforma | Despliegue | Fuente de IP del cliente |
|---|---|---|
| Fly.io | `fly launch` detecta el `Dockerfile`; mantenga `internal_port = 8080` | `ClientIpSource::fly()` |
| Render | Web Service con el runtime Docker; Render define `PORT` | `ClientIpSource::heroku()` |
| Railway | Despliegue desde el repositorio de GitHub; Railway define `PORT` | `ClientIpSource::x_real_ip()` |
| Kubernetes | Deployment, Service e Ingress | `XForwardedFor { trusted_hops }`, un salto por cada proxy adicional |

En Kubernetes, la imagen ya encaja en un contexto de seguridad restringido:

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

> **Consejo:** antes de publicar, envíe un ataque desde el playground a través del proxy real y lea el campo `ip=` de la línea `request blocked`: debe mostrar su propia dirección, no la del proxy.

## Desarrollo local sin Docker

Instale las herramientas una vez:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --locked --version 0.2.129
```

Construya el bundle del navegador y luego ejecute el servidor como en producción, con todas las cabeceras del escudo:

```bash
# Desde la raíz del repositorio
cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release
wasm-bindgen --target web --no-typescript --out-dir site/pkg target/wasm32-unknown-unknown/wasm-release/securite_site.wasm
cargo run -p securite-server   # http://localhost:8080
```

Las páginas, los textos y la documentación se compilan dentro del servidor: tras un cambio, vuelva a ejecutar `cargo run -p securite-server`. Reconstruya el bundle solo cuando cambien las islas o las animaciones de página (`site/src/islands.rs`, `site/src/client/`).

La copia estática publicada en GitHub Pages sale del mismo código (vea [Desplegar en GitHub Pages](/docs/github-pages)):

```bash
BASE_PATH=/Securite SITE_URL=https://maxlestage.github.io/Securite cargo run -p securite-server -- export dist
```

## Páginas relacionadas

* [Desplegar en Heroku desde el móvil](/docs/heroku-from-phone)
* [IP del cliente](/docs/client-ip)
* [Cabeceras de seguridad](/docs/security-headers)
* [CI y fusión automática](/docs/ci-auto-merge)
