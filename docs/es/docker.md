---
title: Imagen Docker
summary: Cómo el Dockerfile multietapa construye el sitio y su servidor, cómo ejecutar la imagen en local o en cualquier plataforma de contenedores, y cómo desarrollar sin Docker.
category: deploy
order: 3
---

El `Dockerfile` de la raíz del repositorio construye este sitio: un front-end Yew + WebAssembly servido por un servidor axum que se protege a sí mismo con `securite`. Heroku construye la misma imagen por usted (vea [Desplegar en Heroku desde el móvil](/docs/heroku-from-phone)); los comandos de esta página requieren un ordenador o un terminal en la nube.

## Las tres etapas

### site

Basada en `rust:1-slim-bookworm` con el target `wasm32-unknown-unknown`.

* Instala Trunk `0.21.14` y wasm-bindgen `0.2.129` (argumentos de build `TRUNK_VERSION` y `WASM_BINDGEN_VERSION`) a partir de los binarios precompilados publicados en GitHub. Si una descarga falla, recurre a `cargo install --locked` de la misma versión, que es más lento.
* Copia solo `site/Cargo.toml` y `site/Cargo.lock` y ejecuta `cargo fetch --locked` con un `main.rs` provisional, de modo que la capa de dependencias queda en caché mientras el lockfile no cambie.
* Copia `docs/` (el `build.rs` del sitio compila estas páginas) y `site/`, y ejecuta `trunk build --release --offline`: todo se descargó antes, así que no hace falta red.

### server

Basada en `rust:1-slim-bookworm`, copia el workspace (`Cargo.toml`, `Cargo.lock`, `crates/`, `server/`) y ejecuta `cargo build --release --locked -p securite-server`. El perfil release usa LTO «thin», una sola unidad de generación de código y un binario sin símbolos.

### runtime

Basada en `debian:bookworm-slim`, solo contiene `/app/securite-server` y los archivos estáticos de `/app/dist`. Se ejecuta con el usuario de sistema no root `app` (uid `10001`, sin directorio personal, shell `nologin`), define `DIST_DIR=/app/dist`, `RUST_LOG=info` y `PORT=8080`, y expone el puerto 8080.

`.dockerignore` reduce el contexto de build: se excluyen `.git`, `.github`, `target`, `site/target`, `site/dist` y los archivos Markdown, salvo `docs/**/*.md` y `crates/securite/README.md`.

> **Atención:** la CLI de wasm-bindgen debe coincidir exactamente con el crate `wasm-bindgen`. Para actualizarla, cambie `0.2.129` en cuatro lugares a la vez: `site/Cargo.toml`, la sección `[tools]` de `site/Trunk.toml`, el argumento `WASM_BINDGEN_VERSION` y el job `site` de `ci.yml`.

## Construir y ejecutar

```bash
docker build -t securite-site .
docker run -p 8080:8080 -e SECURITE_ENV=development securite-site
```

Después abra `http://localhost:8080`. El modo desarrollo permite seguir en HTTP simple: el modo producción envía HSTS y `upgrade-insecure-requests`, que rompen `http://localhost`.

> **Consejo:** los binarios de Trunk y wasm-bindgen descargados están compilados para x86_64. Si el paso `trunk --version` falla en una máquina ARM, añada `--platform linux/amd64` a `docker build`.

## Variables de entorno

| Variable | Valor por defecto | Función |
|---|---|---|
| `PORT` | `8080` | Puerto de escucha en `0.0.0.0`. Heroku, Render y Railway lo definen. |
| `DIST_DIR` | `/app/dist` en la imagen, `dist` en otro caso | Salida de `trunk build`. Sin `index.html`, el servidor registra un aviso y sirve una página provisional. |
| `SECURITE_ENV` | `production` si `DYNO` está definida, si no `development` | `production` activa la redirección a HTTPS (salvo `/api/health`), HSTS, `upgrade-insecure-requests` y `ClientIpSource::heroku()`. Cualquier otro valor significa desarrollo, con `ClientIpSource::Peer`. |
| `RUST_LOG` | `info` | Filtro de `tracing`; los eventos de seguridad usan el target `securite`. |

## Qué ejecuta el servidor

`/api/health` responde `ok`, `/api/stats` devuelve los contadores del escudo en JSON y `/api/demo` devuelve la carga enviada por el playground cuando el WAF la deja pasar. Cualquier otra ruta sirve un archivo estático o recurre a `index.html`.

| Guarda | Configuración |
|---|---|
| `MethodFilter` | Solo `GET`, `HEAD` y `OPTIONS` |
| `BodyLimit` | 16 KiB |
| `RateLimit` | 30 peticiones por segundo y por IP, ráfaga de 150; `/api/demo` 60 por minuto, ráfaga de 20 |
| `ConcurrencyLimit` | 64 peticiones simultáneas por IP |
| `AutoBan` | 30 penalizaciones, `/api/demo` ignorada |
| `SecurityHeaders` | CSP estricta que permite el script inline de Trunk por hash y `'wasm-unsafe-eval'`, COEP `require-corp`, HSTS en producción |
| `HttpsRedirect` | Solo en producción, `/api/health` exenta |
| `RequestId`, `Hygiene`, `BotBlocker`, `Waf`, `Csrf`, `CookieHardening` | Valores por defecto |

## Ejecutarla en cualquier sitio

La imagen escucha en `$PORT` y registra en la salida estándar, así que sirve cualquier plataforma de contenedores. Detrás de HTTPS, defina `SECURITE_ENV=production` y asegúrese de que la fuente de IP del cliente corresponde al proxy, vea [IP del cliente](/docs/client-ip). El sitio usa `ClientIpSource::heroku()` en producción; para otro proxy, cambie la llamada `.client_ip(...)` en `server/src/main.rs`.

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
cargo install trunk --locked --version 0.21.14
cargo install wasm-bindgen-cli --locked --version 0.2.129
```

Para ejecutar el sitio como en producción, con todas las cabeceras del escudo:

```bash
# From the repository root
(cd site && trunk build --release)
DIST_DIR=site/dist cargo run -p securite-server
```

Para la recarga en caliente, deje el servidor en marcha para la API y lance Trunk en `site/`:

```bash
# Terminal 1, repository root: API on http://localhost:8080
DIST_DIR=site/dist cargo run -p securite-server

# Terminal 2: site with live reload on http://127.0.0.1:8081
cd site
trunk serve
```

`site/Trunk.toml` reenvía las peticiones `/api/` a `http://127.0.0.1:8080/api/`, así que el playground y los contadores siguen funcionando. Las páginas que sirve `trunk serve` no llevan las cabeceras del escudo: compruébelas en el puerto 8080.

## Páginas relacionadas

* [Desplegar en Heroku desde el móvil](/docs/heroku-from-phone)
* [IP del cliente](/docs/client-ip)
* [Cabeceras de seguridad](/docs/security-headers)
* [CI y fusión automática](/docs/ci-auto-merge)
