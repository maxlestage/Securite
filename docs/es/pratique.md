---
title: Pratique, middlewares del día a día
summary: El crate hermano de Securite: trece middlewares de Vitesse para caché, registros, métricas, URL, comprobaciones de salud, mantenimiento, idiomas y retirada de API.
category: everyday
order: 1
---

Securite protege tu aplicación. **Pratique** se encarga de todo lo demás que necesita un servicio en producción y que no tiene nada que ver con la seguridad: respuestas `304`, cabeceras de caché, registros de acceso, métricas de Prometheus, comprobaciones de salud, modo de mantenimiento, redirecciones, idiomas… Cada middleware ocupa una línea, y todos viven en el mismo repositorio que Securite.

## Añadir el crate

```bash
cargo add pratique --git https://github.com/maxlestage/Securite
```

```toml
[dependencies]
pratique = { git = "https://github.com/maxlestage/Securite" }
vitesse = { git = "https://github.com/maxlestage/Vitesse" }
```

Pratique solo depende de Vitesse, no contiene código unsafe (`#![forbid(unsafe_code)]`) y es compatible con Rust 1.85 y versiones posteriores.

## Inicio rápido

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

fn main() -> std::io::Result<()> {
    let mut app = App::new();
    app.middleware(AccessLog::json().skip("/health"));
    app.middleware(Metrics::new());
    app.middleware(Health::new().version(env!("CARGO_PKG_VERSION")));
    app.middleware(ResponseTime::new());
    app.middleware(TrailingSlash::trim());
    app.middleware(ETag::new());
    app.middleware(CacheControl::new().fallback(CacheControl::NO_CACHE));
    app.middleware(Locale::new(["en", "fr", "es"]));
    app.get("/", |_req: Request| async { "Hello!" });
    app.run(3000)
}
```

## Los middlewares

| Familia | Middleware | Qué hace |
|---|---|---|
| Caché | [`ETag`](/docs/etag) | `ETag` a partir del cuerpo, `304 Not Modified` con `If-None-Match` |
| | [`CacheControl`](/docs/cache-control) | `Cache-Control` por prefijo de ruta y tipo de contenido |
| | [`ResponseCache`](/docs/response-cache) | Caché en memoria de respuestas `GET` completas, con un handle de purga |
| Observabilidad | [`AccessLog`](/docs/access-log) | Una línea por petición, en JSON o en formato combinado de Apache |
| | [`Metrics`](/docs/metrics) | `/metrics` de Prometheus: contadores, histograma de latencia, peticiones en curso |
| | [`ResponseTime`](/docs/response-time) | `X-Response-Time` y `Server-Timing` |
| URL | [`TrailingSlash`](/docs/trailing-slash) | Una sola dirección por página, con o sin la `/` final |
| | [`Redirects`](/docs/redirects) | Páginas movidas, secciones renombradas, dominio canónico |
| Operaciones | [`Health`](/docs/health) | Sonda `/health` con comprobaciones con nombre |
| | [`Maintenance`](/docs/maintenance) | `503` y `Retry-After`, activable y desactivable en tiempo de ejecución |
| Respuestas y API | [`SetHeaders`](/docs/set-headers) | Añade, sustituye o elimina cabeceras en cada respuesta |
| | [`Locale`](/docs/locale) | Idioma a partir de `?lang=`, una cookie o `Accept-Language` |
| | [`Deprecation`](/docs/deprecation) | Cabeceras `Deprecation`, `Sunset` y `Link` |

## Orden de los middlewares

Vitesse ejecuta los middlewares en el orden en que se añaden: el primero que se añade es el más externo, ve la petición la primera y la respuesta la última. Un buen orden:

1. **Observadores**: `AccessLog`, `Metrics`, `ResponseTime`, para que lo midan todo, incluidas las respuestas de los demás middlewares.
2. **El `Shield` de Securite**, para que `/metrics` y todo lo demás queden protegidos.
3. **Middlewares que responden por sí mismos**: `Health`, `Maintenance`, `Redirects`, `TrailingSlash`.
4. **Middlewares que trabajan sobre las respuestas de tus rutas**: `Locale`, `ETag`, `CacheControl`, `ResponseCache`, `SetHeaders`, `Deprecation`.

```rust
use pratique::prelude::*;
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(AccessLog::json().skip("/health"));
app.middleware(Metrics::new());
app.middleware(Shield::recommended());
app.middleware(Health::new());
app.middleware(Redirects::new().prefix("/blog", "/articles"));
app.middleware(ETag::new());
```

> **Consejo:** También puedes asociar un middleware a una sola ruta con `handler.with(middleware)`, o a un `Router` montado en un prefijo con `router.middleware(…)`.

## Páginas relacionadas

- [Instalación de Securite](/docs/installation)
- [Shield y presets](/docs/shield-presets)
