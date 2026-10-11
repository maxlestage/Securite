---
title: Cache-Control
summary: Establece la cabecera Cache-Control de las respuestas GET correctas por prefijo de ruta y por tipo de contenido, con presets para recursos con huella y datos personales.
category: everyday
order: 3
---

`Cache-Control` indica a los navegadores, las CDN y los proxies durante cuánto tiempo pueden conservar una respuesta. Si aciertas, las visitas repetidas son instantáneas; si te equivocas, se sirven páginas obsoletas o los datos de otra persona. `CacheControl` la establece en un único lugar, por ruta y por tipo de contenido, en vez de en cada handler.

## Funcionamiento

Para cada petición `GET` o `HEAD` respondida con un estado `2xx` o `3xx`:

1. Si el handler ya estableció `Cache-Control`, se conserva (salvo con `.overwrite(true)`).
2. Si no, se usa el valor del **prefijo de ruta coincidente más largo** (`/assets` cubre `/assets/app.js`, no `/assetsx`),
3. si no, el del primer **prefijo de tipo de contenido** que coincida (`image/` cubre `image/png`),
4. si no, el **valor de reserva**, si lo hay.

Los errores (`4xx`, `5xx`) y las escrituras (`POST`, `PUT`…) no se tocan.

## Inicio rápido

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(
    CacheControl::new()
        .fallback(CacheControl::NO_CACHE)
        .route("/assets", CacheControl::IMMUTABLE)
        .route("/account", CacheControl::NO_STORE)
        .content_type("image/", "public, max-age=86400"),
);
```

## Configuración

| Método | Descripción |
|---|---|
| `CacheControl::new()` | Ninguna regla: las respuestas no se tocan hasta que añadas una. |
| `.route(prefix, value)` | Valor para un prefijo de ruta; gana el prefijo más largo. |
| `.content_type(prefix, value)` | Valor para un prefijo de tipo de contenido (`image/`, `text/css`, `application/json`). |
| `.fallback(value)` | Valor cuando no coincide nada más. |
| `.overwrite(true)` | Sustituye un valor establecido por el handler (por defecto: se conserva). |

Todos los métodos provocan un pánico al arrancar si el valor no es un valor de cabecera válido.

## Presets

| Constante | Valor | Úsala para |
|---|---|---|
| `CacheControl::IMMUTABLE` | `public, max-age=31536000, immutable` | Archivos con huella (`app.3f9a.js`) cuyo nombre cambia con su contenido. |
| `CacheControl::NO_CACHE` | `no-cache` | HTML y respuestas de API: se almacenan, pero se revalidan cada vez (combínalo con [ETag](/docs/etag)). |
| `CacheControl::NO_STORE` | `no-store` | Datos personales o sensibles, que nunca se escriben en disco. |

## Errores comunes y consejos

- `immutable` solo es correcto cuando la URL cambia con el contenido. Un simple `/style.css` con `IMMUTABLE` se queda obsoleto durante un año en los navegadores de tus visitantes.
- Las páginas que dependen del usuario conectado no deben ser `public`: usa `private` o `no-store`; si no, una CDN podría servir la página de un usuario a otro.
- `SecurityHeaders::api()` de Securite ya envía `no-store` en las respuestas de API; como se conserva el valor del handler, `CacheControl` no entra en conflicto con él.

## Páginas relacionadas

- [ETag y 304](/docs/etag)
- [Caché de respuestas](/docs/response-cache)
