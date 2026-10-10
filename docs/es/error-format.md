---
title: Formato de las respuestas de error
summary: Elija cómo se responde a las peticiones bloqueadas, desde problem+json según la RFC 9457 hasta texto plano, cuerpos vacíos o su propio renderizador, sin filtrar detalles internos.
category: integrity
order: 4
---

Cuando un guard rechaza una petición, el escudo construye la respuesta por sí mismo: sus handlers nunca se ejecutan. `ErrorFormat` decide qué aspecto tiene esa respuesta. Sea cual sea el formato, los rechazos comparten el mismo endurecimiento: un mensaje breve y genérico, ningún detalle interno, `Cache-Control: no-store` y las mismas cabeceras de seguridad que sus respuestas normales.

## Por qué es importante

- **A05:2021 Security Misconfiguration** y **CWE-209** (mensajes de error con información sensible): los errores verbosos que revelan identificadores de reglas, versiones o trazas de pila ayudan a un atacante a ajustar sus cargas hasta que una pasa. Securite solo envía un mensaje genérico; los identificadores de reglas y los valores detectados se quedan en la pista de auditoría.
- Unos errores coherentes y legibles por máquina permiten a los clientes de una API distinguir una limitación de peticiones de un bloqueo del WAF o de un fallo de autenticación sin analizar texto.

## Los formatos

| Variante | `Content-Type` | Cuerpo |
|---|---|---|
| `ErrorFormat::ProblemJson` (por defecto) | `application/problem+json` | Detalles del problema según la RFC 9457 |
| `ErrorFormat::PlainText` | `text/plain; charset=utf-8` | `403 Forbidden: <message>` |
| `ErrorFormat::Empty` | ninguno | vacío |
| `ErrorFormat::custom(f)` | el suyo | lo que devuelva su closure |

Elija uno en el builder; el valor por defecto es `ProblemJson`:

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .error_format(ErrorFormat::PlainText)
    .build();
```

| Método | Valor por defecto | Descripción |
|---|---|---|
| `ShieldBuilder::error_format(ErrorFormat)` | `ErrorFormat::ProblemJson` | Cómo se renderizan los rechazos. |
| `ErrorFormat::custom(f)` | — | Construye `ErrorFormat::Custom` a partir de una closure `Fn(&Rejection, &Context) -> Response<Bytes>`. |

### ProblemJson

El formato por defecto sigue la RFC 9457 (Problem Details for HTTP APIs), con dos miembros de extensión: `code`, el código de rechazo legible por máquina, y `request_id`, presente cuando hay un guard `RequestId` activo.

```text
HTTP/1.1 403 Forbidden
content-type: application/problem+json
cache-control: no-store
x-request-id: 3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44
x-content-type-options: nosniff
```

```json
{
  "type": "about:blank",
  "title": "Forbidden",
  "status": 403,
  "code": "waf_blocked",
  "detail": "Request blocked by the web application firewall.",
  "request_id": "3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44"
}
```

El cuerpo se envía en una sola línea; `<` y `>` se escapan como `\u003c` y `\u003e`.

### PlainText

```text
403 Forbidden: Request blocked by the web application firewall.
```

Práctico para servicios pequeños y clientes de línea de comandos.

### Empty

Solo el código de estado y las cabeceras, sin cuerpo. Úselo cuando prefiera revelar lo mínimo posible o cuando una CDN o un proxy inverso muestre sus propias páginas de error.

### Custom

Su closure recibe el `Rejection` y el `Context` de la petición, y devuelve un `http::Response<bytes::Bytes>` (`http` se reexporta como `securite::http`; añada el crate `bytes` a sus dependencias o use la reexportación de axum `axum::body::Bytes`). Una página HTML con la imagen de su sitio:

```rust
use bytes::Bytes;
use http::{header, Response};
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .error_format(ErrorFormat::custom(|rejection, ctx| {
        let body = format!(
            "<!doctype html><title>{status}</title><h1>{status}</h1><p>{message}</p><p>Reference: {id}</p>",
            status = rejection.status(),
            message = rejection.message(),
            id = ctx.request_id().unwrap_or("n/a"),
        );
        Response::builder()
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Bytes::from(body))
            .unwrap()
    }))
    .build();
```

O el formato de error que los clientes de su API ya conocen, construido con `serde_json` para que cada valor se escape correctamente:

```rust
use bytes::Bytes;
use http::{header, Response};
use securite::prelude::*;

let shield = ShieldBuilder::api()
    .error_format(ErrorFormat::custom(|rejection, ctx| {
        let body = serde_json::json!({
            "error": {
                "code": rejection.code(),
                "message": rejection.message(),
                "request_id": ctx.request_id(),
            }
        });
        Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Bytes::from(body.to_string()))
            .unwrap()
    }))
    .build();
```

`Rejection` expone `status()`, `code()`, `message()`, `details()`, `headers()` e `is_benign()`. `Context` expone `client_ip()`, `method()`, `uri()`, `path()`, `request_id()`, `rejected_by()`, `started()` y `csp_nonce()`.

> **Atención:** no copie nunca `rejection.details()` en la respuesta. Los detalles contienen identificadores de reglas, patrones detectados y direcciones IP pensados solo para su pista de auditoría.

## Lo que recibe cada rechazo

Tras el renderizado, sea cual sea el formato:

1. El estado pasa a ser el del rechazo, aunque su respuesta personalizada usara otro.
2. Se establece `Cache-Control: no-store`, para que ningún navegador ni caché compartida almacene una página de error.
3. Se añaden las cabeceras que lleva el rechazo: `Retry-After` para las limitaciones de peticiones y los bloqueos, `WWW-Authenticate` para la autenticación y `Allow` para los métodos no permitidos.
4. Cada guard decora la respuesta como de costumbre: cabeceras de seguridad, `X-Request-Id`, cabeceras `RateLimit-*`, cabeceras CORS y cookies endurecidas.

Códigos de rechazo habituales:

| Guard | Estado | `code` |
|---|---|---|
| `waf` | 403 | `waf_blocked` |
| `bot_blocker` | 403 | `bot_blocked` |
| `auth` | 401 | `unauthorized` |
| `rate_limit` | 429 | `rate_limited` |
| `ban` | 403 | `banned` |
| `csrf` | 403 | `csrf_rejected`, `csrf_token_invalid` |
| `body_limit` | 413 | `body_too_large` |
| `method` | 405 | `method_not_allowed` |
| `content_type` | 415 | `unsupported_media_type` |
| `ip_filter` | 403 | `ip_blocked` |
| `host` | 421 | `invalid_host` |

## Respuestas benignas

Algunos cortocircuitos no son ataques: un preflight de CORS respondido con `204 No Content` (`cors_preflight`) o una petición HTTP sin cifrar redirigida con `308 Permanent Redirect` (`https_redirect`). Se crean con `Rejection::respond(status, code)` y siempre tienen el cuerpo vacío, sea cual sea el formato; su closure personalizada no se llama. No reciben `Cache-Control: no-store`, no se registran ni se cuentan como bloqueadas y no activan `on_event`.

## Rechazos de sus propios guards

Un guard personalizado devuelve `Rejection::new(status, code, message)`. El mensaje se envía a los clientes: manténgalo genérico y no incluya nunca datos introducidos por el usuario ni secretos. Ponga los diagnósticos en `.with_details(…)` y las cabeceras de respuesta adicionales en `.with_header(name, value)`.

## Capas independientes

Un guard usado por sí solo (`router.layer(Waf::new())`) construye un escudo interno con el formato por defecto, así que sus rechazos son siempre problem+json. Lo mismo ocurre con `SignatureLayer`. Para elegir el formato, registre sus guards en un `Shield` construido con `error_format`.

## Errores comunes y consejos

- Su closure personalizada se ejecuta en cada rechazo, posiblemente en pleno ataque: manténgala rápida, con pocas asignaciones de memoria y sin operaciones de E/S.
- Escape todo lo que interpole. Los mensajes integrados son estáticos, pero los de sus propios guards puede que no.
- Si su interfaz muestra los errores, enseñe el `request_id`: permite a su equipo de soporte encontrar el evento exacto en los registros.
- `ErrorFormat::Empty` dificulta el diagnóstico a los clientes legítimos. Es preferible `ProblemJson` para las APIs y una página HTML personalizada para los sitios web.

## Páginas relacionadas

- [Guards personalizados](/docs/custom-guards)
- [Eventos de seguridad y estadísticas](/docs/events-stats)
- [Identificadores de petición](/docs/request-id)
- [Escudo y presets](/docs/shield-presets)
