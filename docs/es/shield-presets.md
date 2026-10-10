---
title: Shield y presets
summary: Qué contienen Shield::recommended(), strict() y api(), cómo personalizarlos con ShieldBuilder y el orden exacto en que se ejecutan los guards.
category: start
order: 4
---

Un `Shield` es un pipeline de guards inmutable y barato de clonar. Lo obtienes a partir de un preset (una configuración predefinida) o de `ShieldBuilder`, y lo añades a tu servicio con `.layer()`. `Shield::recommended()` equivale simplemente a `ShieldBuilder::recommended().build()`, y lo mismo vale para `strict()` y `api()`.

## Los tres presets

### Shield::recommended()

Una protección sensata para aplicaciones web y API que consumen navegadores. Diez guards:

| Guard | Nombre | Ajustes |
|---|---|---|
| `RequestId::new()` | `request_id` | `x-request-id`, reutiliza los identificadores entrantes seguros |
| `Hygiene::new()` | `hygiene` | URI de 8 KiB, 100 cabeceras, 32 KiB de cabeceras, 256 parámetros de consulta, sin segmentos `..` ni codificación inválida |
| `MethodFilter::new()` | `method` | `GET HEAD POST PUT PATCH DELETE OPTIONS`, cabeceras de sobrescritura de método rechazadas |
| `BodyLimit::new(2 * 1024 * 1024)` | `body_limit` | Basado en `Content-Length` |
| `RateLimit::new(Quota::per_second(20).burst(100))` | `rate_limit` | 20 req/s por IP, ráfaga de 100, IPv6 agrupado por /64 |
| `BotBlocker::new()` | `bot_blocker` | Lista integrada de escáneres (sqlmap, nikto, nuclei …) |
| `Waf::new()` | `waf` | Paranoia `Low`, umbral 5, cabeceras inspeccionadas |
| `Csrf::new()` | `csrf` | Comprobaciones Fetch Metadata y `Origin`, sin token |
| `SecurityHeaders::new()` | `security_headers` | CSP estricta limitada al propio origen, HSTS de dos años con subdominios, `nosniff`, `DENY` … |
| `CookieHardening::new()` | `cookies` | `Secure; HttpOnly; SameSite=Lax` |

### Shield::strict()

Todo lo de `recommended()`, con límites más estrictos y cuatro guards adicionales:

| Guard | Nombre | Cambio |
|---|---|---|
| `HttpsRedirect::new()` | `https_redirect` | Añadido: `308` a HTTPS, confía en `X-Forwarded-Proto`, desafíos ACME exentos |
| `AutoBan::new()` | `ban` | Añadido: 20 infracciones en un minuto (peticiones bloqueadas por otro guard, respuestas `401`, `403` o `429`) provocan un baneo de 15 min, que se duplica en cada reincidencia hasta 24 h |
| `BodyLimit::new(1024 * 1024)` | `body_limit` | Reducido de 2 MiB a 1 MiB |
| `RateLimit::new(Quota::per_second(10).burst(40))` | `rate_limit` | 10 req/s por IP, ráfaga de 40 |
| `ConcurrencyLimit::per_ip(32)` | `concurrency` | Añadido: 32 peticiones simultáneas por IP |
| `Waf::new().paranoia(Paranoia::Medium)` | `waf` | Paranoia `Medium` |
| `ContentTypeGuard::new()` | `content_type` | Añadido: JSON, `application/*+json`, formularios URL-encoded y multipart |
| `SecurityHeaders::strict()` | `security_headers` | Añade `Cross-Origin-Embedder-Policy: require-corp` y `Referrer-Policy: no-referrer` (sin HSTS `preload`) |
| `CookieHardening::new().same_site(SameSite::Strict)` | `cookies` | `SameSite=Strict` |

> **Consejo:** ningún preset envía la directiva HSTS `preload`, que equivale a dar tu consentimiento para figurar en las listas de precarga de los navegadores. Cuando todos tus subdominios sirvan HTTPS, actívala con `.hsts(Some(Hsts { preload: true, ..Hsts::default() }))` en `SecurityHeaders` (importa `securite::headers::Hsts`), consulta [Cabeceras de seguridad](/docs/security-headers).

### Shield::api()

Pensado para API JSON autenticadas con tokens en lugar de cookies, por lo que no incluye ningún guard CSRF:

| Guard | Nombre | Ajustes |
|---|---|---|
| `RequestId`, `Hygiene`, `MethodFilter` | `request_id`, `hygiene`, `method` | Como en `recommended()` |
| `BodyLimit::new(1024 * 1024)` | `body_limit` | 1 MiB |
| `RateLimit::new(Quota::per_second(20).burst(50))` | `rate_limit` | 20 req/s por IP, ráfaga de 50 |
| `BotBlocker::new()`, `Waf::new()` | `bot_blocker`, `waf` | Como en `recommended()` |
| `ContentTypeGuard::json()` | `content_type` | Solo `application/json` y `application/*+json` |
| `SecurityHeaders::api()` | `security_headers` | CSP `default-src 'none'`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` |
| `CookieHardening::new()` | `cookies` | `Secure; HttpOnly; SameSite=Lax` |

## El builder

`Shield::builder()` parte de un pipeline vacío; `ShieldBuilder::recommended()`, `strict()` y `api()` parten de un preset.

| Método | Efecto | Por defecto |
|---|---|---|
| `.guard(g)` | Añade un guard; si ya hay uno con el mismo `name()`, lo sustituye | — |
| `.without(name)` | Elimina el guard con ese nombre | — |
| `.client_ip(source)` | De dónde se obtiene la IP del cliente, consulta [IP del cliente](/docs/client-ip) | `ClientIpSource::Peer` |
| `.error_format(format)` | Cómo se presentan los rechazos, consulta [Formato de errores](/docs/error-format) | `ErrorFormat::ProblemJson` |
| `.on_event(f)` | Callback para cada bloqueo o infracción observada | Ninguno |
| `.log_events(bool)` | Escribe los eventos con `tracing` (target `securite`) | `true` |
| `.build()` | Ordena los guards por prioridad y devuelve el `Shield` | — |

```rust
use securite::prelude::*;

let shield = ShieldBuilder::strict()
    // Behind Heroku's router.
    .client_ip(ClientIpSource::heroku())
    // Not in the preset: added.
    .guard(Cors::new().allow_origin("https://app.example.com"))
    // Same name as the preset's guard: replaced.
    .guard(BodyLimit::new(10 * 1024 * 1024))
    // Removed by name.
    .without("concurrency")
    .error_format(ErrorFormat::PlainText)
    .on_event(|e| {
        if e.enforced {
            eprintln!("[security] {} blocked {} {}", e.guard, e.method, e.path);
        }
    })
    .build();

assert_eq!(
    shield.guard_names(),
    [
        "request_id", "ban", "hygiene", "method", "https_redirect", "body_limit",
        "cors", "rate_limit", "bot_blocker", "waf", "csrf", "content_type",
        "security_headers", "cookies",
    ]
);
```

Como `.guard()` sustituye por nombre, configurar un preset nunca genera duplicados: siempre hay como máximo un `rate_limit`, un `waf`, etc.

## Orden de ejecución

`build()` ordena los guards por prioridad, de menor a mayor; a igual prioridad, se conserva el orden de inserción. Las constantes están en `securite::priority`:

| Constante | Valor | Guard | Nombre |
|---|---|---|---|
| `REQUEST_ID` | 10 | `RequestId` | `request_id` |
| `BAN` | 30 | `AutoBan` | `ban` |
| `IP_FILTER` | 40 | `IpFilter` | `ip_filter` |
| `HYGIENE` | 50 | `Hygiene` | `hygiene` |
| `METHOD` | 60 | `MethodFilter` | `method` |
| `HOST` | 70 | `HostFilter` | `host` |
| `HTTPS_REDIRECT` | 75 | `HttpsRedirect` | `https_redirect` |
| `BODY_LIMIT` | 80 | `BodyLimit` | `body_limit` |
| `CORS` | 90 | `Cors` | `cors` |
| `RATE_LIMIT` | 100 | `RateLimit` | `rate_limit` |
| `CONCURRENCY` | 105 | `ConcurrencyLimit` | `concurrency` |
| `USER_AGENT` | 110 | `BotBlocker` | `bot_blocker` |
| `WAF` | 120 | `Waf` | `waf` |
| `CSRF` | 130 | `Csrf` | `csrf` |
| `AUTH` | 140 | `Auth` | `auth` |
| `CONTENT_TYPE` | 150 | `ContentTypeGuard` | `content_type` |
| `CUSTOM` | 500 | Tus propios guards (por defecto) | El que elijas |
| `HEADERS` | 900 | `SecurityHeaders` | `security_headers` |
| `COOKIES` | 910 | `CookieHardening` | `cookies` |

Este orden es deliberado. El identificador de petición va primero para que todos los eventos lleven uno. Las IP baneadas o filtradas se descartan antes de cualquier trabajo real, las comprobaciones de protocolo baratas se ejecutan antes que el WAF, la redirección HTTPS va justo después del filtro de host para que su `Location` se construya a partir de un host validado, y la limitación de tasa corta las avalanchas de peticiones antes de la inspección, más costosa. La decoración de respuestas sigue el mismo orden, de modo que las cabeceras de seguridad y el refuerzo de cookies actúan al final, sobre la respuesta definitiva. `shield.guard_names()` devuelve los nombres en orden de ejecución.

## Capas independientes

Cada guard implementa `tower::Layer` y se convierte en un `Shield`, así que una protección puede usarse por sí sola:

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "ok" }))
    .layer(SecurityHeaders::strict())
    .layer(RateLimit::per_minute(120));

let waf_only = Shield::from(Waf::new());
```

> **Atención:** Cada capa independiente es un shield autónomo con un solo guard: usa el formato de error por defecto y lleva sus propias estadísticas. Obtiene la IP del cliente de la dirección del peer TCP, salvo que un shield exterior ya lo haya hecho: detrás de un proxy, pon `Shield::builder().client_ip(ClientIpSource::heroku()).build()` (o la fuente de tu plataforma) como capa más externa, consulta [IP del cliente](/docs/client-ip). Además, las capas no decoran los rechazos de las demás: en axum, la última llamada a `.layer()` es la capa más externa, así que las respuestas `429` del ejemplo no llevan ninguna cabecera de seguridad. Es preferible un único `Shield` construido con `.guard()`.

## Inspeccionar un shield

`shield.stats()` devuelve un `StatsSnapshot` con los contadores `total`, `blocked`, `monitored` y por guard, además de `allowed()` y `to_json()`. Internamente, un `Shield` es un `Arc`: clónalo sin reparos para compartirlo entre tu router y un endpoint de métricas. Consulta [Eventos y estadísticas](/docs/events-stats).
