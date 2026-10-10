---
title: Inicio rápido
summary: Protege una aplicación axum con Shield::recommended(), revisa las cabeceras que añade, comprueba cómo bloquea una inyección SQL y adapta el preset.
category: start
order: 3
---

En cinco minutos pondrás una aplicación axum detrás del shield recomendado, verás qué cambia en los intercambios HTTP y ajustarás el preset a tus necesidades.

## Crear el proyecto

```bash
cargo new secure-app
cd secure-app
cargo add securite axum
cargo add tokio --features macros,rt-multi-thread,net
```

## Añadir el shield

Sustituye el contenido de `src/main.rs` por:

```rust
use std::net::SocketAddr;

use axum::{Router, routing::get};
use securite::prelude::*;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(|| async { "Hello, secure world!" }))
        // Security headers, WAF, rate limiting, CSRF, request ids …
        .layer(Shield::recommended());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on http://{}", listener.local_addr().unwrap());
    axum::serve(
        listener,
        // Gives the shield the real client IP.
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
```

Hay dos detalles importantes. `.layer()` va después de las rutas, porque axum solo envuelve las rutas registradas antes. `into_make_service_with_connect_info` expone la dirección del peer TCP, que necesitan los guards que trabajan por IP (consulta [Instalación](/docs/installation)).

## Ejecutarla

```bash
cargo run
```

## Una petición normal

```bash
curl -i http://127.0.0.1:3000/
```

```text
HTTP/1.1 200 OK
content-type: text/plain; charset=utf-8
content-length: 20
x-request-id: 3f6c2a1e-8b4d-4e7a-9c15-2d0f6b8a7e43
ratelimit-limit: 100
ratelimit-remaining: 99
ratelimit-reset: 1
strict-transport-security: max-age=63072000; includeSubDomains
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: accelerometer=(), autoplay=(), camera=(), …
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
origin-agent-cluster: ?1
x-dns-prefetch-control: off
x-download-options: noopen
x-permitted-cross-domain-policies: none
x-xss-protection: 0
content-security-policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests

Hello, secure world!
```

Tu handler no ha cambiado y, sin embargo, la respuesta ya está reforzada:

| Cabecera | Añadida por | Protección |
|---|---|---|
| `x-request-id` | `request_id` | Relaciona la respuesta con los logs y los eventos de seguridad |
| `ratelimit-*` | `rate_limit` | Indica al cliente cuánto margen le queda (20 req/s, ráfaga de 100) |
| `content-security-policy` | `security_headers` | Bloquea scripts inyectados, plugins y la inserción en marcos (XSS, clickjacking) |
| `strict-transport-security` | `security_headers` | Impone HTTPS durante dos años, subdominios incluidos |
| `cross-origin-*` | `security_headers` | Aísla tu origen de los documentos de otros orígenes |

Las cabeceras que delatan tu stack, como `Server` o `X-Powered-By`, se eliminan.

## Un ataque bloqueado

Envía ahora una inyección SQL clásica en la query string:

```bash
curl -i "http://127.0.0.1:3000/?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"
```

```text
HTTP/1.1 403 Forbidden
content-type: application/problem+json
cache-control: no-store
x-request-id: 9a1d4c7b-2e3f-4a5b-8c6d-0e1f2a3b4c5d
ratelimit-limit: 100
ratelimit-remaining: 99
ratelimit-reset: 1
x-content-type-options: nosniff
x-frame-options: DENY
…
```

El cuerpo sigue la RFC 9457 (formateado aquí para que se lea mejor):

```json
{
  "type": "about:blank",
  "title": "Forbidden",
  "status": 403,
  "code": "waf_blocked",
  "detail": "Request blocked by the web application firewall.",
  "request_id": "9a1d4c7b-2e3f-4a5b-8c6d-0e1f2a3b4c5d"
}
```

El handler no llegó a ejecutarse. El cliente recibe un `code` estable y el `request_id`, pero nada sobre las reglas que se activaron: esos detalles solo van a tus logs. Los rechazos se marcan como `no-store` y reciben igualmente todas las cabeceras de seguridad.

### Verlo en los logs

Las peticiones bloqueadas se escriben con `tracing` bajo el target `securite`. Añade un subscriber (`cargo add tracing-subscriber`) y llama a `tracing_subscriber::fmt::init();` al principio de `main`:

```text
WARN securite: request blocked guard="waf" code="waf_blocked" status=403 ip=Some(127.0.0.1) method=GET path="/" request_id="9a1d4c7b-2e3f-4a5b-8c6d-0e1f2a3b4c5d" details="score=… rules=[…] categories=sqli"
```

## Personalizar el preset

`ShieldBuilder::recommended()` devuelve el mismo preset en forma de builder. `.guard()` añade un guard, o sustituye al que tenga el mismo nombre; `.without()` elimina uno:

```rust
use std::time::Duration;

use axum::http::Method;
use axum::{Router, routing::get};
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    // Same name as the preset's limiter ("rate_limit"): it replaces it.
    .guard(
        RateLimit::new(Quota::per_second(20).burst(100))
            .route_methods("/login", [Method::POST], Quota::per_minute(5))
            .skip_paths(["/health"]),
    )
    // Not in the preset: it is added.
    .guard(AutoBan::new().max_strikes(10).ban_for(Duration::from_secs(600)))
    // Token-authenticated API without cookies: CSRF protection is not needed.
    .without("csrf")
    .build();

println!("{:?}", shield.guard_names());
// ["request_id", "ban", "hygiene", "method", "body_limit", "rate_limit",
//  "bot_blocker", "waf", "security_headers", "cookies"]

let app: Router = Router::new()
    .route("/", get(|| async { "Hello, secure world!" }))
    .route("/health", get(|| async { "ok" }))
    .layer(shield);
```

> **Atención:** Elimina `csrf` solo si ningún endpoint que modifique estado depende de cookies u otras credenciales que el navegador envía automáticamente. Los navegadores adjuntan las cookies a las peticiones entre sitios; la protección CSRF es lo que impide que otro sitio se aproveche de ellas.

> **Consejo:** `CookieHardening` añade `Secure` a todas las cookies. Los navegadores aceptan cookies seguras en `http://localhost`; en otro host de desarrollo con HTTP simple, usa `CookieHardening::new().insecure_dev()`, y nunca en producción.

## Siguientes pasos

- [Shield y presets](/docs/shield-presets): qué contiene cada preset y en qué orden se ejecutan los guards.
- [IP del cliente](/docs/client-ip): lectura obligada antes de desplegar detrás de un proxy.
- [Modo observación](/docs/monitor-mode): despliega el WAF o una CSP más estricta sin romper producción.
