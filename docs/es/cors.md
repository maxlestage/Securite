---
title: CORS
summary: Un intercambio de recursos cross-origin estricto, basado en una lista de permitidos, que nunca refleja orígenes arbitrarios y rechaza las combinaciones inseguras al arrancar.
category: browser
order: 2
---

`Cors` responde a las peticiones de verificación previa (preflight) y añade las cabeceras `Access-Control-*` para los orígenes que usted indique, y solo para ellos. Sus valores por defecto son deliberadamente cerrados: no se permite ningún origen hasta que usted lo nombre.

## La amenaza

La política del mismo origen impide que una página alojada en `evil.example` lea las respuestas de su API. CORS sirve para abrir en ella huecos controlados, y una mala configuración la anula por completo:

- **Reflejo del origen**: devolver cualquier `Origin` junto con `Access-Control-Allow-Credentials: true` permite a cualquier sitio web leer los datos autenticados de sus usuarios.
- **El origen `null`**: los iframes con sandbox y las páginas `file://` envían `Origin: null`; confiar en él equivale a confiar en cualquiera.
- **Comparaciones laxas**: comprobaciones por sufijo o con expresiones regulares que aceptan `app.example.com.evil.com` o `evilexample.com`.

Son fallos clásicos de las categorías A05 Security Misconfiguration y A01 Broken Access Control del OWASP Top 10 2021, que cubre el OWASP Web Security Testing Guide (WSTG-CLNT-07).

## Cómo funciona

`Cors` se ejecuta con prioridad 90, antes de la limitación de tasa, el CSRF y la autenticación, de modo que los preflights, que no llevan credenciales, se responden primero.

- **Sin cabecera `Origin`** (navegación del mismo origen, curl, llamadas entre servidores): la petición no se modifica.
- **Preflight** (`OPTIONS` con `Access-Control-Request-Method`): se comprueban el origen, el método y cada cabecera solicitada. Si todo es correcto, el shield responde directamente `204 No Content` con `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, `Access-Control-Max-Age` y `Access-Control-Allow-Origin`. Si no, responde `403` con el código `cors_rejected` y registra el evento.
- **Petición real desde un origen permitido**: la respuesta recibe `Access-Control-Allow-Origin` (el origen exacto, o `*` con `allow_any_origin()` sin credenciales), además de `Access-Control-Allow-Credentials` y `Access-Control-Expose-Headers` cuando están configurados.
- **Petición real desde otro origen**: no se añade ninguna cabecera CORS, así que el navegador oculta la respuesta al script que la solicitó.
- Todas las respuestas llevan `Vary: Origin`, para que las cachés nunca sirvan a un origen la respuesta de otro.

Los orígenes se comparan sin distinguir mayúsculas de minúsculas y se ignora una posible barra final. `https://*.example.com` abarca subdominios a cualquier profundidad, pero no `example.com`; el esquema y el puerto deben coincidir exactamente. `null` solo se acepta si se incluye de forma explícita. Pasar `"*"` a `allow_origin` provoca un pánico (use `allow_any_origin()`), igual que combinar `allow_any_origin()` con `allow_credentials(true)`.

## Inicio rápido

```rust
use std::time::Duration;

use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let cors = Cors::new()
        .allow_origin("https://app.example.com")
        .allow_credentials(true)
        .max_age(Duration::from_secs(3600));

    let mut app = App::new();
    app.middleware(Shield::builder().guard(cors).build());
    app.get("/api/me", |_req: Request| async { "{}" });
    app
}
```

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `Cors::new()` | ningún origen | Parte de los métodos y cabeceras habituales, pero sin orígenes permitidos. |
| `allow_origin(&str)` | — | Permite un origen (`https://app.example.com`) o un patrón comodín (`https://*.example.com`). |
| `allow_origins(iter)` | — | Permite varios orígenes. |
| `allow_any_origin()` | inactivo | Envía `Access-Control-Allow-Origin: *`. Solo para API públicas sin autenticación. |
| `allow_methods(iter of Method)` | `GET, HEAD, POST, PUT, PATCH, DELETE` | **Sustituye** los métodos permitidos. |
| `allow_headers(iter)` | `accept, accept-language, content-language, content-type, authorization, x-requested-with, x-csrf-token, x-request-id` | **Sustituye** las cabeceras de petición permitidas. |
| `expose_headers(iter)` | ninguna | **Sustituye** las cabeceras de respuesta legibles por los scripts. |
| `allow_credentials(bool)` | `false` | Permite cookies y `Authorization` en peticiones cross-origin. |
| `max_age(Duration)` | 600 segundos | Tiempo durante el que el navegador puede guardar un preflight en caché. |
| `allow_private_network(bool)` | `false` | Responde a los preflights de Private Network Access con `Access-Control-Allow-Private-Network: true`. |

El guard se llama `cors`. Ningún preset lo incluye, porque solo usted conoce sus orígenes.

## Ejemplos

### Front-end en otro subdominio, con cookies

Una aplicación de una sola página en `app.example.com` llama a `api.example.com` con una cookie de sesión. Sus peticiones `POST` son cross-origin, así que la protección CSRF también debe confiar en ese origen:

```rust
use std::time::Duration;

use securite::prelude::*;
use vitesse::prelude::*;

pub fn api() -> App {
    let shield = ShieldBuilder::recommended()
        .guard(
            Cors::new()
                .allow_origin("https://app.example.com")
                .allow_credentials(true)
                .expose_headers(["x-request-id", "ratelimit-remaining"])
                .max_age(Duration::from_secs(3600)),
        )
        // Replaces the preset's CSRF guard: the SPA is a trusted cross-origin caller.
        .guard(Csrf::new().trusted_origin("https://app.example.com"))
        .build();

    let mut app = App::new();
    app.middleware(shield);
    app.get("/me", |_req: Request| async { "{}" });
    app.post("/orders", |_req: Request| async { "created" });
    app
}
```

### API pública de solo lectura

```rust
use securite::http::Method;
use securite::prelude::*;

pub fn public_cors() -> Cors {
    Cors::new()
        .allow_any_origin()
        .allow_methods([Method::GET, Method::HEAD])
        .allow_headers(["accept", "content-type"])
}
```

### Subdominios, despliegues de vista previa y cabeceras propias

```rust
use securite::prelude::*;

pub fn cors(dev: bool) -> Cors {
    let cors = Cors::new()
        .allow_origins(["https://example.com", "https://*.example.com"])
        .allow_headers(["content-type", "authorization", "x-api-key"]);
    if dev { cors.allow_origin("http://localhost:5173") } else { cors }
}
```

### Comprobar un preflight con curl

```bash
curl -i -X OPTIONS https://api.example.com/orders \
  -H "Origin: https://app.example.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type"
```

```text
HTTP/2 204
access-control-allow-methods: GET, HEAD, POST, PUT, PATCH, DELETE
access-control-max-age: 3600
access-control-allow-headers: accept, accept-language, content-language, content-type, authorization, x-requested-with, x-csrf-token, x-request-id
access-control-allow-origin: https://app.example.com
access-control-allow-credentials: true
vary: origin
```

## Uso como guard independiente

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::from(Cors::new().allow_origin("https://app.example.com")));
    app.get("/api/items", |_req: Request| async { "[]" });
    app
}
```

En Vitesse, el primer middleware añadido es el más externo. Si apila guards independientes, añada `Cors` antes de cualquier middleware de autenticación: así los preflights, que nunca llevan credenciales, se responden antes de llegar a él. Dentro de un mismo `Shield`, este orden es automático.

## Errores comunes y consejos

> **Atención:** CORS no es control de acceso. Una petición «simple» desde un origen no permitido llega igualmente a su handler; el navegador solo oculta la respuesta. Proteja los endpoints que modifican el estado con la [protección CSRF](/docs/csrf) y una [lista de Content-Type permitidos](/docs/content-type) limitada a JSON.

- `allow_methods`, `allow_headers` y `expose_headers` sustituyen sus valores por defecto. Añadir solo `x-api-key` eliminaría `content-type` y `authorization`.
- No incluya nunca `null`: lo envían iframes con sandbox y ficheros locales que cualquier atacante puede crear.
- Un comodín abarca todos los subdominios, actuales y futuros, incluido uno secuestrado a través de un registro DNS huérfano. Prefiera una lista exacta para las API que aceptan credenciales.
- `https://app.example.com` y `https://app.example.com:8443` son orígenes distintos.
- Los navegadores limitan `max_age` (Chromium a dos horas), por lo que un valor mayor no tiene efecto.
- Mantenga los orígenes de desarrollo, como `http://localhost:5173`, fuera de la configuración de producción.
- Los scripts solo pueden leer las cabeceras de respuesta que CORS considera seguras. Exponga `x-request-id` o las cabeceras de limitación de tasa si su front-end las necesita.

> **Consejo:** si su CDN guarda en caché las respuestas de la API, compruebe que respeta `Vary: Origin`.

## Páginas relacionadas

- [Protección CSRF](/docs/csrf)
- [Lista de Content-Type permitidos](/docs/content-type)
- [Cabeceras de seguridad](/docs/security-headers)
- [Endurecimiento de cookies](/docs/cookies)
- [Autenticación](/docs/auth)
