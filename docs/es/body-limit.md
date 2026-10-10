---
title: Límite de tamaño del cuerpo
summary: Rechace los cuerpos de petición demasiado grandes antes de que se ejecute su handler, con límites por ruta, y aplique el límite también a los flujos chunked.
category: traffic
order: 4
---

Securite ofrece dos herramientas complementarias contra los cuerpos de petición sobredimensionados. `BodyLimit` es un guard que rechaza las peticiones cuyo `Content-Length` declarado es demasiado grande, antes de leer un solo byte del cuerpo. `BodyLimitLayer` es una capa de tower que aplica el límite mientras se lee el flujo, lo que cubre también los envíos chunked que no declaran longitud.

## Amenazas que mitiga

Aceptar cuerpos de tamaño arbitrario es uno de los ataques de denegación de servicio más baratos: unos pocos clientes que suben gigabytes pueden llenar su memoria o su disco, saturar su ancho de banda y mantener a sus workers ocupados analizando datos (OWASP API4:2023, Unrestricted Resource Consumption). Los parsers de JSON y de formularios son especialmente vulnerables, porque suelen cargar el cuerpo completo en memoria antes de analizarlo.

## Funcionamiento

```text
request head ----> BodyLimit (guard, priority 80)
                     Content-Length present?
                       invalid           -> 400 bad_content_length
                       > limit for path  -> 413 body_too_large
                     no Content-Length, Transfer-Encoding set,
                     POST/PUT/PATCH and require_content_length(true)
                                         -> 411 length_required
body stream -----> BodyLimitLayer (Limited body)
                     more than max bytes read -> error, 413 with axum extractors
```

* `BodyLimit` solo mira las cabeceras: el rechazo no cuesta nada y se produce antes que su handler, el WAF o la autenticación.
* Los límites por ruta se aplican a prefijos de ruta comparados por segmentos; **gana el prefijo coincidente más largo** y en el resto se aplica el límite por defecto.
* Un cuerpo chunked no tiene `Content-Length`, así que `BodyLimit` no puede juzgar su tamaño. Rechace esos cuerpos con `require_content_length(true)` o añada `BodyLimitLayer`, que envuelve el cuerpo en `http_body_util::Limited`: leer más allá del límite falla, y los extractores de axum convierten ese error en `413 Payload Too Large`.

## Inicio rápido

```rust
use axum::{routing::post, Router};
use securite::prelude::*;

let shield = Shield::builder()
    // 1 MiB for every request body.
    .guard(BodyLimit::new(1024 * 1024))
    .build();

let app: Router = Router::new()
    .route("/comments", post(|body: String| async move { format!("{} bytes", body.len()) }))
    .layer(shield);
```

Los preajustes ya incluyen un límite: 2 MiB en `Shield::recommended()` y 1 MiB en `Shield::strict()` y `Shield::api()`.

## Configuración

### BodyLimit (guard)

| Método | Valor por defecto | Descripción |
|---|---|---|
| `BodyLimit::new(max_bytes)` | – | Tamaño máximo por defecto del cuerpo, en bytes (`u64`). |
| `.route(prefix, max_bytes)` | ninguno | Límite distinto para un prefijo de ruta (gana el más largo). |
| `.require_content_length(bool)` | `false` | Rechaza los cuerpos `POST`, `PUT` y `PATCH` enviados con `Transfer-Encoding` y sin `Content-Length` (`411`). |
| `.limit_for(path)` | – | Devuelve el límite que se aplica a `path`. |

### BodyLimitLayer (streaming)

| Método | Valor por defecto | Descripción |
|---|---|---|
| `BodyLimitLayer::new(max_bytes)` | – | Número máximo de bytes del cuerpo que puede leer su servicio (`usize`). |

`BodyLimitLayer` es una simple capa de tower, no un guard: no se puede registrar con `Shield::builder().guard()`, y sus desbordamientos no se notifican como eventos de seguridad.

## Ejemplos

### Cuerpos de API pequeños, subidas grandes

```rust
use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::{routing::post, Router};
use securite::prelude::*;

let shield = Shield::builder()
    .guard(
        BodyLimit::new(256 * 1024)                    // 256 KiB everywhere...
            .route("/upload", 50 * 1024 * 1024)       // ...50 MiB for uploads...
            .route("/upload/avatar", 2 * 1024 * 1024) // ...but 2 MiB for avatars
            .require_content_length(true),
    )
    .build();

let app: Router = Router::new()
    .route("/upload/files", post(|body: Bytes| async move { format!("{} bytes", body.len()) }))
    .route("/upload/avatar", post(|body: Bytes| async move { format!("{} bytes", body.len()) }))
    // axum's own extractor limit (2 MB by default) must be raised as well.
    .layer(DefaultBodyLimit::max(50 * 1024 * 1024))
    .layer(shield);
```

### Envíos chunked

Si hay clientes que envían legítimamente cuerpos sin `Content-Length` (clientes HTTP/2, codificadores chunked), mantenga `require_content_length(false)` y añada la capa de streaming como red de seguridad:

```rust
use axum::body::Bytes;
use axum::{routing::post, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/ingest", post(|body: Bytes| async move { format!("{} bytes", body.len()) }))
    // Hard cap on what the handler can ever read, chunked or not.
    .layer(BodyLimitLayer::new(1024 * 1024))
    // Fast path: honest Content-Length values are rejected before any read.
    .layer(Shield::builder().guard(BodyLimit::new(1024 * 1024)).build());
```

## Uso como capa independiente

```rust
use axum::{routing::post, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/comments", post(|body: String| async move { body }))
    .layer(BodyLimit::new(64 * 1024));
```

## Cabeceras de respuesta

`BodyLimit` no añade ninguna cabecera específica. Los rechazos usan el formato de error del escudo (`application/problem+json` y `Cache-Control: no-store` por defecto):

| Estado | Código | Cuándo |
|---|---|---|
| `413 Payload Too Large` | `body_too_large` | `Content-Length` superior al límite de la ruta. El mensaje indica el límite. |
| `400 Bad Request` | `bad_content_length` | `Content-Length` no es un número. |
| `411 Length Required` | `length_required` | `POST`/`PUT`/`PATCH` chunked con `require_content_length(true)`. |

```text
HTTP/1.1 413 Payload Too Large
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Payload Too Large","status":413,"code":"body_too_large","detail":"Request body too large (max 262144 bytes)."}
```

Los desbordamientos que detecta `BodyLimitLayer` reciben la respuesta de su framework (en axum, un `413` en texto plano).

## Errores comunes y consejos

* **Con axum se aplican dos límites**: los extractores `Bytes`, `String`, `Json` y `Form` mantienen el límite por defecto de axum de 2 MB. Súbalo con `DefaultBodyLimit::max` en las rutas de subida; si no, los archivos de más de 2 MB fallarán aunque Securite los permita.
* **`BodyLimit` por sí solo no cubre los cuerpos chunked**: use `require_content_length(true)` o `BodyLimitLayer`.
* `require_content_length(true)` puede romper clientes HTTP/2 y subidas en streaming que omiten `Content-Length` de forma legítima. Pruebe sus clientes antes de activarlo.
* Los prefijos de ruta se comparan por segmentos: `/upload` cubre `/upload/files`, pero no `/uploads`.
* Las subidas multipart cuentan todo el cuerpo codificado, delimitadores y cabeceras incluidos: deje margen por encima del archivo más grande que acepte.

> **Consejo:** mantenga un límite por defecto bajo y conceda límites grandes solo a las rutas que los necesiten. La mayoría de las API JSON nunca necesitan más de unos cientos de kilobytes.

## Páginas relacionadas

* [Higiene HTTP](/docs/hygiene)
* [Limitación de peticiones](/docs/rate-limit)
* [Límite de concurrencia](/docs/concurrency-limit)
* [Filtrado de métodos](/docs/method-filter)
