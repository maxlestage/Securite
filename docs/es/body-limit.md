---
title: Límite de tamaño del cuerpo
summary: Rechace los cuerpos de petición demasiado grandes antes de que se ejecute su handler, con límites por ruta, y aplique el límite también a los flujos chunked.
category: traffic
order: 4
---

Securite ofrece dos herramientas complementarias contra los cuerpos de petición sobredimensionados. `BodyLimit` es un guard que rechaza las peticiones cuyo `Content-Length` declarado es demasiado grande, antes de leer un solo byte del cuerpo. El límite en flujo, que cubre también los envíos chunked que no declaran longitud, es el del servidor: `app.body_limit` de Vitesse, o la capa de tower `BodyLimitLayer` en otros servicios.

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
body stream -----> Vitesse: app.body_limit (1 MiB by default)
                   tower services: BodyLimitLayer (Limited body)
                     more than max bytes read -> 413
```

* `BodyLimit` solo mira las cabeceras: el rechazo no cuesta nada y se produce antes que su handler, el WAF o la autenticación.
* Los límites por ruta se aplican a prefijos de ruta comparados por segmentos; **gana el prefijo coincidente más largo** y en el resto se aplica el límite por defecto.
* Un cuerpo chunked no tiene `Content-Length`, así que `BodyLimit` no puede juzgar su tamaño. Rechace esos cuerpos con `require_content_length(true)` o confíe en el límite en flujo: `app.body_limit(bytes)` de Vitesse (1 MiB por defecto) deja de leer al superar el límite y responde `413 Payload Too Large`; en los servicios tower, `BodyLimitLayer` envuelve el cuerpo en `http_body_util::Limited` del mismo modo.

## Inicio rápido

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let shield = Shield::builder()
    // 1 MiB for every request body.
    .guard(BodyLimit::new(1024 * 1024))
    .build();

let mut app = App::new();
app.middleware(shield);
app.post("/comments", |req: Request| async move {
    let body = req.text().await?;
    Ok::<_, Error>(format!("{} bytes", body.len()))
});
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

`BodyLimitLayer` es una simple capa de tower para los servicios sin Vitesse (que tiene `app.body_limit`), no un guard: no se puede registrar con `Shield::builder().guard()`, y sus desbordamientos no se notifican como eventos de seguridad.

## Ejemplos

### Cuerpos de API pequeños, subidas grandes

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let shield = Shield::builder()
    .guard(
        BodyLimit::new(256 * 1024)                    // 256 KiB everywhere...
            .route("/upload", 50 * 1024 * 1024)       // ...50 MiB for uploads...
            .route("/upload/avatar", 2 * 1024 * 1024) // ...but 2 MiB for avatars
            .require_content_length(true),
    )
    .build();

async fn upload(req: Request) -> Result<String, Error> {
    let body = req.bytes().await?;
    Ok(format!("{} bytes", body.len()))
}

let mut app = App::new();
// El límite propio de Vitesse (1 MiB por defecto) también debe subirse.
app.body_limit(50 * 1024 * 1024);
app.middleware(shield);
app.post("/upload/files", upload);
app.post("/upload/avatar", upload);
```

### Envíos chunked

Si hay clientes que envían legítimamente cuerpos sin `Content-Length` (clientes HTTP/2, codificadores chunked), mantenga `require_content_length(false)` y añada la capa de streaming como red de seguridad:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
// Hard cap on what the handler can ever read, chunked or not.
app.body_limit(1024 * 1024);
// Fast path: honest Content-Length values are rejected before any read.
app.middleware(Shield::builder().guard(BodyLimit::new(1024 * 1024)).build());
app.post("/ingest", |req: Request| async move {
    let body = req.bytes().await?;
    Ok::<_, Error>(format!("{} bytes", body.len()))
});
```

## Uso como guard independiente

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(BodyLimit::new(64 * 1024)));
app.post("/comments", |req: Request| async move { req.text().await });
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

Los desbordamientos detectados en flujo reciben la respuesta del servidor: Vitesse envía su error `413` (personalizable con `app.on_error`); un servicio tower responde con su propio error para `BodyLimitLayer`.

## Errores comunes y consejos

* **Con Vitesse se aplican dos límites**: `req.bytes()`, `req.text()`, `req.json()` y `req.form()` se detienen en el límite propio del servidor, 1 MiB por defecto. Súbalo con `app.body_limit` para las rutas de subida; si no, los archivos de más de 1 MiB fallarán aunque Securite los permita.
* **`BodyLimit` por sí solo no cubre los cuerpos chunked**: use `require_content_length(true)` o el límite en flujo (`app.body_limit`, `BodyLimitLayer`).
* `require_content_length(true)` puede romper clientes HTTP/2 y subidas en streaming que omiten `Content-Length` de forma legítima. Pruebe sus clientes antes de activarlo.
* Los prefijos de ruta se comparan por segmentos: `/upload` cubre `/upload/files`, pero no `/uploads`.
* Las subidas multipart cuentan todo el cuerpo codificado, delimitadores y cabeceras incluidos: deje margen por encima del archivo más grande que acepte.

> **Consejo:** mantenga un límite por defecto bajo y conceda límites grandes solo a las rutas que los necesiten. La mayoría de las API JSON nunca necesitan más de unos cientos de kilobytes.

## Páginas relacionadas

* [Higiene HTTP](/docs/hygiene)
* [Limitación de peticiones](/docs/rate-limit)
* [Límite de concurrencia](/docs/concurrency-limit)
* [Filtrado de métodos](/docs/method-filter)
