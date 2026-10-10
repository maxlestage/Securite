---
title: Higiene HTTP
summary: Rechace las peticiones malformadas o ambiguas que se usan para el contrabando de peticiones, el path traversal, la inyección de cabeceras y el agotamiento de los parsers.
category: traffic
order: 5
---

`Hygiene` agrupa comprobaciones de coherencia del protocolo muy baratas que se ejecutan sobre la cabecera de cada petición. Los navegadores y clientes HTTP legítimos nunca las activan; las herramientas de ataque, las cargas de contrabando y los escáneres mal hechos, sí. Forma parte de todos los preajustes.

## Amenazas que mitiga

* **Contrabando de peticiones HTTP** (CL.TE, TE.CL, TE.TE): una delimitación ambigua de los mensajes que hace que un proxy y su servidor no se pongan de acuerdo sobre dónde termina una petición.
* **Path traversal** (OWASP A01:2021): secuencias `../`, en bruto, con codificación porcentual o incluso doblemente codificadas, para salir de un directorio.
* **Inyección de cabeceras y división de respuestas**: `NUL`, `CR` y `LF` colados en la ruta.
* **Agotamiento de recursos y HashDoS**: URI enormes, cientos de cabeceras o miles de parámetros de consulta que castigan a los parsers y a las tablas hash.
* **Confusión de host**: varias cabeceras `Host`, usadas para envenenar cachés y eludir el enrutamiento.

## El contrabando de peticiones en pocas palabras

HTTP/1.1 tiene dos formas de delimitar un cuerpo: `Content-Length` (CL) y `Transfer-Encoding: chunked` (TE). Cuando una petición lleva ambas, o una variante ofuscada, el proxy frontal y el servidor de aplicación pueden quedarse cada uno con una distinta. Los bytes que uno considera «el resto del cuerpo» el otro los lee como el **inicio de la petición siguiente**, que acaba adherida a la conexión de otro usuario.

```text
CL.TE: the front-end trusts Content-Length, the back-end trusts Transfer-Encoding

POST / HTTP/1.1
Host: shop.example
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

front-end: forwards the 13 body bytes "0\r\n\r\nSMUGGLED"
back-end : chunk "0" ends the body; "SMUGGLED" is prefixed to the next request
```

TE.CL es el caso simétrico: el frontal sigue los chunks mientras el servidor de aplicación se detiene tras un `Content-Length` pequeño, y el resto de los datos se convierte en una petición. Las variantes TE.TE ocultan la cabecera a uno de los dos con valores como `Transfer-Encoding: xchunked`, `chunked, identity` o una cabecera duplicada.

`Hygiene` no intenta adivinar qué interpretación es la correcta: una petición ambigua se rechaza sin más, así que no queda ningún desacuerdo que explotar.

## Comprobaciones y valores por defecto

Las comprobaciones se ejecutan en este orden; el primer fallo determina la respuesta.

| Comprobación | Valor por defecto | Estado | Código |
|---|---|---|---|
| Longitud de la URI (ruta y consulta) | 8 KiB | `414` | `uri_too_long` |
| Número de cabeceras | 100 | `431` | `too_many_headers` |
| Tamaño total de nombres y valores de cabeceras | 32 KiB | `431` | `headers_too_large` |
| `Content-Length` y `Transfer-Encoding` a la vez | rechazado | `400` | `ambiguous_framing` |
| `Transfer-Encoding` distinto de un único `chunked` | rechazado | `400` | `bad_transfer_encoding` |
| `Content-Length` no válido (signo, letras, valor vacío) | rechazado | `400` | `bad_content_length` |
| Valores de `Content-Length` contradictorios | rechazado | `400` | `bad_content_length` |
| Varias cabeceras `Host` | rechazado | `400` | `duplicate_host` |
| Caracteres de control en la ruta sin decodificar | rechazado | `400` | `bad_path` |
| Codificación porcentual malformada en la ruta | rechazado | `400` | `bad_path_encoding` |
| `NUL`, `CR`, `LF` en la ruta decodificada | rechazado | `400` | `bad_path` |
| Segmentos `..` o `.` (en bruto, codificados, doblemente codificados, separadores `\`) | rechazado | `400` | `path_traversal` |
| Número de parámetros de consulta | 256 | `400` | `too_many_params` |
| `%00` en la cadena de consulta | rechazado | `400` | `bad_query` |

Las longitudes idénticas repetidas (`Content-Length: 5, 5`) se aceptan, tal como permite la RFC 9110. Los segmentos de puntos se comparan completos: `/files/report..pdf` pasa, `/a/%252e%252e/etc` no (la ruta se decodifica dos veces para detectar la doble codificación).

## Inicio rápido

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(Shield::builder().guard(Hygiene::new()).build());
```

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `Hygiene::new()` | – | Todas las comprobaciones activas con los valores anteriores. |
| `.max_uri_length(bytes)` | `8192` | Longitud máxima de la URI (`414 URI Too Long`). |
| `.max_headers(n)` | `100` | Número máximo de cabeceras de petición (`431`). |
| `.max_header_bytes(bytes)` | `32768` | Tamaño acumulado máximo de nombres y valores de cabeceras (`431`). |
| `.max_query_params(n)` | `256` | Número máximo de parámetros de consulta. |
| `.allow_dot_segments()` | rechazado | Acepta segmentos `..` y `.` en las rutas (no recomendado). |
| `.allow_bad_encoding()` | rechazado | Acepta codificación porcentual malformada en las rutas. |

Las comprobaciones de delimitación, de `Host`, de caracteres de control y de `NUL` no se pueden desactivar.

## Ejemplos

### Límites más estrictos para una API JSON

```rust
use securite::prelude::*;

let hygiene = Hygiene::new()
    .max_uri_length(2 * 1024)
    .max_headers(50)
    .max_header_bytes(16 * 1024)
    .max_query_params(32);

let shield = ShieldBuilder::api()
    .guard(hygiene) // replaces the preset's Hygiene
    .build();
```

### Clientes heredados

Algunos clientes antiguos envían signos `%` sin escapar en las rutas. Relaje solo esa comprobación, y únicamente si no le queda otra opción:

```rust
use securite::prelude::*;

let hygiene = Hygiene::new().allow_bad_encoding();
```

## Uso como capa independiente

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(Hygiene::new());
```

## Cabeceras de respuesta

`Hygiene` no añade ninguna cabecera específica. Los rechazos usan el formato de error del escudo:

```text
HTTP/1.1 400 Bad Request
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Bad Request","status":400,"code":"path_traversal","detail":"Dot segments are not allowed."}
```

## Errores comunes y consejos

* **Cookies o tokens grandes**: los JWT voluminosos y las cookies numerosas pueden superar 32 KiB de cabeceras. Aumente `max_header_bytes` en lugar de desactivar comprobaciones.
* **Formularios de búsqueda y filtros** con muchos campos pueden superar `max_query_params`; dimensiónelo según su formulario legítimo más grande.
* `Hygiene` ve la petición después de que su servidor HTTP la haya analizado. Es defensa en profundidad: mantenga también su proxy y su servidor actualizados y configurados para rechazar delimitaciones ambiguas.
* Con `AutoBan` en el mismo shield, cada rechazo de la higiene cuenta como una penalización, así que los reincidentes acaban bloqueados. Entre capas independientes separadas, `AutoBan` solo ve el estado `400`: en ese caso, añada `count_status(400)`.

> **Consejo:** `Hygiene` se ejecuta con prioridad 50, antes de la limitación de peticiones y del WAF. Las peticiones basura se descartan antes de cualquier comprobación costosa.

## Páginas relacionadas

* [Límite de tamaño del cuerpo](/docs/body-limit)
* [Filtrado de métodos](/docs/method-filter)
* [Cortafuegos de aplicaciones web (WAF)](/docs/waf)
* [Bloqueo automático](/docs/auto-ban)
