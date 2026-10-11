---
title: ETag y 304 Not Modified
summary: Da a cada respuesta GET un ETag calculado a partir de su cuerpo y responde 304 Not Modified, sin cuerpo, cuando el cliente ya lo tiene.
category: everyday
order: 2
---

Un navegador o un cliente de API que ya ha descargado una página puede preguntar «¿ha cambiado?» devolviendo el `ETag` que recibió en una cabecera `If-None-Match`. `ETag` calcula esa etiqueta por ti a partir del cuerpo de cada respuesta `GET` y `HEAD`, y responde `304 Not Modified` con un cuerpo vacío cuando nada ha cambiado: los bytes nunca viajan dos veces.

## Funcionamiento

1. Solo se tienen en cuenta las peticiones `GET` y `HEAD` y las respuestas `200 OK`.
2. Si la respuesta ya tiene un `ETag` (los archivos estáticos que sirve Vitesse), se conserva.
3. Si no, cuando el cuerpo está completo, tiene un tamaño conocido (texto, HTML, JSON…) y no supera el límite (4 MiB por defecto), se calcula su hash y la respuesta recibe `ETag: "<length>-<hash>"`. Los streams y los cuerpos más grandes pasan sin cambios.
4. Si el `If-None-Match` de la petición incluye esa etiqueta (o `*`), el estado pasa a ser `304 Not Modified` y se descarta el cuerpo. Las demás cabeceras (`ETag`, `Cache-Control`, `Vary`…) se mantienen.

El hash (FNV-1a de 64 bits) es estable entre reinicios y entre servidores: todas las instancias detrás de un balanceador de carga producen la misma etiqueta para el mismo cuerpo.

## Inicio rápido

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(ETag::new());
app.get("/api/products", |_req: Request| async { Json(json!([{ "id": 1 }])) });
```

```bash
curl -i https://example.com/api/products
# HTTP/1.1 200 OK
# etag: "a-1f3c9b2e8d7a6c54"

curl -i https://example.com/api/products -H 'If-None-Match: "a-1f3c9b2e8d7a6c54"'
# HTTP/1.1 304 Not Modified
```

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `ETag::new()` | etiquetas fuertes, 4 MiB | Crea el middleware (`ETag::default()` es equivalente). |
| `.max_size(bytes)` | `4 * 1024 * 1024` | Tamaño máximo del cuerpo al que se calcula el hash. Los cuerpos más grandes no reciben etiqueta. |
| `.weak(true)` | `false` | Etiquetas débiles (`W/"…"`), para cuando un middleware posterior puede cambiar los bytes pero no el significado. |

## Con Cache-Control

`ETag` decide si hay que volver a enviar los bytes; `Cache-Control` decide si el cliente llega siquiera a preguntar. `Cache-Control: no-cache` significa «pregunta siempre y reutiliza si no ha cambiado», el compañero perfecto de `ETag`:

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(ETag::new());
app.middleware(CacheControl::new().fallback(CacheControl::NO_CACHE));
```

## Errores comunes y consejos

- Hay que calcular el cuerpo para obtener su hash: un `304` ahorra ancho de banda y tiempo al cliente, no trabajo al servidor. Para ahorrar también trabajo al servidor, añade una [caché de respuestas](/docs/response-cache).
- La comparación es débil, como exige la RFC 9110 para `If-None-Match`: `W/"x"` coincide con `"x"`.
- Coloca `ETag` antes de un middleware de compresión (para que se ejecute dentro de él) si quieres calcular el hash de los bytes originales, o usa `.weak(true)`.

## Páginas relacionadas

- [Cache-Control](/docs/cache-control)
- [Caché de respuestas](/docs/response-cache)
