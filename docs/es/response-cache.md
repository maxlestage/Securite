---
title: Caché de respuestas
summary: Guarda en memoria respuestas GET completas durante un tiempo y responde a las peticiones idénticas sin ejecutar el handler, con límites de tamaño, cabeceras X-Cache y Age y un handle de purga.
category: everyday
order: 4
---

Algunos endpoints son costosos y cambian poco: un catálogo de productos, un panel público, una página de inicio renderizada. `ResponseCache` guarda sus respuestas en memoria durante un tiempo fijo (TTL) y responde por sí mismo a las siguientes peticiones idénticas, sin llamar a tu handler ni a tu base de datos.

## Qué se almacena en caché

Una petición se busca en la caché cuando es un `GET` o un `HEAD`, **no** tiene cabecera `Authorization` **ni** `Cookie` y su ruta está bajo uno de los prefijos de `.only(…)` (todas las rutas por defecto). La clave es la ruta **y** la query string: `/products?page=2` no es `/products`.

Una respuesta solo se almacena cuando se puede compartir:

- estado `200 OK`, cuerpo completo de tamaño conocido, como máximo `max_body` bytes;
- sin `Set-Cookie`, sin `Vary`, sin `Content-Encoding`;
- sin `Cache-Control: private`, `no-store` ni `no-cache`.

Las respuestas llevan `X-Cache: MISS` (calculada por el handler) o `X-Cache: HIT` (servida desde la memoria, con una cabecera `Age` en segundos). Una petición con `Cache-Control: no-cache` se salta la búsqueda y refresca la entrada.

## Inicio rápido

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(ResponseCache::new(Duration::from_secs(30)).only("/api/catalog"));
app.get("/api/catalog", |_req: Request| async { Json(json!({ "products": [] })) });
```

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `ResponseCache::new(ttl)` | — | Cuánto tiempo sigue fresca una respuesta. |
| `.only(prefix)` | todas las rutas | Limita la caché a prefijos de ruta (se puede llamar varias veces). |
| `.max_entries(n)` | `1000` | Número máximo de respuestas almacenadas; primero se expulsan las caducadas y después las más antiguas. |
| `.max_body(bytes)` | `1 MiB` | Tamaño máximo del cuerpo almacenado. |
| `.handle()` | — | Un `CacheHandle` para inspeccionar o purgar la caché mientras la aplicación se ejecuta. |

## Purgar tras una actualización

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

let cache = ResponseCache::new(Duration::from_secs(300)).only("/api/catalog");
let purge = cache.handle();

let mut app = App::new();
app.middleware(cache);
app.post("/admin/products", move |_req: Request| {
    let purge = purge.clone();
    async move {
        // … guardar el producto …
        purge.invalidate("/api/catalog"); // todas las query strings, y lo que cuelga debajo
        "saved"
    }
});
```

`CacheHandle` también ofrece `clear()`, `len()` e `is_empty()`.

## Errores comunes y consejos

- La caché vive en la memoria de cada proceso: dos instancias detrás de un balanceador de carga tienen dos cachés. Usa TTL cortos o purga todas las instancias.
- Las respuestas que dependen de algo distinto de la ruta y la query (una cabecera, el idioma) deben indicarlo con `Vary`, lo que desactiva la caché para ellas. Con [Locale](/docs/locale), almacena en caché solo los endpoints que no dependen del idioma, o añade el idioma a la query string.
- Coloca la caché después de un middleware de compresión para que almacene los bytes originales.
- Muchos fallos simultáneos para la misma clave llegan cada uno una vez al handler hasta que se almacena la primera respuesta.

## Páginas relacionadas

- [ETag y 304](/docs/etag)
- [Cache-Control](/docs/cache-control)
