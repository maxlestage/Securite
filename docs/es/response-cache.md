---
title: Caché de respuestas
summary: Guarda respuestas GET completas en memoria o en Redis y responde a las peticiones idénticas sin ejecutar el handler, con una entrada por idioma y por variante de Vary, compartida por todas las instancias de la aplicación.
category: everyday
order: 4
---

Algunos endpoints son costosos y cambian poco: un catálogo de productos, un panel público, una página de inicio renderizada. `ResponseCache` guarda sus respuestas durante un tiempo fijo (TTL) y responde por sí mismo a las siguientes peticiones idénticas, sin llamar a tu handler ni a tu base de datos. Por defecto, las respuestas viven en la memoria del proceso, o en Redis para que todas las instancias de la aplicación compartan una sola caché.

## Qué se almacena en caché

Una petición se busca en la caché cuando es un `GET` o un `HEAD`, **no lleva credenciales** (`Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key`, más las cabeceras que añadas con `.bypass_header(…)`) y su ruta está bajo uno de los prefijos de `.only(…)` (todas las rutas por defecto).

Una respuesta solo se almacena cuando se puede compartir:

- estado `200 OK`, cuerpo completo de tamaño conocido, como máximo `max_body` bytes;
- sin `Set-Cookie`, sin `Vary: *`, sin nonce de CSP (`'nonce-…'` debe cambiar en cada respuesta);
- sin `Cache-Control: private`, `no-store` ni `no-cache`.

Se almacena durante el TTL de la caché, o menos si la respuesta lo indica: `Cache-Control: max-age=10` (o `s-maxage`) la conserva 10 segundos; `max-age=0` o una edad inválida (`-1`, `10.5`), nada. Una petición con `Cache-Control: no-store` ni lee ni llena la caché.

## Una entrada por variante

La clave de una entrada es la ruta **y** la query string tal como las envió el cliente (`/products?page=2` no es `/products`), más:

- **el sitio**: la cabecera `Host`, y `Forwarded`, `X-Forwarded-Host` y `X-Forwarded-Proto` detrás de un proxy, para que una página que construye sus enlaces a partir de su dirección nunca se sirva a otro dominio;
- **el `Origin` de CORS**, para que una respuesta permitida para un origen nunca se sirva a otro;
- **el idioma elegido por [Locale](/docs/locale)**, cuando `Locale` se añade antes de la caché: la página en francés y la página en inglés son dos entradas, y todos los `Accept-Language` que negocian el francés (`fr`, `fr-CA`, `de, fr;q=0.8`…) comparten la francesa;
- **las cabeceras que nombra el `Vary` de la respuesta**: con `Vary: Accept-Encoding`, los clientes que piden Brotli y los que piden gzip tienen cada uno su propia entrada.

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Locale::new(["en", "fr", "es"])); // antes de la caché
app.middleware(ResponseCache::new(Duration::from_secs(60)));
app.get("/", |req: Request| async move {
    match req.get::<Lang>().map(Lang::as_str) {
        Some("fr") => "Bonjour",
        Some("es") => "Hola",
        _ => "Hello",
    }
});
```

Las respuestas llevan `X-Cache: MISS` (calculada por el handler) o `X-Cache: HIT` (servida desde la caché, con una cabecera `Age` en segundos). Un acierto responde por sí mismo `304 Not Modified` cuando el `If-None-Match` de la petición coincide con el `ETag` almacenado. Una petición con `Cache-Control: no-cache` se salta la búsqueda y refresca la entrada.

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
| `.store(store)` | `MemoryStore` (1000 entradas, 64 MiB) | Dónde viven las respuestas: `MemoryStore`, `RedisStore` o tu propio `CacheStore`. |
| `.only(prefix)` | todas las rutas | Limita la caché a prefijos de ruta (se puede llamar varias veces). |
| `.bypass_header(name)` | — | Una cabecera de credenciales más, cuyas peticiones siempre llegan al handler. |
| `.max_body(bytes)` | `1 MiB` | Tamaño máximo del cuerpo almacenado. |
| `.on_error(f)` | — | Se llama cuando el almacén falla (la petición la sirve entonces el handler). |
| `.handle()` | — | Un `CacheHandle` para purgar la caché y leer sus contadores. |

## Compartir la caché con Redis

Con varias instancias detrás de un balanceador de carga (dynos, pods, servidores), cada `MemoryStore` es una caché independiente: una página se calcula una vez por instancia y una purga solo llega a una de ellas. Un `RedisStore` (feature `redis`) guarda las entradas en Redis o Valkey, de modo que cada instancia lee lo que ha calculado cualquier otra, y las purgas llegan a todas.

```toml
[dependencies]
pratique = { git = "https://github.com/maxlestage/Securite", features = ["redis-tls"] }
```

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

fn main() -> std::io::Result<()> {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into());
    let store = RedisStore::open(&url).expect("invalid REDIS_URL").prefix("shop:cache:");
    let mut app = App::new();
    app.middleware(
        ResponseCache::new(Duration::from_secs(60))
            .store(store)
            .on_error(|e| eprintln!("response cache: {e}")),
    );
    app.get("/", |_req: Request| async { "home" });
    app.run(3000)
}
```

| Feature | Aporta |
|---|---|
| `redis` | `RedisStore` para las direcciones `redis://`. |
| `redis-tls` | También las direcciones `rediss://` (rustls). Añade `#insecure` a la dirección para un certificado autofirmado, como el que usa Heroku Data for Redis. |

Cómo se comporta el almacén:

- **Conexiones diferidas**: `RedisStore::open` solo comprueba la dirección. Cada hilo de trabajo abre su propia conexión en su primera petición (Vitesse ejecuta un runtime por núcleo), y la vuelve a abrir tras un fallo.
- **Timeouts**: cada operación, conexión incluida, se rinde a los 250 ms (`.timeout(…)`).
- **Pausa**: tras un fallo, Redis se deja de lado durante 1 s (`.cooldown(…)`); mientras tanto, las peticiones van directamente al handler, sin esperar. Un Redis caído o mudo cuesta como mucho un timeout por segundo, nunca uno por petición: la caché puede perderse, el sitio sigue rápido. Los fallos se cuentan (`handle.errors()`) y se pasan a `.on_error`.
- **Caducidad**: las entradas se escriben con `PX`, así que Redis las elimina por sí mismo.
- **Aislamiento**: cada clave empieza por el prefijo (`pratique:cache:` por defecto). Da a cada aplicación su propio prefijo cuando comparten un Redis; `clear` nunca toca otro prefijo, aunque empiece igual.
- **Las purgas** usan `SCAN` y `UNLINK`, nunca `KEYS`, así que no bloquean Redis.

Las features `redis` requieren Rust 1.88 o posterior (como el crate `redis`); sin ellas, Pratique es compatible con Rust 1.85.

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
        // Todas las query strings, todas las variantes y las rutas que cuelgan debajo.
        if let Err(e) = purge.invalidate("/api/catalog").await {
            eprintln!("purge failed: {e}");
        }
        "saved"
    }
});
```

| Método de `CacheHandle` | Descripción |
|---|---|
| `invalidate(path).await` | Olvida `path` y lo que cuelga debajo (`/api/catalog` cubre `/api/catalog?page=2` y `/api/catalog/42`, no `/api/catalogs`). |
| `clear().await` | Lo olvida todo (con Redis, solo las claves del prefijo de esta caché). |
| `hits()`, `misses()`, `errors()` | Contadores de este proceso. |

Una petición que ya se estaba calculando durante una purga no se almacena después: una purga nunca la deshace la página antigua (para las purgas hechas desde este proceso).

Para dimensionar el `MemoryStore`, usa `MemoryStore::new().max_entries(n).max_bytes(bytes)`; cuando está lleno, las entradas más próximas a caducar hacen sitio. Para inspeccionarlo, guárdalo en un `Arc`: `let store = Arc::new(MemoryStore::new()); ResponseCache::new(ttl).store(store.clone())`, y después `store.len()` y `store.bytes()`.

## Tu propio almacén

`CacheStore` tiene cuatro métodos (`get`, `set` con un TTL, `remove_prefixes`, `clear`), y cada uno devuelve un future: impleméntalo para Memcached, una base de datos o un doble de pruebas. Un almacén que devuelve un error se trata como un fallo de caché.

## Errores comunes y consejos

- Almacena en caché solo respuestas públicas. Las peticiones con cabeceras de credenciales se saltan la caché, pero una respuesta que depende de otra cosa (una IP, una sesión pasada en la query string) debe quedar fuera con `.only(…)` o indicar `Cache-Control: private`.
- Añade [Locale](/docs/locale) **antes** de la caché: si se añade después, `Locale` sigue funcionando, pero el `Accept-Language` en bruto pasa a formar parte de la clave, lo que divide la caché en muchas entradas.
- Añade [Cache-Control](/docs/cache-control) **después** de la caché: así la caché ve el `private` o el `no-store` que pone y deja fuera esas páginas. Si se añade antes, solo cambia la cabecera que recibe el navegador.
- Añade el `Shield` de Securite y CORS **antes** de la caché, para que cada petición se compruebe y cada respuesta, en caché o no, reciba sus cabeceras de seguridad.
- Las cabeceras propias de un único intercambio (`X-Request-Id`, `X-Response-Time`, `Server-Timing`, `Date`, `Age`) no se almacenan; con [ETag](/docs/etag) (antes o después de la caché), los aciertos se responden con `304` cuando el cliente ya tiene la página.
- Muchos fallos simultáneos para la misma clave llegan todos al handler hasta que se almacena la primera respuesta.

## Páginas relacionadas

- [ETag y 304](/docs/etag)
- [Cache-Control](/docs/cache-control)
- [Negociación del idioma](/docs/locale)
