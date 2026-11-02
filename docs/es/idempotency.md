---
title: Claves de idempotencia
summary: Responde a un POST o PATCH reenviado con la misma Idempotency-Key con la primera respuesta almacenada en vez de ejecutarlo dos veces, como la API de Stripe y el borrador IETF.
category: everyday
order: 13
---

Un teléfono pierde la red justo después de pulsar «Pagar»: ¿se hizo el pago? La aplicación reenvía el mismo `POST`, con la misma cabecera `Idempotency-Key` (como la API de Stripe y el borrador IETF `Idempotency-Key`). Sin `Idempotency`, el cliente paga dos veces; con él, la segunda petición no se ejecuta: recibe la respuesta almacenada de la primera, marcada con `Idempotent-Replayed: true`.

## Qué pasa con una petición

Se procesan las peticiones `POST` y `PATCH` que llevan una `Idempotency-Key`; las demás pasan directamente (`PUT` y `DELETE` son idempotentes por naturaleza).

| Situación | Respuesta |
|---|---|
| Primera petición con esta clave | Se ejecuta normalmente; la respuesta se guarda 24 horas. |
| Misma clave, misma petición | La respuesta almacenada, con `Idempotent-Replayed: true`. No se llama al handler. |
| Misma clave mientras la primera petición sigue en curso | `409 Conflict` con `Retry-After: 1`. |
| Misma clave con otra petición (otra ruta, otro cuerpo) | `422 Unprocessable Content`: un error del cliente, no un reintento. |
| Clave no válida (vacía, más de 255 caracteres, no ASCII visible) | `400 Bad Request`. |
| Sin clave, con `.required()` | `400 Bad Request`. |

Los errores del servidor (`5xx`), `408`, `409` y `429` no se almacenan: el cliente puede reintentar, y el reintento se ejecuta. Las claves están separadas por las credenciales del cliente (`Authorization`, `X-Api-Key`): un cliente no puede leer las respuestas de otro adivinando su clave. Las respuestas de error son `application/problem+json`.

## Inicio rápido

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Idempotency::new()); // POST y PATCH que llevan una `Idempotency-Key`
app.post("/payments", |_req: Request| async { (201, "paid") });
```

## Configuración

| Método | Por defecto | Descripción |
|---|---|---|
| `.ttl(duration)` | 24 horas | Cuánto tiempo se guarda una respuesta. |
| `.methods([...])` | `POST`, `PATCH` | Los métodos a los que se aplica. |
| `.required()` | desactivado | Rechaza (`400`) las peticiones de esos métodos que no llevan clave. |
| `.header(name)` | `Idempotency-Key` | Otra cabecera (`X-Idempotency-Key`…). |
| `.max_body(bytes)` | `1 MiB` | Cuerpo de petición más grande (más: `413`) y respuesta más grande almacenada (más: se envía pero no se almacena). |
| `.store(store)` | `MemoryStore` | Dónde se guardan las respuestas: `MemoryStore`, o un `RedisStore` compartido por todas las instancias. |
| `.on_error(f)` | — | Se llama cuando falla el almacenamiento (la petición se ejecuta entonces como si no llevara clave). |

## Compartir las respuestas con Redis

Con varias instancias detrás de un balanceador de carga, un reintento puede llegar a otra instancia que la primera petición. Dale a `Idempotency` el mismo `RedisStore` que a la [caché de respuestas](/docs/response-cache) (feature `redis` o `redis-tls`) para que todas las instancias vean las respuestas almacenadas:

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into());
let store = RedisStore::open(&url).expect("REDIS_URL no válida").prefix("shop:idempotency:");
let mut app = App::new();
app.middleware(
    Idempotency::new()
        .store(store)
        .on_error(|e| eprintln!("idempotency: {e}")),
);
```

## Páginas relacionadas

- [Pratique, middlewares del día a día](/docs/pratique)
- [Caché de respuestas](/docs/response-cache)
- [Firmas de webhooks](/docs/webhook-signatures)
