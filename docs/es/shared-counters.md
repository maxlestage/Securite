---
title: Contadores compartidos
summary: Un único límite de intentos de inicio de sesión para todas las instancias de su aplicación, con contadores en Redis o cualquier almacén, claves con hash y comportamiento cerrado ante fallos.
category: traffic
order: 8
---

Cada instancia de una aplicación cuenta en su propia memoria: detrás de un balanceador con cuatro instancias, «5 fallos cada 15 minutos» se convierte en 20. Un `CounterStore` saca los contadores del proceso (Redis, Memcached, una base de datos) y `LoginThrottle::with_store` lo utiliza.

## Amenazas mitigadas

- **Fuerza bruta distribuida** (CWE-307): un atacante reparte sus intentos entre todas las instancias para multiplicar el límite.
- **Caídas del almacén**: cuando el almacén responde con un error, la clave se trata como bloqueada (fallo cerrado); tumbar Redis no abre la puerta.
- **Privacidad**: las claves llegan al almacén como `securite:throttle:<sha-256>`, nunca como direcciones de e-mail o IP.

## Inicio rápido

```rust
use std::sync::Arc;
use std::time::Duration;
use securite::throttle::LoginThrottle;

let store = Arc::new(MyRedisCounters::new(pool)); // implementa CounterStore
let throttle = LoginThrottle::with_store(5, Duration::from_secs(15 * 60), store);
// La misma API que antes: attempt, check, hit, clear …
```

`MemoryCounterStore` implementa el trait en memoria (pruebas, una sola instancia).

## Implementar un almacén

El modelo es un contador de ventana fija, que cualquier almacén sabe hacer de forma atómica:

```rust
use std::time::Duration;
use securite::counter::{CounterStore, StoreError, Window};

impl CounterStore for MyRedisCounters {
    fn increment(&self, key: &str, window: Duration) -> Result<Window, StoreError> {
        let mut c = self.pool.get().map_err(|_| StoreError)?;
        let (count, ttl): (u64, i64) = redis::pipe().atomic()
            .incr(key, 1)
            .cmd("PEXPIRE").arg(key).arg(window.as_millis() as u64).arg("NX").ignore()
            .cmd("PTTL").arg(key)
            .query(&mut *c).map_err(|_| StoreError)?;
        Ok(Window { count, resets_in: Duration::from_millis(ttl.max(1) as u64) })
    }
    fn get(&self, key: &str) -> Result<Option<Window>, StoreError> { /* GET + PTTL */ }
    fn delete(&self, key: &str) -> Result<(), StoreError> { /* DEL */ }
}
```

Las llamadas son síncronas: use un pool de conexiones y tiempos de espera cortos (unos cientos de milisegundos), porque un almacén lento ralentiza los inicios de sesión.

## Trampas y consejos

- `PEXPIRE … NX` (Redis 7) solo fija el tiempo de vida de una ventana nueva; en versiones anteriores, fíjelo cuando `INCR` devuelve 1.
- Conserve el throttle en memoria para despliegues de una instancia: es más rápido y no tiene dependencias externas.
- La [limitación de peticiones](/docs/rate-limit) y el [auto-ban](/docs/auto-ban) siguen contando por instancia.

## Páginas relacionadas

- [Limitación de intentos de inicio de sesión](/docs/login-throttle)
- [Limitación de peticiones](/docs/rate-limit)
