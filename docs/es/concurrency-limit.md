---
title: Límite de concurrencia
summary: Limite cuántas peticiones puede tener en curso a la vez un mismo cliente, para frenar avalanchas de peticiones lentas o costosas.
category: traffic
order: 2
---

`ConcurrencyLimit` limita cuántas peticiones puede tener **en curso simultáneamente** una misma IP de cliente. La limitación de peticiones cuenta peticiones a lo largo del tiempo; este guard cuenta las que se están procesando en este preciso momento.

## Amenazas que mitiga

Un cliente que envía un número modesto de peticiones *lentas* o *costosas* puede quedarse por debajo de cualquier cuota por segundo y, aun así, acaparar sus recursos: exportaciones de informes, búsquedas, procesamiento de imágenes, rutas que retienen una conexión a la base de datos durante segundos. Con suficientes peticiones en paralelo, un solo cliente agota su pool de workers, su pool de conexiones o su memoria, y todos los demás esperan. Es una denegación de servicio a nivel de aplicación (OWASP API4:2023, Unrestricted Resource Consumption).

Limitar las peticiones en curso por cliente acota la parte de su capacidad que cada uno puede ocupar, sea cual sea el coste de cada petición.

## Funcionamiento

```text
ConcurrencyLimit::per_ip(2), one client IP

t0  request A arrives     in flight 1/2   accepted
t1  request B arrives     in flight 2/2   accepted
t2  request C arrives     in flight 2/2   429 too_many_concurrent
t3  response head of A    in flight 1/2   permit released
t4  request D arrives     in flight 2/2   accepted
```

* El guard mantiene un contador por IP de cliente (IPv6 agrupada por `/64`) en un almacén particionado y acotado: 64 particiones protegidas por un mutex, con las claves repartidas mediante SipHash de clave aleatoria.
* Cuando se acepta una petición, se guarda un permiso RAII en el contexto de la petición. Se libera en cuanto se genera la **cabecera de la respuesta**, o cuando la petición se cancela (desconexión del cliente, timeout): una conexión cortada nunca deja un permiso sin liberar.
* Los contadores que vuelven a cero se eliminan en cuanto un cliente no tiene nada en curso, así que la memoria sigue el número de clientes *activos*.
* El almacén sigue como máximo 500.000 clientes. Cuando está lleno, los clientes nuevos se rechazan (fallo en modo cerrado).
* Las peticiones cuya IP de cliente se desconoce no se limitan.

## Inicio rápido

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let shield = Shield::builder()
    // At most 16 simultaneous requests per client IP.
    .guard(ConcurrencyLimit::per_ip(16))
    .build();

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(shield);
```

Sirva la aplicación con `into_make_service_with_connect_info::<SocketAddr>()` para que el guard vea la dirección del cliente.

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `ConcurrencyLimit::per_ip(max)` | – | Como máximo `max` peticiones en curso por IP de cliente (mínimo 1). |
| `.monitor()` | bloqueo | Informa de las infracciones sin bloquear. |
| `.in_flight(ip)` | – | Número de peticiones en curso para `ip` en este momento. |

Comportamiento fijo: agrupación IPv6 por `/64`, como máximo 500.000 clientes seguidos.

## Ejemplos

### Proteger solo una ruta costosa

El límite de concurrencia rinde al máximo donde las peticiones son caras. Aplique el guard como capa sobre un subrouter:

```rust
use axum::{routing::{get, post}, Router};
use securite::prelude::*;

// At most 2 report exports at a time per client.
let reports = Router::new()
    .route("/reports/export", post(|| async { "export queued" }))
    .layer(ConcurrencyLimit::per_ip(2));

let app: Router = Router::new()
    .route("/", get(|| async { "home" }))
    .merge(reports)
    .layer(Shield::recommended());
```

### Detrás de un proxy inverso

Una capa independiente obtiene la IP del cliente de la dirección TCP del par, salvo que un escudo exterior ya lo haya hecho: en ese caso reutiliza el `ClientIp` de ese escudo. Detrás de un proxy, configure la fuente una sola vez, en el escudo más externo:

```rust
use axum::{routing::{get, post}, Router};
use securite::prelude::*;

let reports = Router::new()
    .route("/reports/export", post(|| async { "export queued" }))
    .layer(ConcurrencyLimit::per_ip(2));

let app: Router = Router::new()
    .route("/", get(|| async { "home" }))
    .merge(reports)
    // Outermost: the inner ConcurrencyLimit reuses the client IP it resolves.
    .layer(
        ShieldBuilder::recommended()
            .client_ip(ClientIpSource::cloudflare())
            .build(),
    );
```

### Consultar el uso en directo

Los clones comparten sus contadores, algo práctico para una ruta de diagnóstico o de métricas:

```rust
use securite::prelude::*;

let limit = ConcurrencyLimit::per_ip(8);
let handle = limit.clone(); // give `limit` to the shield, keep `handle`

let busy = handle.in_flight("203.0.113.7".parse().unwrap());
println!("203.0.113.7 has {busy} requests in flight");
```

## Uso como capa independiente

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/search", get(|| async { "results" }))
    .layer(ConcurrencyLimit::per_ip(4));
```

## Cabeceras de respuesta

Una petición rechazada recibe `429 Too Many Requests` con el código `too_many_concurrent`, en formato `application/problem+json` y con `Cache-Control: no-store`. No se envía `Retry-After`: el momento adecuado para reintentar depende de cuándo terminen las demás peticiones del cliente.

```text
HTTP/1.1 429 Too Many Requests
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Too Many Requests","status":429,"code":"too_many_concurrent","detail":"Too many concurrent requests."}
```

## Errores comunes y consejos

* **Respuestas en streaming** (descargas, Server-Sent Events, upgrades a WebSocket): el permiso se libera en cuanto se envía la cabecera de la respuesta, y el tiempo dedicado a transmitir el cuerpo no se cuenta.
* **Multiplexación HTTP/2**: un navegador que carga una página puede lanzar decenas de peticiones a la vez por una sola conexión. Deje margen por encima del número habitual de peticiones por página, o reserve el límite para las rutas de API o costosas, como en el ejemplo anterior.
* **Direcciones compartidas**: oficinas, operadores móviles y NAT corporativos sitúan a muchos usuarios detrás de una sola IP. Prefiera límites generosos en las páginas públicas.
* **Las IP desconocidas pasan**: si olvida `with_connect_info`, el guard no hace nada; el escudo solo registra una advertencia, una única vez, bajo el target `securite`.
* `ConcurrencyLimit` complementa, pero no sustituye, un tope global en su servidor: acota la parte de cada cliente, no el total.

> **Consejo:** use `ConcurrencyLimit` junto con la [limitación de peticiones](/docs/rate-limit). La limitación de peticiones acota con qué frecuencia puede llamarle un cliente; el límite de concurrencia, cuánta capacidad puede retener a la vez.

## Páginas relacionadas

* [Limitación de peticiones](/docs/rate-limit)
* [Bloqueo automático](/docs/auto-ban)
* [Límite de tamaño del cuerpo](/docs/body-limit)
* [IP del cliente detrás de un proxy](/docs/client-ip)
