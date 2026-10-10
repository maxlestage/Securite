---
title: Limitación de peticiones
summary: Limitación de peticiones GCRA exacta por IP, clave de API, ruta o clave personalizada, con las cabeceras RateLimit estándar y un almacén acotado que falla en modo cerrado.
category: traffic
order: 1
---

`RateLimit` limita cuántas peticiones puede enviar un cliente a lo largo del tiempo: por IP de cliente de forma predeterminada, con reglas opcionales por ruta y claves de API o personalizadas. El tráfico excedente recibe `429 Too Many Requests` con una cabecera `Retry-After`.

## Amenazas que mitiga

* **Fuerza bruta y credential stuffing** en el inicio de sesión, el restablecimiento de contraseña o los códigos de un solo uso (OWASP A07:2021, Identification and Authentication Failures).
* **Denegación de servicio a nivel de aplicación y scraping**: un único cliente que machaca rutas costosas (OWASP API4:2023, Unrestricted Resource Consumption).
* **Abuso de efectos secundarios costosos**: correos, SMS o llamadas de pago a API de terceros.

Se ejecuta dentro de su proceso, así que no detiene un DDoS volumétrico: para eso, mantenga una CDN o un balanceador de carga delante.

## Funcionamiento

### GCRA en un esquema

El limitador usa GCRA (Generic Cell Rate Algorithm) y guarda un único `u64` por cliente: el *tiempo teórico de llegada* (TAT). Una cuota define un intervalo de emisión `T` y una tolerancia `tau = T x (burst - 1)`.

```text
Quota::per_second(10).burst(3)
  T   = 1 s / 10        = 100 ms
  tau = T x (burst - 1) = 200 ms

time     request  TAT - now          verdict                  new TAT
0 ms     #1       0                  ok   (remaining 2)       100
0 ms     #2       100                ok   (remaining 1)       200
0 ms     #3       200                ok   (remaining 0)       300
0 ms     #4       300  > tau         429, retry in 100 ms     300
100 ms   #5       200 <= tau         ok                       400
```

Para cada petición, `tat = max(TAT, now)`. Si `tat - now > tau`, la petición llega demasiado pronto: se rechaza con `Retry-After = tat - now - tau`, redondeado al segundo superior. Si no, el TAT avanza a `tat + T`. Se comporta como un cubo de tokens de capacidad `burst` que recibe un token a cada intervalo `T`, sin temporizadores en segundo plano y sin las ráfagas en el borde de ventana típicas de las ventanas fijas.

### Un almacén particionado y acotado

* Cada regla tiene su propio almacén de 64 particiones protegidas por un mutex, de modo que clientes distintos rara vez compiten entre sí.
* Las claves se reparten con SipHash de clave aleatoria: no es posible fabricar claves que colisionen (HashDoS).
* Una entrada caduca en cuanto su cubo vuelve a estar lleno; las entradas caducadas se purgan cada 4.096 operaciones en una partición y siempre que una partición se llena.
* Cada regla sigue como máximo `max_entries` claves (1.000.000 por defecto, unos 50 MB en el peor caso). Cuando una partición está llena de clientes activos, los clientes **nuevos** reciben `429` (fallo en modo cerrado) mientras los conocidos conservan su cubo: rotar claves no puede agotar su memoria.
* Los clientes IPv6 se agrupan por `/64`, el bloque que los proveedores suelen asignar a cada abonado, así que cambiar de dirección no permite eludir el límite.

## Inicio rápido

```rust
use std::net::SocketAddr;

use axum::{routing::get, Router};
use securite::prelude::*;

#[tokio::main]
async fn main() {
    let shield = Shield::builder()
        // 10 requests per second per client IP, bursts of up to 30.
        .guard(RateLimit::per_second(10).burst(30))
        .build();

    let app = Router::new()
        .route("/", get(|| async { "hello" }))
        .layer(shield);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    // `with_connect_info` gives the shield the real peer address.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
```

## Configuración

### Quota

| Método | Valor por defecto | Descripción |
|---|---|---|
| `Quota::new(n, period)` | burst = `n` | `n` peticiones por `period`. Entra en pánico si `n == 0` o si `period` es cero. |
| `Quota::per_second(n)`, `Quota::per_minute(n)`, `Quota::per_hour(n)` | burst = `n` | Atajos para los periodos habituales. |
| `.burst(b)` | `n` | Capacidad del cubo: peticiones permitidas de golpe (mínimo 1). |
| `.burst_size()`, `.replenish_interval()` | – | Devuelven la capacidad y `T = period / n`. |

### RateLimit

| Método | Valor por defecto | Descripción |
|---|---|---|
| `RateLimit::new(quota)` | – | Una regla global, por IP de cliente. |
| `RateLimit::per_second(n)`, `RateLimit::per_minute(n)`, `RateLimit::per_hour(n)` | burst = `n` | Atajos de `RateLimit::new(Quota::per_second(n))`, `per_minute` y `per_hour`. |
| `.burst(n)` | burst de la cuota | Ráfaga de la regla global. |
| `.key(key)` | `RateLimitKey::Ip` | Qué cuenta la regla global. |
| `.route(prefix, quota)` | – | Regla adicional por IP para un prefijo de ruta. |
| `.route_keyed(prefix, quota, key)` | – | Regla adicional para un prefijo, con cualquier clave. |
| `.route_methods(prefix, methods, quota)` | – | Regla adicional por IP para algunos métodos en un prefijo. |
| `.headers(style)` | `HeaderStyle::Standard` | Qué cabeceras de limitación se envían. |
| `.ipv6_prefix(bits)` | `64` | Prefijo de agrupación IPv6 (limitado a 128). |
| `.skip_paths(prefixes)` | ninguno | Prefijos de ruta que nunca se limitan. |
| `.max_entries(n)` | `1_000_000` | Claves seguidas por regla, repartidas en 64 particiones (al menos 16 por partición). |
| `.monitor()` | bloqueo | Informa de las infracciones sin bloquear. |

La regla global se aplica a todas las rutas salvo `skip_paths`. Toda regla que coincida debe cumplirse; las reglas se evalúan en orden de declaración y el primer fallo responde `429`. Los prefijos se comparan por segmentos: `/api` cubre `/api/users`, pero no `/apiary`.

### Claves

| Variante | Cuenta las peticiones por |
|---|---|
| `RateLimitKey::Ip` | IP del cliente, IPv6 enmascarada a `ipv6_prefix`. Por defecto. |
| `RateLimitKey::Header(name)` | Valor de una cabecera; si falta, está vacía o supera 256 bytes, se usa la IP. |
| `RateLimitKey::Global` | Un único cubo compartido por todos (tope de caudal). |
| `RateLimitKey::custom(f)` | Su closure `Fn(&Parts, &Context) -> Option<String>`. Devolver `None` omite la regla para esa petición. |

`RateLimitKey::custom(f)` construye por usted la variante `RateLimitKey::Custom(Arc<KeyFn>)`.

## Ejemplos

### Inicio de sesión y restablecimiento de contraseña

```rust
use axum::http::Method;
use securite::prelude::*;

let limiter = RateLimit::new(Quota::per_second(20).burst(50))
    // 5 login attempts per minute and per IP, POST only.
    .route_methods("/login", [Method::POST], Quota::per_minute(5))
    // Reset e-mails are expensive and easy to abuse.
    .route("/password-reset", Quota::per_hour(10))
    // Never throttle load balancer probes.
    .skip_paths(["/health", "/ready"]);
```

`Quota::per_minute(5)` permite 5 intentos de golpe y, después, uno cada 12 segundos.

### Claves de API y topes globales

```rust
use axum::http::HeaderName;
use securite::prelude::*;

let limiter = RateLimit::per_second(50)
    // Each API key gets its own bucket on /api.
    .route_keyed(
        "/api",
        Quota::per_minute(600).burst(100),
        RateLimitKey::Header(HeaderName::from_static("x-api-key")),
    )
    // Protect a fragile upstream: 200 searches per second for all clients combined.
    .route_keyed("/search", Quota::per_second(200), RateLimitKey::Global);
```

> **Atención:** el valor de una cabecera lo elige el cliente, y `Auth` se ejecuta después de `RateLimit`. Un atacante que envía una clave aleatoria distinta en cada petición obtiene un cubo nuevo cada vez. Mantenga la regla global por IP para que esas peticiones sigan limitadas por dirección.

### Clave personalizada

```rust
use securite::prelude::*;

let internal = IpSet::private_networks();
// Count by IP, but never limit internal callers.
let key = RateLimitKey::custom(move |_req, ctx| {
    let ip = ctx.client_ip()?;
    (!internal.contains(ip)).then(|| ip.to_string())
});

let limiter = RateLimit::per_second(10).key(key);
```

Las claves personalizadas reciben la IP sin procesar: aplique su propia agrupación IPv6 si construye claves a partir de ella.

### Empezar en modo monitorización

```rust
use securite::prelude::*;

let shield = Shield::builder()
    .guard(RateLimit::per_second(5).monitor())
    .on_event(|e| {
        if e.guard == "rate_limit" {
            eprintln!("would throttle {:?} on {}", e.client_ip, e.path);
        }
    })
    .build();
```

Observe durante unos días a quién se habría limitado y después quite `.monitor()`.

## Uso como capa independiente

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(RateLimit::per_minute(120));

// Or replace the limiter of a preset (guards with the same name are replaced).
let shield = ShieldBuilder::recommended()
    .guard(RateLimit::per_minute(600))
    .build();
```

Los clones de un `RateLimit` comparten sus contadores: el mismo limitador aplicado a varias rutas las contabiliza juntas.

## Cabeceras de respuesta

Las respuestas aceptadas reflejan el estado de la regla coincidente más restrictiva. Con `HeaderStyle::Standard` (borrador del IETF):

```text
ratelimit-limit: 30
ratelimit-remaining: 29
ratelimit-reset: 1
```

`HeaderStyle::Legacy` envía `x-ratelimit-*` en su lugar; `HeaderStyle::None` solo mantiene `Retry-After` en los rechazos. `HeaderStyle` forma parte del preludio. Un rechazo tiene este aspecto:

```text
HTTP/1.1 429 Too Many Requests
content-type: application/problem+json
cache-control: no-store
retry-after: 12
ratelimit-limit: 5
ratelimit-remaining: 0
ratelimit-reset: 12

{"type":"about:blank","title":"Too Many Requests","status":429,"code":"rate_limited","detail":"Too many requests, slow down."}
```

## Errores comunes y consejos

* **IP de cliente desconocida**: sin `into_make_service_with_connect_info::<SocketAddr>()`, las reglas por IP no ven al cliente y *todas* las peticiones comparten un solo cubo. En ese caso, el shield registra una advertencia una sola vez, bajo el target `securite`.
* **Detrás de un proxy**, configure `ShieldBuilder::client_ip`; de lo contrario, todos los clientes son el proxy. Con capas independientes, ponga `Shield::builder().client_ip(ClientIpSource::heroku()).build()` (o la fuente de su plataforma) como capa más externa: las capas interiores reutilizan la dirección que este resolvió, consulte [IP del cliente](/docs/client-ip).
* **Un solo limitador por escudo**: un segundo `RateLimit` pasado a `.guard()` sustituye al primero. Añada reglas con `.route*()`.
* **El estado es propio de cada proceso**: con N réplicas, el límite efectivo es N veces mayor.
* Las reglas evaluadas antes de la que falla ya han consumido un token.
* `RateLimit` se ejecuta después de `AutoBan`, `IpFilter`, `Hygiene`, `MethodFilter` y `BodyLimit`, y antes del WAF, CSRF y `Auth`.

> **Consejo:** combínelo con el [bloqueo automático](/docs/auto-ban): cada `429` cuenta como una penalización, así que los clientes que chocan una y otra vez con el límite acaban bloqueados.

## Páginas relacionadas

* [Bloqueo automático](/docs/auto-ban)
* [Límite de concurrencia](/docs/concurrency-limit)
* [Filtrado por IP](/docs/ip-filter)
* [IP del cliente detrás de un proxy](/docs/client-ip)
