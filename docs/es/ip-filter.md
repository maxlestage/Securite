---
title: Filtrado por IP
summary: Listas CIDR de permitidos y denegados para IPv4 e IPv6, acotables a ciertas rutas, con búsquedas en O(log n) y listas que se pueden actualizar en caliente.
category: access
order: 1
---

`IpFilter` decide, a partir de la dirección del cliente, si una petición puede seguir adelante. Úselo para limitar los paneles de administración a la red interna, bloquear redes maliciosas conocidas procedentes de un feed de threat intelligence o reservar una API de socios a los rangos de sus clientes.

## Amenazas que mitiga

* **Back-offices expuestos** (OWASP A01:2021, Broken Access Control): paneles de administración, métricas y herramientas internas accesibles desde Internet. Una lista de permitidos añade una barrera de red además de la autenticación.
* **Orígenes maliciosos conocidos**: escáneres, botnets, proveedores de hosting abusivos, nodos de salida de Tor o regiones a las que no da servicio, expresados como bloques CIDR.
* **Respuesta a incidentes**: bloquee una red atacante en segundos, sin volver a desplegar.

## Funcionamiento

### Reglas de decisión

```text
only_paths set and path not matched -> pass (filter not applied)
client IP in deny-list              -> 403 ip_blocked   (deny always wins)
allow-list empty                    -> pass
client IP in allow-list             -> pass
otherwise                           -> 403 ip_blocked
```

| Lista de permitidos | Cliente | Resultado |
|---|---|---|
| vacía | en la lista de denegados | bloqueado |
| vacía | no listado | permitido |
| vacía | IP desconocida | permitido |
| no vacía | en la lista de denegados | bloqueado |
| no vacía | en la lista de permitidos | permitido |
| no vacía | no listado | bloqueado |
| no vacía | IP desconocida | bloqueado (fallo en modo cerrado) |

### IpSet: rangos ordenados, búsqueda binaria

Las listas se guardan como un `IpSet`. Cada IP o CIDR se convierte en un rango `[start, end]` dentro de un único espacio de 128 bits: IPv4 ocupa el bloque IPv4-mapped `::ffff:0:0/96`, y las direcciones de cliente IPv4-mapped (`::ffff:203.0.113.9`) se convierten antes a IPv4. Los rangos se ordenan y los que se solapan o son contiguos se fusionan, de modo que una consulta es una única búsqueda binaria: `O(log n)`, tenga la lista diez entradas o cien mil.

Sintaxis aceptada: `"192.0.2.7"` (host único), `"10.0.0.0/8"`, `"2001:db8::/32"`. Los bits de host posteriores al prefijo se ignoran (`10.1.2.3/8` equivale a `10.0.0.0/8`).

### Actualizaciones en caliente

Las listas están protegidas por un cerrojo de lectura-escritura compartido por todos los clones del filtro. Las peticiones toman el cerrojo de lectura lo que dura una búsqueda binaria. `replace_deny_list` y `replace_allow_list` reciben un conjunto construido de antemano, así que el cerrojo de escritura solo se mantiene durante un intercambio; `deny_now` y `allow_now` fusionan su red en la lista con el cerrojo tomado. Los métodos de construcción (`allow`, `deny`, `try_allow`, `try_deny`, `allow_private`) funcionan con copia en escritura: el filtro que devuelven recibe sus propias listas, y los clones creados antes no cambian. Termine primero la configuración y después conserve un clon como manejador y entregue el otro al escudo.

## Inicio rápido

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let shield = Shield::builder()
    .guard(IpFilter::new().deny(["203.0.113.0/24", "2001:db8:bad::/48"]))
    .build();

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(shield);
```

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `IpFilter::new()` | – | Filtro vacío: todo el mundo pasa. |
| `.allow(networks)` | vacía | Añade IP o CIDR a la lista de permitidos. Entra en pánico con una entrada no válida. |
| `.deny(networks)` | vacía | Añade IP o CIDR a la lista de denegados. Entra en pánico con una entrada no válida. |
| `.try_allow(networks)` | – | Variante falible de `allow`; devuelve `Result<IpFilter, InvalidNetwork>`. |
| `.try_deny(networks)` | – | Variante falible de `deny`. |
| `.allow_private()` | – | Añade a la lista de permitidos los rangos privados, de loopback, link-local y CGNAT. |
| `.only_paths(prefixes)` | todas las rutas | Aplica el filtro solo a estos prefijos de ruta. |
| `.monitor()` | bloqueo | Informa de las infracciones sin bloquear. |
| `.deny_now(network)` | – | Añade una red a la lista de denegados en caliente (`Result`), para todos los clones. |
| `.allow_now(network)` | – | Añade una red a la lista de permitidos en caliente (`Result`), para todos los clones. |
| `.replace_deny_list(set)` | – | Sustituye toda la lista de denegados. |
| `.replace_allow_list(set)` | – | Sustituye toda la lista de permitidos. |
| `.is_allowed(Option<IpAddr>)` | – | Evalúa las listas para una dirección. |

Un `IpSet` se construye con `IpSet::parse(items)`, con `str::parse` sobre una lista separada por comas o espacios, o con `IpSet::private_networks()` (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `100.64.0.0/10`, `::1/128`, `fc00::/7`, `fe80::/10`). Ofrece `contains(ip)`, `len()` e `is_empty()`. Como IPv4 reside en el rango IPv4-mapped, un conjunto que contiene `::/0` contiene también todas las direcciones IPv4. Los errores de análisis son de tipo `securite::ip_filter::InvalidNetwork`, que también exporta el preludio.

## Ejemplos

### Panel de administración restringido a la oficina y a la VPN

```rust
use securite::prelude::*;

let shield = Shield::builder()
    .client_ip(ClientIpSource::cloudflare())
    .guard(
        IpFilter::new()
            .allow_private() // VPN and internal tools
            .allow(["198.51.100.10", "2001:db8:abcd::/48"]) // office
            .only_paths(["/admin", "/metrics"]),
    )
    .build();
```

Cualquiera puede acceder al sitio público; solo las redes de la lista llegan a `/admin` y `/metrics`.

### Bloquear una red durante un incidente

```rust
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use securite::prelude::*;

async fn block(State(filter): State<IpFilter>, Path(cidr): Path<String>) -> StatusCode {
    // `cidr` arrives percent-decoded, e.g. "203.0.113.0/24" sent as 203.0.113.0%2F24.
    match filter.deny_now(&cidr) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

fn app() -> Router {
    let filter = IpFilter::new();
    let admin = IpFilter::new().allow_private().only_paths(["/admin"]);
    // Both guards are named "ip_filter": the second would replace the first in
    // one shield, so each one gets its own layer.
    Router::new()
        .route("/admin/block/{cidr}", post(block))
        .with_state(filter.clone())
        .layer(admin)
        .layer(Shield::builder().guard(filter).build())
}
```

### Refrescar una lista de denegados desde un feed

```rust
use std::time::Duration;

use securite::prelude::*;

async fn load_blocklist() -> std::io::Result<String> {
    tokio::fs::read_to_string("/etc/myapp/blocklist.txt").await
}

fn spawn_refresher(filter: IpFilter) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(600));
        loop {
            every.tick().await;
            let Ok(text) = load_blocklist().await else { continue };
            let entries = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'));
            match IpSet::parse(entries) {
                Ok(set) => filter.replace_deny_list(set),
                Err(e) => eprintln!("blocklist ignored: {e}"),
            }
        }
    });
}
```

Llame a `spawn_refresher(filter.clone())` y entregue `filter` al escudo. Un archivo no válido se ignora y la lista anterior sigue activa.

## Uso como capa independiente

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/metrics", get(|| async { "up 1" }))
    .layer(IpFilter::new().allow_private());
```

## Cabeceras de respuesta

`IpFilter` no añade ninguna cabecera específica. Los clientes bloqueados reciben una respuesta deliberadamente escueta; la dirección del cliente solo se anota en los detalles de auditoría del evento de seguridad (`ip=203.0.113.9`).

```text
HTTP/1.1 403 Forbidden
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Forbidden","status":403,"code":"ip_blocked","detail":"Access denied."}
```

## Errores comunes y consejos

* **Detrás de un proxy, configure `ShieldBuilder::client_ip`**. De lo contrario, todas las peticiones parecen venir del proxy: con `allow_private()`, su panel de administración queda abierto a todo Internet, y una regla de denegación puede bloquear a todo el mundo. Con capas independientes, ponga `Shield::builder().client_ip(ClientIpSource::heroku()).build()` (o la fuente de su plataforma) como capa más externa, consulte [IP del cliente](/docs/client-ip).
* **`::/0` también abarca todas las direcciones IPv4**, porque IPv4 se proyecta en el espacio IPv6. `0.0.0.0/0` solo abarca IPv4.
* **Los métodos de construcción funcionan con copia en escritura**: llamar a `.allow()`, `.deny()`, `try_allow`, `try_deny` o `allow_private()` sobre un clon devuelve un filtro con sus propias listas y nunca modifica el original. Solo `deny_now`, `allow_now`, `replace_deny_list` y `replace_allow_list` actúan sobre las listas vivas que comparten todos los clones, así que obtenga su manejador después de la última llamada de construcción.
* Un solo `IpFilter` por escudo: los guards se identifican por su nombre, así que un segundo sustituye al primero. Use capas separadas, como en el ejemplo anterior.
* No existe la eliminación de una entrada suelta: reconstruya la lista y llame a `replace_deny_list` o `replace_allow_list`.
* `IpFilter` se ejecuta con prioridad 40, justo después de `AutoBan`, así que los clientes bloqueados apenas cuestan nada.

> **Consejo:** una lista de IP permitidas es una segunda barrera, no una autenticación. Mantenga también la [autenticación](/docs/auth) en las rutas de administración.

## Páginas relacionadas

* [Bloqueo automático](/docs/auto-ban)
* [Limitación de peticiones](/docs/rate-limit)
* [IP del cliente detrás de un proxy](/docs/client-ip)
* [Autenticación](/docs/auth)
