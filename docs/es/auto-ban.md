---
title: Bloqueo automático
summary: Bloqueo automático al estilo fail2ban de los clientes que fallan una y otra vez la autenticación, disparan el WAF o chocan con los límites de peticiones, con duraciones crecientes.
category: traffic
order: 3
---

`AutoBan` observa el desenlace de cada petición. Cada petición bloqueada por otro guard del mismo escudo, y cada respuesta con un *estado penalizable*, suma una penalización al cliente; demasiadas penalizaciones en una ventana corta provocan su bloqueo, y los reincidentes quedan bloqueados cada vez más tiempo.

## Amenazas que mitiga

* **Fuerza bruta y credential stuffing** (OWASP A07:2021): una serie de `401` en su ruta de inicio de sesión.
* **Escáneres de vulnerabilidades y fuzzers**: una ráfaga de rechazos del WAF, de la higiene o del bloqueador de bots, o de URL desconocidas (`404`, si decide contarlas).
* **Abusos persistentes**: clientes que chocan una y otra vez con el límite de peticiones (`429`) en lugar de frenar.

Cada guard rechaza peticiones sueltas; `AutoBan` convierte un *patrón* de rechazos en un bloqueo, de modo que el atacante deja de llegar a su aplicación.

## Funcionamiento

* Tras cada respuesta, el guard suma una penalización cuando otro guard del mismo escudo ha bloqueado la petición, sea cual sea el estado: WAF, limitación de peticiones, higiene `400`, filtrado de métodos `405`, límite de cuerpo `413`, filtrado de host `421`, tipo de contenido `415`, bloqueador de bots, CSRF, filtrado por IP, `Auth` o uno de sus propios guards. También suma una cuando el estado final es *penalizable*, por defecto `401`, `403` y `429`, lo que abarca sus propios handlers, por ejemplo los inicios de sesión fallidos. Los cortocircuitos benignos (preflights CORS, redirecciones HTTPS) nunca cuentan, como tampoco las infracciones notificadas en modo monitorización.
* Las penalizaciones se cuentan en una ventana que se abre con la primera. Si se alcanza `max_strikes` dentro de `window`, el cliente queda bloqueado; si la ventana ya ha transcurrido, la cuenta vuelve a empezar.
* La comprobación del bloqueo se ejecuta con prioridad 30, justo después de los identificadores de petición: un cliente bloqueado se rechaza antes de cualquier otro trabajo, con `403 Forbidden`, el código `banned` y una cabecera `Retry-After`.
* Los bloqueos se agravan: cada nuevo bloqueo dobla la duración del anterior, hasta `max_ban`.

```text
AutoBan::new(): 20 strikes in 60 s, ban_for 15 min, max_ban 24 h

1st ban   15 min x 1    = 15 min
2nd ban   15 min x 2    = 30 min
3rd ban   15 min x 4    =  1 h
4th ban   15 min x 8    =  2 h
5th ban   15 min x 16   =  4 h
6th ban   15 min x 32   =  8 h
7th ban   15 min x 64   = 16 h
8th ban   15 min x 128  = 32 h -> capped at 24 h
```

El estado vive en un almacén en memoria particionado y acotado (64 particiones, SipHash de clave aleatoria, como máximo 500.000 clientes). Los clientes IPv6 se agrupan por `/64`, así que un atacante no puede eludir el bloqueo pasando a la siguiente dirección de su prefijo. Un cliente que nunca ha sido bloqueado se olvida en cuanto pasa `window` sin incidentes. Un cliente bloqueado al menos una vez conserva su registro, incluido su número de bloqueos, hasta que pasa `max(window, max_ban)` sin incidentes: así es como los reincidentes reciben bloqueos más largos.

## Inicio rápido

```rust
use std::time::Duration;

use axum::{routing::get, Router};
use securite::prelude::*;

let shield = Shield::builder()
    .guard(
        AutoBan::new()
            .max_strikes(10)
            .window(Duration::from_secs(60))
            .ban_for(Duration::from_secs(15 * 60)),
    )
    .build();

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(shield);
```

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `AutoBan::new()` | – | 20 penalizaciones por minuto, bloqueo de 15 minutos que se dobla hasta 24 horas. |
| `.max_strikes(n)` | `20` | Penalizaciones antes del bloqueo (mínimo 1). |
| `.window(duration)` | 60 s | Ventana en la que se cuentan las penalizaciones. |
| `.ban_for(duration)` | 15 min | Duración del primer bloqueo. |
| `.max_ban(duration)` | 24 h | Tope de los bloqueos crecientes. |
| `.count_status(code)` | – | Añade un estado penalizable (por ejemplo `404`, `400`). |
| `.statuses(codes)` | `401, 403, 429` | Sustituye la lista de estados penalizables. Las peticiones bloqueadas por otro guard cuentan en cualquier caso. |
| `.never_ban(networks)` | ninguna | IP o CIDR que nunca reciben penalizaciones. Entra en pánico con una red no válida. |
| `.ignore_paths(prefixes)` | ninguno | Las peticiones en estos prefijos de ruta nunca penalizan, estén bloqueadas o no. |
| `.monitor()` | bloqueo | Registra e informa de los bloqueos, pero deja pasar a los clientes bloqueados. |

Todos los clones de un `AutoBan` comparten el mismo estado. Conserve uno para gestionar los bloqueos en tiempo de ejecución:

| Método | Descripción |
|---|---|
| `.ban(ip, duration)` | Bloquea un cliente manualmente (cuenta para el agravamiento). |
| `.unban(ip)` | Levanta el bloqueo y olvida el historial del cliente. |
| `.is_banned(ip)` | Indica si el cliente está bloqueado ahora mismo. |
| `.banned()` | Todos los clientes bloqueados con el tiempo restante, como `Vec<(IpAddr, Duration)>`. |

## Ejemplos

### Protección en profundidad del inicio de sesión

```rust
use std::time::Duration;

use axum::http::Method;
use securite::prelude::*;

let shield = Shield::builder()
    .guard(
        RateLimit::per_second(20)
            .route_methods("/login", [Method::POST], Quota::per_minute(5)),
    )
    .guard(
        AutoBan::new()
            .max_strikes(10)
            .window(Duration::from_secs(5 * 60))
            .ban_for(Duration::from_secs(30 * 60))
            .max_ban(Duration::from_secs(7 * 24 * 3600))
            .count_status(404) // scanners probe unknown URLs
            .never_ban(["10.0.0.0/8", "192.0.2.10"]) // internal network, uptime monitor
            .ignore_paths(["/api/session"]), // SPA "am I logged in?" probe answers 401
    )
    .build();
```

Los inicios de sesión fallidos producen `401` y, cuando se agota la cuota de inicio de sesión, `429`; ambos penalizan, de modo que un cliente que intenta adivinar contraseñas queda bloqueado 30 minutos tras 10 fallos en 5 minutos.

### Rutas de administración para gestionar los bloqueos

```rust
use std::net::IpAddr;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use securite::prelude::*;

async fn list_bans(State(ban): State<AutoBan>) -> String {
    ban.banned()
        .into_iter()
        .map(|(ip, left)| format!("{ip}\t{}s\n", left.as_secs()))
        .collect()
}

async fn ban_ip(State(ban): State<AutoBan>, Path(ip): Path<IpAddr>) -> StatusCode {
    ban.ban(ip, Duration::from_secs(24 * 3600));
    StatusCode::NO_CONTENT
}

async fn unban_ip(State(ban): State<AutoBan>, Path(ip): Path<IpAddr>) -> StatusCode {
    ban.unban(ip);
    StatusCode::NO_CONTENT
}

fn app() -> Router {
    let ban = AutoBan::new();
    let shield = Shield::builder()
        // Only the internal network may reach /admin.
        .guard(IpFilter::new().allow_private().only_paths(["/admin"]))
        .guard(ban.clone())
        .build();

    Router::new()
        .route("/admin/bans", get(list_bans))
        .route("/admin/bans/{ip}", post(ban_ip).delete(unban_ip))
        .with_state(ban)
        .layer(shield)
}
```

## Uso como capa independiente

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(RateLimit::per_second(10))
    .layer(AutoBan::new()); // outermost: sees the 429s of the inner layer
```

Con axum, la última llamada a `.layer()` es la capa más externa. Coloque `AutoBan` por fuera de las capas cuyos rechazos deban contar: así, además, detiene a los clientes bloqueados antes de que lleguen a ellas. Entre capas separadas solo cuentan los estados penalizables: un `413` de un `BodyLimit` independiente no penaliza, salvo que lo añada con `count_status(413)`. Dentro de un mismo `Shield`, cada bloqueo cuenta.

## Cabeceras de respuesta

```text
HTTP/1.1 403 Forbidden
content-type: application/problem+json
cache-control: no-store
retry-after: 840

{"type":"about:blank","title":"Forbidden","status":403,"code":"banned","detail":"Your address is temporarily banned."}
```

`Retry-After` indica el tiempo de bloqueo restante en segundos. El rechazo por bloqueo nunca cuenta como penalización.

## Errores comunes y consejos

* **Direcciones compartidas**: un solo abusador detrás de un NAT corporativo o del CGNAT de un operador puede provocar el bloqueo de todos los que comparten su dirección. Use `never_ban` para los socios y las oficinas que conozca.
* **Detrás de un proxy**, configure `ShieldBuilder::client_ip`; de lo contrario, el primer bloqueo deja fuera al proxy y, con él, a todo el mundo. Con capas independientes, ponga `Shield::builder().client_ip(ClientIpSource::heroku()).build()` (o la fuente de su plataforma) como capa más externa, consulte [IP del cliente](/docs/client-ip).
* **Cuente los `404` con cautela**: los enlaces rotos, los marcadores antiguos y los rastreadores también los generan. Aumente `max_strikes` si los añade.
* **Los bloqueos manuales ignoran `never_ban`**, y `unban` reinicia el historial de agravamiento.
* `banned()` identifica a los clientes IPv6 por la dirección de su red `/64`.
* El estado es propio de cada proceso y se pierde al reiniciar. Con varias réplicas, cada instancia bloquea por su cuenta.
* En modo monitorización, los bloqueos se siguen registrando y anotando en el log (`client banned`), y las peticiones de los clientes bloqueados se notifican en lugar de rechazarse.

> **Atención:** proteja las rutas que llaman a `ban` y `unban` (filtrado por IP, `Auth`): cualquiera que pueda alcanzarlas puede dejar fuera a usuarios legítimos o desbloquearse a sí mismo.

## Páginas relacionadas

* [Limitación de peticiones](/docs/rate-limit)
* [Filtrado por IP](/docs/ip-filter)
* [Límite de concurrencia](/docs/concurrency-limit)
* [Cortafuegos de aplicaciones web (WAF)](/docs/waf)
