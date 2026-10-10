---
title: Eventos de seguridad y estadísticas
summary: Cada bloqueo o detección en modo monitorización se convierte en un evento de seguridad estructurado para sus registros, métricas, SIEM o alertas, y los contadores en tiempo real pueden exponerse en JSON.
category: integrity
order: 3
---

Bloquear ataques es solo la mitad del trabajo: también hay que saber qué se bloquea, con qué guard, desde dónde y si una regla nueva está perjudicando a usuarios reales. Cada vez que un guard rechaza una petición, o la habría rechazado en modo monitorización, el escudo emite un `SecurityEvent`, lo escribe con `tracing` y actualiza unos contadores en tiempo real que puede consultar en cualquier momento.

## Por qué es importante

**A09:2021 Security Logging and Monitoring Failures** sitúa entre las debilidades más comunes la falta de registros de los eventos de seguridad, de umbrales de alerta y de detección en tiempo real. Los eventos que se describen a continuación le proporcionan de serie una pista de auditoría estructurada y de baja cardinalidad, y el hook le permite enviarla allí donde su equipo ya mira.

## El `SecurityEvent`

| Campo | Tipo | Descripción |
|---|---|---|
| `guard` | `&'static str` | Nombre del guard: `waf`, `rate_limit`, `auth`, `bot_blocker`… |
| `code` | `&'static str` | Código de rechazo legible por máquina: `waf_blocked`, `rate_limited`… |
| `status` | `StatusCode` | Estado devuelto (o que se habría devuelto en modo monitorización). |
| `enforced` | `bool` | `false` cuando el guard funciona en modo monitorización. |
| `client_ip` | `Option<IpAddr>` | Dirección IP del cliente resuelta, si se conoce. |
| `method` | `&Method` | Método de la petición. |
| `path` | `&str` | Ruta de la petición, sin la cadena de consulta. |
| `request_id` | `Option<&str>` | Identificador de la petición, cuando hay un guard `RequestId` activo. |
| `message` | `&str` | Mensaje enviado al cliente. |
| `details` | `Option<&str>` | Detalles solo para auditoría, como `score=8 rules=[143, 100] categories=sqli`. |

Se emite un evento por cada rechazo de un guard del escudo, tanto en modo bloqueo como en modo monitorización. No se emite ningún evento para las peticiones permitidas, para los cortocircuitos benignos (respuestas a preflights de CORS, redirecciones HTTPS), para los rechazos de `SignatureLayer` (que solo se escriben con `tracing`) ni para las llamadas a `Waf::inspect_text` hechas en sus handlers.

## Registro integrado con tracing

Por defecto, los eventos se escriben con `tracing` bajo el target `securite`:

- con nivel `WARN` y el mensaje `request blocked` para los rechazos efectivos;
- con nivel `INFO` y el mensaje `violation (monitor mode)` para las detecciones en modo monitorización.

Cada línea incluye los campos `guard`, `code`, `status`, `ip`, `method`, `path`, `request_id` y `details`. `AutoBan` también registra `client banned` con nivel `WARN`, y `SignatureLayer` registra `webhook signature rejected`.

```rust
// Requires tracing-subscriber with the "env-filter" feature.
tracing_subscriber::fmt()
    .with_env_filter("info,securite=info")
    .init();
```

```text
2026-10-10T08:12:44.913245Z  WARN securite: request blocked guard="waf" code="waf_blocked" status=403 ip=Some(203.0.113.7) method=GET path="/search" request_id="3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44" details="score=8 rules=[143, 100] categories=sqli"
```

```bash
# Blocked requests only
RUST_LOG=info,securite=warn ./my-service
# Blocked requests and monitor-mode findings
RUST_LOG=info,securite=info ./my-service
```

Llame a `.log_events(false)` en el builder si prefiere tratar los eventos únicamente a través de su hook.

## El hook `on_event`

`ShieldBuilder::on_event` registra una función que se llama de forma síncrona para cada evento. Conecte ahí sus métricas, su SIEM o sus alertas.

### Contador de métricas

Con el crate `metrics` (exportadores de Prometheus, StatsD, OpenTelemetry…):

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .on_event(|e| {
        metrics::counter!(
            "securite_events_total",
            "guard" => e.guard,
            "code" => e.code,
            "enforced" => if e.enforced { "true" } else { "false" }
        )
        .increment(1);
    })
    .build();
```

### Alertas

El hook se ejecuta en la ruta de la petición: no bloquee nunca dentro de él. Copie lo que necesite en un valor con propiedad y páselo a una tarea en segundo plano mediante un canal:

```rust
use std::net::IpAddr;

use securite::prelude::*;
use tokio::sync::mpsc;

#[derive(Debug)]
struct Alert {
    guard: &'static str,
    code: &'static str,
    ip: Option<IpAddr>,
    path: String,
    request_id: Option<String>,
    details: Option<String>,
}

let (tx, mut rx) = mpsc::channel::<Alert>(1024);

tokio::spawn(async move {
    while let Some(alert) = rx.recv().await {
        // Post to Slack, PagerDuty or your SIEM here.
        eprintln!("security alert: {alert:?}");
    }
});

let shield = ShieldBuilder::recommended()
    .on_event(move |e| {
        if e.enforced && matches!(e.guard, "waf" | "auth" | "ban") {
            // try_send never blocks: alerts are dropped if the queue is full.
            let _ = tx.try_send(Alert {
                guard: e.guard,
                code: e.code,
                ip: e.client_ip,
                path: e.path.to_owned(),
                request_id: e.request_id.map(str::to_owned),
                details: e.details.map(str::to_owned),
            });
        }
    })
    .build();
```

## Estadísticas en tiempo real

`Shield::stats()` devuelve un `StatsSnapshot`, una copia instantánea de contadores sin bloqueos:

| Elemento | Tipo | Descripción |
|---|---|---|
| `total` | `u64` | Peticiones vistas por el escudo. |
| `blocked` | `u64` | Peticiones rechazadas por un guard en modo bloqueo. |
| `monitored` | `u64` | Infracciones notificadas por guards en modo monitorización. |
| `by_guard` | `Vec<(&'static str, u64)>` | Infracciones por guard (bloqueadas y monitorizadas), en orden de ejecución. |
| `allowed()` | `u64` | `total` menos `blocked`. |
| `to_json()` | `String` | La instantánea como objeto JSON compacto. |

### Exponer un endpoint de administración

Conserve un clon del escudo (es un `Arc`) y sirva la instantánea detrás de una autenticación:

```rust
use axum::{extract::State, http::header, response::IntoResponse, routing::get, Router};
use securite::prelude::*;

async fn security_stats(State(shield): State<Shield>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        shield.stats().to_json(),
    )
}

let admin_token = std::env::var("ADMIN_TOKEN").expect("ADMIN_TOKEN must be set");
let shield = ShieldBuilder::recommended()
    .guard(Auth::bearer().token("ops", &admin_token).protect(["/admin"]))
    .build();

let app: Router = Router::new()
    .route("/admin/security/stats", get(security_stats))
    .with_state(shield.clone())
    .layer(shield);
```

```json
{
  "total": 15230,
  "allowed": 15102,
  "blocked": 128,
  "monitored": 0,
  "by_guard": {
    "request_id": 0,
    "hygiene": 4,
    "method": 2,
    "body_limit": 0,
    "rate_limit": 61,
    "bot_blocker": 17,
    "waf": 39,
    "csrf": 1,
    "auth": 4,
    "security_headers": 0,
    "cookies": 0
  }
}
```

`to_json()` devuelve el mismo objeto en una sola línea.

## Errores comunes y consejos

- Los contadores viven en memoria, por escudo y por proceso: vuelven a cero en cada despliegue y no se comparten entre instancias. Use el hook y su sistema de métricas para obtener cifras de toda la flota y a largo plazo.
- Una capa independiente construye su propio escudo interno, cuyas estadísticas no puede leer. Construya un `Shield`, conserve un clon y registre en él sus guards.
- `total` también cuenta los cortocircuitos benignos, como los preflights de CORS y las redirecciones HTTPS; forman parte de `allowed()`.
- No use nunca la dirección IP del cliente ni la ruta como etiquetas de métricas: su cardinalidad es ilimitada y la controlan los atacantes. Quédese con `guard`, `code` y `enforced`.
- Proteja el endpoint de estadísticas: le revela a un atacante qué guards están activos y cuáles de sus intentos tienen éxito.
- Los `details` son solo para usted. Nunca se envían a los clientes, así que no los copie en las respuestas.

## Páginas relacionadas

- [Modo monitorización](/docs/monitor-mode)
- [Identificadores de petición](/docs/request-id)
- [Formato de las respuestas de error](/docs/error-format)
- [Firewall de aplicaciones web (WAF)](/docs/waf)
- [Autenticación](/docs/auth)
