---
title: Guards personalizados
summary: Escribe tus propias reglas de seguridad implementando el trait Guard, rechaza peticiones con errores estructurados y regístralas en cualquier shield.
category: start
order: 6
---

Los guards integrados cubren las amenazas genéricas, pero tu aplicación tiene sus propias reglas: una ventana de mantenimiento, una red de socios, una restricción al horario laboral. Implementa el trait `Guard` y tu regla obtendrá todo lo que tienen los guards integrados: orden de ejecución, errores estructurados, eventos, estadísticas y modo observación.

## El trait Guard

```rust
pub trait Guard: Send + Sync + 'static {
    /// Stable, machine readable name (logs, events, stats, `without`).
    fn name(&self) -> &'static str;

    /// Execution order, lower runs first. Default: `priority::CUSTOM` (500).
    fn priority(&self) -> u16 { priority::CUSTOM }

    /// `Mode::Enforce` (default) or `Mode::Monitor`.
    fn mode(&self) -> Mode { Mode::Enforce }

    /// Inspect (and possibly modify) the request head. `Err` stops the pipeline.
    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        Ok(())
    }

    /// Decorate the response head (handler responses and rejections alike).
    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {}
}
```

Solo `name()` es obligatorio. Los módulos `request` y `response` proceden del crate `http`, que securite reexporta: `use securite::http::{request::Parts, StatusCode};` funciona sin añadir `http` a tus dependencias.

| Método | Función |
|---|---|
| `name` | Identifica el guard; `.guard()` sustituye a cualquier guard con el mismo nombre |
| `priority` | Posición en el pipeline; consulta las constantes en [Shield y presets](/docs/shield-presets) |
| `mode` | Devuelve `Mode::Monitor` para notificar infracciones sin bloquear |
| `on_request` | Examina el método, la URI, las cabeceras y las extensiones; devuelve `Err(Rejection)` para bloquear |
| `on_response` | Añade o quita cabeceras de respuesta; se llama para todas las respuestas |

## Rechazos

| API | Efecto |
|---|---|
| `Rejection::new(status, code, message)` | Rechazo bloqueante: se registra, se contabiliza y se presenta con el formato de error del shield |
| `Rejection::respond(status, code)` | Cortocircuito benigno (redirección, preflight): cuerpo vacío, ni se registra ni se contabiliza |
| `.with_header(name, value)` | Añade una cabecera de respuesta como `Retry-After` o `WWW-Authenticate` |
| `.with_details(text)` | Detalles solo para auditoría: se escriben en eventos y logs, nunca se envían al cliente |

`code` es un identificador corto y estable, como `maintenance`, que aparece en el cuerpo problem+json, en los eventos y en las estadísticas. `message` se muestra al cliente: mantenlo genérico y deja los valores detectados para `details`.

## El contexto de la petición

Todos los guards comparten `Context` durante toda la vida de una petición:

| Método | Descripción |
|---|---|
| `client_ip()` | Dirección resuelta del cliente, `Option<IpAddr>` (consulta [IP del cliente](/docs/client-ip)) |
| `method()`, `uri()`, `path()` | Línea de petición tal y como la recibió el shield |
| `request_id()` | Identificador asignado por `RequestId`, que se ejecuta primero |
| `rejected_by()` | Nombre del guard que rechazó la petición, útil en `on_response` |
| `blocked()` | Indica si un guard bloqueó la petición; los cortocircuitos benignos, como los preflights CORS o las redirecciones HTTPS, no cuentan |
| `started()` | `Instant` en el que el shield empezó a procesar la petición |
| `csp_nonce()` | Nonce de CSP de la petición, cuando está activado |
| `add_set_cookie(value)` | Añade una cabecera `Set-Cookie` a la respuesta final |
| `hold(value)` | Mantiene vivo un valor hasta que se genera la cabecera de la respuesta y luego lo libera |
| `extensions()`, `extensions_mut()` | Almacenamiento tipado reservado a los guards |
| `Context::new(method, uri, client_ip)` | Crea un contexto fuera de cualquier shield, para hacer pruebas unitarias de un guard |

## Ejemplo: modo mantenimiento

Este guard responde `503 Service Unavailable` mientras dura el mantenimiento, salvo a la red del equipo y al health check, y puede activarse o desactivarse en caliente:

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use securite::http::header::{HeaderValue, RETRY_AFTER};
use securite::http::{StatusCode, request, response};
use securite::prelude::*;
use securite::priority;

/// Marker stored in the context when staff bypass maintenance.
#[derive(Clone)]
struct StaffBypass;

/// Answers `503` to everyone but staff while maintenance is on.
#[derive(Clone)]
pub struct Maintenance {
    enabled: Arc<AtomicBool>,
    staff: IpSet,
}

impl Maintenance {
    pub fn new(staff: IpSet) -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(false)),
            staff,
        }
    }

    /// Shared by every clone: flip it from an admin endpoint or a signal handler.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }
}

impl Guard for Maintenance {
    fn name(&self) -> &'static str {
        "maintenance"
    }

    // Right after the request id, before bans, rate limiting and the WAF.
    fn priority(&self) -> u16 {
        priority::REQUEST_ID + 5
    }

    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        if !self.enabled.load(Ordering::Relaxed) || req.uri.path() == "/health" {
            return Ok(());
        }
        if ctx.client_ip().is_some_and(|ip| self.staff.contains(ip)) {
            ctx.extensions_mut().insert(StaffBypass);
            return Ok(());
        }
        Err(Rejection::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "maintenance",
            "The service is under maintenance, please retry in a few minutes.",
        )
        .with_header(RETRY_AFTER, HeaderValue::from_static("600"))
        .with_details(format!("path={}", req.uri.path())))
    }

    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {
        if ctx.extensions().get::<StaffBypass>().is_some() {
            res.headers
                .insert("x-maintenance-bypass", HeaderValue::from_static("staff"));
        }
    }
}
```

### Registrarlo

Guarda un clon del guard: todos los clones comparten el mismo indicador.

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

let maintenance = Maintenance::new(
    IpSet::parse(["10.0.0.0/8", "192.0.2.0/24"]).expect("valid networks"),
);

let shield = ShieldBuilder::recommended()
    .guard(maintenance.clone())
    .build();

let app: Router = Router::new()
    .route("/", get(|| async { "Hello, secure world!" }))
    .route("/health", get(|| async { "ok" }))
    .layer(shield);

// Later, from wherever you kept the clone:
maintenance.set_enabled(true);
```

A partir de ese momento, los visitantes reciben un cuerpo problem+json con `"code":"maintenance"` y una cabecera `Retry-After`, y cada rechazo aparece en tus logs y estadísticas. Si prefieres dejar el mantenimiento fuera del registro de auditoría de seguridad, usa `Rejection::respond(StatusCode::SERVICE_UNAVAILABLE, "maintenance")`, que es silencioso y tiene el cuerpo vacío.

## Retener recursos

`ctx.hold` vincula un valor a la vida de la petición: se libera cuando se genera la cabecera de la respuesta o cuando se cancela la petición. Así es como el límite de concurrencia devuelve sus permisos. Aquí sirve para detectar respuestas lentas:

```rust
use std::time::{Duration, Instant};

use securite::http::request;
use securite::{Context, Guard, Rejection};

/// Logs requests whose response head took more than one second.
struct SlowRequests;

struct Timer {
    path: String,
    started: Instant,
}

impl Drop for Timer {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        if elapsed > Duration::from_secs(1) {
            eprintln!("slow request: {} took {:?}", self.path, elapsed);
        }
    }
}

impl Guard for SlowRequests {
    fn name(&self) -> &'static str {
        "slow_requests"
    }

    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        ctx.hold(Timer {
            path: req.uri.path().to_owned(),
            started: Instant::now(),
        });
        Ok(())
    }
}
```

## Probar un guard

Un guard es una estructura normal: llama directamente a `on_request` con las partes de una petición y un contexto creado con `Context::new`, sin necesidad de servidor. En el fichero que define `Maintenance`:

```rust
#[cfg(test)]
mod tests {
    use securite::http::{Method, Request, StatusCode, Uri};
    use securite::prelude::*;

    use super::Maintenance;

    #[test]
    fn maintenance_blocks_visitors_but_not_staff() {
        let guard = Maintenance::new(IpSet::parse(["10.0.0.0/8"]).unwrap());
        guard.set_enabled(true);
        let (mut req, ()) = Request::get("/orders").body(()).unwrap().into_parts();

        // A visitor gets a 503.
        let visitor = Some("203.0.113.7".parse().unwrap());
        let mut ctx = Context::new(Method::GET, Uri::from_static("/orders"), visitor);
        let rejection = guard.on_request(&mut req, &mut ctx).unwrap_err();
        assert_eq!(rejection.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(rejection.code(), "maintenance");

        // Staff go through.
        let staff = Some("10.1.2.3".parse().unwrap());
        let mut ctx = Context::new(Method::GET, Uri::from_static("/orders"), staff);
        assert!(guard.on_request(&mut req, &mut ctx).is_ok());
    }
}
```

## Buenas prácticas

- **Mantén el guard síncrono y rápido.** Los guards se ejecutan en cada petición y no pueden usar `.await`. Evita cualquier E/S bloqueante y refresca un estado compartido en segundo plano (un `Arc<RwLock<…>>` o un atómico, como arriba).
- **Elige un nombre único.** `.guard()` sustituye al guard con el mismo nombre: llamar al tuyo `waf` eliminaría en silencio el WAF integrado.
- **No des por hecho que `on_request` se ejecutó.** `on_response` se llama para todas las respuestas, incluidos los rechazos emitidos por guards que se ejecutan antes que el tuyo. Comprueba `ctx.rejected_by()` o `ctx.blocked()` cuando importe.
- **Pasa datos a los handlers a través de la petición.** Insértalos en `req.extensions` y léelos con el extractor `Extension<T>` de axum; `ctx.extensions_mut()` está reservado a los guards. Los valores que guardes en cualquiera de los dos deben implementar `Clone + Send + Sync`.
- **Nada de secretos en los mensajes.** El mensaje llega al cliente; `with_details` se queda en tus logs.
- **Despliega de forma gradual.** Devuelve `Mode::Monitor` desde `mode()` para observar una regla nueva antes de aplicarla; consulta [Modo observación](/docs/monitor-mode).
