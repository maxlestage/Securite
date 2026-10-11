---
title: Comprobaciones de salud
summary: Responde a GET /health para los balanceadores de carga, Kubernetes y los monitores de disponibilidad, en el formato application/health+json, con comprobaciones con nombre que convierten la respuesta en un 503.
category: everyday
order: 10
---

Los balanceadores de carga, los orquestadores (Kubernetes, Nomad, Fly.io, Heroku…) y los monitores de disponibilidad preguntan con regularidad «¿sigues vivo?». `Health` responde por sí mismo a esa pregunta, antes de tus rutas, así que las sondas nunca llegan a tus handlers ni a tus registros.

## La respuesta

```json
{"status":"pass","uptime":3600,"version":"1.4.0","checks":{"database":{"status":"pass"},"cache":{"status":"pass"}}}
```

- `200 OK` con `"status":"pass"` cuando todas las comprobaciones pasan;
- `503 Service Unavailable` con `"status":"fail"` en cuanto una falla, para que el balanceador de carga deje de enviar tráfico a esta instancia.

El tipo de contenido es `application/health+json` y la respuesta nunca se almacena en caché (`Cache-Control: no-store`). Solo se responde a `GET` y `HEAD` en la ruta exacta; todo lo demás va a tus rutas.

## Inicio rápido

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Health::new().version(env!("CARGO_PKG_VERSION")));
```

```bash
curl -i https://example.com/health
# HTTP/1.1 200 OK
# content-type: application/health+json
#
# {"status":"pass","uptime":42,"version":"1.4.0"}
```

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `Health::new()` | `/health`, sin comprobaciones | Crea el middleware. |
| `.path(path)` | `/health` | Otra ruta (`/healthz`, `/_health`…). |
| `.version(v)` | ninguna | Versión que se muestra en la respuesta. |
| `.check(name, f)` | ninguna | Comprobación con nombre; `f() == false` hace fallar la sonda. |

## Comprobaciones

Las comprobaciones se ejecutan en cada sonda, de forma síncrona: haz que sean baratas. El patrón habitual es un indicador que una tarea en segundo plano mantiene actualizado:

```rust
use pratique::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use vitesse::prelude::*;

async fn ping_database() -> bool {
    true // p. ej. `SELECT 1` con un timeout corto
}

let db_up = Arc::new(AtomicBool::new(true));

let flag = db_up.clone();
vitesse::tokio::spawn(async move {
    loop {
        let ok = ping_database().await;
        flag.store(ok, Ordering::Relaxed);
        vitesse::tokio::time::sleep(Duration::from_secs(5)).await;
    }
});

let mut app = App::new();
app.middleware(Health::new().check("database", move || db_up.load(Ordering::Relaxed)));
```

## Liveness y readiness

Kubernetes distingue entre «reiníciame» (liveness) y «todavía no me envíes tráfico» (readiness). Usa dos instancias en dos rutas:

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Health::new().path("/livez"));
app.middleware(Health::new().path("/readyz").check("database", || true));
```

## Errores comunes y consejos

- Añade `Health` antes del `Shield` de Securite si tu plataforma envía las sondas sin cabecera `Host` o desde una dirección que tus reglas bloquearían, y antes de [Maintenance](/docs/maintenance) (o permite su ruta con `allow`) para que las sondas sigan funcionando durante el mantenimiento.
- Excluye la ruta de tus [registros de acceso](/docs/access-log): `.skip("/health")`.
- No hagas que la liveness dependa de la base de datos: una caída de la base de datos reiniciaría todas las instancias en bucle.

## Páginas relacionadas

- [Modo de mantenimiento](/docs/maintenance)
- [Métricas de Prometheus](/docs/metrics)
