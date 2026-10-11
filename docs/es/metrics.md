---
title: Métricas de Prometheus
summary: Cuenta cada petición y sirve en /metrics, en el formato de texto de Prometheus, el número de peticiones por método y clase de estado, un histograma de latencia, las peticiones en curso y el tiempo de actividad.
category: everyday
order: 6
---

`Metrics` da a tu aplicación las cuatro cifras con las que empieza cualquier panel (tráfico, errores, latencia, saturación) y las sirve en `GET /metrics` en el formato de texto de Prometheus, que leen Prometheus, Grafana Agent, VictoriaMetrics, Datadog o el collector de OpenTelemetry.

## Qué se mide

```text
# TYPE http_requests_total counter
http_requests_total{method="GET",status="2xx"} 1027
http_requests_total{method="POST",status="4xx"} 3
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{le="0.001"} 812
http_request_duration_seconds_bucket{le="0.005"} 1001
…
http_request_duration_seconds_bucket{le="+Inf"} 1030
http_request_duration_seconds_sum 1.734
http_request_duration_seconds_count 1030
# TYPE http_requests_in_flight gauge
http_requests_in_flight 2
# TYPE process_uptime_seconds gauge
process_uptime_seconds 86400
```

| Métrica | Tipo | Etiquetas |
|---|---|---|
| `http_requests_total` | counter | `method` (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `OTHER`), `status` (`1xx` … `5xx`) |
| `http_request_duration_seconds` | histogram | buckets de 1 ms a 10 s |
| `http_requests_in_flight` | gauge | — |
| `process_uptime_seconds` | gauge | — |

Las etiquetas forman un conjunto fijo de 40 series como máximo: la ruta **no** es una etiqueta, a propósito, para que un atacante o un crawler no pueda crear millones de series. Contar cuesta unas pocas sumas atómicas por petición, sin bloqueos.

## Inicio rápido

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Metrics::new());
app.get("/", |_req: Request| async { "home" });
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: my-app
    static_configs:
      - targets: ["my-app:3000"]
```

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `Metrics::new()` | `/metrics`, prefijo `http` | Crea el middleware. |
| `.path(path)` | `/metrics` | Ruta del endpoint. |
| `.prefix(prefix)` | `http` | Prefijo de los nombres de las métricas, por ejemplo `shop_http`; provoca un pánico si no es válido. |
| `.handle()` | — | Un `MetricsHandle` para leer las cifras desde tu código. |

```rust
use pratique::prelude::*;

let metrics = Metrics::new();
let numbers = metrics.handle();
// más tarde: numbers.total(), numbers.by_class(5), numbers.in_flight(), numbers.render()
```

## Mantener el endpoint privado

Cualquiera que pueda acceder a `/metrics` ve tu tráfico. Añádelo después del `Shield` de Securite con un guard `Auth` o `IpFilter`:

```rust
use pratique::prelude::*;
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(
    Shield::builder()
        .guard(Auth::bearer().token("prometheus", "long-random-token").protect(["/metrics"]))
        .build(),
);
app.middleware(Metrics::new());
```

## Errores comunes y consejos

- El endpoint no se cuenta a sí mismo, así que los scrapes no distorsionan las cifras.
- Las duraciones se detienen cuando la cabecera de la respuesta está lista, no cuando termina un cuerpo en streaming.
- Añade `Metrics` pronto (el primero o justo después de `AccessLog`) para que también se cuenten las respuestas de los demás middlewares (redirecciones, `304`, mantenimiento).
- Cada proceso tiene sus propios contadores; Prometheus suma las instancias.

## Páginas relacionadas

- [Registros de acceso](/docs/access-log)
- [Comprobaciones de salud](/docs/health)
- [Autenticación](/docs/auth)
