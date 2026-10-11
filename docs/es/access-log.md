---
title: Registros de acceso
summary: Escribe una línea por petición, en JSON para los pipelines de registros o en el formato combinado de Apache para los analizadores clásicos, en la salida estándar o en cualquier destino, con la dirección real del cliente detrás de un proxy.
category: everyday
order: 5
---

El `middleware::logger()` de Vitesse imprime líneas en color pensadas para personas. `AccessLog` escribe líneas pensadas para máquinas: Loki, Elasticsearch, CloudWatch, Datadog, GoAccess o AWStats las leen sin ninguna regla de análisis.

## Formatos

**Líneas JSON** (`AccessLog::json()`), un objeto por petición; los campos ausentes se omiten:

```json
{"time":"2026-10-11T08:49:37.042Z","ip":"203.0.113.9","method":"GET","path":"/search?q=shoes","version":"HTTP/1.1","referer":"https://example.com/","user_agent":"Mozilla/5.0","request_id":"3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44","status":200,"bytes":5120,"duration_ms":1.842}
```

**Formato combinado de Apache / Nginx** (`AccessLog::combined()`):

```text
203.0.113.9 - - [11/Oct/2026:08:49:37 +0000] "GET /search?q=shoes HTTP/1.1" 200 5120 "https://example.com/" "Mozilla/5.0"
```

| Campo | Contenido |
|---|---|
| `time` | Momento de llegada de la petición, en UTC, RFC 3339 con milisegundos. |
| `ip` | Dirección del cliente (ver más abajo). |
| `method`, `path`, `version` | Línea de petición; `path` incluye la query string. |
| `status`, `bytes` | Estado y tamaño del cuerpo de la respuesta (`bytes` no aparece en los cuerpos en streaming). |
| `duration_ms` | Tiempo necesario para producir la cabecera de la respuesta. |
| `referer`, `user_agent` | Cabeceras de la petición. |
| `request_id` | `X-Request-Id` de la petición, o de la respuesta (`RequestId` de Securite). |

## Inicio rápido

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(AccessLog::json().skip("/health").skip("/metrics"));
app.get("/", |_req: Request| async { "home" });
```

## Configuración

| Método | Descripción |
|---|---|
| `AccessLog::json()` | Líneas JSON en la salida estándar. |
| `AccessLog::combined()` | Líneas en formato combinado en la salida estándar. |
| `.to(sink)` | Envía cada línea (sin el salto de línea) a un closure: un archivo, un canal, `tracing`… |
| `.skip(prefix)` | No registra las peticiones bajo un prefijo de ruta (comprobaciones de salud, métricas). Se puede llamar varias veces. |
| `.ip_from_header(name)` | Lee la dirección del cliente de una cabecera escrita por tu proxy inverso. |

```rust
use pratique::prelude::*;

let log = AccessLog::json().to(|line| tracing::info!(target: "access", "{line}"));
```

## Detrás de un proxy inverso

Detrás de Heroku, Render, Fly.io, Nginx o Cloudflare, la conexión viene del proxy, así que la dirección registrada sería la del proxy. Indica a `AccessLog` qué cabecera escribe el proxy:

```rust
use pratique::prelude::*;

let log = AccessLog::combined().ip_from_header("x-forwarded-for"); // Heroku, Nginx, Render…
let log = AccessLog::combined().ip_from_header("cf-connecting-ip"); // Cloudflare
```

Se usa la **última** dirección de la cabecera: la que añade el proxy situado delante de tu aplicación, que un cliente no puede falsificar (todo lo que envía el propio cliente queda antes). Sin la cabecera, o con un valor no válido, se registra la dirección del peer.

## Errores comunes y consejos

- El registro es síncrono. La salida estándar funciona bien en todas las plataformas; para un destino lento, haz que el sink envíe las líneas a un canal leído por una tarea en segundo plano.
- Todos los campos entre comillas del formato combinado escapan `"`, `\` y los caracteres de control, y las cadenas JSON se escapan: un `User-Agent` manipulado no puede falsificar una línea de registro.
- Los registros de acceso contienen direcciones IP, que son datos personales según el RGPD: fija un periodo de conservación.

## Páginas relacionadas

- [Métricas de Prometheus](/docs/metrics)
- [Identificadores de petición](/docs/request-id)
- [IP del cliente](/docs/client-ip)
