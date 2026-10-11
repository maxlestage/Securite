---
title: Tiempo de respuesta
summary: Añade las cabeceras X-Response-Time y Server-Timing con el tiempo empleado en producir cada respuesta, visible en las herramientas para desarrolladores del navegador.
category: everyday
order: 7
---

`ResponseTime` mide cuánto ha tardado el resto de la cadena en producir la cabecera de la respuesta y lo escribe en dos cabeceras:

```text
x-response-time: 1.842ms
server-timing: app;dur=1.842
```

Los navegadores muestran `Server-Timing` en sus herramientas para desarrolladores (pestaña Red y, después, Tiempos), junto a los tiempos de DNS, TLS y descarga, lo que facilita distinguir un servidor lento de una red lenta.

## Inicio rápido

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(ResponseTime::new());
app.get("/", |_req: Request| async { "home" });
```

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `ResponseTime::new()` | ambas cabeceras, 3 decimales | Crea el middleware. |
| `.header(Some(name))` / `.header(None)` | `x-response-time` | Otro nombre de cabecera, o ninguna cabecera de este tipo. |
| `.server_timing(Some(metric))` / `.server_timing(None)` | `app` | Nombre de la métrica en `Server-Timing`, o ninguna. |
| `.digits(n)` | `3` | Decimales de los milisegundos. |

```rust
use pratique::prelude::*;

// Solo Server-Timing, con el nombre "backend", en milisegundos enteros.
let timing = ResponseTime::new().header(None).server_timing(Some("backend")).digits(0);
```

## Errores comunes y consejos

- El tiempo cubre lo que viene después del middleware en la cadena: añádelo el primero para incluir todos los demás middlewares.
- `Server-Timing` se añade a continuación de lo existente, así que los handlers pueden incluir sus propias métricas (`db;dur=4.2`) junto a ella.
- Los tiempos revelan lo ocupado que está tu servidor. En un servicio público quizá prefieras enviar `Server-Timing` solo a tu equipo, o usar en su lugar las [métricas de Prometheus](/docs/metrics).

## Páginas relacionadas

- [Métricas de Prometheus](/docs/metrics)
- [Registros de acceso](/docs/access-log)
