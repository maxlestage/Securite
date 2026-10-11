---
title: Modo de mantenimiento
summary: Responde a cada petición con 503 Service Unavailable y Retry-After mientras un interruptor está activado, en HTML, JSON o texto, y mantiene abiertas las rutas que elijas.
category: everyday
order: 11
---

Durante una migración de la base de datos o un incidente, es mejor decir «volvemos en diez minutos» que servir errores. `Maintenance` lo hace con un interruptor que accionas mientras la aplicación se ejecuta, sin volver a desplegar.

## Funcionamiento

Mientras el interruptor está activado, cada petición fuera de las rutas permitidas recibe:

- `503 Service Unavailable`, el estado que los buscadores entienden como «temporal, vuelve más tarde»;
- `Retry-After: <seconds>` si se ha configurado;
- `Cache-Control: no-store`, para que nadie almacene en caché la página de mantenimiento;
- una página HTML para los navegadores (si has proporcionado una y la petición acepta `text/html`), JSON `{"error":"maintenance","message":"…"}` para los clientes que aceptan JSON y texto plano en los demás casos.

El interruptor es un indicador atómico: comprobarlo no cuesta nada cuando el mantenimiento está desactivado.

## Inicio rápido

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

let maintenance = Maintenance::new()
    .allow("/health")
    .allow("/admin")
    .retry_after(Duration::from_secs(600))
    .html("<!doctype html><title>Maintenance</title><h1>Back in a few minutes</h1>");
let switch = maintenance.switch();

let mut app = App::new();
app.middleware(maintenance);
app.post("/admin/maintenance", move |req: Request| {
    let switch = switch.clone();
    async move {
        switch.set(req.query("on").as_deref() == Some("1"));
        format!("maintenance: {}", switch.is_on())
    }
});
```

> **Atención:** Protege la ruta que acciona el interruptor, por ejemplo con la [autenticación](/docs/auth) de Securite.

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `Maintenance::new()` | desactivado | Crea el middleware. |
| `.enabled(true)` | `false` | Arranca en mantenimiento (por ejemplo, a partir de una variable de entorno). |
| `.switch()` | — | El `MaintenanceSwitch`, que debes guardar antes de entregar el middleware a la aplicación. |
| `.allow(prefix)` | ninguno | Prefijo de ruta que se sigue sirviendo. Se puede llamar varias veces. |
| `.retry_after(duration)` | ninguno | `Retry-After`, en segundos enteros. |
| `.message(text)` | una frase genérica | Texto de las respuestas en texto y en JSON. |
| `.html(page)` | ninguna | Página que se muestra a los navegadores. |

`MaintenanceSwitch` es barato de clonar y ofrece `on()`, `off()`, `set(bool)` e `is_on()`.

## Arrancar a partir del entorno

```rust
use pratique::prelude::*;

let maintenance = Maintenance::new()
    .enabled(std::env::var("MAINTENANCE").as_deref() == Ok("1"))
    .allow("/health");
```

## Errores comunes y consejos

- Permite la ruta de tu comprobación de salud; si no, tu orquestador creerá que las instancias están muertas y las reiniciará.
- Cada proceso tiene su propio interruptor: con varias instancias, acciona cada uno (o lee un indicador compartido en una tarea en segundo plano y llama a `set`).
- Haz que la página HTML sea autosuficiente (estilos en línea, sin recursos externos): puede que tus archivos estáticos tampoco estén disponibles.

## Páginas relacionadas

- [Comprobaciones de salud](/docs/health)
- [Autenticación](/docs/auth)
