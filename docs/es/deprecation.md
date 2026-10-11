---
title: Retirada de API
summary: Anuncia que unos endpoints están obsoletos, cuándo dejarán de funcionar y dónde leer sobre la migración, con las cabeceras estándar Deprecation, Sunset y Link.
category: everyday
order: 14
---

Cuando `/api/v2` sustituye a `/api/v1`, sus clientes deben saberlo, idealmente por la propia API y no por un correo que nadie lee. `Deprecation` añade las cabeceras estándar que entienden las pasarelas de API, los SDK y las herramientas de monitorización:

```text
deprecation: @1767225600
sunset: Fri, 01 Jan 2027 00:00:00 GMT
link: <https://example.com/docs/v2>; rel="deprecation"; type="text/html"
```

| Cabecera | Estándar | Significado |
|---|---|---|
| `Deprecation` | RFC 9745 | Desde cuándo está obsoleto el recurso (tiempo Unix). |
| `Sunset` | RFC 8594 | Cuándo dejará de funcionar (fecha HTTP). |
| `Link` con `rel="deprecation"` | RFC 9745 | Página que describe la retirada y la migración. |

## Inicio rápido

```rust
use pratique::prelude::*;
use std::time::{Duration, UNIX_EPOCH};
use vitesse::prelude::*;

let since = UNIX_EPOCH + Duration::from_secs(1_767_225_600); // 2026-01-01
let mut app = App::new();
app.middleware(
    Deprecation::since(since)
        .sunset(since + Duration::from_secs(365 * 86_400))
        .link("https://example.com/docs/v2")
        .only("/api/v1"),
);
```

## Configuración

| Método | Descripción |
|---|---|
| `Deprecation::since(time)` | Obsoleto desde `time` (`SystemTime`). |
| `.sunset(time)` | Deja de funcionar en `time`. |
| `.link(url)` | Página de migración; provoca un pánico si la URL contiene caracteres no permitidos en una cabecera. |
| `.only(prefix)` | Solo las respuestas bajo un prefijo de ruta (se puede llamar varias veces). Por defecto: todas las respuestas. |

¿Varias retiradas con fechas distintas? Añade varios middlewares, cada uno con su `.only(…)`, o asocia uno al `Router` de la versión antigua.

## Después de la fecha de retirada

`Deprecation` solo informa. Cuando haya pasado la fecha, elimina las rutas o responde `410 Gone` y conserva las cabeceras para que los clientes entiendan el motivo:

```rust
use vitesse::prelude::*;

let mut app = App::new();
app.all("/api/v1/*rest", |_req: Request| async {
    res::status(410).json(json!({ "error": "gone", "see": "https://example.com/docs/v2" }))
});
```

## Errores comunes y consejos

- Anuncia la fecha de retirada con antelación (meses en el caso de las API públicas) y vigila quién sigue llamando a la versión antigua, por ejemplo con los [registros de acceso](/docs/access-log) filtrados por `/api/v1`.
- Las cabeceras son informativas: los navegadores las ignoran, y las herramientas y pasarelas de API las muestran.

## Páginas relacionadas

- [Registros de acceso](/docs/access-log)
- [Redirecciones](/docs/redirects)
