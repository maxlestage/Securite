---
title: Cabeceras de respuesta
summary: Añade, sustituye, agrega o elimina cabeceras en cada respuesta, incluidas las que genera el propio Vitesse, como los 404.
category: everyday
order: 12
---

Algunas cabeceras deben ir en todas las respuestas: un valor `Server` o `X-Powered-By`, un `Content-Language` por defecto, una precarga con `Link`, un `Timing-Allow-Origin`… y otras no deberían salir nunca del servidor, como una cabecera de depuración que añade una biblioteca. `SetHeaders` las gestiona en un único lugar.

## Operaciones

| Método | Efecto |
|---|---|
| `.set(name, value)` | Establece la cabecera y sustituye lo que haya puesto el handler. |
| `.if_missing(name, value)` | Añade la cabecera solo cuando la respuesta no la tiene. |
| `.append(name, value)` | Añade un valor más y conserva los existentes (`Link`, `Vary`…). |
| `.remove(name)` | Elimina la cabecera. |

Las operaciones se ejecutan en el orden indicado, en cada respuesta: las de tus handlers, las de Vitesse (`404`, `405`) y las de los middlewares añadidos después de `SetHeaders`. Un nombre o un valor no válido hace que el método provoque un pánico al arrancar, nunca durante una petición.

## Inicio rápido

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(
    SetHeaders::new()
        .set("x-powered-by", "Vitesse")
        .if_missing("content-language", "en")
        .append("link", "</app.css>; rel=preload; as=style")
        .remove("x-debug"),
);
```

## Errores comunes y consejos

- Para las cabeceras de seguridad (CSP, HSTS, `X-Frame-Options`…), usa las [cabeceras de seguridad](/docs/security-headers) de Securite: incluyen valores por defecto seguros y nonces por petición.
- `X-Powered-By` le dice a todo el mundo qué stack usas. Es inofensivo con un stack mantenido, pero también puedes usar `.remove("x-powered-by")`.
- Para modificar las cabeceras de una sola ruta, envuelve su handler: `handler.with(SetHeaders::new()…)`.

## Páginas relacionadas

- [Cache-Control](/docs/cache-control)
- [Cabeceras de seguridad](/docs/security-headers)
