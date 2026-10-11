---
title: Barra final
summary: Da a cada página una única dirección quitando o añadiendo la barra final, con una redirección 308 que siguen los buscadores o reescribiendo la petición sin redirigir.
category: everyday
order: 8
---

`/about` y `/about/` son dos direcciones distintas para los buscadores, las cachés y las herramientas de analítica. `TrailingSlash` elige un único estilo para toda la aplicación.

## Estilos

| Constructor | Efecto |
|---|---|
| `TrailingSlash::trim()` | `/about/` → `/about` (`/` por sí sola no se toca; `/about///` → `/about`). |
| `TrailingSlash::append()` | `/about` → `/about/`, salvo las rutas cuyo último segmento parece un archivo (`/app.js`). |

Por defecto, el cliente recibe una **`308 Permanent Redirect`** hacia la dirección normalizada: los buscadores fusionan ambas URL, y el método y el cuerpo de un `POST` se conservan. La query string se mantiene.

Con `.rewrite()` no hay redirección: la petición se reescribe en el sitio y tus rutas ven la ruta normalizada mientras el navegador conserva su dirección.

## Inicio rápido

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(TrailingSlash::trim());
app.get("/about", |_req: Request| async { "about" });
```

```bash
curl -i "https://example.com/about/?ref=mail"
# HTTP/1.1 308 Permanent Redirect
# location: /about?ref=mail
```

## Reescribir en lugar de redirigir

```rust
use pratique::prelude::*;

let slash = TrailingSlash::trim().rewrite(); // `/about/` responde como `/about`
```

## Errores comunes y consejos

- Añádelo antes de tus rutas y antes de los middlewares que miran la ruta (`CacheControl`, `ResponseCache`).
- Una ruta que empieza por varias barras nunca se convierte en una dirección relativa al protocolo (`//evil.example`): la redirección siempre se queda en tu sitio.
- Si sirves un sitio estático cuyas carpetas contienen `index.html`, `append()` coincide con sus enlaces.

## Páginas relacionadas

- [Redirecciones](/docs/redirects)
