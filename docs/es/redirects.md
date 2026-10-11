---
title: Redirecciones
summary: Envía las direcciones antiguas a las nuevas antes de que se ejecuten las rutas, para páginas sueltas, secciones completas y un dominio entero, con el estado 3xx adecuado y conservando la query string.
category: everyday
order: 9
---

Las páginas se mueven, las secciones cambian de nombre, el `www.` desaparece. Cada dirección antigua sigue teniendo enlaces y posicionamiento en los buscadores. `Redirects` las mantiene vivas con una sola tabla de reglas en lugar de una ruta por cada dirección antigua.

## Reglas

| Método | Ejemplo | Estado |
|---|---|---|
| `.permanent(from, to)` | `/old-pricing` → `/pricing` | `308 Permanent Redirect` |
| `.temporary(from, to)` | `/sale` → `/products?promo=autumn` | `307 Temporary Redirect` |
| `.exact(from, to, status)` | cualquier `3xx` (`301`, `302`, `303`…) | el indicado; provoca un pánico si no es una redirección |
| `.prefix(from, to)` | `/blog/2024/hello` → `/articles/2024/hello` | `308` |
| `.host(host, origin)` | `www.example.com/x` → `https://example.com/x` | `308` |

Las reglas se comprueban en este orden: host, ruta exacta y, por último, el prefijo coincidente más largo. Un prefijo cubre segmentos completos: `/blog` cubre `/blog` y `/blog/x`, no `/blogger`. La query string de la petición se añade al destino, salvo que este tenga la suya propia.

`308` y `307` conservan el método y el cuerpo: un formulario enviado a una dirección antigua sigue llegando como `POST`.

## Inicio rápido

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(
    Redirects::new()
        .host("www.example.com", "https://example.com")
        .permanent("/old-pricing", "/pricing")
        .prefix("/blog", "/articles")
        .temporary("/sale", "/products?promo=autumn"),
);
```

```bash
curl -i "https://example.com/blog/2024/hello?utm_source=mail"
# HTTP/1.1 308 Permanent Redirect
# location: /articles/2024/hello?utm_source=mail
```

## Dominio canónico

`.host(host, origin)` redirige cada petición cuyo `Host` (sin puerto, sin distinguir mayúsculas y minúsculas) sea `host` a la misma ruta en `origin`. Solo se redirigen los hosts que indicas, así que `localhost` y los dominios de previsualización siguen funcionando.

```rust
use pratique::prelude::*;

let canonical = Redirects::new()
    .host("www.example.com", "https://example.com")
    .host("example.fr", "https://example.com/fr");
```

> **Consejo:** Para forzar HTTPS en todos los hosts, usa la [redirección a HTTPS](/docs/https-redirect) de Securite, que entiende los proxies.

## Errores comunes y consejos

- Los navegadores recuerdan las redirecciones permanentes durante mucho tiempo. Prueba primero con `.temporary(…)` y después cambia a `.permanent(…)`.
- Los destinos forman parte de tu propia configuración y nunca se toman de la petición, así que el middleware no puede convertirse en una redirección abierta.
- Evita las cadenas (`/a` → `/b` → `/c`): apunta cada dirección antigua directamente a la final.

## Páginas relacionadas

- [Barra final](/docs/trailing-slash)
- [Redirección a HTTPS](/docs/https-redirect)
