---
title: Lista de Content-Type permitidos
summary: Rechaza los cuerpos de petición cuyo tipo de medio su servicio no espera, lo que cierra la confusión de tipos, el CSRF mediante peticiones simples y los vectores XXE.
category: access
order: 5
---

`ContentTypeGuard` responde `415 Unsupported Media Type` cuando el cuerpo de una petición se declara con un tipo de medio que usted no ha permitido. Es una comprobación temprana y barata que elimina familias enteras de confusiones de análisis antes de que se ejecute ningún handler.

## La amenaza

- **CSRF contra endpoints JSON**: los navegadores envían `text/plain`, `application/x-www-form-urlencoded` y `multipart/form-data` entre sitios sin preflight CORS. Un handler que analiza el cuerpo en bruto como JSON, sea cual sea el tipo declarado, puede manejarse desde un formulario oculto en cualquier sitio web.
- **XML External Entities (XXE)**: un endpoint que negocia formatos puede pasar el XML de un atacante a un analizador XML, con la consiguiente divulgación de ficheros o SSRF.
- **Diferencias de análisis**: un WAF, un proxy y su handler pueden interpretar de forma distinta un mismo cuerpo cuando su tipo es ambiguo o falta.

La OWASP REST Security Cheat Sheet pide a los servicios que validen el `Content-Type` de las peticiones; consulte también la OWASP XXE Prevention Cheat Sheet, la categoría A05 Security Misconfiguration del OWASP Top 10 2021 (que absorbió XXE) y el OWASP API Security Top 10 2023 (API8 Security Misconfiguration).

## Cómo funciona

El guard se ejecuta con prioridad 150, después de la autenticación. Solo examina las peticiones `POST`, `PUT`, `PATCH` y `DELETE` que llevan cuerpo y cuya ruta no se haya omitido. Una petición lleva cuerpo si tiene un `Content-Length` distinto de `0` o una cabecera `Transfer-Encoding`; en HTTP/2 y HTTP/3, que no necesitan ninguna de las dos para enviar un cuerpo, se supone que una petición sin `Content-Length` lleva uno.

La esencia del tipo de medio (la parte anterior a `;`, en minúsculas) debe coincidir con una entrada permitida:

- un tipo exacto, como `application/json`;
- un subtipo comodín, como `text/*` (o `*/*`, que lo permite todo);
- un sufijo de sintaxis estructurada, como `application/*+json`, que abarca `application/problem+json` o `application/merge-patch+json`.

Un `Content-Type` ausente o no permitido produce `415` con el código `unsupported_media_type`. El valor rechazado solo se guarda en los detalles del evento.

| `Content-Type` | `json()` | `new()` |
|---|---|---|
| `application/json; charset=utf-8` | permitido | permitido |
| `application/merge-patch+json` | permitido | permitido |
| `application/x-www-form-urlencoded` | 415 | permitido |
| `multipart/form-data; boundary=x` | 415 | permitido |
| `text/plain` | 415 | 415 |
| `application/xml` | 415 | 415 |
| ausente | 415 | 415 |

## Inicio rápido

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::builder().guard(ContentTypeGuard::json()).build());
    app.post("/orders", |req: Request| async move { req.text().await });
    app
}
```

`Shield::api()` incluye `ContentTypeGuard::json()` y `Shield::strict()` incluye `ContentTypeGuard::new()`. El guard se llama `content_type`.

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `ContentTypeGuard::new()` | JSON, `*+json`, formularios URL-encoded y multipart | Pensado para aplicaciones web. |
| `ContentTypeGuard::json()` | `application/json`, `application/*+json` | Pensado para API JSON. |
| `allow(&str)` | — | Añade un tipo de medio (`application/xml`, `text/csv`, `text/*`…). Se puede llamar varias veces. |
| `skip(prefix)` | ninguno | Prefijo de ruta que no se comprueba. Se puede llamar varias veces. |
| `is_allowed(&str)` | — | Indica si un valor de `Content-Type`, parámetros incluidos, está permitido. |

## Ejemplos

### Aplicación web con importación CSV y webhooks

```rust
use securite::prelude::*;

pub fn content_types() -> ContentTypeGuard {
    ContentTypeGuard::new()
        .allow("text/csv") // bulk import endpoint
        .skip("/webhooks") // third-party payloads, verified by signature
}
```

### Probar su configuración

```rust
use securite::prelude::*;

#[test]
fn json_api_accepts_only_json() {
    let guard = ContentTypeGuard::json();
    assert!(guard.is_allowed("application/json; charset=utf-8"));
    assert!(guard.is_allowed("application/merge-patch+json"));
    assert!(!guard.is_allowed("text/plain"));
    assert!(!guard.is_allowed("application/xml"));
}
```

### Comprobar con curl

```bash
curl -i -X POST https://api.example.com/orders \
  -H "Content-Type: text/plain" \
  --data '{"amount": 10}'
```

```text
HTTP/2 415
content-type: application/problem+json
cache-control: no-store
```

## Uso como guard independiente

Aplique el guard solo a un subrouter, por ejemplo una API JSON montada junto a páginas HTML:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut api = Router::new();
    api.middleware(Shield::from(ContentTypeGuard::json()));
    api.post("/orders", |req: Request| async move { req.text().await });

    let mut app = App::new();
    app.get("/", |_req: Request| async { "home" });
    app.mount("/api", api);
    app
}
```

El guard ve la ruta completa de la petición, prefijo de montaje incluido: escriba los prefijos de `skip` tal como los envía el cliente (`/api/orders`).

## Errores comunes y consejos

> **Atención:** en HTTP/2 y HTTP/3, un `POST`, `PUT`, `PATCH` o `DELETE` sin `Content-Length` se comprueba como si llevara cuerpo, de modo que un cuerpo enviado en streaming no puede colarse. Una de esas peticiones sin cuerpo, por ejemplo un `DELETE` enviado sin `Content-Length: 0` ni `Content-Type`, recibe `415`: haga que el cliente envíe `Content-Length: 0` u omita la ruta.

- **Defensa en profundidad**: un handler que analiza JSON por sí mismo rara vez comprueba antes el tipo de contenido; el guard rechaza los tipos inesperados antes de leer cualquier cuerpo, para todas las rutas a la vez.
- `allow()` solo añade tipos. Para aceptar menos tipos que `new()`, parta de `json()` y añada lo que necesite.
- `*/*` o un `text/*` demasiado amplio anulan la protección; permita tipos concretos.
- Los cuerpos de las peticiones `GET` no se comprueban; los de `DELETE`, sí.
- Las subidas multipart se aceptan en bloque; el tipo de cada parte y de cada fichero debe validarse igualmente en su código.

> **Consejo:** una API exclusivamente JSON combinada con un [CORS](/docs/cors) estricto obliga a que toda escritura entre sitios pase por un preflight, lo que complementa muy bien la [protección CSRF](/docs/csrf).

## Páginas relacionadas

- [Protección CSRF](/docs/csrf)
- [CORS](/docs/cors)
- [Filtro de hosts](/docs/host-filter)
- [Cabeceras de seguridad](/docs/security-headers)
- [Límite de tamaño del cuerpo](/docs/body-limit)
- [Firmas de webhooks](/docs/webhook-signatures)
