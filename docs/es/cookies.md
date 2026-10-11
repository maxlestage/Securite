---
title: Endurecimiento de cookies
summary: Añade los atributos Secure, HttpOnly y SameSite que falten en cada cabecera Set-Cookie, incluidas las cookies que fijan crates que usted no controla.
category: browser
order: 3
---

`CookieHardening` reescribe las cabeceras `Set-Cookie` de sus respuestas para que cada cookie lleve `Secure`, `HttpOnly` y `SameSite`, sea cual sea el handler, la biblioteca de sesiones o el crate de OAuth que la haya creado. Los atributos ya presentes nunca se modifican.

## La amenaza

Una cookie de sesión es una credencial al portador: quien la tiene se convierte en el usuario. Cada atributo ausente abre una vía conocida para robarla o abusar de ella:

- sin `HttpOnly`, basta un solo XSS para leer `document.cookie` y exfiltrar la sesión;
- sin `Secure`, la cookie viaja sin cifrar en cualquier petición HTTP, incluida una forzada por un atacante en una red Wi-Fi pública;
- sin `SameSite`, el navegador adjunta la cookie a las peticiones cross-site, que es la causa raíz del CSRF.

Estos fallos pertenecen a la categoría A07 Identification and Authentication Failures del OWASP Top 10 2021. La OWASP Session Management Cheat Sheet exige los tres atributos y la prueba WSTG-SESS-02 los verifica. Es fácil olvidarlos porque las cookies se fijan en muchos sitios; este guard los corrige en uno solo.

## Cómo funciona

El guard actúa sobre la respuesta, con prioridad 910, después de todos los demás, y reescribe cada valor `Set-Cookie`:

- Se añade `Secure` si falta. Se añade siempre a las cookies `SameSite=None` y a las cookies con prefijo `__Host-` o `__Secure-`, incluso en modo desarrollo, porque de lo contrario los navegadores las rechazan.
- Se añade `HttpOnly` si falta, salvo que el nombre de la cookie figure en `readable_by_js` o se haya activado `no_http_only()`.
- Se añade `SameSite=<valor por defecto>` solo cuando la cookie no tiene atributo `SameSite`.
- Los demás atributos (`Path`, `Domain`, `Max-Age`, `Partitioned`…) no se tocan, y los valores que no son UTF-8 válido se transmiten sin cambios.

Las cookies que añaden otros guards, como la cookie del token [CSRF](/docs/csrf), también se endurecen.

| Fijada por la aplicación | Enviada al navegador (valores por defecto) |
|---|---|
| `sid=abc` | `sid=abc; Secure; HttpOnly; SameSite=Lax` |
| `sid=abc; Path=/;` | `sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax` |
| `sid=abc; secure; HTTPONLY; SameSite=Strict` | sin cambios |

## Inicio rápido

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::builder().guard(CookieHardening::new()).build());
    app.get("/login", |_req: Request| async {
        res::text("welcome").header("set-cookie", "sid=abc; Path=/")
    });
    app
}
```

`Shield::recommended()` y `Shield::api()` ya incluyen `CookieHardening::new()`; `Shield::strict()` usa `SameSite::Strict`. El guard se llama `cookies`.

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `CookieHardening::new()` | `Secure; HttpOnly; SameSite=Lax` | Valores recomendados. |
| `same_site(SameSite)` | `SameSite::Lax` | Valor de `SameSite` que se añade a las cookies que no lo tienen. |
| `readable_by_js(names)` | ninguna | Nombres de cookies que deben seguir siendo legibles desde JavaScript (sin `HttpOnly`). Se puede llamar varias veces. |
| `no_http_only()` | se añade `HttpOnly` | No añade nunca `HttpOnly`. |
| `insecure_dev()` | se añade `Secure` | No añade `Secure`; solo para desarrollo local con HTTP sin cifrar. |
| `harden(&str)` | — | Devuelve la versión endurecida de un valor `Set-Cookie`; útil en pruebas unitarias. |

### Valores de SameSite

| Valor | Se envía la cookie en | Uso típico |
|---|---|---|
| `SameSite::Strict` | solo peticiones same-site | paneles de administración, operaciones bancarias |
| `SameSite::Lax` | peticiones same-site y navegaciones `GET` de primer nivel desde otros sitios | cookies de sesión de la mayoría de los sitios |
| `SameSite::None` | todas las peticiones (se impone `Secure`) | widgets incrustados, SSO entre sitios |

## Ejemplos

### Sesiones estrictas para un panel de administración

```rust
use securite::prelude::*;

pub fn shield() -> Shield {
    Shield::builder()
        .guard(SecurityHeaders::new())
        .guard(CookieHardening::new().same_site(SameSite::Strict))
        .build()
}
```

### Cookies que lee JavaScript

Una preferencia de tema o la cookie `XSRF-TOKEN` de un framework deben seguir siendo legibles por los scripts; todas las demás cookies conservan `HttpOnly`:

```rust
use securite::prelude::*;

pub fn cookies() -> CookieHardening {
    CookieHardening::new().readable_by_js(["theme", "XSRF-TOKEN"])
}
```

### Desarrollo local con HTTP sin cifrar

```rust
use securite::prelude::*;

pub fn cookies(dev: bool) -> CookieHardening {
    let cookies = CookieHardening::new();
    if dev { cookies.insecure_dev() } else { cookies }
}
```

### Probar sus cookies

```rust
use securite::prelude::*;

#[test]
fn session_cookie_is_hardened() {
    let hardening = CookieHardening::new();
    assert_eq!(
        hardening.harden("sid=abc; Path=/"),
        "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
    );
}
```

## Uso como guard independiente

El guard solo ve las cabeceras `Set-Cookie` que existen cuando la respuesta lo atraviesa. En Vitesse, el primer middleware añadido es el más externo, así que añádalo antes de los middlewares que fijan cookies:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::from(CookieHardening::new())); // primero: ve las cabeceras Set-Cookie definitivas
    // app.middleware(session_middleware);               // fija la cookie de sesión
    app.post("/login", |_req: Request| async {
        res::text("ok").header("set-cookie", "sid=abc; Path=/")
    });
    app
}
```

La misma regla se aplica a un `Shield`: debe envolver su middleware de sesiones.

## Errores comunes y consejos

> **Atención:** `insecure_dev()` nunca debe llegar a producción. Hágalo depender de su configuración, no de un indicador fijado en el código.

- **`SameSite=Strict` y enlaces entrantes**: un usuario que sigue un enlace desde un correo o desde otro sitio llega sin la cookie y parece haber cerrado sesión en esa primera página. `Lax` es el valor adecuado por defecto para las cookies de sesión; reserve `Strict` para las cookies sensibles.
- **SameSite no basta contra el CSRF**: no cubre los ataques desde subdominios vecinos, que se consideran «same-site», y `Lax` sigue permitiendo las navegaciones `GET` de primer nivel. Mantenga activo el guard [CSRF](/docs/csrf).
- **Prefijo `__Host-`**: los navegadores también exigen `Path=/` y que no haya atributo `Domain`. El guard añade `Secure`, pero no puede deducir el resto; defínalo en su código.
- **Desarrollo local**: los navegadores basados en Chromium y Firefox aceptan cookies `Secure` en `http://localhost`. `insecure_dev()` hace falta sobre todo al probar con HTTP sin cifrar en una dirección de la red local o con un nombre de host propio.
- **Alcance**: las cookies que escribe JavaScript (`document.cookie`) o que añade un proxy inverso nunca pasan por el guard.
- `HttpOnly` evita el robo de la cookie, no el XSS en sí; combínelo con una [CSP](/docs/security-headers) estricta.

> **Consejo:** `readable_by_js` compara los nombres de cookie de forma exacta y distinguiendo mayúsculas, igual que los navegadores.

## Páginas relacionadas

- [Protección CSRF](/docs/csrf)
- [Cabeceras de seguridad](/docs/security-headers)
- [Redirección a HTTPS](/docs/https-redirect)
- [CORS](/docs/cors)
