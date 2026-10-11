---
title: Protección CSRF
summary: Protección Fetch Metadata sin estado, basada en el algoritmo de CrossOriginProtection de Go 1.25, con un token double-submit firmado con HMAC opcional.
category: access
order: 4
---

`Csrf` rechaza las peticiones que modifican el estado cuando un navegador las envía en nombre de otro sitio. Su modo por defecto no necesita configuración, ni sesión, ni cambios en las plantillas; un modo opcional con token firmado añade una segunda barrera independiente.

## La amenaza

En una falsificación de petición en sitios cruzados (CSRF), una página maliciosa consigue que el navegador de la víctima envíe una petición a su aplicación (un formulario oculto, una etiqueta `<img>`, una llamada `fetch`). El navegador adjunta las credenciales ambientales (cookies, autenticación HTTP, certificados de cliente), así que su servidor ve una petición perfectamente autenticada: una transferencia, un cambio de contraseña, la eliminación de una cuenta.

El CSRF (CWE-352) pertenece a la categoría A01 Broken Access Control del OWASP Top 10 2021; consulte la Cross-Site Request Forgery Prevention Cheat Sheet de OWASP y la prueba WSTG-SESS-05. Las cookies `SameSite` ayudan, pero no cubren los ataques desde subdominios vecinos, y `Lax` sigue permitiendo las navegaciones `GET` de primer nivel.

## Cómo funciona

### Fetch Metadata y verificación del origen

Los navegadores modernos etiquetan cada petición con `Sec-Fetch-Site`, que la página de un atacante no puede falsificar. El guard (prioridad 130) aplica el mismo procedimiento de decisión que `http.CrossOriginProtection` de Go 1.25:

1. `GET`, `HEAD` y `OPTIONS`, así como las rutas bajo un prefijo `exempt`, no se comprueban nunca. Todos los demás métodos sí, `TRACE` incluido.
2. Si `Sec-Fetch-Site` está presente: `same-origin` y `none` (el usuario escribió la URL o usó un marcador) pasan; `same-site` solo pasa con `allow_same_site(true)`; cualquier otro valor solo pasa si `Origin` es un origen de confianza.
3. Sin `Sec-Fetch-Site` (navegadores antiguos): la ausencia de cabecera `Origin` indica un cliente que no es un navegador, que pasa; un `Origin` de confianza pasa; en otro caso, el host de `Origin` debe coincidir con la cabecera `Host`.
4. Los rechazos responden `403` con el código `csrf_rejected`.

### Token double-submit firmado

Con `with_token(secret)`, cada cliente recibe además un token: 24 bytes aleatorios seguidos de su firma HMAC-SHA256, codificados en base64url. Se guarda en la cookie `__Host-csrf` (`Path=/; HttpOnly; SameSite=Strict; Secure`) y se pone a disposición de los handlers como la extensión de petición `CsrfToken`. Cada petición no segura debe superar la verificación de origen **y** enviar el mismo token en la cabecera `X-CSRF-Token`. La comparación se hace en tiempo constante, y la firma impide que un atacante imponga un token elegido por él. Un token ausente o incorrecto produce `403` con el código `csrf_token_invalid`.

La cookie es `HttpOnly`: los scripts nunca la leen. Inserte en sus páginas el token que proporciona `CsrfToken`.

## Inicio rápido

`Shield::recommended()` y `Shield::strict()` ya incluyen `Csrf::new()`. Por separado:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::builder().guard(Csrf::new()).build());
    app.get("/", |_req: Request| async { "form" });
    app.post("/transfer", |_req: Request| async { "done" });
    app
}
```

El guard se llama `csrf`; `ShieldBuilder::recommended().without("csrf")` lo elimina.

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `Csrf::new()` | solo Fetch Metadata | Protección sin estado. |
| `trusted_origin(&str)` | ninguno | Acepta peticiones no seguras desde este origen (`https://admin.example.com`). Se puede llamar varias veces. |
| `exempt(prefix)` | ninguno | Prefijo de ruta que se salta las comprobaciones (webhooks, API autenticadas con token). |
| `allow_same_site(bool)` | `false` | Acepta `Sec-Fetch-Site: same-site`, es decir, todos los subdominios de su sitio. |
| `with_token(secret)` | inactivo | Activa el token double-submit firmado. Provoca un pánico si el secreto tiene menos de 32 bytes. |
| `cookie_name(&str)` | `__Host-csrf` | Nombre de la cookie del token. Solo en modo token. |
| `header_name(&str)` | `x-csrf-token` | Cabecera que transporta el token. Solo en modo token. |
| `insecure_dev_cookie()` | cookie `Secure` | Quita `Secure` y renombra `__Host-csrf` a `csrf`, para desarrollo con HTTP sin cifrar. Solo en modo token. |
| `monitor()` | bloqueo | Notifica las infracciones sin bloquear. |

> **Consejo:** `cookie_name`, `header_name` e `insecure_dev_cookie` pueden llamarse antes o después de `with_token`: el orden es indiferente. Sin `with_token`, no tienen ningún efecto.

## Ejemplos

### Aplicación renderizada en el servidor con htmx

```rust
use securite::prelude::*;
use vitesse::prelude::*;

async fn page(req: Request) -> Html<String> {
    let token = req.get::<CsrfToken>().map(|t| t.0.clone()).unwrap_or_default();
    // htmx adds this header to every request it sends.
    Html(format!(
        r#"<body hx-headers='{{"X-CSRF-Token": "{token}"}}'>
  <button hx-post="/transfer">Send</button>
</body>"#
    ))
}

pub fn app(secret: String) -> App {
    let shield = ShieldBuilder::recommended()
        .guard(Csrf::new().with_token(secret).exempt("/webhooks"))
        .build();

    let mut app = App::new();
    app.middleware(shield);
    app.get("/", page);
    app.post("/transfer", |_req: Request| async { "sent" });
    app.post("/webhooks/payments", |_req: Request| async { "ok" });
    app
}
```

Cargue el secreto desde su gestor de secretos, por ejemplo con `std::env::var("CSRF_SECRET")`, y compártalo entre todas las instancias.

### Enviar el token con fetch

Si la página genera `<meta name="csrf-token" content="…">` a partir de `CsrfToken`:

```text
const token = document.querySelector('meta[name="csrf-token"]').content;
await fetch("/transfer", {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
  body: JSON.stringify({ amount: 10 }),
});
```

### Front-end de administración, webhooks y una API con token bearer

```rust
use securite::prelude::*;

pub fn csrf() -> Csrf {
    Csrf::new()
        .trusted_origin("https://admin.example.com")
        .exempt("/webhooks") // verified by signature instead
        .exempt("/api/v1") // bearer tokens, no cookies
}
```

### Desarrollo local

```rust
use securite::prelude::*;

pub fn csrf(secret: &str, dev: bool) -> Csrf {
    let csrf = Csrf::new().with_token(secret);
    if dev { csrf.insecure_dev_cookie() } else { csrf }
}
```

### Aspecto de un rechazo

```json
{"type":"about:blank","title":"Forbidden","status":403,"code":"csrf_rejected","detail":"Cross-site request rejected."}
```

## Uso como guard independiente

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::from(Csrf::new()));
    app.post("/settings", |_req: Request| async { "saved" });
    app
}
```

## Errores comunes y consejos

- **Los métodos seguros nunca se comprueban**: un handler `GET` que modifica el estado queda, por diseño, sin protección. Mantenga `GET`, `HEAD` y `OPTIONS` libres de efectos secundarios.
- **Los formularios HTML clásicos no pueden enviar cabeceras**: el modo token requiere JavaScript (`fetch`, htmx…). Los formularios clásicos quedan cubiertos por el modo Fetch Metadata en todos los navegadores modernos.
- **`allow_same_site(true)`** confía en todos los subdominios, incluidos los que alojan contenido de usuarios o uno secuestrado mediante un registro DNS huérfano. Prefiera `trusted_origin` para cada front-end.
- **Las rutas exentas** deben protegerse de otra forma, por ejemplo con firmas de webhook o tokens bearer. Los prefijos respetan los límites de segmento.
- **Proxies**: el mecanismo de respaldo para navegadores antiguos compara `Origin` con `Host`; su proxy inverso debe reenviar el `Host` original.
- **La rotación del secreto** invalida todos los tokens. Los clientes reciben una cookie nueva en su siguiente petición, pero una petición que ya esté en curso fallará una vez.
- **Nombre de la cookie**: renombrarla sin el prefijo `__Host-` permite que un subdominio vecino la sobrescriba.
- **API**: `Shield::api()` no incluye el guard CSRF, porque las API suelen autenticarse con tokens. Vuelva a añadir `Csrf::new()` si su API depende de cookies.
- **Token ausente**: sin `with_token`, `req.get::<CsrfToken>()` es `None`.

> **Consejo:** cualquier XSS anula toda defensa CSRF, ya que el script se ejecuta en su propio origen. Combine este guard con una [Content-Security-Policy](/docs/security-headers) estricta.

## Páginas relacionadas

- [Endurecimiento de cookies](/docs/cookies)
- [CORS](/docs/cors)
- [Lista de Content-Type permitidos](/docs/content-type)
- [Filtro de hosts](/docs/host-filter)
- [Firmas de webhooks](/docs/webhook-signatures)
- [Modo monitor](/docs/monitor-mode)
