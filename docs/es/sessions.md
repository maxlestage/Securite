---
title: Sesiones
summary: Sesiones en el servidor con nuevo identificador al iniciar sesión, tiempos de inactividad y absoluto, identificadores con hash en el almacén, cierre de sesión con Clear-Site-Data y enlaces de verificación de e-mail.
category: access
order: 11
---

`SessionManager` guarda las sesiones en el servidor y solo da al navegador un identificador aleatorio en una cookie reforzada. Sigue la guía de OWASP sobre gestión de sesiones: nuevo identificador al iniciar sesión, tiempos aplicados en el servidor, cierre de sesión completo. El guard `Sessions` carga la sesión de cada petición.

## Amenazas mitigadas

- **Fijación de sesión** (CWE-384): `login` y `regenerate` dan un nuevo identificador a la sesión; un identificador plantado por un atacante muere al instante.
- **Robo de sesión**: identificadores de 256 bits del generador del sistema, cookie `__Host-` con `Secure`, `HttpOnly`, `SameSite=Lax` y `Path=/`.
- **Sesiones olvidadas** (CWE-613): tiempo de inactividad (30 min) y tiempo absoluto (12 h), comprobados en el servidor diga lo que diga la cookie.
- **Fuga del almacén**: el almacén solo ve el SHA-256 de cada identificador; un volcado de Redis no entrega ninguna sesión viva.
- **Datos que quedan tras cerrar sesión**: `logout` borra la sesión, hace caducar la cookie y envía `Clear-Site-Data`.

## Inicio rápido

```rust
use std::sync::Arc;
use securite::session::{MemorySessionStore, Session, SessionManager, Sessions};
use securite::prelude::*;

let sessions = SessionManager::new(Arc::new(MemorySessionStore::new(100_000)));
let shield = Shield::builder().guard(Sessions::new(sessions.clone())).build();

// POST /login, tras comprobar la contraseña:
let mut session = req.extensions().get::<Session>().cloned().unwrap_or_else(|| sessions.start());
sessions.login(&mut session, &user.id);      // nuevo identificador + usuario
let set_cookie = sessions.commit(&session);  // añadir como `Set-Cookie`

// Cualquier handler:
if let Some(session) = req.extensions().get::<Session>() {
    let user = session.user();
}

// POST /logout:
for (name, value) in sessions.logout(session) { /* añadir a la respuesta */ }
```

Con `Sessions` en el shield, una sesión iniciada también deja un `Principal` (esquema `session`) en la petición, así que el [control de acceso](/docs/access-control) funciona con ella.

## Configuración

| Método | Descripción |
|---|---|
| `SessionManager::new(almacén)` | Cookie `__Host-session`, 30 min de inactividad, 12 h en total. |
| `.idle_timeout(d)` / `.absolute_timeout(d)` | Tiempos. |
| `.cookie_name(nombre)` / `.same_site(s)` | Ajustes de la cookie. |
| `.insecure_dev()` | Solo `http://localhost`: sin `Secure` ni prefijo `__Host-`. |
| `.start()` / `.load(cabeceras)` / `.commit(&session)` | Ciclo de vida. |
| `.regenerate(&mut s)` / `.login(&mut s, usuario)` | Nuevo identificador (en cada cambio de privilegios). |
| `.logout(s)` / `.destroy(s)` | Termina una sesión, con o sin `Clear-Site-Data`. |

`Session` ofrece `get`, `insert`, `remove`, `user` y `created_at`. Su salida `Debug` nunca muestra el identificador.

## Almacén compartido

`MemorySessionStore` está acotado y sirve para una instancia. Para varias, implemente `SessionStore` (`load`, `save` con un tiempo de vida, `delete`) sobre Redis o su base de datos. Las claves tienen 64 caracteres hexadecimales; trate un error del almacén como una sesión ausente: el usuario queda fuera en lugar de dentro.

## Clear-Site-Data al cerrar sesión

`logout` ya lo envía. Para añadirlo a cualquier ruta, use el guard `ClearSiteData`:

```rust
use securite::clear_site_data::{ClearSiteData, Directive};

Shield::builder().guard(ClearSiteData::on(["/logout", "/account/delete"]));
// o a elegir: .directives([Directive::Cookies, Directive::Storage])
```

Solo decora las respuestas correctas (`2xx` / `3xx`); los navegadores solo lo aplican en HTTPS.

## Enlaces de verificación de e-mail

`Signer` crea enlaces que prueban que un usuario lee un buzón, como el `MustVerifyEmail` de Laravel:

```rust
use std::time::Duration;
use securite::signing::Signer;

let signer = Signer::new(secret).purpose("verify-email");
let link = signer.email_verification_url("/email/verify", &user.id, &user.email, Duration::from_secs(3600));
// → /email/verify/42/<hash de la dirección>?expires=…&signature=…

// GET /email/verify/...:
let user_id = signer.verify_email_url(req.uri().path_and_query().unwrap().as_str(), &current_email)?;
```

El enlace solo vale para el mismo usuario **y** la misma dirección: tras un cambio de e-mail, los enlaces anteriores dejan de funcionar.

## Trampas y consejos

- Llame a `login` (o `regenerate`) en cada cambio de privilegios: inicio de sesión, modo sudo, cambio de rol.
- Combínelo con la [protección CSRF](/docs/csrf): el navegador envía la cookie de sesión en las peticiones entre sitios.
- Mantenga `SameSite=Lax` o `Strict`; `None` necesita un motivo.

## Páginas relacionadas

- [Cookies](/docs/cookies)
- [CSRF](/docs/csrf)
- [Control de acceso](/docs/access-control)
- [URL y tokens firmados](/docs/signed-urls)
