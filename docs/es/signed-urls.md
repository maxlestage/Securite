---
title: URL y tokens firmados
summary: Tokens y URL a prueba de manipulaciones, con caducidad y ligados a un uso, con HMAC-SHA256 y rotación de claves, más un guard que verifica los enlaces firmados antes de su handler.
category: integrity
order: 5
---

`Signer` hace que los valores no puedan manipularse: enlaces de restablecimiento de contraseña y de verificación de correo, enlaces de baja, invitaciones, enlaces de descarga temporales o cualquier identificador que entregue al cliente y deba volver intacto. El guard `SignedUrls` verifica los enlaces firmados antes de que se ejecute su handler, como el middleware `signed` de Laravel.

## Amenazas mitigadas

- **A01:2021 Pérdida de control de acceso**: enlaces cuyos parámetros se pueden editar (`/unsubscribe?user=42` → `user=43`), enlaces de descarga que nunca caducan.
- **A08:2021 Fallos de integridad de software y datos**: valores que pasan por el cliente y se creen sin verificación (CWE-345, CWE-565).
- **Confusión de tokens**: un token emitido para una funcionalidad reutilizado en otra; cada token está ligado a un *uso* (purpose).

## URL firmadas

```rust
use std::time::Duration;
use securite::prelude::*;

let signer = Signer::new(std::env::var("LINK_SECRET").expect("LINK_SECRET must be set"));

// En el correo:
let link = signer.sign_url("/downloads/report.pdf?user=42", Some(Duration::from_secs(15 * 60)));
// /downloads/report.pdf?user=42&expires=1767225600&signature=Qm9...
let absolute = format!("https://example.com{link}");

// En la aplicación:
let mut app = App::new();
app.middleware(
    ShieldBuilder::recommended()
        .guard(SignedUrls::new(signer).protect(["/downloads", "/unsubscribe"]))
        .build(),
);
```

En los prefijos protegidos, una petición cuya URL no se firmó, se modificó o caducó recibe `403 Forbidden` con el código `invalid_signature` o `expired_signature`.

La firma cubre la ruta y todos los parámetros que la preceden, `expires` incluido. El parámetro `signature` debe ser el último: un parámetro añadido después (`&admin=1`) invalida el enlace. Un `#fragmento` se conserva al final y no se firma, ya que los navegadores nunca lo envían.

## Tokens

```rust
use std::time::Duration;
use securite::signing::{Signer, TokenError};

let resets = Signer::new(secret).purpose("password-reset");
let token = resets.sign_with_ttl(&user.id.to_string(), Duration::from_secs(3600));

// Más tarde, al abrir el enlace:
match resets.unsign(&token) {
    Ok(user_id) => { /* mostrar el formulario de restablecimiento para user_id */ }
    Err(TokenError::Expired) => { /* ofrecer un enlace nuevo */ }
    Err(_) => { /* 400 */ }
}
```

Un token tiene la forma `base64url(contenido).caducidad.base64url(hmac)`. Está **firmado, no cifrado**: cualquiera puede leer su contenido, así que nunca ponga secretos en él. Para un uso único (restablecimiento de contraseña), incluya también un valor que cambie una vez usado el token, por ejemplo los últimos caracteres del hash de la contraseña actual o un contador guardado con el usuario.

## Cómo funciona

- HMAC-SHA256 sobre un separador de dominio (tokens y URL nunca son intercambiables), el uso (precedido de su longitud) y el texto firmado.
- Las firmas se comparan en tiempo constante con cada clave configurada, sin salida anticipada.
- La caducidad solo se comprueba después de la firma: un enlace falsificado no aprende nada.
- Los secretos de menos de 32 bytes se rechazan al arrancar.

## Rotación de claves

```rust
use securite::signing::Signer;

let signer = Signer::new(new_secret)    // firma todo lo nuevo
    .fallback_key(old_secret);          // se sigue aceptando hasta que caduquen los enlaces antiguos
```

## Configuración

| Método | Descripción |
|---|---|
| `Signer::new(secret)` | 32 bytes como mínimo (`openssl rand -base64 48`). |
| `.purpose(name)` | Liga tokens y URL a un uso (`"default"` por defecto). |
| `.fallback_key(secret)` | Verifica también con un secreto antiguo. |
| `.sign(value)` / `.sign_with_ttl(value, ttl)` / `.sign_bytes(bytes, ttl)` | Tokens. |
| `.unsign(token)` / `.unsign_bytes(token)` | `Result<_, TokenError>` (`Malformed`, `Invalid`, `Expired`). |
| `.sign_url(url, ttl)` | URL relativa ya codificada; entra en pánico con `//host` o con parámetros `signature` / `expires` existentes. |
| `.verify_url(path_and_query)` | `Result<(), TokenError>`. |
| `SignedUrls::new(signer)` | Guard; todas las rutas hasta que `.protect(prefixes)` lo restrinja. |
| `.monitor()` | Informa de los enlaces no válidos sin bloquear. |

## Errores frecuentes y consejos

- Firme la URL exactamente como la pedirá el navegador: misma ruta, misma codificación, mismo orden de parámetros. Constrúyala, fírmela y no la toque más.
- Los clientes de correo y los rastreadores a veces añaden parámetros `utm_`: mantenga los enlaces firmados fuera de las campañas con seguimiento, o elimine esos parámetros en el frontal.
- Un uso por funcionalidad, y vidas cortas para todo lo que dé acceso.
- `SignedUrls` comprueba la integridad, no la identidad: un enlace de descarga firmado funciona para quien lo tenga. Combínelo con la [autenticación](/docs/auth) cuando el usuario también deba haber iniciado sesión.

## Páginas relacionadas

- [Firmas de webhooks](/docs/webhook-signatures)
- [Autorización](/docs/authorization)
- [Protección CSRF](/docs/csrf)
