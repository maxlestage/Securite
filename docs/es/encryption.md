---
title: Cifrado
summary: El Crypt de Laravel con XChaCha20-Poly1305, claves versionadas y su rotación, usos y contextos, tokens que caducan y cookies cifradas ligadas a su nombre.
category: integrity
order: 6
---

`Encrypter` convierte bytes en un token opaco, seguro en una URL o una cookie, que solo su servidor puede leer y que no se puede modificar sin que se note. Es el `Crypt` de Laravel para Rust, construido sobre el crate auditado RustCrypto `chacha20poly1305` (feature `crypt`, activa por defecto).

## Amenazas mitigadas

- **A02:2021 Fallos criptográficos**: valores que el cliente debe guardar sin leerlos (CWE-311) ni modificarlos (CWE-345).
- **Manipulación**: XChaCha20-Poly1305 es cifrado autenticado; un solo bit cambiado hace fallar el descifrado.
- **Reutilización de nonce**: el nonce de 192 bits sale del generador aleatorio del sistema en cada mensaje; en la práctica dos nonces aleatorios nunca coinciden.
- **Intercambio de cookies**: una cookie cifrada solo se descifra con su propio nombre; el valor de `prefs` no puede reutilizarse como `role`.

## Inicio rápido

```rust
use securite::crypt::Encrypter;

// Una vez: `Encrypter::generate_key()` → guárdela en un secreto (APP_KEY).
let crypt = Encrypter::from_base64(&std::env::var("APP_KEY")?)?;

let token = crypt.encrypt_str("4111 1111 1111 1111");
let card = crypt.decrypt_str(&token)?;
```

## Usos, contextos y caducidad

```rust
use std::time::Duration;

// Un token para un uso no se abre en ningún otro.
let remember = crypt.clone().purpose("remember-me");
let t = remember.encrypt_with_ttl(b"user:42", Duration::from_secs(30 * 24 * 3600));

// Ligue un valor a su fila: copiado en la fila de otro usuario, ya no se abre.
let iban = crypt.encrypt_in("user:42:iban", b"ES91...", None);
assert!(crypt.decrypt_in("user:43:iban", &iban).is_err());
```

## Cookies cifradas

```rust
let value = crypt.encrypt_cookie("prefs", "theme=dark", None);
// Set-Cookie: prefs=<value>; Path=/; HttpOnly; Secure; SameSite=Lax
// (o deje que CookieHardening añada los atributos)

let prefs = crypt.read_cookie(req.headers(), "prefs"); // None si es falsa, caducada o movida
```

Cuando el cliente puede leer el valor pero no debe cambiarlo, fírmelo en su lugar: `Signer::sign_cookie(nombre, valor)` y `unsign_cookie` (vea [URL y tokens firmados](/docs/signed-urls)).

## Rotación de claves

Cada token lleva una versión de formato y el identificador de la clave que lo selló (una huella de 4 bytes, nunca la clave). Cambie de clave sin cerrar la sesión de nadie:

```rust
let crypt = Encrypter::from_base64(&new_key)?
    .fallback_key_base64(&old_key)?; // aún descifra los tokens antiguos
```

Los nuevos tokens se sellan con la nueva clave; retire la antigua cuando caduque el token más duradero. `crypt.key_id()` muestra el identificador de la clave actual, útil para comprobar un despliegue.

## Configuración

| Método | Descripción |
|---|---|
| `Encrypter::new(&[u8; 32])` / `try_new` / `from_base64` | La clave (32 bytes aleatorios; se acepta el prefijo `base64:`). |
| `Encrypter::generate_key()` | Una nueva clave aleatoria, en base64. |
| `.purpose(p)` | Liga los tokens a un uso. |
| `.fallback_key(antigua)` | Rotación de claves. |
| `.encrypt` / `.encrypt_str` / `.encrypt_with_ttl` | Sella. |
| `.decrypt` / `.decrypt_str` | `Err(Malformed / Invalid / Expired)`. |
| `.encrypt_in(contexto, …)` / `.decrypt_in` | Valores ligados a un contexto. |
| `.encrypt_cookie` / `.decrypt_cookie` / `.read_cookie` | Cookies cifradas. |

## Trampas y consejos

- La clave lo es todo: manténgala fuera del repositorio y no la reutilice nunca para otra cosa (como secreto de firma, por ejemplo).
- El cifrado oculta el contenido, no el tamaño: rellene los valores si su longitud es sensible.
- No cifre contraseñas: [aplíqueles un hash](/docs/passwords).

## Páginas relacionadas

- [URL y tokens firmados](/docs/signed-urls)
- [Cookies](/docs/cookies)
- [Sesiones](/docs/sessions)
