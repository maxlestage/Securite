---
title: Autenticación de dos factores
summary: Contraseñas de un solo uso basadas en el tiempo (RFC 6238) compatibles con todas las aplicaciones de autenticación, con protección contra la reutilización, código QR y códigos de recuperación.
category: access
order: 8
---

`Totp` implementa las contraseñas de un solo uso basadas en el tiempo (RFC 6238), los códigos de 6 cifras de Google Authenticator, Authy, 1Password, Bitwarden o FreeOTP. Un segundo factor detiene la mayoría de los robos de cuenta que empiezan con una contraseña filtrada, robada por phishing o reutilizada.

## Amenazas mitigadas

- **A07:2021 Fallos de identificación y autenticación**: cuentas protegidas solo por una contraseña (CWE-308); el nivel 2 de OWASP ASVS exige autenticación multifactor.
- **Reutilización de códigos**: un código visto por encima del hombro, en un registro o por un proxy de phishing se rechaza una vez usado (RFC 6238 §5.2).
- **Fugas por tiempos**: los códigos se comparan en tiempo constante y cada paso de tiempo aceptado se comprueba sin salida anticipada.

## Alta

```rust
use securite::totp::{Totp, recovery_codes};

let totp = Totp::generate(); // secreto aleatorio de 160 bits
let uri = totp.provisioning_uri("Example Inc", &user.email);
// otpauth://totp/Example%20Inc:alice%40example.com?secret=JBSWY3DP...&issuer=Example%20Inc
// Muestre `uri` como código QR; muestre `totp.secret_base32()` para la introducción manual.

// Guarde el secreto (cifrado) con el usuario solo después de que escriba un código válido:
assert!(totp.verify(&code_typed_by_user));
db.save_totp_secret(user.id, &totp.secret_base32());

// Códigos de recuperación: muéstrelos una vez, guarde solo sus resúmenes.
let codes = recovery_codes(10); // ["k3m7q-2vx9t", ...]
```

## Inicio de sesión

```rust
use securite::totp::Totp;

let totp = Totp::from_base32(&user.totp_secret)?;
match totp.verify_once(&form.code, user.totp_last_step) {
    Some(step) => {
        db.set_totp_last_step(user.id, step); // el mismo código no podrá volver a usarse
        // segundo factor OK
    }
    None => { /* código incorrecto, caducado o reutilizado */ }
}
```

`verify_once` rechaza todos los pasos de tiempo hasta el guardado en el inicio de sesión correcto anterior: un código solo sirve una vez, incluso dentro de su periodo de validez. Proteja este endpoint con la [limitación de intentos de inicio de sesión](/docs/login-throttle): sin límite, un millón de combinaciones caen rápido.

## Cómo funciona

- El secreto y el paso de tiempo actual (`tiempo unix / 30`) pasan por HMAC-SHA1 (o SHA-256 / SHA-512), y el truncamiento dinámico de la RFC 4226 convierte el resultado en 6 a 8 cifras. La implementación supera todos los vectores de prueba de la RFC 6238.
- Por defecto se acepta un paso de desfase de reloj a cada lado: un código es válido unos 90 segundos.
- Los espacios del código introducido se ignoran (`123 456`); todo lo que no sea una serie de cifras ASCII de la longitud correcta se rechaza.
- Los secretos de menos de 128 bits se rechazan; el `Debug` nunca muestra el secreto, que se borra cuando se libera el valor.

## Configuración

| Método | Por defecto | Descripción |
|---|---|---|
| `Totp::generate()` | — | Secreto de 160 bits del generador criptográfico del sistema. |
| `Totp::new(bytes)` | — | Secreto en bruto; entra en pánico por debajo de 16 bytes. |
| `Totp::from_base32(s)` | — | Secreto guardado; se ignoran mayúsculas, espacios, guiones y relleno. |
| `.algorithm(a)` | `Sha1` | `Sha1`, `Sha256` o `Sha512` (compruebe que las aplicaciones de sus usuarios los admiten). |
| `.digits(n)` | `6` | De 6 a 8. |
| `.period(d)` | 30 s | Duración de un paso de tiempo. |
| `.skew(n)` | `1` | Pasos aceptados a cada lado (10 como máximo). |
| `.verify(code)` / `.verify_at(code, t)` | — | Comprobación sin protección contra la reutilización. |
| `.verify_once(code, last_step)` | — | Comprobación con protección contra la reutilización; devuelve el paso que hay que guardar. |
| `.provisioning_uri(issuer, account)` | — | URI `otpauth://` para códigos QR. |
| `recovery_codes(n)` | — | `n` códigos de un solo uso de 50 bits aleatorios. |

## Errores frecuentes y consejos

- Cifre los secretos TOTP en reposo: a diferencia de un hash de contraseña, el secreto debe poder leerse para verificar los códigos.
- Pida un código válido antes de activar la 2FA, para que un secreto mal introducido no bloquee al usuario.
- Aplique un hash a los códigos de recuperación como a las contraseñas (por ejemplo con [`PasswordHasher`](/docs/passwords)) y borre cada uno cuando se use.
- Sincronice los relojes de los servidores con NTP; amplíe `skew` solo si los usuarios informan de códigos rechazados.
- TOTP no detiene los proxies de phishing en tiempo real; WebAuthn / las passkeys sí. Ofrézcalos también cuando pueda.

## Páginas relacionadas

- [Limitación de intentos de inicio de sesión](/docs/login-throttle)
- [Hash de contraseñas](/docs/passwords)
- [Autenticación](/docs/auth)
