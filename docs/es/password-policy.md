---
title: Política de contraseñas
summary: Las reglas de contraseñas del NIST SP 800-63B (longitud, listas de bloqueo, palabras del contexto, sin reglas de composición) y la comprobación de contraseñas filtradas con la API k-anónima de Have I Been Pwned.
category: access
order: 12
---

`PasswordPolicy` comprueba las contraseñas nuevas como piden el NIST SP 800-63B y el OWASP ASVS: suficientemente largas, no demasiado comunes, no derivadas del nombre o el e-mail del usuario, ni trivialmente repetitivas o secuenciales, y ausentes de las filtraciones. **No** impone «una mayúscula, un número, un símbolo»: esas reglas producen `Password1!` y el NIST las desaconseja.

## Amenazas mitigadas

- **A07:2021 Fallos de identificación y autenticación**: contraseñas débiles (CWE-521).
- **Credential stuffing**: contraseñas ya filtradas en otro sitio, rechazadas gracias a Have I Been Pwned.
- **Adivinación dirigida**: contraseñas construidas a partir del nombre de usuario, del e-mail o del nombre del sitio.

## Inicio rápido

```rust
use securite::password_policy::PasswordPolicy;

let policy = PasswordPolicy::new().context([&form.username, &form.email, "Acme"]);

if let Err(e) = policy.check(&form.password) {
    // e.violations(): TooShort, TooLong, Common, Context, Repetitive, Sequential …
    return Err(format!("Elija otra contraseña: {e}"));
}
let hash = hasher.hash(&form.password)?;
```

Se devuelven todas las reglas incumplidas, cada una con un mensaje legible (`Display`).

## Contraseñas filtradas (Have I Been Pwned)

Con k-anonimato, solo los 5 primeros caracteres hexadecimales del SHA-1 de la contraseña salen de su servidor. `securite` construye la petición y lee la respuesta; la llamada HTTP es suya, con cualquier cliente:

```rust
use securite::password_policy::hibp::RangeQuery;

let query = RangeQuery::new(&form.password);
let body = http_get(&query.url(), [("Add-Padding", "true")]).await?; // su cliente HTTP
let count = query.count(&body);
policy.check_with_breaches(&form.password, count)?; // Violation::Breached { count }
```

Si la API no responde, decida de forma explícita: rechazar el cambio, o aceptarlo y volver a comprobar en el siguiente inicio de sesión.

## Reglas

| Regla | Por defecto |
|---|---|
| Longitud mínima | 12 caracteres (`min_length`, al menos 8) |
| Longitud máxima | 128 caracteres (`max_length`, al menos 64), limita el coste del hash |
| Contraseñas comunes | ~200 de las más comunes, también rodeadas de números y símbolos |
| Palabras del contexto | `context([...])`: palabras de 4 caracteres o más, sin distinguir mayúsculas; también la parte local de los e-mails |
| Repetitivas | Muy pocos caracteres distintos (`aaaaaaaaaaaa`, `abababababab`) |
| Secuenciales | Sobre todo una serie del alfabeto, de números o del teclado (`abcdefgh`, `12345678`, `qwertyui`, `azertyui`) |
| Lista de bloqueo propia | `blocklist([...])` |

La longitud se cuenta en caracteres, no en bytes: se permiten todos los caracteres Unicode y los espacios, así que las frases de contraseña funcionan.

## Trampas y consejos

- Aplique la política al registrarse y al cambiar la contraseña, nunca al iniciar sesión (las contraseñas antiguas deben seguir permitiendo entrar y luego cambiarse).
- Muestre todas las infracciones a la vez, con una indicación de robustez, en lugar de un error tras otro.
- No registre nunca la contraseña ni el sufijo de `RangeQuery` (su `Debug` lo oculta).

## Páginas relacionadas

- [Hash de contraseñas](/docs/passwords)
- [Limitación de intentos de inicio de sesión](/docs/login-throttle)
- [Autenticación de dos factores](/docs/two-factor)
