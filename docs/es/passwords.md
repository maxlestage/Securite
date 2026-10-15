---
title: Hash de contraseñas
summary: Hash Argon2id con los parámetros de OWASP, actualización transparente al iniciar sesión, pimienta opcional y protección contra la enumeración de cuentas.
category: access
order: 6
---

`PasswordHasher` almacena las contraseñas como recomiendan OWASP y la RFC 9106: con **Argon2id**, una función que consume mucha memoria y encarece el crackeo con GPU o ASIC, y una sal aleatoria nueva para cada contraseña. Se apoya en el crate `argon2` auditado de RustCrypto y añade lo que necesita un flujo de inicio de sesión: rehash al iniciar sesión cuando sube el coste, verificación ficticia para cuentas inexistentes, pimienta y límites razonables.

## Amenazas mitigadas

- **A02:2021 Fallos criptográficos** / **A07:2021 Fallos de identificación y autenticación**: contraseñas guardadas en claro, con un hash rápido (MD5, SHA-256) o sin sal se rompen en horas en cuanto se filtra la base de datos (CWE-916, CWE-759).
- **Enumeración de cuentas** (CWE-204): un inicio de sesión que responde más rápido cuando el correo no existe revela a los atacantes qué cuentas hay.
- **Denegación de servicio mediante el hash**: contraseñas enormes, o una fila de hash manipulada que pide gigabytes de memoria.

## Inicio rápido

El módulo depende de la feature `password`, activada por defecto.

```rust
use securite::password::PasswordHasher;

let hasher = PasswordHasher::new(); // Argon2id, m = 19 MiB, t = 2, p = 1

// Registro: guarde esta cadena tal cual (contiene la sal y los parámetros).
let stored = hasher.hash("correct horse battery staple")?;
// $argon2id$v=19$m=19456,t=2,p=1$<sal>$<hash>

// Inicio de sesión.
assert!(hasher.verify("correct horse battery staple", &stored));
```

El hash es lento a propósito (decenas de milisegundos, 19 MiB de memoria). En un servidor asíncrono, ejecútelo en un hilo bloqueante para no frenar las demás peticiones:

```rust
let hasher = hasher.clone(); // barato: el hasher es compartido
let ok = tokio::task::spawn_blocking(move || hasher.verify(&password, &stored)).await?;
```

## Un inicio de sesión completo

```rust
use securite::password::{PasswordCheck, PasswordHasher};

fn login(hasher: &PasswordHasher, db: &Db, email: &str, password: &str) -> Result<User, LoginError> {
    let Some(user) = db.find_user_by_email(email) else {
        // El mismo trabajo que una verificación real: el tiempo de respuesta no
        // revela si la dirección está registrada.
        hasher.verify_dummy(password);
        return Err(LoginError::InvalidCredentials);
    };
    match hasher.check(password, &user.password_hash) {
        PasswordCheck::Valid => Ok(user),
        PasswordCheck::ValidNeedsRehash(new_hash) => {
            // El hash guardado usaba parámetros más débiles (o Argon2i): se actualiza
            // ahora, el único momento en que se conoce la contraseña.
            db.update_password_hash(user.id, &new_hash);
            Ok(user)
        }
        PasswordCheck::Invalid => Err(LoginError::InvalidCredentials),
    }
}
```

Devuelva el mismo error y el mismo mensaje para una cuenta inexistente y para una contraseña incorrecta. Combínelo con la [limitación de intentos de inicio de sesión](/docs/login-throttle) para que ninguna cuenta pueda adivinarse.

## Cómo funciona

1. **Hash.** Se extrae una sal de 16 bytes del generador criptográfico del sistema y Argon2id (versión 0x13) calcula un hash de 32 bytes. El resultado es una cadena PHC que registra el algoritmo, la versión, los costes y la sal: cada hash sigue siendo verificable aunque cambien los valores por defecto.
2. **Verificación.** Se analiza la cadena PHC y la contraseña se vuelve a calcular con *los parámetros guardados*; las salidas se comparan en tiempo constante. Las cadenas mal formadas, los hashes bcrypt o PBKDF2, las contraseñas vacías y las que superan el límite de longitud nunca coinciden.
3. **Tope de coste.** Antes de calcular nada, los costes guardados se comparan con los configurados: una fila que pide más de cuatro veces la memoria o el tiempo configurados se rechaza, así una base manipulada no puede hacer que el servidor reserve gigabytes.
4. **Actualizaciones.** `check` devuelve `ValidNeedsRehash` cuando el hash guardado es más débil que los parámetros actuales o no es Argon2id, junto con un hash nuevo hecho con los parámetros actuales.

## Configuración

| Método | Por defecto | Descripción |
|---|---|---|
| `PasswordHasher::new()` | — | Argon2id, `m = 19456 KiB, t = 2, p = 1` (OWASP). |
| `PasswordHasher::with_params(m_kib, t, p)` | — | Costes propios; entra en pánico por debajo del mínimo de OWASP (`m ≥ 7168 KiB`, `m × t ≥ 35840`). |
| `.pepper(secret)` | ninguna | Secreto mezclado en cada hash (entrada secreta de Argon2); 16 bytes como mínimo. |
| `.max_password_bytes(n)` | `1024` | Las contraseñas más largas se rechazan, nunca se truncan. |
| `.hash(password)` | — | `Result<String, PasswordError>` (`Empty`, `TooLong`, `Hashing`). |
| `.verify(password, hash)` | — | `bool`. |
| `.check(password, hash)` | — | `Invalid`, `Valid` o `ValidNeedsRehash(new_hash)`. |
| `.needs_rehash(hash)` | — | Si el hash es más débil que los parámetros actuales. |
| `.verify_dummy(password)` | — | Consume una verificación y devuelve `false`. |

OWASP enumera ajustes equivalentes que cambian memoria por iteraciones, por ejemplo `with_params(47104, 1, 1)`, `with_params(12288, 3, 1)` o `with_params(9216, 4, 1)`. Súbalos según su hardware: los usuarios existentes se actualizan en su próximo inicio de sesión.

## Pimienta

Una pimienta es un secreto que vive fuera de la base de datos (variable de entorno, gestor de secretos). Con ella, una base filtrada no le basta a un atacante:

```rust
use securite::password::PasswordHasher;

let pepper = std::env::var("PASSWORD_PEPPER").expect("PASSWORD_PEPPER must be set");
let hasher = PasswordHasher::new().pepper(pepper);
```

Perder la pimienta obliga a todos los usuarios a restablecer su contraseña, y un hash hecho con ella solo se verifica con ella: guarde una copia como si fuera una clave de cifrado.

## Errores frecuentes y consejos

- Nunca aplique SHA-256, MD5 o HMAC a una contraseña: están pensados para ser rápidos. `Auth::token_sha256` sirve para tokens de API aleatorios, no para contraseñas humanas.
- No trunque ni normalice las contraseñas en silencio. Deje que los usuarios escriban frases largas; `1024` bytes es generoso.
- Aplique aparte una política de contraseñas: longitud mínima (8 a 15 caracteres según NIST SP 800-63B), comprobación contra contraseñas filtradas, sin reglas de composición.
- El `Debug` de `PasswordCheck` nunca muestra el hash, pero mantenga los propios hashes fuera de sus registros.

## Páginas relacionadas

- [Limitación de intentos de inicio de sesión](/docs/login-throttle)
- [Autenticación de dos factores](/docs/two-factor)
- [Autenticación](/docs/auth)
- [Autorización](/docs/authorization)
