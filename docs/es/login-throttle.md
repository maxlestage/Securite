---
title: Limitación de intentos de inicio de sesión
summary: Bloquea una cuenta, una dirección o ambas tras fallos repetidos, contra la adivinación de contraseñas, el credential stuffing y la fuerza bruta sobre la 2FA.
category: traffic
order: 7
---

`LoginThrottle` cuenta los **intentos fallidos** por una clave que usted elige y bloquea la clave al alcanzar el límite, hasta que termina su ventana. Es el `RateLimiter` / `ThrottlesLogins` de Laravel para Rust. Mientras la [limitación de peticiones](/docs/rate-limit) cuenta peticiones por IP antes de su handler, `LoginThrottle` se llama desde el handler, cuando ya sabe qué cuenta se ataca y si el intento falló.

## Amenazas mitigadas

- **A07:2021 Fallos de identificación y autenticación**: adivinación de contraseñas en línea contra una cuenta (CWE-307).
- **Credential stuffing y password spraying**: credenciales filtradas probadas desde miles de IP, o una contraseña común probada en todas las cuentas.
- **Fuerza bruta sobre la 2FA**: un código de 6 cifras solo tiene un millón de valores; sin límite, cae en horas.

## Inicio rápido

```rust
use std::time::Duration;
use securite::prelude::*;

// 5 fallos por cuenta e IP; después, bloqueado hasta que pasen los 15 minutos.
let throttle = LoginThrottle::new(5, Duration::from_secs(15 * 60));

// En el handler de inicio de sesión:
let key = LoginThrottle::key(&form.email, client_ip); // "alice@example.com|203.0.113.7"
match throttle.attempt(&key, || hasher.verify(&form.password, &user.password_hash)) {
    Ok(true) => { /* sesión iniciada: se olvidan los fallos de esta clave */ }
    Ok(false) => { /* 401: credenciales incorrectas */ }
    Err(retry_after) => { /* 429 con `Retry-After: retry_after.as_secs()` */ }
}
```

`attempt` rechaza una clave bloqueada **sin ejecutar** la verificación: incluso la contraseña correcta se rechaza hasta el final de la ventana, así que un atacante no aprende nada de un intento afortunado.

## Cómo funciona

1. El primer fallo de una clave abre una ventana de duración `decay`.
2. Cada fallo dentro de la ventana incrementa el contador; `check` falla en cuanto llega a `max_attempts`, con el tiempo restante como `Retry-After`.
3. Al terminar la ventana, el contador vuelve a cero; un éxito (`clear`) lo olvida de inmediato.
4. Las claves se guardan como resúmenes SHA-256 en una tabla particionada, acotada (100 000 claves por defecto) y que se limpia sola. Cuando está llena de entradas vivas, las claves nuevas se rechazan (fallo cerrado) en lugar de quedar sin contar en silencio.

## Elegir las claves

Un throttle por cada pregunta que quiera responder:

| Clave | Detiene | Ejemplo |
|---|---|---|
| cuenta + IP | a un atacante sobre una cuenta, sin bloquear al usuario real desde otro sitio | `LoginThrottle::key(email, Some(ip))` |
| cuenta | el credential stuffing desde muchas IP | `LoginThrottle::key(email, None)`, con un límite más alto |
| IP | el password spraying sobre todas las cuentas | `ip.to_string()` |

```rust
use std::time::Duration;
use securite::prelude::*;

let per_account_ip = LoginThrottle::new(5, Duration::from_secs(15 * 60));
let per_account = LoginThrottle::new(50, Duration::from_secs(60 * 60));

let k1 = LoginThrottle::key(&email, Some(ip));
let k2 = LoginThrottle::key(&email, None);
per_account_ip.check(&k1).and(per_account.check(&k2))?; // Err(retry_after): 429
if hasher.verify(&password, &hash) {
    per_account_ip.clear(&k1);
    per_account.clear(&k2);
} else {
    per_account_ip.hit(&k1);
    per_account.hit(&k2);
}
```

`key` quita los espacios del identificador y lo pasa a minúsculas: `Alice@Example.com` y `alice@example.com` comparten contador.

## Configuración

| Método | Descripción |
|---|---|
| `LoginThrottle::new(max_attempts, decay)` | Límite y ventana; sigue hasta 100 000 claves. |
| `LoginThrottle::default()` | 5 fallos cada 15 minutos. |
| `LoginThrottle::with_capacity(max, decay, keys)` | Límite propio del número de claves seguidas. |
| `LoginThrottle::key(identifier, ip)` | `"identificador\|ip"`, normalizado. |
| `.attempt(key, verify)` | `Ok(bool)` o `Err(retry_after)`; borra en caso de éxito, cuenta los fallos. |
| `.check(key)` / `.too_many_attempts(key)` | Si la clave está bloqueada. |
| `.check_all(keys)` | Varias claves de un mismo throttle; gana la espera más larga. |
| `.hit(key)` | Registra un fallo y devuelve el contador. |
| `.clear(key)` | Olvida los fallos (tras un éxito). |
| `.attempts(key)` / `.remaining(key)` | Contadores actuales. |

## Errores frecuentes y consejos

- Un bloqueo solo por cuenta permite a un atacante bloquear a propósito a cualquier usuario: prefiera cuenta + IP para el límite estricto y mantenga alto el límite por cuenta.
- Use la misma herramienta para los códigos 2FA, las solicitudes de restablecimiento de contraseña y los reenvíos de correos de verificación, cada uno con sus claves.
- El estado está en memoria, por proceso. Con varias instancias, cada una cuenta por su lado: divida sus límites en consecuencia, o mantenga el inicio de sesión en sesiones persistentes.
- Detrás de un proxy, configure la [IP del cliente](/docs/client-ip) (y los proxies de confianza), o todos los usuarios compartirán la dirección del proxy.
- El [bloqueo automático](/docs/auto-ban) lo complementa: respuestas `401` y `429` repetidas bloquean la dirección en toda la aplicación.

## Páginas relacionadas

- [Hash de contraseñas](/docs/passwords)
- [Autenticación de dos factores](/docs/two-factor)
- [Limitación de peticiones](/docs/rate-limit)
- [Bloqueo automático](/docs/auto-ban)
