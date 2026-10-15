---
title: JWT y JWKS
summary: Valida JSON Web Tokens de cualquier proveedor de identidad con una lista de algoritmos permitidos, expiración obligatoria, comprobación de emisor y audiencia y rotación de claves JWKS.
category: access
order: 9
---

`Auth::jwt` autentica las peticiones `Authorization: Bearer <jwt>` con un `JwtValidator`: tokens de acceso emitidos por Auth0, Keycloak, Cognito, Entra ID, Google, Supabase o su propio servicio. Necesita la feature `jwt` y se apoya en el crate auditado `jsonwebtoken` con su backend RustCrypto.

```toml
securite = { version = "0.1", features = ["jwt"] }
```

## Amenazas mitigadas

- **A07:2021 Fallos de identificación y autenticación**: tokens falsificados o reutilizados (CWE-287, CWE-347).
- **`alg: none`**: un token sin firma nunca se acepta, sea cual sea la configuración.
- **Confusión de algoritmo**: un token firmado en HS256 con la clave *pública* del proveedor como secreto HMAC se rechaza, porque el algoritmo debe estar en la lista permitida **y** corresponder a la familia de la clave.
- **Tokens caducados o futuros**: `exp` es obligatorio y `nbf` se comprueba (30 s de tolerancia).
- **Reutilización de un token entre servicios**: una vez configurados, el emisor y la audiencia son obligatorios; un token que nombra una audiencia se rechaza cuando no hay ninguna configurada.

## Inicio rápido

```rust
use securite::jwt::{Algorithm, JwtValidator};
use securite::prelude::*;

let jwks = std::fs::read_to_string("jwks.json")?; // el documento del `jwks_uri` del proveedor
let validator = JwtValidator::jwks(&jwks)?
    .algorithms([Algorithm::RS256])
    .issuer("https://id.example.com/")
    .audience("api://orders")
    .roles_claim("realm_access.roles"); // Keycloak

let shield = Shield::builder()
    .guard(Auth::jwt(validator.clone()).protect(["/api"]).public(["/api/health"]))
    .build();
```

En un handler, la petición lleva el `Principal` (esquema `jwt`, con el nombre de `sub`), los `JwtClaims` y los `Roles`:

```rust
use securite::jwt::JwtClaims;

let claims = req.extensions().get::<JwtClaims>().unwrap();
let tenant = claims.get_str("tenant");
```

## Claves y rotación

| Constructor | Algoritmos por defecto |
|---|---|
| `JwtValidator::hmac(secret)` (32 bytes como mínimo) | HS256 |
| `JwtValidator::rsa_pem(pem)` | RS256 |
| `JwtValidator::ec_pem(pem)` | ES256 |
| `JwtValidator::ed_pem(pem)` | EdDSA |
| `JwtValidator::jwks(json)` | RS256, ES256, EdDSA |

Con un JWKS, la clave se elige por el `kid` de la cabecera del token; una clave que declara un `alg` solo verifica ese algoritmo. Las claves simétricas (`oct`) y las de cifrado del conjunto se ignoran.

Los proveedores rotan sus claves: descargue el `jwks_uri` con regularidad (cada 10 minutos, por ejemplo, con el cliente HTTP que prefiera) y llame a `set_jwks`. Todos los clones del validador, incluido el del guard, ven las nuevas claves al instante; un documento inválido o vacío conserva las claves actuales.

```rust
let v = validator.clone();
tokio::spawn(async move {
    loop {
        if let Ok(body) = fetch(JWKS_URI).await {
            if let Err(e) = v.set_jwks(&body) { tracing::warn!(%e, "JWKS rechazado"); }
        }
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
    }
});
```

## Configuración

| Método | Descripción |
|---|---|
| `.algorithms([...])` | Sustituye la lista permitida. |
| `.issuer(iss)` / `.audience(aud)` | Valores aceptados; el claim pasa a ser obligatorio. Repetible. |
| `.leeway(duración)` | Desfase de reloj tolerado en `exp` / `nbf` (30 s). |
| `.require_claims(["tenant"])` | Claims que deben estar presentes. |
| `.subject_claim("sub")` | Claim que nombra al usuario (obligatorio). |
| `.roles_claim("roles")` | Array o cadena separada por espacios (`scope`); rutas con puntos para claims anidados. `.no_roles()` lo desactiva. |
| `.validate(token)` | `Result<JwtClaims, JwtError>`, fuera del guard. |
| `.set_jwks(json)` | Sustituye el conjunto de claves en caliente. |

Si falla, el guard responde `401` con `WWW-Authenticate: Bearer realm="…", error="invalid_token"` (RFC 6750); el motivo preciso (`expired token`, `algorithm not allowed` …) solo va al registro de auditoría.

## Trampas y consejos

- Configure siempre `issuer` y `audience`: si no, un token emitido por el mismo proveedor para otra aplicación vale para la suya.
- Mantenga tokens de acceso cortos (5 a 15 minutos): un JWT no se revoca antes de caducar. Para sesiones largas, prefiera las [sesiones](/docs/sessions).
- Los tokens de más de 8 KiB se rechazan antes de analizarlos.
- El crate RustCrypto `rsa` tiene un canal lateral de tiempo en las operaciones con clave privada (RUSTSEC-2023-0071); este módulo solo verifica con claves públicas, que no se ven afectadas.
- Combínelo con el [control de acceso](/docs/access-control) para exigir roles por URL.

## Páginas relacionadas

- [Autenticación](/docs/auth)
- [Control de acceso](/docs/access-control)
- [Autorización](/docs/authorization)
