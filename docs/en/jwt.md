---
title: JWT and JWKS
summary: Validates JSON Web Tokens from any identity provider with an algorithm allow-list, required expiry, issuer and audience checks and JWKS key rotation.
category: access
order: 9
---

`Auth::jwt` authenticates `Authorization: Bearer <jwt>` requests with a `JwtValidator`: access tokens issued by Auth0, Keycloak, Cognito, Entra ID, Google, Supabase or your own service. It needs the `jwt` feature and uses the audited `jsonwebtoken` crate with its RustCrypto backend.

```toml
securite = { version = "0.1", features = ["jwt"] }
```

## Threats mitigated

- **A07:2021 Identification and Authentication Failures**: forged or replayed tokens (CWE-287, CWE-347).
- **`alg: none`**: unsigned tokens are never accepted, whatever the configuration.
- **Algorithm confusion**: a token signed with HS256 using the provider's *public* key as HMAC secret is refused, because the algorithm must be in the allow-list **and** match the family of the key.
- **Expired and future tokens**: `exp` is required, `nbf` is checked (30 s leeway).
- **Token reuse across services**: once an issuer and an audience are configured, they are required; a token that names an audience is refused when none is configured.

## Quick start

```rust
use securite::jwt::{Algorithm, JwtValidator};
use securite::prelude::*;

let jwks = std::fs::read_to_string("jwks.json")?; // the document at the provider's `jwks_uri`
let validator = JwtValidator::jwks(&jwks)?
    .algorithms([Algorithm::RS256])
    .issuer("https://id.example.com/")
    .audience("api://orders")
    .roles_claim("realm_access.roles"); // Keycloak

let shield = Shield::builder()
    .guard(Auth::jwt(validator.clone()).protect(["/api"]).public(["/api/health"]))
    .build();
```

In a handler, the request carries the `Principal` (scheme `jwt`, named after `sub`), the `JwtClaims` and the `Roles`:

```rust
use securite::jwt::JwtClaims;

let claims = req.extensions().get::<JwtClaims>().unwrap();
let tenant = claims.get_str("tenant");
```

## Keys and rotation

| Constructor | Default algorithms |
|---|---|
| `JwtValidator::hmac(secret)` (32 bytes minimum) | HS256 |
| `JwtValidator::rsa_pem(pem)` | RS256 |
| `JwtValidator::ec_pem(pem)` | ES256 |
| `JwtValidator::ed_pem(pem)` | EdDSA |
| `JwtValidator::jwks(json)` | RS256, ES256, EdDSA |

With a JWKS, the key is chosen by the `kid` of the token header; a key that declares an `alg` only verifies that algorithm. Symmetric (`oct`) keys and encryption keys of the set are ignored.

Providers rotate their keys: download the `jwks_uri` regularly (say every 10 minutes, with the HTTP client of your choice) and call `set_jwks`. Every clone of the validator, the one inside the guard included, sees the new keys at once; an invalid or empty document keeps the current keys.

```rust
let v = validator.clone();
tokio::spawn(async move {
    loop {
        if let Ok(body) = fetch(JWKS_URI).await {
            if let Err(e) = v.set_jwks(&body) { tracing::warn!(%e, "JWKS refused"); }
        }
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
    }
});
```

## Configuration

| Method | Description |
|---|---|
| `.algorithms([...])` | Replaces the allow-list. |
| `.issuer(iss)` / `.audience(aud)` | Accepted values; the claim becomes required. Repeatable. |
| `.leeway(duration)` | Clock skew on `exp` / `nbf` (30 s). |
| `.require_claims(["tenant"])` | Claims that must be present. |
| `.subject_claim("sub")` | Claim naming the user (required). |
| `.roles_claim("roles")` | Array or space separated string (`scope`); dotted paths for nested claims. `.no_roles()` disables it. |
| `.validate(token)` | `Result<JwtClaims, JwtError>`, for use outside the guard. |
| `.set_jwks(json)` | Replaces the key set at runtime. |

On failure the guard answers `401` with `WWW-Authenticate: Bearer realm="…", error="invalid_token"` (RFC 6750); the precise reason (`expired token`, `algorithm not allowed` …) only goes to the audit log.

## Pitfalls and tips

- Always configure `issuer` and `audience`: a token issued by the same provider for another application is otherwise valid for yours.
- Keep access tokens short-lived (5 to 15 minutes): a JWT cannot be revoked before it expires. For long sessions, prefer [sessions](/docs/sessions).
- Tokens over 8 KiB are refused before parsing.
- The RustCrypto `rsa` crate has a timing side channel on private-key operations (RUSTSEC-2023-0071); this module only verifies with public keys, which are not affected.
- Combine with [access control](/docs/access-control) to require roles by URL.

## Related pages

- [Authentication](/docs/auth)
- [Access control](/docs/access-control)
- [Authorization](/docs/authorization)
