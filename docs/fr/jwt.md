---
title: JWT et JWKS
summary: Valide les JSON Web Tokens de n'importe quel fournisseur d'identité avec une liste d'algorithmes autorisés, une expiration obligatoire, les contrôles d'émetteur et d'audience et la rotation des clés JWKS.
category: access
order: 9
---

`Auth::jwt` authentifie les requêtes `Authorization: Bearer <jwt>` avec un `JwtValidator` : jetons d'accès émis par Auth0, Keycloak, Cognito, Entra ID, Google, Supabase ou votre propre service. Il demande la feature `jwt` et s'appuie sur la crate auditée `jsonwebtoken` avec son backend RustCrypto.

```toml
securite = { version = "0.2", features = ["jwt"] }
```

## Menaces couvertes

- **A07:2021 Identification et authentification de mauvaise qualité** : jetons forgés ou rejoués (CWE-287, CWE-347).
- **`alg: none`** : un jeton non signé n'est jamais accepté, quelle que soit la configuration.
- **Confusion d'algorithme** : un jeton signé en HS256 avec la clé *publique* du fournisseur comme secret HMAC est refusé, car l'algorithme doit figurer dans la liste autorisée **et** correspondre à la famille de la clé.
- **Jetons expirés ou futurs** : `exp` est obligatoire, `nbf` est vérifié (30 s de tolérance).
- **Réutilisation d'un jeton entre services** : une fois configurés, l'émetteur et l'audience sont obligatoires ; un jeton qui nomme une audience est refusé quand aucune n'est configurée.

## Démarrage rapide

```rust
use securite::jwt::{Algorithm, JwtValidator};
use securite::prelude::*;

let jwks = std::fs::read_to_string("jwks.json")?; // le document du `jwks_uri` du fournisseur
let validator = JwtValidator::jwks(&jwks)?
    .algorithms([Algorithm::RS256])
    .issuer("https://id.example.com/")
    .audience("api://orders")
    .roles_claim("realm_access.roles"); // Keycloak

let shield = Shield::builder()
    .guard(Auth::jwt(validator.clone()).protect(["/api"]).public(["/api/health"]))
    .build();
```

Dans un handler, la requête porte le `Principal` (schéma `jwt`, nommé d'après `sub`), les `JwtClaims` et les `Roles` :

```rust
use securite::jwt::JwtClaims;

let claims = req.extensions().get::<JwtClaims>().unwrap();
let tenant = claims.get_str("tenant");
```

## Clés et rotation

| Constructeur | Algorithmes par défaut |
|---|---|
| `JwtValidator::hmac(secret)` (32 octets minimum) | HS256 |
| `JwtValidator::rsa_pem(pem)` | RS256 |
| `JwtValidator::ec_pem(pem)` | ES256 |
| `JwtValidator::ed_pem(pem)` | EdDSA |
| `JwtValidator::jwks(json)` | RS256, ES256, EdDSA |

Avec un JWKS, la clé est choisie d'après le `kid` de l'en-tête du jeton ; une clé qui déclare un `alg` ne vérifie que cet algorithme. Les clés symétriques (`oct`) et les clés de chiffrement du jeu sont ignorées.

Les fournisseurs font tourner leurs clés : téléchargez régulièrement le `jwks_uri` (toutes les 10 minutes par exemple, avec le client HTTP de votre choix) et appelez `set_jwks`. Tous les clones du validateur, celui du guard compris, voient aussitôt les nouvelles clés ; un document invalide ou vide conserve les clés actuelles.

```rust
let v = validator.clone();
tokio::spawn(async move {
    loop {
        if let Ok(body) = fetch(JWKS_URI).await {
            if let Err(e) = v.set_jwks(&body) { tracing::warn!(%e, "JWKS refusé"); }
        }
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
    }
});
```

## Configuration

| Méthode | Description |
|---|---|
| `.algorithms([...])` | Remplace la liste autorisée. |
| `.issuer(iss)` / `.audience(aud)` | Valeurs acceptées ; le claim devient obligatoire. Répétable. |
| `.leeway(durée)` | Décalage d'horloge toléré sur `exp` / `nbf` (30 s). |
| `.require_claims(["tenant"])` | Claims qui doivent être présents. |
| `.subject_claim("sub")` | Claim qui nomme l'utilisateur (obligatoire). |
| `.roles_claim("roles")` | Tableau ou chaîne séparée par des espaces (`scope`) ; chemins pointés pour les claims imbriqués. `.no_roles()` le désactive. |
| `.validate(jeton)` | `Result<JwtClaims, JwtError>`, hors du guard. |
| `.set_jwks(json)` | Remplace le jeu de clés à chaud. |

En cas d'échec, le guard répond `401` avec `WWW-Authenticate: Bearer realm="…", error="invalid_token"` (RFC 6750) ; la raison précise (`expired token`, `algorithm not allowed` …) ne va que dans le journal d'audit.

## Pièges et conseils

- Configurez toujours `issuer` et `audience` : sinon un jeton émis par le même fournisseur pour une autre application est valide pour la vôtre.
- Gardez des jetons d'accès courts (5 à 15 minutes) : un JWT ne se révoque pas avant son expiration. Pour de longues sessions, préférez les [sessions](/docs/sessions).
- Les jetons de plus de 8 Kio sont refusés avant toute analyse.
- La crate RustCrypto `rsa` a un canal auxiliaire temporel sur les opérations à clé privée (RUSTSEC-2023-0071) ; ce module ne fait que vérifier avec des clés publiques, ce qui n'est pas concerné.
- Combinez avec le [contrôle d'accès](/docs/access-control) pour exiger des rôles par URL.

## Pages liées

- [Authentification](/docs/auth)
- [Contrôle d'accès](/docs/access-control)
- [Autorisations](/docs/authorization)
