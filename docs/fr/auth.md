---
title: Authentification
summary: Jetons bearer, clés d'API, HTTP Basic ou votre propre validateur comme JWT, avec des secrets stockés sous forme d'empreintes SHA-256 et comparés en temps constant.
category: access
order: 3
---

`Auth` place un contrôle d'identifiants devant vos routes. Il prend en charge les schémas dont la plupart des services ont besoin (jetons bearer, clés d'API dans un en-tête dédié, HTTP Basic) et vous permet de brancher votre propre logique de validation, par exemple la vérification de JWT. Les secrets sont conservés sous forme d'empreintes SHA-256 et comparés en temps constant à chacun des identifiants configurés, puis l'identité authentifiée est transmise à vos handlers.

## Menaces couvertes

- **A01:2021 Broken Access Control** : panneaux d'administration, API internes et points d'accès de métriques laissés accessibles sans identifiants.
- **A07:2021 Identification and Authentication Failures** : comparaisons de jetons qui fuient par le temps de réponse (CWE-208), identifiants vérifiés de façon inégale d'un handler à l'autre.
- **A02:2021 Cryptographic Failures** : secrets en clair qui traînent dans les fichiers de configuration ; avec `token_sha256`, votre configuration ne contient qu'une empreinte.

## Fonctionnement

1. **Sélection des chemins.** Une requête est protégée lorsque son chemin correspond à l'un des préfixes `protect` (tous les chemins si aucun n'est configuré) et à aucun des préfixes `public`. Les préfixes sont comparés par segments : `/api` couvre `/api` et `/api/orders`, pas `/apiary`.
2. **Requêtes de pré-vérification.** Les requêtes `OPTIONS` passent par défaut, car les navigateurs n'attachent jamais d'identifiants aux preflights CORS.
3. **Extraction.** L'identifiant est lu selon le schéma : `Authorization: Bearer …`, un en-tête dédié ou `Authorization: Basic …`.
4. **Vérification.** Le secret présenté est haché en SHA-256 puis comparé à chaque empreinte configurée avec une égalité en temps constant, sans sortie anticipée. Ni la longueur ni la position de l'identifiant correspondant ne peuvent être déduites des temps de réponse.
5. **Résultat.** En cas de succès, un `Principal` est inséré dans les extensions de la requête. En cas d'échec, la requête est rejetée avec `401 Unauthorized`, le code `unauthorized`, le message `Authentication required.` et un défi `WWW-Authenticate`.

Le guard s'exécute tard dans la chaîne, après la limitation de débit, le blocage des robots, le WAF et les contrôles CSRF : les tentatives de force brute sont freinées avant même la vérification d'un identifiant.

## Démarrage rapide

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let token = std::env::var("API_TOKEN").expect("API_TOKEN must be set");

let app: Router = Router::new()
    .route("/api/health", get(|| async { "ok" }))
    .route("/api/orders", get(|| async { "[]" }))
    .layer(
        ShieldBuilder::recommended()
            .guard(
                Auth::bearer()
                    .token("ci-pipeline", &token)
                    .protect(["/api"])
                    .public(["/api/health"]),
            )
            .build(),
    );
```

```bash
curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/api/orders
```

## Schémas

### Jetons bearer

`Auth::bearer()` lit `Authorization: Bearer <token>` (le nom du schéma est insensible à la casse). Enregistrez autant de jetons que nécessaire, chacun avec un libellé qui devient le nom du principal : vous savez ainsi quel client a appelé.

### Clés d'API

```rust
use securite::prelude::*;

let partner_key = std::env::var("PARTNER_ACME_KEY").expect("PARTNER_ACME_KEY must be set");
let auth = Auth::api_key("x-api-key").token("partner-acme", &partner_key);
```

La valeur de l'en-tête est comparée telle qu'elle est reçue.

### HTTP Basic

```rust
use securite::prelude::*;

let password = std::env::var("ADMIN_PASSWORD").expect("ADMIN_PASSWORD must be set");
let auth = Auth::basic("Admin area").user("admin", &password);
```

C'est l'empreinte de `user:password` qui est stockée, et le nom du principal est le nom d'utilisateur. Les identifiants Basic accompagnent chaque requête : ne les utilisez qu'en HTTPS.

### Validation personnalisée

`Auth::custom` transmet le jeton bearer et l'en-tête de la requête à votre fonction, qui renvoie le nom du principal lorsque le jeton est valide. Un exemple complet avec JWT figure plus bas.

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `Auth::bearer()` | — | `Authorization: Bearer <token>`. |
| `Auth::api_key(header)` | — | Clé dans un en-tête dédié ; panique si le nom d'en-tête est invalide. |
| `Auth::basic(realm)` | — | Authentification HTTP Basic avec le realm indiqué. |
| `Auth::custom(f)` | — | Jeton bearer vérifié par `Fn(&str, &request::Parts) -> Option<String>`. |
| `.token(label, secret)` | aucun | Jeton ou clé d'API accepté ; panique si le secret fait moins de 8 octets. |
| `.token_sha256(label, hex)` | aucun | Jeton accepté, fourni par son empreinte SHA-256 en hexadécimal ; panique s'il ne s'agit pas de 64 caractères hexadécimaux. |
| `.user(user, password)` | aucun | Utilisateur Basic ; panique si le nom contient `:`. |
| `.realm(realm)` | `restricted` | Realm annoncé dans `WWW-Authenticate` (guillemets et barres obliques inverses supprimés). |
| `.protect(prefixes)` | tous les chemins | Seuls ces préfixes de chemins exigent des identifiants. |
| `.public(prefixes)` | aucun | Préfixes de chemins qui n'exigent jamais d'identifiants ; ils l'emportent sur `protect`. |
| `.protect_options()` | `OPTIONS` autorisé | Exige aussi des identifiants sur les requêtes `OPTIONS`. |

## Garder les secrets hors de votre configuration

Avec `token_sha256`, seule l'empreinte d'un jeton est stockée dans votre configuration ou vos variables d'environnement. Calculez-la ainsi :

```bash
# printf %s does not append a newline (echo would, and the digest would change).
printf %s "s3cr3t-token-from-vault" | sha256sum
# 316c2c9705150d9a064339f9af33986ffd585a65b1d3ff481c5a9941d45abe1f  -
```

```rust
use securite::prelude::*;

let auth = Auth::bearer()
    .token_sha256("deploy-bot", "316c2c9705150d9a064339f9af33986ffd585a65b1d3ff481c5a9941d45abe1f")
    .protect(["/deploy"]);
```

Les identifiants Basic sont vérifiés via l'empreinte de `user:password` : `token_sha256` fonctionne donc aussi avec `Auth::basic`, et le libellé devient alors le nom du principal :

```bash
printf %s "admin:correct horse battery staple" | sha256sum
# 1ced36b78267abc485730b6921c0fe42edac8704d5fabe97bf6bb09b46b4164a  -
```

```rust
use securite::prelude::*;

let auth = Auth::basic("Admin area")
    .token_sha256("admin", "1ced36b78267abc485730b6921c0fe42edac8704d5fabe97bf6bb09b46b4164a")
    .protect(["/admin"]);
```

> **Astuce :** générez vos jetons avec un générateur cryptographiquement sûr, par exemple `openssl rand -hex 32`. Une simple empreinte SHA-256 convient à des jetons d'une telle entropie, mais elle ne protégerait pas un mot de passe humain trop court contre un cassage hors ligne : choisissez des mots de passe Basic longs et aléatoires.

## L'extension `Principal`

```rust
use axum::{routing::get, Extension, Router};
use securite::prelude::*;

async fn whoami(Extension(principal): Extension<Principal>) -> String {
    // name: the credential label (or the Basic user name)
    // scheme: "bearer", "api_key", "basic" or "custom"
    format!("authenticated as {} via {}", principal.name, principal.scheme)
}

let token = std::env::var("API_TOKEN").expect("API_TOKEN must be set");
let app: Router = Router::new()
    .route("/api/whoami", get(whoami))
    .layer(Shield::builder().guard(Auth::bearer().token("ci-pipeline", &token)).build());
```

`Principal` n'est inséré que sur les chemins protégés. L'extraire depuis une route publique conduit axum à répondre `500 Internal Server Error`, faute d'extension.

## Le défi `WWW-Authenticate`

Chaque `401` porte un défi qui indique au client le schéma à utiliser :

```text
Bearer realm="restricted"
ApiKey realm="restricted", header="x-api-key"
Basic realm="Admin area", charset="UTF-8"
```

`Auth::custom` envoie un défi `Bearer`. En Basic, les navigateurs affichent leur boîte de connexion native.

## Requêtes OPTIONS

Les preflights CORS ne portent jamais d'identifiants : `Auth` laisse donc passer `OPTIONS` par défaut. Lorsqu'un guard `Cors` est configuré, il répond aux preflights avant même l'exécution d'`Auth`. Si votre API n'est jamais appelée depuis un navigateur, `.protect_options()` ferme aussi cette porte.

## Brancher une validation JWT

`Auth::custom` accepte n'importe quelle fonction synchrone. Ici avec le crate `jsonwebtoken` :

```rust
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use securite::prelude::*;
use serde::Deserialize;

#[derive(Clone, Deserialize)]
struct Claims {
    sub: String,
}

let key = DecodingKey::from_secret(
    std::env::var("JWT_SECRET").expect("JWT_SECRET must be set").as_bytes(),
);
let mut validation = Validation::new(Algorithm::HS256);
validation.set_audience(&["orders-api"]);
validation.set_issuer(&["https://auth.example.com"]);

let auth = Auth::custom(move |token, _req| {
    // Signature, expiry, audience and issuer are checked by `decode`.
    decode::<Claims>(token, &key, &validation)
        .ok()
        .map(|data| data.claims.sub)
})
.protect(["/api"])
.public(["/api/health"]);
```

Le validateur s'exécute sur le chemin de la requête : limitez-le à du calcul (vérification de signature, recherches en mémoire). Chargez les clés de signature ou le JWKS au démarrage et rafraîchissez-les dans une tâche de fond plutôt que de les récupérer à chaque requête. Le second argument donne accès à l'en-tête de la requête, par exemple pour lire un en-tête de tenant.

## Plusieurs schémas dans une même application

Un `Shield` ne contient qu'un guard par nom : un second `Auth` remplacerait le premier. Utilisez plutôt des couches autonomes sur des routeurs distincts, avec `route_layer` pour que les URL inconnues répondent toujours `404` :

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let admin_password = std::env::var("ADMIN_PASSWORD").expect("ADMIN_PASSWORD must be set");
let partner_key = std::env::var("PARTNER_ACME_KEY").expect("PARTNER_ACME_KEY must be set");

let admin = Router::new()
    .route("/admin/dashboard", get(|| async { "admin" }))
    .route_layer(Auth::basic("Admin area").user("admin", &admin_password));

let partners = Router::new()
    .route("/partners/orders", get(|| async { "[]" }))
    .route_layer(Auth::api_key("x-api-key").token("partner-acme", &partner_key));

let app: Router = Router::new()
    .route("/", get(|| async { "public home" }))
    .merge(admin)
    .merge(partners)
    .layer(Shield::recommended());
```

## Pièges et conseils

- Ne servez les routes authentifiées qu'en HTTPS (`HttpsRedirect` et HSTS), faute de quoi jetons et mots de passe Basic circulent en clair.
- Faites tourner les jetons sans interruption de service : ajoutez le nouveau jeton sous un nouveau libellé, déployez, migrez les clients, puis retirez l'ancien.
- `401` est un statut pénalisant par défaut d'`AutoBan` : avec le [bannissement automatique](/docs/auto-ban) activé, les clients qui s'acharnent à deviner des identifiants sont bannis automatiquement. Ajoutez aussi un `RateLimit` strict sur les points d'accès de type connexion.
- `.public` l'emporte toujours sur `.protect` : vérifiez qu'un préfixe public ne couvre pas par mégarde un sous-chemin sensible.
- Avec `Auth::custom`, la comparaison en temps constant relève de votre validateur ; les bibliothèques de vérification de signature s'en chargent déjà.

## Pages associées

- [Filtrage IP](/docs/ip-filter)
- [Bannissement automatique](/docs/auto-ban)
- [Limitation de débit](/docs/rate-limit)
- [Redirection HTTPS](/docs/https-redirect)
- [CORS](/docs/cors)
- [Signatures de webhooks](/docs/webhook-signatures)
- [Événements de sécurité et statistiques](/docs/events-stats)
