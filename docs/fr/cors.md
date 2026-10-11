---
title: CORS
summary: Un partage de ressources cross-origin strict, fondé sur une liste d'autorisation, qui ne renvoie jamais d'origine arbitraire et refuse les combinaisons dangereuses dès le démarrage.
category: browser
order: 2
---

`Cors` répond aux requêtes de pré-vérification (preflight) et ajoute les en-têtes `Access-Control-*` pour les origines que vous listez, et uniquement pour elles. Ses valeurs par défaut sont volontairement fermées : aucune origine n'est autorisée tant que vous n'en nommez pas une.

## La menace

La politique de même origine empêche une page hébergée sur `evil.example` de lire les réponses de votre API. CORS permet d'y ouvrir des brèches contrôlées, et une erreur de configuration la désactive purement et simplement :

- **Réflexion de l'origine** : renvoyer n'importe quel `Origin` accompagné de `Access-Control-Allow-Credentials: true` permet à tous les sites de lire les données authentifiées de vos utilisateurs.
- **L'origine `null`** : les iframes sandboxées et les pages `file://` envoient `Origin: null` ; lui faire confiance revient à faire confiance à n'importe qui.
- **Comparaisons laxistes** : des vérifications par suffixe ou par expression régulière qui acceptent `app.example.com.evil.com` ou `evilexample.com`.

Ce sont des failles classiques des catégories A05 Security Misconfiguration et A01 Broken Access Control de l'OWASP Top 10 2021, couvertes par l'OWASP Web Security Testing Guide (WSTG-CLNT-07).

## Fonctionnement

`Cors` s'exécute à la priorité 90, avant la limitation de débit, le CSRF et l'authentification : les preflights, qui ne portent aucun identifiant, reçoivent donc leur réponse en premier.

- **Sans en-tête `Origin`** (navigation de même origine, curl, appel de serveur à serveur) : la requête n'est pas modifiée.
- **Preflight** (`OPTIONS` avec `Access-Control-Request-Method`) : l'origine, la méthode et chaque en-tête demandé sont vérifiés. En cas de succès, le shield répond lui-même `204 No Content` avec `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, `Access-Control-Max-Age` et `Access-Control-Allow-Origin`. En cas d'échec, il répond `403` avec le code `cors_rejected`, et l'événement est journalisé.
- **Requête réelle depuis une origine autorisée** : la réponse reçoit `Access-Control-Allow-Origin` (l'origine exacte, ou `*` avec `allow_any_origin()` sans identifiants), ainsi que `Access-Control-Allow-Credentials` et `Access-Control-Expose-Headers` lorsqu'ils sont configurés.
- **Requête réelle depuis une autre origine** : aucun en-tête CORS n'est ajouté, et le navigateur masque la réponse au script appelant.
- Chaque réponse porte `Vary: Origin`, pour que les caches ne servent jamais la réponse d'une origine à une autre.

Les origines sont comparées sans tenir compte de la casse, et une éventuelle barre oblique finale est ignorée. `https://*.example.com` couvre les sous-domaines à n'importe quelle profondeur, mais pas `example.com` lui-même ; le schéma et le port doivent correspondre exactement. `null` n'est accepté que s'il est listé explicitement. Passer `"*"` à `allow_origin` provoque une panique (utilisez `allow_any_origin()`), tout comme combiner `allow_any_origin()` avec `allow_credentials(true)`.

## Démarrage rapide

```rust
use std::time::Duration;

use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let cors = Cors::new()
        .allow_origin("https://app.example.com")
        .allow_credentials(true)
        .max_age(Duration::from_secs(3600));

    let mut app = App::new();
    app.middleware(Shield::builder().guard(cors).build());
    app.get("/api/me", |_req: Request| async { "{}" });
    app
}
```

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `Cors::new()` | aucune origine | Démarre avec les méthodes et en-têtes courants, mais sans origine autorisée. |
| `allow_origin(&str)` | — | Autorise une origine (`https://app.example.com`) ou un motif générique (`https://*.example.com`). |
| `allow_origins(iter)` | — | Autorise plusieurs origines. |
| `allow_any_origin()` | inactif | Envoie `Access-Control-Allow-Origin: *`. Réservé aux API publiques non authentifiées. |
| `allow_methods(iter of Method)` | `GET, HEAD, POST, PUT, PATCH, DELETE` | **Remplace** les méthodes autorisées. |
| `allow_headers(iter)` | `accept, accept-language, content-language, content-type, authorization, x-requested-with, x-csrf-token, x-request-id` | **Remplace** les en-têtes de requête autorisés. |
| `expose_headers(iter)` | aucun | **Remplace** les en-têtes de réponse lisibles par les scripts. |
| `allow_credentials(bool)` | `false` | Autorise les cookies et `Authorization` sur les requêtes cross-origin. |
| `max_age(Duration)` | 600 secondes | Durée pendant laquelle le navigateur peut mettre un preflight en cache. |
| `allow_private_network(bool)` | `false` | Répond aux preflights Private Network Access avec `Access-Control-Allow-Private-Network: true`. |

Le guard s'appelle `cors`. Aucun preset ne l'inclut, car vous seul connaissez vos origines.

## Exemples

### Front-end sur un autre sous-domaine, avec cookies

Une application monopage hébergée sur `app.example.com` appelle `api.example.com` avec un cookie de session. Ses requêtes `POST` sont cross-origin : la protection CSRF doit donc, elle aussi, faire confiance à cette origine.

```rust
use std::time::Duration;

use securite::prelude::*;
use vitesse::prelude::*;

pub fn api() -> App {
    let shield = ShieldBuilder::recommended()
        .guard(
            Cors::new()
                .allow_origin("https://app.example.com")
                .allow_credentials(true)
                .expose_headers(["x-request-id", "ratelimit-remaining"])
                .max_age(Duration::from_secs(3600)),
        )
        // Replaces the preset's CSRF guard: the SPA is a trusted cross-origin caller.
        .guard(Csrf::new().trusted_origin("https://app.example.com"))
        .build();

    let mut app = App::new();
    app.middleware(shield);
    app.get("/me", |_req: Request| async { "{}" });
    app.post("/orders", |_req: Request| async { "created" });
    app
}
```

### API publique en lecture seule

```rust
use securite::http::Method;
use securite::prelude::*;

pub fn public_cors() -> Cors {
    Cors::new()
        .allow_any_origin()
        .allow_methods([Method::GET, Method::HEAD])
        .allow_headers(["accept", "content-type"])
}
```

### Sous-domaines, déploiements de prévisualisation et en-têtes personnalisés

```rust
use securite::prelude::*;

pub fn cors(dev: bool) -> Cors {
    let cors = Cors::new()
        .allow_origins(["https://example.com", "https://*.example.com"])
        .allow_headers(["content-type", "authorization", "x-api-key"]);
    if dev { cors.allow_origin("http://localhost:5173") } else { cors }
}
```

### Vérifier un preflight avec curl

```bash
curl -i -X OPTIONS https://api.example.com/orders \
  -H "Origin: https://app.example.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type"
```

```text
HTTP/2 204
access-control-allow-methods: GET, HEAD, POST, PUT, PATCH, DELETE
access-control-max-age: 3600
access-control-allow-headers: accept, accept-language, content-language, content-type, authorization, x-requested-with, x-csrf-token, x-request-id
access-control-allow-origin: https://app.example.com
access-control-allow-credentials: true
vary: origin
```

## Utilisation comme guard autonome

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::from(Cors::new().allow_origin("https://app.example.com")));
    app.get("/api/items", |_req: Request| async { "[]" });
    app
}
```

Avec Vitesse, le premier middleware ajouté correspond au plus externe. Si vous empilez des guards autonomes, ajoutez `Cors` avant tout middleware d'authentification : les preflights, qui ne portent jamais d'identifiants, reçoivent ainsi leur réponse avant de l'atteindre. Au sein d'un même `Shield`, cet ordre est automatique.

## Pièges et conseils

> **Attention :** CORS n'est pas un contrôle d'accès. Une requête « simple » venant d'une origine non autorisée atteint quand même votre handler ; le navigateur se contente d'en masquer la réponse. Protégez les points d'entrée qui modifient l'état avec la [protection CSRF](/docs/csrf) et une [liste d'autorisation Content-Type](/docs/content-type) limitée au JSON.

- `allow_methods`, `allow_headers` et `expose_headers` remplacent leurs valeurs par défaut. Ajouter `x-api-key` seul ferait disparaître `content-type` et `authorization`.
- Ne listez jamais `null` : cette origine est envoyée par des iframes sandboxées et des fichiers locaux que n'importe quel attaquant peut créer.
- Un motif générique couvre tous les sous-domaines, présents et futurs, y compris un sous-domaine détourné via un enregistrement DNS orphelin. Préférez une liste exacte pour les API qui acceptent des identifiants.
- `https://app.example.com` et `https://app.example.com:8443` sont deux origines différentes.
- Les navigateurs plafonnent `max_age` (Chromium à deux heures) : une valeur plus élevée est sans effet.
- Gardez les origines de développement comme `http://localhost:5173` hors de la configuration de production.
- Les scripts ne peuvent lire que les en-têtes de réponse autorisés par CORS. Exposez `x-request-id` ou les en-têtes de limitation de débit si votre front-end en a besoin.

> **Astuce :** si votre CDN met en cache les réponses de l'API, vérifiez qu'il respecte `Vary: Origin`.

## Pages associées

- [Protection CSRF](/docs/csrf)
- [Liste d'autorisation Content-Type](/docs/content-type)
- [En-têtes de sécurité](/docs/security-headers)
- [Durcissement des cookies](/docs/cookies)
- [Authentification](/docs/auth)
