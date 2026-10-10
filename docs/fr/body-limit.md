---
title: Limite de taille du corps
summary: Rejetez les corps de requête trop volumineux avant l'exécution de votre handler, avec des limites par route, et appliquez la limite aux flux chunked.
category: traffic
order: 4
---

Securite fournit deux outils complémentaires contre les corps de requête surdimensionnés. `BodyLimit` est un garde qui rejette les requêtes dont le `Content-Length` déclaré est trop grand, avant la lecture du moindre octet du corps. `BodyLimitLayer` est une couche tower qui applique la limite pendant la lecture du flux, ce qui couvre aussi les envois chunked qui ne déclarent aucune longueur.

## Menaces couvertes

Accepter des corps de taille arbitraire est l'une des attaques par déni de service les moins chères : quelques clients qui envoient des gigaoctets peuvent remplir votre mémoire ou votre disque, saturer votre bande passante et occuper vos workers à analyser des données (OWASP API4:2023, Unrestricted Resource Consumption). Les parseurs JSON et de formulaires sont particulièrement exposés, car ils chargent généralement tout le corps en mémoire avant de l'analyser.

## Fonctionnement

```text
request head ----> BodyLimit (guard, priority 80)
                     Content-Length present?
                       invalid           -> 400 bad_content_length
                       > limit for path  -> 413 body_too_large
                     no Content-Length, Transfer-Encoding set,
                     POST/PUT/PATCH and require_content_length(true)
                                         -> 411 length_required
body stream -----> BodyLimitLayer (Limited body)
                     more than max bytes read -> error, 413 with axum extractors
```

* `BodyLimit` ne regarde que les en-têtes : le rejet ne coûte rien et intervient avant votre handler, le WAF ou l'authentification.
* Les limites par route s'appliquent à des préfixes de chemin comparés segment par segment ; **le préfixe correspondant le plus long l'emporte**, la limite par défaut s'applique ailleurs.
* Un corps chunked n'a pas de `Content-Length` : `BodyLimit` ne peut donc pas juger sa taille. Refusez ces corps avec `require_content_length(true)` ou ajoutez `BodyLimitLayer`, qui enveloppe le corps dans `http_body_util::Limited` : lire au-delà de la limite échoue, et les extracteurs d'axum transforment cette erreur en `413 Payload Too Large`.

## Démarrage rapide

```rust
use axum::{routing::post, Router};
use securite::prelude::*;

let shield = Shield::builder()
    // 1 MiB for every request body.
    .guard(BodyLimit::new(1024 * 1024))
    .build();

let app: Router = Router::new()
    .route("/comments", post(|body: String| async move { format!("{} bytes", body.len()) }))
    .layer(shield);
```

Les préréglages incluent déjà une limite : 2 Mio pour `Shield::recommended()`, 1 Mio pour `Shield::strict()` et `Shield::api()`.

## Configuration

### BodyLimit (garde)

| Méthode | Défaut | Description |
|---|---|---|
| `BodyLimit::new(max_bytes)` | – | Taille maximale par défaut du corps, en octets (`u64`). |
| `.route(prefix, max_bytes)` | aucune | Limite spécifique à un préfixe de chemin (le plus long l'emporte). |
| `.require_content_length(bool)` | `false` | Rejette les corps `POST`, `PUT` et `PATCH` envoyés avec `Transfer-Encoding` et sans `Content-Length` (`411`). |
| `.limit_for(path)` | – | Renvoie la limite applicable à `path`. |

### BodyLimitLayer (streaming)

| Méthode | Défaut | Description |
|---|---|---|
| `BodyLimitLayer::new(max_bytes)` | – | Nombre maximal d'octets du corps que votre service peut lire (`usize`). |

`BodyLimitLayer` est une simple couche tower, pas un garde : on ne peut pas l'enregistrer avec `Shield::builder().guard()`, et ses dépassements ne sont pas signalés comme événements de sécurité.

## Exemples

### Petits corps d'API, gros envois de fichiers

```rust
use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::{routing::post, Router};
use securite::prelude::*;

let shield = Shield::builder()
    .guard(
        BodyLimit::new(256 * 1024)                    // 256 KiB everywhere...
            .route("/upload", 50 * 1024 * 1024)       // ...50 MiB for uploads...
            .route("/upload/avatar", 2 * 1024 * 1024) // ...but 2 MiB for avatars
            .require_content_length(true),
    )
    .build();

let app: Router = Router::new()
    .route("/upload/files", post(|body: Bytes| async move { format!("{} bytes", body.len()) }))
    .route("/upload/avatar", post(|body: Bytes| async move { format!("{} bytes", body.len()) }))
    // axum's own extractor limit (2 MB by default) must be raised as well.
    .layer(DefaultBodyLimit::max(50 * 1024 * 1024))
    .layer(shield);
```

### Envois chunked

Lorsque des clients envoient légitimement des corps sans `Content-Length` (clients HTTP/2, encodeurs chunked), conservez `require_content_length(false)` et ajoutez la couche de streaming en filet de sécurité :

```rust
use axum::body::Bytes;
use axum::{routing::post, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/ingest", post(|body: Bytes| async move { format!("{} bytes", body.len()) }))
    // Hard cap on what the handler can ever read, chunked or not.
    .layer(BodyLimitLayer::new(1024 * 1024))
    // Fast path: honest Content-Length values are rejected before any read.
    .layer(Shield::builder().guard(BodyLimit::new(1024 * 1024)).build());
```

## Utilisation en couche autonome

```rust
use axum::{routing::post, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/comments", post(|body: String| async move { body }))
    .layer(BodyLimit::new(64 * 1024));
```

## En-têtes de réponse

`BodyLimit` n'ajoute aucun en-tête particulier. Les rejets utilisent le format d'erreur du bouclier (`application/problem+json` et `Cache-Control: no-store` par défaut) :

| Statut | Code | Cas |
|---|---|---|
| `413 Payload Too Large` | `body_too_large` | `Content-Length` supérieur à la limite du chemin. Le message indique la limite. |
| `400 Bad Request` | `bad_content_length` | `Content-Length` n'est pas un nombre. |
| `411 Length Required` | `length_required` | `POST`/`PUT`/`PATCH` chunked avec `require_content_length(true)`. |

```text
HTTP/1.1 413 Payload Too Large
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Payload Too Large","status":413,"code":"body_too_large","detail":"Request body too large (max 262144 bytes)."}
```

Les dépassements détectés par `BodyLimitLayer` reçoivent la réponse de votre framework (axum : un `413` en texte brut).

## Pièges et conseils

* **Deux limites s'appliquent avec axum** : les extracteurs `Bytes`, `String`, `Json` et `Form` conservent la limite par défaut d'axum de 2 Mo. Relevez-la avec `DefaultBodyLimit::max` sur les routes d'envoi, sinon les fichiers de plus de 2 Mo échouent même quand Securite les autorise.
* **`BodyLimit` seul ne couvre pas les corps chunked** : utilisez `require_content_length(true)` ou `BodyLimitLayer`.
* `require_content_length(true)` peut casser les clients HTTP/2 et les envois en streaming qui omettent légitimement `Content-Length`. Testez vos clients avant de l'activer.
* Les préfixes de route sont comparés segment par segment : `/upload` couvre `/upload/files` mais pas `/uploads`.
* Les envois multipart comptent tout le corps encodé, délimiteurs et en-têtes compris : gardez une marge au-dessus du plus gros fichier accepté.

> **Astuce :** gardez une limite par défaut basse et n'accordez de grandes limites qu'aux routes qui en ont besoin. La plupart des API JSON n'ont jamais besoin de plus de quelques centaines de kilo-octets.

## Pages associées

* [Hygiène HTTP](/docs/hygiene)
* [Limitation de débit](/docs/rate-limit)
* [Limite de concurrence](/docs/concurrency-limit)
* [Filtrage des méthodes](/docs/method-filter)
