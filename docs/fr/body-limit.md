---
title: Limite de taille du corps
summary: Rejetez les corps de requête trop volumineux avant l'exécution de votre handler, avec des limites par route, et appliquez la limite aux flux chunked.
category: traffic
order: 4
---

Securite fournit deux outils complémentaires contre les corps de requête surdimensionnés. `BodyLimit` est un garde qui rejette les requêtes dont le `Content-Length` déclaré est trop grand, avant la lecture du moindre octet du corps. La limite en flux, qui couvre aussi les envois chunked qui ne déclarent aucune longueur, est celle du serveur : `app.body_limit` de Vitesse, ou la couche tower `BodyLimitLayer` dans les autres services.

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
body stream -----> Vitesse: app.body_limit (1 MiB by default)
                   tower services: BodyLimitLayer (Limited body)
                     more than max bytes read -> 413
```

* `BodyLimit` ne regarde que les en-têtes : le rejet ne coûte rien et intervient avant votre handler, le WAF ou l'authentification.
* Les limites par route s'appliquent à des préfixes de chemin comparés segment par segment ; **le préfixe correspondant le plus long l'emporte**, la limite par défaut s'applique ailleurs.
* Un corps chunked n'a pas de `Content-Length` : `BodyLimit` ne peut donc pas juger sa taille. Refusez ces corps avec `require_content_length(true)` ou comptez sur la limite en flux : `app.body_limit(octets)` de Vitesse (1 Mio par défaut) arrête la lecture au-delà de la limite et répond `413 Payload Too Large` ; dans les services tower, `BodyLimitLayer` enveloppe le corps dans `http_body_util::Limited` de la même façon.

## Démarrage rapide

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let shield = Shield::builder()
    // 1 MiB for every request body.
    .guard(BodyLimit::new(1024 * 1024))
    .build();

let mut app = App::new();
app.middleware(shield);
app.post("/comments", |req: Request| async move {
    let body = req.text().await?;
    Ok::<_, Error>(format!("{} bytes", body.len()))
});
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

`BodyLimitLayer` est une simple couche tower pour les services sans Vitesse (qui a `app.body_limit`), pas un garde : on ne peut pas l'enregistrer avec `Shield::builder().guard()`, et ses dépassements ne sont pas signalés comme événements de sécurité.

## Exemples

### Petits corps d'API, gros envois de fichiers

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let shield = Shield::builder()
    .guard(
        BodyLimit::new(256 * 1024)                    // 256 KiB everywhere...
            .route("/upload", 50 * 1024 * 1024)       // ...50 MiB for uploads...
            .route("/upload/avatar", 2 * 1024 * 1024) // ...but 2 MiB for avatars
            .require_content_length(true),
    )
    .build();

async fn upload(req: Request) -> Result<String, Error> {
    let body = req.bytes().await?;
    Ok(format!("{} bytes", body.len()))
}

let mut app = App::new();
// La limite propre à Vitesse (1 Mio par défaut) doit être relevée aussi.
app.body_limit(50 * 1024 * 1024);
app.middleware(shield);
app.post("/upload/files", upload);
app.post("/upload/avatar", upload);
```

### Envois chunked

Lorsque des clients envoient légitimement des corps sans `Content-Length` (clients HTTP/2, encodeurs chunked), conservez `require_content_length(false)` et ajoutez la couche de streaming en filet de sécurité :

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
// Hard cap on what the handler can ever read, chunked or not.
app.body_limit(1024 * 1024);
// Fast path: honest Content-Length values are rejected before any read.
app.middleware(Shield::builder().guard(BodyLimit::new(1024 * 1024)).build());
app.post("/ingest", |req: Request| async move {
    let body = req.bytes().await?;
    Ok::<_, Error>(format!("{} bytes", body.len()))
});
```

## Utilisation en guard autonome

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(BodyLimit::new(64 * 1024)));
app.post("/comments", |req: Request| async move { req.text().await });
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

Les dépassements détectés en flux reçoivent la réponse du serveur : Vitesse envoie son erreur `413` (personnalisable avec `app.on_error`) ; un service tower répond avec sa propre erreur pour `BodyLimitLayer`.

## Pièges et conseils

* **Deux limites s'appliquent avec Vitesse** : `req.bytes()`, `req.text()`, `req.json()` et `req.form()` s'arrêtent à la limite propre du serveur, 1 Mio par défaut. Relevez-la avec `app.body_limit` pour les routes d'envoi, sinon les fichiers de plus de 1 Mio échouent même quand Securite les autorise.
* **`BodyLimit` seul ne couvre pas les corps chunked** : utilisez `require_content_length(true)` ou la limite en flux (`app.body_limit`, `BodyLimitLayer`).
* `require_content_length(true)` peut casser les clients HTTP/2 et les envois en streaming qui omettent légitimement `Content-Length`. Testez vos clients avant de l'activer.
* Les préfixes de route sont comparés segment par segment : `/upload` couvre `/upload/files` mais pas `/uploads`.
* Les envois multipart comptent tout le corps encodé, délimiteurs et en-têtes compris : gardez une marge au-dessus du plus gros fichier accepté.

> **Astuce :** gardez une limite par défaut basse et n'accordez de grandes limites qu'aux routes qui en ont besoin. La plupart des API JSON n'ont jamais besoin de plus de quelques centaines de kilo-octets.

## Pages associées

* [Hygiène HTTP](/docs/hygiene)
* [Limitation de débit](/docs/rate-limit)
* [Limite de concurrence](/docs/concurrency-limit)
* [Filtrage des méthodes](/docs/method-filter)
