---
title: Pratique, les middlewares du quotidien
summary: La crate sœur de Securite : treize middlewares Vitesse pour le cache, les journaux, les métriques, les URL, les sondes de santé, la maintenance, les langues et la dépréciation d'API.
category: everyday
order: 1
---

Securite protège votre application. **Pratique** s'occupe de tout le reste, ce dont un service en production a besoin sans que cela relève de la sécurité : réponses `304`, en-têtes de cache, journaux d'accès, métriques Prometheus, sondes de santé, mode maintenance, redirections, langues… Chaque middleware tient en une ligne, et tous vivent dans le même dépôt que Securite.

## Ajouter la crate

```bash
cargo add pratique --git https://github.com/maxlestage/Securite
```

```toml
[dependencies]
pratique = { git = "https://github.com/maxlestage/Securite" }
vitesse = { git = "https://github.com/maxlestage/Vitesse" }
```

Pratique ne dépend que de Vitesse, ne contient aucun code unsafe (`#![forbid(unsafe_code)]`) et prend en charge Rust 1.85 et versions ultérieures.

## Démarrage rapide

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

fn main() -> std::io::Result<()> {
    let mut app = App::new();
    app.middleware(AccessLog::json().skip("/health"));
    app.middleware(Metrics::new());
    app.middleware(Health::new().version(env!("CARGO_PKG_VERSION")));
    app.middleware(ResponseTime::new());
    app.middleware(TrailingSlash::trim());
    app.middleware(ETag::new());
    app.middleware(CacheControl::new().fallback(CacheControl::NO_CACHE));
    app.middleware(Locale::new(["en", "fr", "es"]));
    app.get("/", |_req: Request| async { "Hello!" });
    app.run(3000)
}
```

## Les middlewares

| Famille | Middleware | Rôle |
|---|---|---|
| Cache | [`ETag`](/docs/etag) | `ETag` calculé à partir du corps, `304 Not Modified` sur `If-None-Match` |
| | [`CacheControl`](/docs/cache-control) | `Cache-Control` par préfixe de chemin et par type de contenu |
| | [`ResponseCache`](/docs/response-cache) | Cache de réponses `GET` entières, en mémoire ou partagé dans Redis, une entrée par langue et par variante |
| Observabilité | [`AccessLog`](/docs/access-log) | Une ligne par requête, en JSON ou au format Apache combined |
| | [`Metrics`](/docs/metrics) | `/metrics` Prometheus : compteurs, histogramme de latence, requêtes en cours |
| | [`ResponseTime`](/docs/response-time) | `X-Response-Time` et `Server-Timing` |
| URL | [`TrailingSlash`](/docs/trailing-slash) | Une seule adresse par page, avec ou sans `/` final |
| | [`Redirects`](/docs/redirects) | Pages déplacées, sections renommées, domaine canonique |
| Exploitation | [`Health`](/docs/health) | Sonde `/health` avec des vérifications nommées |
| | [`Maintenance`](/docs/maintenance) | `503` et `Retry-After`, activé et désactivé à chaud |
| Réponses et API | [`SetHeaders`](/docs/set-headers) | Ajoute, remplace ou supprime des en-têtes sur chaque réponse |
| | [`Locale`](/docs/locale) | Langue issue de `?lang=`, d'un cookie ou d'`Accept-Language` |
| | [`Deprecation`](/docs/deprecation) | En-têtes `Deprecation`, `Sunset` et `Link` |

## Ordre des middlewares

Vitesse exécute les middlewares dans l'ordre où ils sont ajoutés : le premier ajouté est le plus externe, il voit la requête en premier et la réponse en dernier. Un bon ordre :

1. **Les observateurs** : `AccessLog`, `Metrics`, `ResponseTime`, pour qu'ils mesurent tout, y compris les réponses des autres middlewares.
2. **Le `Shield` de Securite** (et CORS), pour que `/metrics` et le reste soient protégés, pages en cache comprises.
3. **Les middlewares qui répondent d'eux-mêmes** : `Health`, `Maintenance`, `Redirects`, `TrailingSlash`.
4. **`Locale`**, puis **`ResponseCache`** : le cache garde une entrée par langue.
5. **Les middlewares qui façonnent les réponses de vos routes** : `CacheControl`, `ETag`, `SetHeaders`, `Deprecation`. À l'intérieur du cache, les réponses stockées portent leurs en-têtes, et un `Cache-Control: private` qu'ils posent tient la page hors du cache.

```rust
use pratique::prelude::*;
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(AccessLog::json().skip("/health"));
app.middleware(Metrics::new());
app.middleware(Shield::recommended());
app.middleware(Health::new());
app.middleware(Redirects::new().prefix("/blog", "/articles"));
app.middleware(Locale::new(["en", "fr"]));
app.middleware(ResponseCache::new(std::time::Duration::from_secs(60)));
app.middleware(CacheControl::new().route("/account", CacheControl::NO_STORE));
app.middleware(ETag::new());
```

> **Astuce :** un middleware peut aussi être attaché à une seule route avec `handler.with(middleware)`, ou à un `Router` monté sur un préfixe avec `router.middleware(…)`.

## Pages associées

- [Installation de Securite](/docs/installation)
- [Shield et préréglages](/docs/shield-presets)
