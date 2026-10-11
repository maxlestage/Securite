---
title: Cache de réponses
summary: Conserve en mémoire des réponses GET entières pendant un temps donné et répond aux requêtes identiques sans exécuter le handler, avec des limites de taille, les en-têtes X-Cache et Age et une poignée de purge.
category: everyday
order: 4
---

Certains endpoints coûtent cher et changent rarement : un catalogue de produits, un tableau de bord public, une page d'accueil rendue côté serveur. `ResponseCache` stocke leurs réponses en mémoire pendant une durée fixe (TTL) et répond lui-même aux requêtes identiques suivantes, sans appeler votre handler ni votre base de données.

## Ce qui est mis en cache

Une requête est recherchée dans le cache lorsqu'il s'agit d'un `GET` ou d'un `HEAD`, qu'elle ne porte **ni** en-tête `Authorization` **ni** en-tête `Cookie`, et que son chemin se trouve sous l'un des préfixes `.only(…)` (tous les chemins par défaut). La clé est le chemin **et** la chaîne de requête : `/products?page=2` n'est pas `/products`.

Une réponse n'est stockée que si elle peut être partagée :

- statut `200 OK`, corps complet de taille connue, d'au plus `max_body` octets ;
- pas de `Set-Cookie`, de `Vary` ni de `Content-Encoding` ;
- pas de `Cache-Control: private`, `no-store` ou `no-cache`.

Les réponses portent `X-Cache: MISS` (calculée par le handler) ou `X-Cache: HIT` (servie depuis la mémoire, avec un en-tête `Age` en secondes). Une requête avec `Cache-Control: no-cache` saute la recherche et rafraîchit l'entrée.

## Démarrage rapide

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(ResponseCache::new(Duration::from_secs(30)).only("/api/catalog"));
app.get("/api/catalog", |_req: Request| async { Json(json!({ "products": [] })) });
```

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `ResponseCache::new(ttl)` | — | Durée pendant laquelle une réponse reste fraîche. |
| `.only(prefix)` | tous les chemins | Restreint le cache à des préfixes de chemin (peut être appelé plusieurs fois). |
| `.max_entries(n)` | `1000` | Nombre maximal de réponses stockées ; les entrées expirées sont évincées en premier, puis les plus anciennes. |
| `.max_body(bytes)` | `1 MiB` | Taille maximale d'un corps stocké. |
| `.handle()` | — | Un `CacheHandle` pour inspecter ou purger le cache pendant que l'application tourne. |

## Purger après une mise à jour

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

let cache = ResponseCache::new(Duration::from_secs(300)).only("/api/catalog");
let purge = cache.handle();

let mut app = App::new();
app.middleware(cache);
app.post("/admin/products", move |_req: Request| {
    let purge = purge.clone();
    async move {
        // … enregistrer le produit …
        purge.invalidate("/api/catalog"); // toutes les chaînes de requête, et en dessous
        "saved"
    }
});
```

`CacheHandle` propose aussi `clear()`, `len()` et `is_empty()`.

## Pièges et conseils

- Le cache vit dans la mémoire de chaque processus : deux instances derrière un répartiteur de charge ont deux caches. Gardez des TTL courts, ou purgez chaque instance.
- Les réponses qui dépendent d'autre chose que du chemin et de la chaîne de requête (un en-tête, la langue) doivent le signaler avec `Vary`, ce qui désactive leur mise en cache. Avec [Locale](/docs/locale), ne mettez en cache que les endpoints indépendants de la langue, ou ajoutez la langue à la chaîne de requête.
- Placez le cache après un middleware de compression pour qu'il stocke les octets d'origine.
- Tant que la première réponse n'est pas stockée, plusieurs échecs simultanés sur la même clé atteignent chacun le handler.

## Pages associées

- [ETag et 304](/docs/etag)
- [Cache-Control](/docs/cache-control)
