---
title: Cache de réponses
summary: Conserve des réponses GET entières en mémoire ou dans Redis et répond aux requêtes identiques sans exécuter le handler, avec une entrée par langue et par variante Vary, partagée par toutes les instances de l'application.
category: everyday
order: 4
---

Certains endpoints coûtent cher et changent rarement : un catalogue de produits, un tableau de bord public, une page d'accueil rendue côté serveur. `ResponseCache` stocke leurs réponses pendant une durée fixe (TTL) et répond lui-même aux requêtes identiques suivantes, sans appeler votre handler ni votre base de données. Par défaut, les réponses vivent dans la mémoire du processus ; elles peuvent aussi vivre dans Redis, pour que toutes les instances de l'application partagent un même cache.

## Ce qui est mis en cache

Une requête est recherchée dans le cache lorsqu'il s'agit d'un `GET` ou d'un `HEAD`, qu'elle ne porte **aucun identifiant** (`Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key`, ainsi que les en-têtes que vous ajoutez avec `.bypass_header(…)`) et que son chemin se trouve sous l'un des préfixes `.only(…)` (tous les chemins par défaut).

Une réponse n'est stockée que si elle peut être partagée :

- statut `200 OK`, corps complet de taille connue, d'au plus `max_body` octets ;
- pas de `Set-Cookie` ni de `Vary: *` ;
- pas de `Cache-Control: private`, `no-store` ou `no-cache`.

Elle est conservée pendant le TTL du cache, ou moins longtemps si la réponse le demande : `Cache-Control: max-age=10` (ou `s-maxage`) la conserve 10 secondes, `max-age=0` pas du tout.

## Une entrée par variante

La clé d'une entrée est le chemin **et** la chaîne de requête (`/products?page=2` n'est pas `/products`), plus :

- **la langue choisie par [Locale](/docs/locale)**, lorsque `Locale` est ajouté avant le cache : la page française et la page anglaise sont deux entrées, et tous les `Accept-Language` qui aboutissent au français (`fr`, `fr-CA`, `de, fr;q=0.8`…) partagent l'entrée française ;
- **les en-têtes nommés par le `Vary` de la réponse** : avec `Vary: Accept-Encoding`, les clients qui demandent du Brotli et ceux qui demandent du gzip obtiennent chacun leur propre entrée.

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Locale::new(["en", "fr", "es"])); // avant le cache
app.middleware(ResponseCache::new(Duration::from_secs(60)));
app.get("/", |req: Request| async move {
    match req.get::<Lang>().map(Lang::as_str) {
        Some("fr") => "Bonjour",
        Some("es") => "Hola",
        _ => "Hello",
    }
});
```

Les réponses portent `X-Cache: MISS` (calculée par le handler) ou `X-Cache: HIT` (servie depuis le cache, avec un en-tête `Age` en secondes). Lors d'un HIT, le cache répond lui-même `304 Not Modified` lorsque l'`If-None-Match` de la requête correspond à l'`ETag` stocké. Une requête avec `Cache-Control: no-cache` saute la recherche et rafraîchit l'entrée.

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
| `.store(store)` | `MemoryStore` de 1 000 entrées | Emplacement des réponses : `MemoryStore`, `RedisStore` ou votre propre `CacheStore`. |
| `.only(prefix)` | tous les chemins | Restreint le cache à des préfixes de chemin (peut être appelé plusieurs fois). |
| `.bypass_header(name)` | — | Un en-tête d'identifiant supplémentaire : les requêtes qui le portent atteignent toujours le handler. |
| `.max_body(bytes)` | `1 MiB` | Taille maximale d'un corps stocké. |
| `.on_error(f)` | — | Appelée lorsque le stockage échoue (la requête est alors servie par le handler). |
| `.handle()` | — | Un `CacheHandle` pour purger le cache et lire ses compteurs. |

## Partager le cache avec Redis

Avec plusieurs instances derrière un répartiteur de charge (dynos, pods, serveurs), chaque `MemoryStore` est un cache distinct : une page est calculée une fois par instance, et une purge n'atteint que l'une d'elles. Un `RedisStore` (feature `redis`) place les entrées dans Redis ou Valkey : chaque instance lit ce que les autres ont calculé, et les purges les atteignent toutes.

```toml
[dependencies]
pratique = { git = "https://github.com/maxlestage/Securite", features = ["redis-tls"] }
```

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

fn main() -> std::io::Result<()> {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into());
    let store = RedisStore::open(&url).expect("invalid REDIS_URL").prefix("shop:cache:");
    let mut app = App::new();
    app.middleware(
        ResponseCache::new(Duration::from_secs(60))
            .store(store)
            .on_error(|e| eprintln!("response cache: {e}")),
    );
    app.get("/", |_req: Request| async { "home" });
    app.run(3000)
}
```

| Feature | Apporte |
|---|---|
| `redis` | `RedisStore` pour les adresses `redis://`. |
| `redis-tls` | Les adresses `rediss://` en plus (rustls). Ajoutez `#insecure` à l'adresse pour un certificat auto-signé, comme celui qu'utilise Heroku Data for Redis. |

Comportement du stockage :

- **Connexion différée** : `RedisStore::open` vérifie seulement l'adresse. La connexion est ouverte par la première requête, depuis le runtime de l'application, et rouverte automatiquement après une panne.
- **Délais d'expiration** : chaque commande expire au bout de 250 ms (`.timeout(…)`). Quand Redis est lent ou indisponible, les requêtes sont servies par le handler au lieu d'attendre : le cache peut être perdu, le site reste en ligne. Les échecs sont comptés (`handle.errors()`) et transmis à `.on_error`.
- **Expiration** : les entrées sont écrites avec `PX`, si bien que Redis les supprime de lui-même.
- **Isolation** : chaque clé commence par le préfixe (`pratique:cache:` par défaut). Donnez à chaque application son propre préfixe lorsqu'elles partagent un même Redis.
- **Les purges** utilisent `SCAN` et `UNLINK`, jamais `KEYS`, et ne bloquent donc pas Redis.

Les features `redis` nécessitent Rust 1.88 ou une version ultérieure (comme la crate `redis`) ; sans elles, Pratique prend en charge Rust 1.85.

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
        // Toutes les chaînes de requête, toutes les variantes, et les chemins en dessous.
        if let Err(e) = purge.invalidate("/api/catalog").await {
            eprintln!("purge failed: {e}");
        }
        "saved"
    }
});
```

| Méthode de `CacheHandle` | Description |
|---|---|
| `invalidate(path).await` | Oublie `path` et ce qui se trouve en dessous (`/api/catalog` couvre `/api/catalog?page=2` et `/api/catalog/42`, pas `/api/catalogs`). |
| `clear().await` | Oublie tout (avec Redis, uniquement les clés portant le préfixe de ce cache). |
| `hits()`, `misses()`, `errors()` | Compteurs de ce processus. |

Pour inspecter un `MemoryStore`, conservez-le dans un `Arc` : `let store = Arc::new(MemoryStore::new()); ResponseCache::new(ttl).store(store.clone())`, puis `store.len()`.

## Votre propre stockage

`CacheStore` possède quatre méthodes (`get`, `set` avec un TTL, `remove_prefixes`, `clear`), qui renvoient chacune une future : implémentez-le pour Memcached, une base de données ou une doublure de test. Un stockage qui renvoie une erreur est traité comme un défaut de cache.

## Pièges et conseils

- Ne mettez en cache que des réponses publiques. Les requêtes qui portent un en-tête d'identifiant contournent le cache, mais une réponse qui dépend d'autre chose (une adresse IP, une session passée dans la chaîne de requête) doit être tenue à l'écart avec `.only(…)`, ou indiquer `Cache-Control: private`.
- Ajoutez [Locale](/docs/locale) **avant** le cache : ajouté après, `Locale` fonctionne toujours, mais l'`Accept-Language` brut entre dans la clé, ce qui morcelle le cache en de nombreuses entrées.
- Les en-têtes propres à un seul échange (`X-Request-Id`, `X-Response-Time`, `Server-Timing`, `Date`, `Age`) ne sont pas stockés ; avec [ETag](/docs/etag) (avant ou après le cache), les réponses servies depuis le cache deviennent des `304` lorsque le client possède déjà la page.
- Tant que la première réponse n'est pas stockée, de nombreux défauts de cache simultanés sur la même clé atteignent tous le handler.

## Pages associées

- [ETag et 304](/docs/etag)
- [Cache-Control](/docs/cache-control)
- [Négociation de la langue](/docs/locale)
