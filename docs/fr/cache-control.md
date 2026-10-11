---
title: Cache-Control
summary: Définit l'en-tête Cache-Control des réponses GET réussies par préfixe de chemin et par type de contenu, avec des préréglages pour les fichiers à empreinte et les données personnelles.
category: everyday
order: 3
---

`Cache-Control` indique aux navigateurs, aux CDN et aux proxys combien de temps ils peuvent conserver une réponse. Bien réglé, il rend les visites suivantes instantanées ; mal réglé, il sert des pages périmées ou les données de quelqu'un d'autre. `CacheControl` le définit en un seul endroit, par chemin et par type de contenu, au lieu de le répéter dans chaque handler.

## Fonctionnement

Pour chaque requête `GET` ou `HEAD` qui reçoit un statut `2xx`, un `304` ou une redirection permanente (`301`, `308`) :

1. Si le handler a déjà défini `Cache-Control`, la valeur est conservée (sauf avec `.overwrite(true)`).
2. Sinon, la valeur du **plus long préfixe de chemin correspondant** est utilisée (`/assets` couvre `/assets/app.js`, pas `/assetsx`),
3. à défaut, celle du premier **préfixe de type de contenu** correspondant (`image/` couvre `image/png`),
4. à défaut, la **valeur de repli**, s'il y en a une.

Les erreurs (`4xx`, `5xx`), les redirections temporaires (`302`, `303`, `307`, qui ne doivent pas être mises en cache aussi longtemps que la page) et les écritures (`POST`, `PUT`…) ne sont pas touchées.

> **Attention :** les fichiers statiques servis par Vitesse (`app.static_dir`, `ServeDir`) portent toujours leur propre `Cache-Control` (`public, max-age=0`, sauf si `ServeDir::max_age(…)` en décide autrement), qui l'emporte par défaut. Définissez la valeur à cet endroit, ou ajoutez `.overwrite(true)` pour que vos règles la remplacent.

## Démarrage rapide

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(
    CacheControl::new()
        .fallback(CacheControl::NO_CACHE)
        .route("/assets", CacheControl::IMMUTABLE)
        .route("/account", CacheControl::NO_STORE)
        .content_type("image/", "public, max-age=86400"),
);
```

## Configuration

| Méthode | Description |
|---|---|
| `CacheControl::new()` | Aucune règle : les réponses restent intactes tant que vous n'en ajoutez pas. |
| `.route(prefix, value)` | Valeur pour un préfixe de chemin ; le préfixe le plus long l'emporte. |
| `.content_type(prefix, value)` | Valeur pour un préfixe de type de contenu (`image/`, `text/css`, `application/json`). |
| `.fallback(value)` | Valeur utilisée quand rien d'autre ne correspond. |
| `.overwrite(true)` | Remplace une valeur définie par le handler (par défaut, elle est conservée). |

Chaque méthode panique au démarrage si la valeur n'est pas une valeur d'en-tête valide.

## Préréglages

| Constante | Valeur | À utiliser pour |
|---|---|---|
| `CacheControl::IMMUTABLE` | `public, max-age=31536000, immutable` | Les fichiers à empreinte (`app.3f9a.js`), dont le nom change avec le contenu. |
| `CacheControl::NO_CACHE` | `no-cache` | Le HTML et les réponses d'API : stockés, mais revalidés à chaque fois (à associer à [ETag](/docs/etag)). |
| `CacheControl::NO_STORE` | `no-store` | Les données personnelles ou sensibles, jamais écrites sur disque. |

## Pièges et conseils

- `immutable` n'est correct que si l'URL change avec le contenu. Un simple `/style.css` en `IMMUTABLE` restera périmé pendant un an dans le navigateur de vos visiteurs.
- Les pages qui dépendent de l'utilisateur connecté ne doivent pas être `public` : utilisez `private` ou `no-store`, sinon un CDN risque de servir la page d'un utilisateur à un autre.
- `SecurityHeaders::api()` de Securite envoie déjà `no-store` sur les réponses d'API ; comme la valeur du handler est conservée, `CacheControl` n'entre pas en conflit avec lui.

## Pages associées

- [ETag et 304](/docs/etag)
- [Cache de réponses](/docs/response-cache)
