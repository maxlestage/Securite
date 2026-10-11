---
title: En-têtes de réponse
summary: Ajoute, remplace, complète ou supprime des en-têtes sur chaque réponse, y compris celles construites par Vitesse lui-même, comme les 404.
category: everyday
order: 12
---

Certains en-têtes ont leur place sur chaque réponse : une valeur `Server` ou `X-Powered-By`, un `Content-Language` par défaut, un préchargement `Link`, un `Timing-Allow-Origin`… et d'autres ne devraient jamais quitter le serveur, comme un en-tête de débogage ajouté par une bibliothèque. `SetHeaders` les gère en un seul endroit.

## Opérations

| Méthode | Effet |
|---|---|
| `.set(name, value)` | Définit l'en-tête, en remplaçant la valeur définie par le handler. |
| `.if_missing(name, value)` | Ajoute l'en-tête uniquement si la réponse ne l'a pas déjà. |
| `.append(name, value)` | Ajoute une valeur supplémentaire en conservant les existantes (`Link`, `Vary`…). |
| `.remove(name)` | Supprime l'en-tête. |

Les opérations s'exécutent dans l'ordre indiqué, sur chaque réponse : celles de vos handlers, celles de Vitesse (`404`, `405`) et celles des middlewares ajoutés après `SetHeaders`. Un nom ou une valeur invalide fait paniquer la méthode au démarrage, jamais pendant le traitement d'une requête.

## Démarrage rapide

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(
    SetHeaders::new()
        .set("x-powered-by", "Vitesse")
        .if_missing("content-language", "en")
        .append("link", "</app.css>; rel=preload; as=style")
        .remove("x-debug"),
);
```

## Pièges et conseils

- Pour les en-têtes de sécurité (CSP, HSTS, `X-Frame-Options`…), utilisez les [en-têtes de sécurité](/docs/security-headers) de Securite : ils sont fournis avec des valeurs par défaut sûres et des nonces par requête.
- `X-Powered-By` révèle à tout le monde la pile que vous utilisez. C'est sans danger avec une pile maintenue, mais vous pouvez tout aussi bien faire `.remove("x-powered-by")`.
- Pour modifier les en-têtes d'une seule route, enveloppez son handler : `handler.with(SetHeaders::new()…)`.

## Pages associées

- [Cache-Control](/docs/cache-control)
- [En-têtes de sécurité](/docs/security-headers)
