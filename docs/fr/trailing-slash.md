---
title: Barre oblique finale
summary: Donne à chaque page une adresse unique en retirant ou en ajoutant la barre oblique finale, avec une redirection 308 que suivent les moteurs de recherche ou en réécrivant la requête sur place.
category: everyday
order: 8
---

Pour les moteurs de recherche, les caches et les outils d'analyse d'audience, `/about` et `/about/` sont deux adresses différentes. `TrailingSlash` choisit un seul style pour toute l'application.

## Styles

| Constructeur | Effet |
|---|---|
| `TrailingSlash::trim()` | `/about/` → `/about` (`/` lui-même n'est pas touché ; `/about///` → `/about`). |
| `TrailingSlash::append()` | `/about` → `/about/`, sauf pour les chemins dont le dernier segment ressemble à un fichier (`/app.js`). |

Par défaut, le client reçoit une **`308 Permanent Redirect`** vers l'adresse normalisée : les moteurs de recherche fusionnent les deux URL, et la méthode et le corps d'un `POST` sont conservés. La chaîne de requête suit.

Avec `.rewrite()`, il n'y a pas de redirection : la requête est réécrite sur place, vos routes voient le chemin normalisé et le navigateur conserve son adresse.

## Démarrage rapide

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(TrailingSlash::trim());
app.get("/about", |_req: Request| async { "about" });
```

```bash
curl -i "https://example.com/about/?ref=mail"
# HTTP/1.1 308 Permanent Redirect
# location: /about?ref=mail
```

## Réécrire plutôt que rediriger

```rust
use pratique::prelude::*;

let slash = TrailingSlash::trim().rewrite(); // `/about/` répond comme `/about`
```

## Pièges et conseils

- Ajoutez-le avant vos routes et avant les middlewares qui examinent le chemin (`CacheControl`, `ResponseCache`).
- Un chemin qui commence par plusieurs barres obliques n'est jamais transformé en adresse relative au protocole (`//evil.example`) : la redirection reste toujours sur votre site.
- Si vous servez un site statique dont les dossiers contiennent un `index.html`, `append()` correspond à ses liens.

## Pages associées

- [Redirections](/docs/redirects)
