---
title: Redirections
summary: Envoie les anciennes adresses vers les nouvelles avant l'exécution des routes, pour des pages isolées, des sections entières ou un domaine complet, avec le bon statut 3xx et la chaîne de requête conservée.
category: everyday
order: 9
---

Les pages déménagent, les sections sont renommées, le `www.` disparaît. Chaque ancienne adresse reste la cible de liens et conserve son classement dans les moteurs de recherche. `Redirects` les maintient en vie grâce à une seule table de règles, au lieu d'une route par ancienne adresse.

## Règles

| Méthode | Exemple | Statut |
|---|---|---|
| `.permanent(from, to)` | `/old-pricing` → `/pricing` | `308 Permanent Redirect` |
| `.temporary(from, to)` | `/sale` → `/products?promo=autumn` | `307 Temporary Redirect` |
| `.exact(from, to, status)` | n'importe quel `3xx` (`301`, `302`, `303`…) | celui fourni ; panique s'il ne s'agit pas d'une redirection |
| `.prefix(from, to)` | `/blog/2024/hello` → `/articles/2024/hello` | `308` |
| `.host(host, origin)` | `www.example.com/x` → `https://example.com/x` | `308` |

Les règles sont vérifiées dans cet ordre : hôte, chemin exact, puis le plus long préfixe correspondant. Un préfixe couvre des segments entiers : `/blog` couvre `/blog` et `/blog/x`, pas `/blogger`. La chaîne de requête est ajoutée à la cible, sauf si celle-ci possède déjà la sienne.

`308` et `307` conservent la méthode et le corps : un formulaire envoyé à une ancienne adresse arrive toujours sous forme de `POST`.

## Démarrage rapide

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(
    Redirects::new()
        .host("www.example.com", "https://example.com")
        .permanent("/old-pricing", "/pricing")
        .prefix("/blog", "/articles")
        .temporary("/sale", "/products?promo=autumn"),
);
```

```bash
curl -i "https://example.com/blog/2024/hello?utm_source=mail"
# HTTP/1.1 308 Permanent Redirect
# location: /articles/2024/hello?utm_source=mail
```

## Domaine canonique

`.host(host, origin)` redirige chaque requête dont le `Host` (sans port, insensible à la casse) vaut `host` vers le même chemin sur `origin`. Seuls les hôtes que vous listez sont redirigés : `localhost` et les domaines de prévisualisation continuent de fonctionner.

```rust
use pratique::prelude::*;

let canonical = Redirects::new()
    .host("www.example.com", "https://example.com")
    .host("example.fr", "https://example.com/fr");
```

> **Astuce :** pour imposer HTTPS sur tous les hôtes, utilisez la [redirection HTTPS](/docs/https-redirect) de Securite, qui sait composer avec les proxys.

## Pièges et conseils

- Les navigateurs mémorisent longtemps les redirections permanentes. Testez d'abord avec `.temporary(…)`, puis passez à `.permanent(…)`.
- Les cibles proviennent de votre configuration, jamais de la requête : le middleware ne peut pas devenir une redirection ouverte.
- Évitez les chaînes (`/a` → `/b` → `/c`) : faites pointer chaque ancienne adresse directement vers la destination finale.

## Pages associées

- [Barre oblique finale](/docs/trailing-slash)
- [Redirection HTTPS](/docs/https-redirect)
