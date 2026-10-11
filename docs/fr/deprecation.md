---
title: Dépréciation d'API
summary: Annonce que des endpoints sont dépréciés, quand ils cesseront de fonctionner et où lire les consignes de migration, avec les en-têtes standard Deprecation, Sunset et Link.
category: everyday
order: 14
---

Quand `/api/v2` remplace `/api/v1`, les clients de ce dernier doivent le savoir, idéalement par l'API elle-même plutôt que par un e-mail que personne ne lit. `Deprecation` ajoute les en-têtes standard que comprennent les passerelles d'API, les SDK et les outils de supervision :

```text
deprecation: @1767225600
sunset: Fri, 01 Jan 2027 00:00:00 GMT
link: <https://example.com/docs/v2>; rel="deprecation"; type="text/html"
```

| En-tête | Norme | Signification |
|---|---|---|
| `Deprecation` | RFC 9745 | Depuis quand la ressource est dépréciée (temps Unix). |
| `Sunset` | RFC 8594 | Quand elle cessera de fonctionner (date HTTP). |
| `Link` avec `rel="deprecation"` | RFC 9745 | Page décrivant la dépréciation et la migration. |

## Démarrage rapide

```rust
use pratique::prelude::*;
use std::time::{Duration, UNIX_EPOCH};
use vitesse::prelude::*;

let since = UNIX_EPOCH + Duration::from_secs(1_767_225_600); // 2026-01-01
let mut app = App::new();
app.middleware(
    Deprecation::since(since)
        .sunset(since + Duration::from_secs(365 * 86_400))
        .link("https://example.com/docs/v2")
        .only("/api/v1"),
);
```

## Configuration

| Méthode | Description |
|---|---|
| `Deprecation::since(time)` | Déprécié depuis `time` (`SystemTime`). |
| `.sunset(time)` | Cesse de fonctionner à `time`. |
| `.link(url)` | Page de migration ; panique si l'URL contient des caractères interdits dans un en-tête. |
| `.only(prefix)` | Uniquement les réponses sous un préfixe de chemin (peut être appelé plusieurs fois). Par défaut : toutes les réponses. |

Plusieurs dépréciations à des dates différentes ? Ajoutez plusieurs middlewares, chacun avec son `.only(…)`, ou attachez-en un au `Router` de l'ancienne version.

## Après la date de fin

`Deprecation` ne fait qu'informer. Une fois la date passée, supprimez les routes, ou répondez `410 Gone` en conservant les en-têtes pour que les clients comprennent pourquoi :

```rust
use vitesse::prelude::*;

let mut app = App::new();
app.all("/api/v1/*rest", |_req: Request| async {
    res::status(410).json(json!({ "error": "gone", "see": "https://example.com/docs/v2" }))
});
```

## Pièges et conseils

- Annoncez la date de fin tôt (plusieurs mois à l'avance pour une API publique) et surveillez qui appelle encore l'ancienne version, par exemple avec des [journaux d'accès](/docs/access-log) filtrés sur `/api/v1`.
- Ces en-têtes sont informatifs : les navigateurs les ignorent, les outils d'API et les passerelles les mettent en évidence.

## Pages associées

- [Journaux d'accès](/docs/access-log)
- [Redirections](/docs/redirects)
