---
title: Négociation de la langue
summary: Choisit la langue de chaque requête parmi celles prises en charge, d'après la chaîne de requête, un cookie ou Accept-Language, la transmet à vos handlers et définit Content-Language et Vary.
category: everyday
order: 13
---

`Locale` décide une seule fois, pour chaque requête, dans laquelle de vos langues répondre : aucun handler n'a besoin d'analyser lui-même `Accept-Language`.

## Choix de la langue

La première source qui fournit une langue prise en charge l'emporte :

1. la chaîne de requête, `?lang=fr` (permet à un visiteur de changer de langue grâce à un lien) ;
2. un cookie, `lang=fr` (mémorise ce choix) ;
3. l'en-tête `Accept-Language` du navigateur, pondérations comprises : `de, fr-CA;q=0.9, en;q=0.5` donne `fr`. Une variante régionale correspond à sa langue (`fr-CA` → `fr`) et une langue correspond à une variante régionale que vous prenez en charge (`pt` → `pt-BR`) ;
4. la langue par défaut, la première de votre liste.

Les valeurs non prises en charge sont ignorées, jamais renvoyées telles quelles. Le résultat est toujours l'une de vos étiquettes, écrite comme vous l'avez écrite.

Les handlers la lisent avec `req.get::<Lang>()`. La réponse reçoit `Content-Language` (sauf si le handler en a défini un) et `Vary: Accept-Language`, plus `Cookie` tant que la source cookie est active, pour que les caches partagés ne donnent jamais la langue d'un visiteur à un autre. Toutes les valeurs de `Vary` sont regroupées sur une seule ligne.

## Démarrage rapide

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Locale::new(["en", "fr", "es"]));
app.get("/", |req: Request| async move {
    match req.get::<Lang>().map(Lang::as_str) {
        Some("fr") => "Bonjour !",
        Some("es") => "¡Hola!",
        _ => "Hello!",
    }
});
```

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `Locale::new([..])` | — | Étiquettes prises en charge ; la première est la langue par défaut. Panique si la liste est vide. |
| `.fallback(tag)` | la première étiquette | Une autre langue par défaut (ajoutée aux langues prises en charge si nécessaire). |
| `.query_param(Some(name))` / `.query_param(None)` | `lang` | Paramètre de requête qui impose la langue, ou aucun. |
| `.cookie(Some(name))` / `.cookie(None)` | `lang` | Cookie qui la mémorise, ou aucun. |

## Mémoriser le choix

`Locale` lit le cookie ; votre sélecteur de langue le définit :

```rust
use vitesse::prelude::*;
use std::time::Duration;

let mut app = App::new();
app.get("/lang/:tag", |req: Request| async move {
    let tag = req.param("tag").unwrap_or("en").to_owned();
    Redirect::to("/").into_response().cookie(
        Cookie::new("lang", tag).path("/").max_age(Duration::from_secs(365 * 86_400)),
    )
});
```

## Pièges et conseils

- Ajoutez `Locale` avant un [ResponseCache](/docs/response-cache) : chaque langue a alors sa propre entrée, quel que soit l'`Accept-Language` envoyé par le navigateur.
- La plupart des CDN ne mettent pas en cache les réponses qui portent `Vary: Cookie`. Pour les pages qu'un CDN doit mettre en cache, désactivez le cookie avec `.cookie(None)` et utilisez des liens `?lang=` ou une adresse par langue.
- Une langue refusée avec `q=0` n'est jamais choisie, pas même par l'intermédiaire d'une variante régionale : `fr;q=0, fr-CA` donne la langue par défaut.
- Pour les moteurs de recherche, préférez une adresse par langue (`/fr/…`, `/en/…`) et utilisez `Locale` pour choisir la cible de la redirection sur `/`.

## Pages associées

- [Cache de réponses](/docs/response-cache)
- [En-têtes de réponse](/docs/set-headers)
