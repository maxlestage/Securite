---
title: Temps de réponse
summary: Ajoute les en-têtes X-Response-Time et Server-Timing avec le temps passé à produire chaque réponse, visible dans les outils de développement du navigateur.
category: everyday
order: 7
---

`ResponseTime` mesure le temps qu'a mis le reste de la chaîne à produire l'en-tête de la réponse et l'écrit dans deux en-têtes :

```text
x-response-time: 1.842ms
server-timing: app;dur=1.842
```

Les navigateurs affichent `Server-Timing` dans leurs outils de développement (onglet Réseau, puis Minutage), à côté des temps DNS, TLS et de téléchargement : on distingue ainsi facilement un serveur lent d'un réseau lent.

## Démarrage rapide

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(ResponseTime::new());
app.get("/", |_req: Request| async { "home" });
```

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `ResponseTime::new()` | les deux en-têtes, 3 décimales | Crée le middleware. |
| `.header(Some(name))` / `.header(None)` | `x-response-time` | Un autre nom d'en-tête, ou aucun en-tête de ce type. |
| `.server_timing(Some(metric))` / `.server_timing(None)` | `app` | Nom de la métrique dans `Server-Timing`, ou aucune. |
| `.digits(n)` | `3` | Nombre de décimales des millisecondes. |

```rust
use pratique::prelude::*;

// Seulement Server-Timing, nommé "backend", en millisecondes entières.
let timing = ResponseTime::new().header(None).server_timing(Some("backend")).digits(0);
```

## Pièges et conseils

- La mesure couvre ce qui suit le middleware dans la chaîne : ajoutez-le en premier pour inclure tous les autres middlewares.
- `Server-Timing` est ajouté à la suite des valeurs existantes : les handlers peuvent y joindre leurs propres métriques (`db;dur=4.2`).
- Les temps révèlent la charge de votre serveur. Pour un service public, vous préférerez peut-être n'envoyer `Server-Timing` qu'à votre équipe, ou utiliser plutôt les [métriques Prometheus](/docs/metrics).

## Pages associées

- [Métriques Prometheus](/docs/metrics)
- [Journaux d'accès](/docs/access-log)
