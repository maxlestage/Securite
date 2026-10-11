---
title: Journaux d'accès
summary: Écrit une ligne par requête, en JSON pour les pipelines de journaux ou au format Apache combined pour les analyseurs classiques, sur la sortie standard ou vers n'importe quelle destination, avec la véritable adresse du client derrière un proxy.
category: everyday
order: 5
---

Le `middleware::logger()` de Vitesse affiche des lignes colorées destinées aux humains. `AccessLog` écrit des lignes destinées aux machines : Loki, Elasticsearch, CloudWatch, Datadog, GoAccess ou AWStats les lisent sans la moindre règle d'analyse.

## Formats

**Lignes JSON** (`AccessLog::json()`), un objet par requête ; les champs absents sont omis :

```json
{"time":"2026-10-11T08:49:37.042Z","ip":"203.0.113.9","method":"GET","path":"/search?q=shoes","version":"HTTP/1.1","referer":"https://example.com/","user_agent":"Mozilla/5.0","request_id":"3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44","status":200,"bytes":5120,"duration_ms":1.842}
```

**Apache / Nginx combined** (`AccessLog::combined()`) :

```text
203.0.113.9 - - [11/Oct/2026:08:49:37 +0000] "GET /search?q=shoes HTTP/1.1" 200 5120 "https://example.com/" "Mozilla/5.0"
```

| Champ | Contenu |
|---|---|
| `time` | Heure d'arrivée de la requête, en UTC, au format RFC 3339 avec millisecondes. |
| `ip` | Adresse du client (voir ci-dessous). |
| `method`, `path`, `version` | Ligne de requête ; `path` inclut la chaîne de requête, exactement telle que le client l'a envoyée (y compris les caractères non valides dans une adresse, que contiennent souvent les tentatives d'attaque). |
| `status`, `bytes` | Statut et nombre d'octets du corps envoyés : `0` pour `HEAD`, `204` et `304` (`-` au format combined, comme Apache), absent pour les corps en flux. |
| `duration_ms` | Temps de production de l'en-tête de la réponse. |
| `referer`, `user_agent` | En-têtes de la requête. |
| `request_id` | `X-Request-Id` de la requête, ou de la réponse (`RequestId` de Securite). |

## Démarrage rapide

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(AccessLog::json().skip("/health").skip("/metrics"));
app.get("/", |_req: Request| async { "home" });
```

## Configuration

| Méthode | Description |
|---|---|
| `AccessLog::json()` | Lignes JSON sur la sortie standard. |
| `AccessLog::combined()` | Lignes combined sur la sortie standard. |
| `.to(sink)` | Envoie chaque ligne (sans le saut de ligne) à une closure : un fichier, un canal, `tracing`… |
| `.skip(prefix)` | Ne journalise pas les requêtes sous un préfixe de chemin (sondes de santé, métriques). Peut être appelé plusieurs fois. |
| `.ip_from_header(name)` | Lit l'adresse du client dans un en-tête écrit par votre proxy inverse. |

```rust
use pratique::prelude::*;

let log = AccessLog::json().to(|line| tracing::info!(target: "access", "{line}"));
```

## Derrière un proxy inverse

Derrière Heroku, Render, Fly.io, Nginx ou Cloudflare, la connexion provient du proxy : l'adresse journalisée serait donc la sienne. Indiquez à `AccessLog` l'en-tête que le proxy écrit :

```rust
use pratique::prelude::*;

let log = AccessLog::combined().ip_from_header("x-forwarded-for"); // Heroku, Nginx, Render…
let log = AccessLog::combined().ip_from_header("cf-connecting-ip"); // Cloudflare
```

C'est la **dernière** adresse de l'en-tête qui est utilisée : celle ajoutée par le proxy placé devant votre application, qu'un client ne peut pas falsifier (tout ce qu'un client envoie lui-même se trouve avant). Sans l'en-tête, ou avec une valeur invalide, c'est l'adresse du pair qui est journalisée.

## Pièges et conseils

- La journalisation est synchrone. La sortie standard convient sur toutes les plateformes ; pour une destination lente, faites en sorte que le sink pousse les lignes dans un canal lu par une tâche en arrière-plan.
- Chaque champ entre guillemets du format combined échappe `"`, `\` et les caractères de contrôle, et les chaînes JSON sont échappées : un `User-Agent` forgé ne peut pas fabriquer de fausse ligne de journal.
- Les journaux d'accès contiennent des adresses IP, qui sont des données personnelles au sens du RGPD : fixez une durée de conservation.

## Pages associées

- [Métriques Prometheus](/docs/metrics)
- [Identifiants de requête](/docs/request-id)
- [IP du client](/docs/client-ip)
