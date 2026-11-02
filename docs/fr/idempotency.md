---
title: Clés d'idempotence
summary: Répond à un POST ou PATCH renvoyé avec la même Idempotency-Key par la première réponse stockée au lieu de l'exécuter deux fois, comme l'API de Stripe et le brouillon IETF.
category: everyday
order: 13
---

Un téléphone perd le réseau juste après avoir touché « Payer » : le paiement est-il passé ? L'application renvoie le même `POST`, avec le même en-tête `Idempotency-Key` (comme l'API de Stripe et le brouillon IETF `Idempotency-Key`). Sans `Idempotency`, le client paie deux fois ; avec, la deuxième requête n'est pas exécutée : elle reçoit la réponse stockée de la première, marquée `Idempotent-Replayed: true`.

## Ce que devient une requête

Les requêtes `POST` et `PATCH` qui portent une `Idempotency-Key` sont traitées ; les autres passent directement (`PUT` et `DELETE` sont idempotentes par nature).

| Situation | Réponse |
|---|---|
| Première requête avec cette clé | S'exécute normalement ; la réponse est stockée 24 heures. |
| Même clé, même requête | La réponse stockée, avec `Idempotent-Replayed: true`. Le handler n'est pas appelé. |
| Même clé pendant que la première requête tourne encore | `409 Conflict` avec `Retry-After: 1`. |
| Même clé avec une autre requête (autre chemin, autre corps) | `422 Unprocessable Content` : un bug du client, pas une nouvelle tentative. |
| Clé invalide (vide, plus de 255 caractères, pas en ASCII visible) | `400 Bad Request`. |
| Pas de clé, avec `.required()` | `400 Bad Request`. |

Les erreurs serveur (`5xx`), `408`, `409` et `429` ne sont pas stockées : le client peut réessayer, et la nouvelle tentative s'exécute. Les clés sont cloisonnées par les identifiants du client (`Authorization`, `X-Api-Key`) : un client ne peut pas lire les réponses d'un autre en devinant sa clé. Les réponses d'erreur sont en `application/problem+json`.

## Démarrage rapide

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Idempotency::new()); // POST et PATCH portant une `Idempotency-Key`
app.post("/payments", |_req: Request| async { (201, "paid") });
```

## Configuration

| Méthode | Par défaut | Description |
|---|---|---|
| `.ttl(duration)` | 24 heures | Durée de conservation d'une réponse. |
| `.methods([...])` | `POST`, `PATCH` | Les méthodes concernées. |
| `.required()` | désactivé | Refuse (`400`) les requêtes de ces méthodes qui n'ont pas de clé. |
| `.header(name)` | `Idempotency-Key` | Un autre en-tête (`X-Idempotency-Key`…). |
| `.max_body(bytes)` | `1 MiB` | Plus grand corps de requête (au-delà : `413`) et plus grande réponse stockée (au-delà : envoyée mais pas stockée). |
| `.store(store)` | `MemoryStore` | Où les réponses sont gardées : `MemoryStore`, ou un `RedisStore` partagé par toutes les instances. |
| `.on_error(f)` | — | Appelé quand le stockage échoue (la requête s'exécute alors comme si elle n'avait pas de clé). |

## Partager les réponses avec Redis

Avec plusieurs instances derrière un répartiteur de charge, une nouvelle tentative peut arriver sur une autre instance que la première requête. Donnez à `Idempotency` le même `RedisStore` que le [cache de réponses](/docs/response-cache) (feature `redis` ou `redis-tls`) pour que toutes les instances voient les réponses stockées :

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into());
let store = RedisStore::open(&url).expect("REDIS_URL invalide").prefix("shop:idempotency:");
let mut app = App::new();
app.middleware(
    Idempotency::new()
        .store(store)
        .on_error(|e| eprintln!("idempotency : {e}")),
);
```

## Pages associées

- [Pratique, les middlewares du quotidien](/docs/pratique)
- [Cache de réponses](/docs/response-cache)
- [Signatures de webhooks](/docs/webhook-signatures)
