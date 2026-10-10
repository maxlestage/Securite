---
title: Limite de concurrence
summary: Plafonnez le nombre de requêtes qu'un même client peut avoir en cours de traitement simultanément, pour stopper les rafales de requêtes lentes ou coûteuses.
category: traffic
order: 2
---

`ConcurrencyLimit` limite le nombre de requêtes qu'une même IP cliente peut avoir **en cours de traitement simultanément**. La limitation de débit compte les requêtes dans le temps ; ce garde compte celles qui sont traitées à l'instant présent.

## Menaces couvertes

Un client qui envoie un nombre modeste de requêtes *lentes* ou *coûteuses* peut rester sous n'importe quel quota par seconde tout en accaparant vos ressources : exports de rapports, recherches, traitement d'images, routes qui monopolisent une connexion à la base de données pendant plusieurs secondes. Avec suffisamment de requêtes parallèles, un seul client épuise votre pool de workers, votre pool de connexions ou votre mémoire, et tous les autres attendent. C'est un déni de service applicatif (OWASP API4:2023, Unrestricted Resource Consumption).

Plafonner les requêtes en cours par client borne la part de votre capacité que chacun peut occuper, quel que soit le coût de chaque requête.

## Fonctionnement

```text
ConcurrencyLimit::per_ip(2), one client IP

t0  request A arrives     in flight 1/2   accepted
t1  request B arrives     in flight 2/2   accepted
t2  request C arrives     in flight 2/2   429 too_many_concurrent
t3  response head of A    in flight 1/2   permit released
t4  request D arrives     in flight 2/2   accepted
```

* Le garde tient un compteur par IP cliente (IPv6 regroupée par `/64`) dans un stockage partitionné et borné : 64 partitions protégées par un mutex, clés réparties avec SipHash à clé aléatoire.
* Quand une requête est acceptée, un permis RAII est placé dans le contexte de la requête. Il est libéré dès que l'**en-tête de la réponse** est produit, ou quand la requête est annulée (déconnexion du client, timeout) : une connexion interrompue ne fait jamais fuir de permis.
* Les compteurs revenus à zéro sont supprimés dès qu'un client n'a plus rien en cours : la mémoire suit le nombre de clients *actifs*.
* Le stockage suit au plus 500 000 clients. Lorsqu'il est plein, les nouveaux clients sont rejetés (échec en mode fermé).
* Les requêtes dont l'IP cliente est inconnue ne sont pas limitées.

## Démarrage rapide

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let shield = Shield::builder()
    // At most 16 simultaneous requests per client IP.
    .guard(ConcurrencyLimit::per_ip(16))
    .build();

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(shield);
```

Servez l'application avec `into_make_service_with_connect_info::<SocketAddr>()` pour que le garde voie l'adresse du client.

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `ConcurrencyLimit::per_ip(max)` | – | Au plus `max` requêtes en cours par IP cliente (minimum 1). |
| `.monitor()` | blocage | Signale les violations sans bloquer. |
| `.in_flight(ip)` | – | Nombre de requêtes actuellement en cours pour `ip`. |

Comportement fixe : regroupement IPv6 par `/64`, au plus 500 000 clients suivis.

## Exemples

### Protéger uniquement une route coûteuse

La limite de concurrence est la plus utile là où les requêtes coûtent cher. Appliquez le garde comme couche sur un sous-routeur :

```rust
use axum::{routing::{get, post}, Router};
use securite::prelude::*;

// At most 2 report exports at a time per client.
let reports = Router::new()
    .route("/reports/export", post(|| async { "export queued" }))
    .layer(ConcurrencyLimit::per_ip(2));

let app: Router = Router::new()
    .route("/", get(|| async { "home" }))
    .merge(reports)
    .layer(Shield::recommended());
```

### Derrière un reverse proxy

Une couche autonome détermine l'IP du client à partir de l'adresse TCP du pair, sauf si un bouclier extérieur l'a déjà fait : elle réutilise alors le `ClientIp` de ce bouclier. Derrière un proxy, configurez la source une seule fois, sur le bouclier le plus externe :

```rust
use axum::{routing::{get, post}, Router};
use securite::prelude::*;

let reports = Router::new()
    .route("/reports/export", post(|| async { "export queued" }))
    .layer(ConcurrencyLimit::per_ip(2));

let app: Router = Router::new()
    .route("/", get(|| async { "home" }))
    .merge(reports)
    // Outermost: the inner ConcurrencyLimit reuses the client IP it resolves.
    .layer(
        ShieldBuilder::recommended()
            .client_ip(ClientIpSource::cloudflare())
            .build(),
    );
```

### Observer l'utilisation en direct

Les clones partagent leurs compteurs, ce qui est pratique pour une route de diagnostic ou de métriques :

```rust
use securite::prelude::*;

let limit = ConcurrencyLimit::per_ip(8);
let handle = limit.clone(); // give `limit` to the shield, keep `handle`

let busy = handle.in_flight("203.0.113.7".parse().unwrap());
println!("203.0.113.7 has {busy} requests in flight");
```

## Utilisation en couche autonome

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/search", get(|| async { "results" }))
    .layer(ConcurrencyLimit::per_ip(4));
```

## En-têtes de réponse

Une requête rejetée reçoit `429 Too Many Requests` avec le code `too_many_concurrent`, au format `application/problem+json` avec `Cache-Control: no-store`. Aucun `Retry-After` n'est envoyé : le bon moment pour réessayer dépend de la fin des autres requêtes du client.

```text
HTTP/1.1 429 Too Many Requests
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Too Many Requests","status":429,"code":"too_many_concurrent","detail":"Too many concurrent requests."}
```

## Pièges et conseils

* **Réponses en streaming** (téléchargements, Server-Sent Events, upgrades WebSocket) : le permis est libéré dès l'envoi de l'en-tête de réponse, le temps passé à diffuser le corps n'est pas compté.
* **Multiplexage HTTP/2** : un navigateur qui charge une page peut lancer des dizaines de requêtes d'un coup sur une seule connexion. Gardez de la marge au-dessus du nombre habituel de requêtes par page, ou réservez la limite aux routes d'API ou coûteuses comme ci-dessus.
* **Adresses partagées** : bureaux, opérateurs mobiles et NAT d'entreprise placent de nombreux utilisateurs derrière une seule IP. Préférez des limites généreuses sur les pages publiques.
* **Les IP inconnues passent** : oubliez `with_connect_info` et le garde ne fait rien ; le bouclier se contente de journaliser un avertissement, une seule fois, sous la cible `securite`.
* `ConcurrencyLimit` complète, sans le remplacer, un plafond global sur votre serveur : il borne la part de chaque client, pas le total.

> **Astuce :** utilisez `ConcurrencyLimit` avec la [limitation de débit](/docs/rate-limit). La limitation de débit borne la fréquence à laquelle un client peut vous appeler, la limite de concurrence borne la part de votre capacité qu'il peut occuper à un instant donné.

## Pages associées

* [Limitation de débit](/docs/rate-limit)
* [Bannissement automatique](/docs/auto-ban)
* [Limite de taille du corps](/docs/body-limit)
* [IP client derrière un proxy](/docs/client-ip)
