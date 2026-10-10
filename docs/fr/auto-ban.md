---
title: Bannissement automatique
summary: Bannissement automatique à la fail2ban des clients qui échouent sans cesse à s'authentifier, déclenchent le WAF ou atteignent les limites de débit, avec des durées croissantes.
category: traffic
order: 3
---

`AutoBan` observe l'issue de chaque requête. Chaque requête bloquée par un autre garde du même bouclier, et chaque réponse dont le statut est *pénalisant*, inflige une pénalité au client ; trop de pénalités dans une courte fenêtre entraînent un bannissement, et les récidivistes sont bannis de plus en plus longtemps.

## Menaces couvertes

* **Force brute et credential stuffing** (OWASP A07:2021) : une série de `401` sur votre route de connexion.
* **Scanners de vulnérabilités et fuzzers** : une rafale de rejets du WAF, de l'hygiène ou du bloqueur de bots, ou d'URL inconnues (`404`, si vous les comptez).
* **Abus persistants** : des clients qui butent sans cesse sur la limite de débit (`429`) au lieu de ralentir.

Chaque garde rejette des requêtes isolées ; `AutoBan` transforme un *schéma* de rejets en bannissement, si bien que l'attaquant n'atteint plus du tout votre application.

## Fonctionnement

* Après chaque réponse, le garde inflige une pénalité quand un autre garde du même bouclier a bloqué la requête, quel que soit le statut : WAF, limitation de débit, hygiène `400`, filtrage des méthodes `405`, limite de corps `413`, filtrage d'hôte `421`, type de contenu `415`, bloqueur de bots, CSRF, filtrage IP, `Auth` ou l'un de vos propres gardes. Il en inflige aussi une quand le statut final est *pénalisant*, par défaut `401`, `403` et `429`, ce qui couvre vos propres handlers, par exemple les échecs de connexion. Les courts-circuits bénins (preflights CORS, redirections HTTPS) ne comptent jamais, pas plus que les violations signalées en mode surveillance.
* Les pénalités sont comptées dans une fenêtre qui s'ouvre à la première pénalité. Quand `max_strikes` est atteint pendant `window`, le client est banni ; si la fenêtre est écoulée, le compte repart de zéro.
* La vérification du bannissement s'exécute en priorité 30, juste après les identifiants de requête : un client banni est rejeté avant tout autre traitement, avec `403 Forbidden`, le code `banned` et un en-tête `Retry-After`.
* Les bannissements s'aggravent : chaque nouveau bannissement double la durée précédente, jusqu'à `max_ban`.

```text
AutoBan::new(): 20 strikes in 60 s, ban_for 15 min, max_ban 24 h

1st ban   15 min x 1    = 15 min
2nd ban   15 min x 2    = 30 min
3rd ban   15 min x 4    =  1 h
4th ban   15 min x 8    =  2 h
5th ban   15 min x 16   =  4 h
6th ban   15 min x 32   =  8 h
7th ban   15 min x 64   = 16 h
8th ban   15 min x 128  = 32 h -> capped at 24 h
```

L'état réside dans un stockage en mémoire partitionné et borné (64 partitions, SipHash à clé aléatoire, au plus 500 000 clients). Les clients IPv6 sont regroupés par `/64` : un attaquant ne peut pas échapper au bannissement en passant à l'adresse suivante de son préfixe. Un client jamais banni est oublié dès qu'il est resté tranquille pendant `window`. Un client banni au moins une fois garde sa fiche, nombre de bannissements compris, jusqu'à ce qu'il soit resté tranquille pendant `max(window, max_ban)` : c'est ainsi que les récidivistes écopent de bannissements plus longs.

## Démarrage rapide

```rust
use std::time::Duration;

use axum::{routing::get, Router};
use securite::prelude::*;

let shield = Shield::builder()
    .guard(
        AutoBan::new()
            .max_strikes(10)
            .window(Duration::from_secs(60))
            .ban_for(Duration::from_secs(15 * 60)),
    )
    .build();

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(shield);
```

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `AutoBan::new()` | – | 20 pénalités par minute, bannissement de 15 minutes, doublé jusqu'à 24 heures. |
| `.max_strikes(n)` | `20` | Pénalités avant bannissement (minimum 1). |
| `.window(duration)` | 60 s | Fenêtre dans laquelle les pénalités sont comptées. |
| `.ban_for(duration)` | 15 min | Durée du premier bannissement. |
| `.max_ban(duration)` | 24 h | Plafond des bannissements croissants. |
| `.count_status(code)` | – | Ajoute un statut pénalisant (par exemple `404`, `400`). |
| `.statuses(codes)` | `401, 403, 429` | Remplace la liste des statuts pénalisants. Les requêtes bloquées par un autre garde comptent dans tous les cas. |
| `.never_ban(networks)` | aucun | IP ou CIDR qui ne reçoivent jamais de pénalité. Panique sur un réseau invalide. |
| `.ignore_paths(prefixes)` | aucun | Les requêtes sur ces préfixes de chemin ne sont jamais pénalisées, qu'elles soient bloquées ou non. |
| `.monitor()` | blocage | Enregistre et signale les bannissements, mais laisse passer les clients bannis. |

Tous les clones d'un `AutoBan` partagent le même état. Gardez-en un pour gérer les bannissements à l'exécution :

| Méthode | Description |
|---|---|
| `.ban(ip, duration)` | Bannit un client manuellement (compte pour l'aggravation). |
| `.unban(ip)` | Lève le bannissement et efface l'historique du client. |
| `.is_banned(ip)` | Indique si le client est actuellement banni. |
| `.banned()` | Tous les clients bannis avec la durée restante, sous forme de `Vec<(IpAddr, Duration)>`. |

## Exemples

### Protection en profondeur de la connexion

```rust
use std::time::Duration;

use axum::http::Method;
use securite::prelude::*;

let shield = Shield::builder()
    .guard(
        RateLimit::per_second(20)
            .route_methods("/login", [Method::POST], Quota::per_minute(5)),
    )
    .guard(
        AutoBan::new()
            .max_strikes(10)
            .window(Duration::from_secs(5 * 60))
            .ban_for(Duration::from_secs(30 * 60))
            .max_ban(Duration::from_secs(7 * 24 * 3600))
            .count_status(404) // scanners probe unknown URLs
            .never_ban(["10.0.0.0/8", "192.0.2.10"]) // internal network, uptime monitor
            .ignore_paths(["/api/session"]), // SPA "am I logged in?" probe answers 401
    )
    .build();
```

Les connexions ratées produisent des `401`, puis des `429` une fois le quota de connexion épuisé ; les deux sont pénalisants, si bien qu'un client qui devine des mots de passe est banni 30 minutes après 10 échecs en 5 minutes.

### Routes d'administration pour gérer les bannissements

```rust
use std::net::IpAddr;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use securite::prelude::*;

async fn list_bans(State(ban): State<AutoBan>) -> String {
    ban.banned()
        .into_iter()
        .map(|(ip, left)| format!("{ip}\t{}s\n", left.as_secs()))
        .collect()
}

async fn ban_ip(State(ban): State<AutoBan>, Path(ip): Path<IpAddr>) -> StatusCode {
    ban.ban(ip, Duration::from_secs(24 * 3600));
    StatusCode::NO_CONTENT
}

async fn unban_ip(State(ban): State<AutoBan>, Path(ip): Path<IpAddr>) -> StatusCode {
    ban.unban(ip);
    StatusCode::NO_CONTENT
}

fn app() -> Router {
    let ban = AutoBan::new();
    let shield = Shield::builder()
        // Only the internal network may reach /admin.
        .guard(IpFilter::new().allow_private().only_paths(["/admin"]))
        .guard(ban.clone())
        .build();

    Router::new()
        .route("/admin/bans", get(list_bans))
        .route("/admin/bans/{ip}", post(ban_ip).delete(unban_ip))
        .with_state(ban)
        .layer(shield)
}
```

## Utilisation en couche autonome

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(RateLimit::per_second(10))
    .layer(AutoBan::new()); // outermost: sees the 429s of the inner layer
```

Avec axum, le dernier appel à `.layer()` est la couche la plus externe. Placez `AutoBan` à l'extérieur des couches dont les rejets doivent compter : il bloque aussi les clients bannis avant qu'ils ne les atteignent. D'une couche à l'autre, seuls les statuts pénalisants comptent : un `413` renvoyé par un `BodyLimit` autonome n'est pas une pénalité, sauf si vous l'ajoutez avec `count_status(413)`. Au sein d'un même `Shield`, chaque blocage compte.

## En-têtes de réponse

```text
HTTP/1.1 403 Forbidden
content-type: application/problem+json
cache-control: no-store
retry-after: 840

{"type":"about:blank","title":"Forbidden","status":403,"code":"banned","detail":"Your address is temporarily banned."}
```

`Retry-After` indique la durée de bannissement restante en secondes. Le rejet d'un client banni ne compte jamais comme une pénalité.

## Pièges et conseils

* **Adresses partagées** : un seul abuseur derrière un NAT d'entreprise ou un CGNAT d'opérateur peut faire bannir tous ceux qui partagent son adresse. Utilisez `never_ban` pour les partenaires et les bureaux que vous connaissez.
* **Derrière un proxy**, configurez `ShieldBuilder::client_ip` ; sinon le premier bannissement exclut le proxy, donc tout le monde. Avec des couches autonomes, placez `Shield::builder().client_ip(ClientIpSource::heroku()).build()` (ou la source de votre plateforme) en couche la plus externe, voir [IP du client](/docs/client-ip).
* **Comptez les `404` avec prudence** : liens cassés, anciens favoris et robots d'indexation en produisent aussi. Augmentez `max_strikes` si vous les ajoutez.
* **Les bannissements manuels ignorent `never_ban`**, et `unban` remet à zéro l'historique d'aggravation.
* `banned()` désigne les clients IPv6 par l'adresse de leur réseau `/64`.
* L'état est propre à chaque processus et perdu au redémarrage. Avec plusieurs réplicas, chaque instance bannit indépendamment.
* En mode surveillance, les bannissements sont tout de même enregistrés et journalisés (`client banned`), et les requêtes des clients bannis sont signalées au lieu d'être bloquées.

> **Attention :** protégez les routes qui appellent `ban` et `unban` (filtrage IP, `Auth`) : quiconque peut les atteindre peut exclure des utilisateurs ou lever son propre bannissement.

## Pages associées

* [Limitation de débit](/docs/rate-limit)
* [Filtrage IP](/docs/ip-filter)
* [Limite de concurrence](/docs/concurrency-limit)
* [Pare-feu applicatif (WAF)](/docs/waf)
