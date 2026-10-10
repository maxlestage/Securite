---
title: Limitation de débit
summary: Limitation de débit GCRA exacte par IP, clé d'API, route ou clé personnalisée, avec les en-têtes RateLimit standard et un stockage borné qui échoue en mode fermé.
category: traffic
order: 1
---

`RateLimit` plafonne le nombre de requêtes qu'un client peut envoyer dans le temps : par adresse IP par défaut, avec des règles par route et des clés d'API ou personnalisées en option. Le trafic excédentaire reçoit une réponse `429 Too Many Requests` accompagnée d'un en-tête `Retry-After`.

## Menaces couvertes

* **Force brute et credential stuffing** sur les pages de connexion, de réinitialisation de mot de passe ou de code à usage unique (OWASP A07:2021, Identification and Authentication Failures).
* **Déni de service applicatif et scraping** : un seul client qui martèle des routes coûteuses (OWASP API4:2023, Unrestricted Resource Consumption).
* **Abus d'effets de bord coûteux** : e-mails, SMS ou appels payants à des API tierces.

Le limiteur s'exécute dans votre processus : il n'arrête pas un DDoS volumétrique. Gardez pour cela un CDN ou un répartiteur de charge en frontal.

## Fonctionnement

### GCRA en un schéma

Le limiteur utilise GCRA (Generic Cell Rate Algorithm) et ne stocke qu'un `u64` par client : l'*heure d'arrivée théorique* (TAT). Un quota définit un intervalle d'émission `T` et une tolérance `tau = T x (burst - 1)`.

```text
Quota::per_second(10).burst(3)
  T   = 1 s / 10        = 100 ms
  tau = T x (burst - 1) = 200 ms

time     request  TAT - now          verdict                  new TAT
0 ms     #1       0                  ok   (remaining 2)       100
0 ms     #2       100                ok   (remaining 1)       200
0 ms     #3       200                ok   (remaining 0)       300
0 ms     #4       300  > tau         429, retry in 100 ms     300
100 ms   #5       200 <= tau         ok                       400
```

Pour chaque requête, `tat = max(TAT, now)`. Si `tat - now > tau`, la requête arrive trop tôt : elle est rejetée avec `Retry-After = tat - now - tau`, arrondi à la seconde supérieure. Sinon, la TAT avance à `tat + T`. Le comportement est celui d'un seau à jetons de capacité `burst` qui reçoit un jeton à chaque intervalle `T`, sans minuterie en arrière-plan et sans les rafales en bordure de fenêtre propres aux fenêtres fixes.

### Un stockage partitionné et borné

* Chaque règle possède son propre stockage de 64 partitions protégées par un mutex : des clients différents se gênent rarement.
* Les clés sont réparties avec SipHash à clé aléatoire : impossible de forger des clés qui entrent en collision (HashDoS).
* Une entrée expire dès que son seau est de nouveau plein ; les entrées expirées sont purgées toutes les 4 096 opérations sur une partition, et dès qu'une partition est pleine.
* Chaque règle suit au plus `max_entries` clés (1 000 000 par défaut, environ 50 Mo dans le pire des cas). Quand une partition est remplie de clients actifs, les **nouveaux** clients reçoivent un `429` (échec en mode fermé) tandis que les clients connus conservent leur seau : faire tourner les clés ne peut pas épuiser votre mémoire.
* Les clients IPv6 sont regroupés par `/64`, le bloc que les FAI attribuent généralement à chaque abonné : changer d'adresse ne permet pas d'échapper à la limite.

## Démarrage rapide

```rust
use std::net::SocketAddr;

use axum::{routing::get, Router};
use securite::prelude::*;

#[tokio::main]
async fn main() {
    let shield = Shield::builder()
        // 10 requests per second per client IP, bursts of up to 30.
        .guard(RateLimit::per_second(10).burst(30))
        .build();

    let app = Router::new()
        .route("/", get(|| async { "hello" }))
        .layer(shield);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    // `with_connect_info` gives the shield the real peer address.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
```

## Configuration

### Quota

| Méthode | Défaut | Description |
|---|---|---|
| `Quota::new(n, period)` | burst = `n` | `n` requêtes par `period`. Panique si `n == 0` ou si `period` est nulle. |
| `Quota::per_second(n)`, `Quota::per_minute(n)`, `Quota::per_hour(n)` | burst = `n` | Raccourcis pour les périodes courantes. |
| `.burst(b)` | `n` | Capacité du seau : requêtes autorisées d'un coup (minimum 1). |
| `.burst_size()`, `.replenish_interval()` | – | Renvoient la capacité et `T = period / n`. |

### RateLimit

| Méthode | Défaut | Description |
|---|---|---|
| `RateLimit::new(quota)` | – | Une règle globale, par IP client. |
| `RateLimit::per_second(n)`, `RateLimit::per_minute(n)`, `RateLimit::per_hour(n)` | burst = `n` | Raccourcis pour `RateLimit::new(Quota::per_second(n))`, `per_minute` et `per_hour`. |
| `.burst(n)` | burst du quota | Rafale de la règle globale. |
| `.key(key)` | `RateLimitKey::Ip` | Ce que compte la règle globale. |
| `.route(prefix, quota)` | – | Règle supplémentaire par IP pour un préfixe de chemin. |
| `.route_keyed(prefix, quota, key)` | – | Règle supplémentaire pour un préfixe, avec n'importe quelle clé. |
| `.route_methods(prefix, methods, quota)` | – | Règle supplémentaire par IP pour certaines méthodes sur un préfixe. |
| `.headers(style)` | `HeaderStyle::Standard` | En-têtes de limitation renvoyés. |
| `.ipv6_prefix(bits)` | `64` | Préfixe de regroupement IPv6 (plafonné à 128). |
| `.skip_paths(prefixes)` | aucun | Préfixes de chemin jamais limités. |
| `.max_entries(n)` | `1_000_000` | Clés suivies par règle, réparties sur 64 partitions (au moins 16 par partition). |
| `.monitor()` | blocage | Signale les violations sans bloquer. |

La règle globale s'applique à tous les chemins sauf `skip_paths`. Chaque règle correspondante doit être respectée ; les règles sont évaluées dans l'ordre de déclaration et le premier échec renvoie `429`. Les préfixes sont comparés segment par segment : `/api` couvre `/api/users`, pas `/apiary`.

### Clés

| Variante | Compte les requêtes par |
|---|---|
| `RateLimitKey::Ip` | IP du client, IPv6 masquée à `ipv6_prefix`. Par défaut. |
| `RateLimitKey::Header(name)` | Valeur d'un en-tête ; l'IP est utilisée si l'en-tête est absent, vide ou dépasse 256 octets. |
| `RateLimitKey::Global` | Un seau unique partagé par tous (plafond de débit). |
| `RateLimitKey::custom(f)` | Votre closure `Fn(&Parts, &Context) -> Option<String>`. Renvoyer `None` désactive la règle pour cette requête. |

`RateLimitKey::custom(f)` construit pour vous la variante `RateLimitKey::Custom(Arc<KeyFn>)`.

## Exemples

### Connexion et réinitialisation de mot de passe

```rust
use axum::http::Method;
use securite::prelude::*;

let limiter = RateLimit::new(Quota::per_second(20).burst(50))
    // 5 login attempts per minute and per IP, POST only.
    .route_methods("/login", [Method::POST], Quota::per_minute(5))
    // Reset e-mails are expensive and easy to abuse.
    .route("/password-reset", Quota::per_hour(10))
    // Never throttle load balancer probes.
    .skip_paths(["/health", "/ready"]);
```

`Quota::per_minute(5)` autorise 5 tentatives d'un coup, puis une toutes les 12 secondes.

### Clés d'API et plafonds globaux

```rust
use axum::http::HeaderName;
use securite::prelude::*;

let limiter = RateLimit::per_second(50)
    // Each API key gets its own bucket on /api.
    .route_keyed(
        "/api",
        Quota::per_minute(600).burst(100),
        RateLimitKey::Header(HeaderName::from_static("x-api-key")),
    )
    // Protect a fragile upstream: 200 searches per second for all clients combined.
    .route_keyed("/search", Quota::per_second(200), RateLimitKey::Global);
```

> **Attention :** la valeur d'un en-tête est choisie par le client, et `Auth` s'exécute après `RateLimit`. Un attaquant qui envoie une clé aléatoire différente à chaque requête obtient un seau neuf à chaque fois. Conservez la règle globale par IP pour que ces requêtes restent limitées par adresse.

### Clé personnalisée

```rust
use securite::prelude::*;

let internal = IpSet::private_networks();
// Count by IP, but never limit internal callers.
let key = RateLimitKey::custom(move |_req, ctx| {
    let ip = ctx.client_ip()?;
    (!internal.contains(ip)).then(|| ip.to_string())
});

let limiter = RateLimit::per_second(10).key(key);
```

Les clés personnalisées reçoivent l'IP brute du client : appliquez votre propre regroupement IPv6 si vous construisez vos clés à partir d'elle.

### Commencer en mode surveillance

```rust
use securite::prelude::*;

let shield = Shield::builder()
    .guard(RateLimit::per_second(5).monitor())
    .on_event(|e| {
        if e.guard == "rate_limit" {
            eprintln!("would throttle {:?} on {}", e.client_ip, e.path);
        }
    })
    .build();
```

Observez pendant quelques jours qui aurait été limité, puis retirez `.monitor()`.

## Utilisation en couche autonome

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(RateLimit::per_minute(120));

// Or replace the limiter of a preset (guards with the same name are replaced).
let shield = ShieldBuilder::recommended()
    .guard(RateLimit::per_minute(600))
    .build();
```

Les clones d'un `RateLimit` partagent leurs compteurs : le même limiteur appliqué à plusieurs routes les comptabilise ensemble.

## En-têtes de réponse

Les réponses acceptées indiquent l'état de la règle correspondante la plus restrictive. Avec `HeaderStyle::Standard` (brouillon IETF) :

```text
ratelimit-limit: 30
ratelimit-remaining: 29
ratelimit-reset: 1
```

`HeaderStyle::Legacy` envoie `x-ratelimit-*` à la place ; `HeaderStyle::None` ne conserve que `Retry-After` sur les rejets. `HeaderStyle` fait partie du prélude. Un rejet ressemble à ceci :

```text
HTTP/1.1 429 Too Many Requests
content-type: application/problem+json
cache-control: no-store
retry-after: 12
ratelimit-limit: 5
ratelimit-remaining: 0
ratelimit-reset: 12

{"type":"about:blank","title":"Too Many Requests","status":429,"code":"rate_limited","detail":"Too many requests, slow down."}
```

## Pièges et conseils

* **IP client inconnue** : sans `into_make_service_with_connect_info::<SocketAddr>()`, les règles par IP ne voient pas le client et *toutes* les requêtes partagent un seul seau. Le shield journalise alors un avertissement, une seule fois, sous la cible `securite`.
* **Derrière un proxy**, configurez `ShieldBuilder::client_ip`, sinon chaque client est le proxy. Avec des couches autonomes, placez `Shield::builder().client_ip(ClientIpSource::heroku()).build()` (ou la source de votre plateforme) en couche la plus externe : les couches intérieures réutilisent l'adresse qu'il a résolue, voir [IP du client](/docs/client-ip).
* **Un seul limiteur par bouclier** : un second `RateLimit` passé à `.guard()` remplace le premier. Ajoutez plutôt des règles avec `.route*()`.
* **L'état est propre à chaque processus** : avec N réplicas, la limite effective est N fois plus élevée.
* Les règles évaluées avant celle qui échoue ont déjà consommé un jeton.
* `RateLimit` s'exécute après `AutoBan`, `IpFilter`, `Hygiene`, `MethodFilter` et `BodyLimit`, et avant le WAF, CSRF et `Auth`.

> **Astuce :** combinez-le avec le [bannissement automatique](/docs/auto-ban) : chaque `429` compte comme une pénalité, si bien que les clients qui butent sans cesse sur la limite finissent bannis.

## Pages associées

* [Bannissement automatique](/docs/auto-ban)
* [Limite de concurrence](/docs/concurrency-limit)
* [Filtrage IP](/docs/ip-filter)
* [IP client derrière un proxy](/docs/client-ip)
