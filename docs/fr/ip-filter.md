---
title: Filtrage IP
summary: Listes d'autorisation et de refus CIDR pour IPv4 et IPv6, limitables à certains chemins, avec des recherches en O(log n) et des listes modifiables à chaud.
category: access
order: 1
---

`IpFilter` décide, d'après l'adresse du client, si une requête peut aller plus loin. Servez-vous-en pour cantonner les panneaux d'administration au réseau interne, bloquer des réseaux malveillants connus issus d'un flux de threat intelligence, ou réserver une API partenaire aux plages d'adresses de vos clients.

## Menaces couvertes

* **Back-offices exposés** (OWASP A01:2021, Broken Access Control) : panneaux d'administration, métriques et outils internes accessibles depuis Internet. Une liste d'autorisation ajoute une barrière réseau en plus de l'authentification.
* **Sources malveillantes connues** : scanners, botnets, hébergeurs abusifs, nœuds de sortie Tor ou régions que vous ne servez pas, sous forme de blocs CIDR.
* **Réponse à incident** : bloquez un réseau attaquant en quelques secondes, sans redéploiement.

## Fonctionnement

### Règles de décision

```text
only_paths set and path not matched -> pass (filter not applied)
client IP in deny-list              -> 403 ip_blocked   (deny always wins)
allow-list empty                    -> pass
client IP in allow-list             -> pass
otherwise                           -> 403 ip_blocked
```

| Liste d'autorisation | Client | Résultat |
|---|---|---|
| vide | dans la liste de refus | bloqué |
| vide | non listé | autorisé |
| vide | IP inconnue | autorisé |
| non vide | dans la liste de refus | bloqué |
| non vide | dans la liste d'autorisation | autorisé |
| non vide | non listé | bloqué |
| non vide | IP inconnue | bloqué (échec en mode fermé) |

### IpSet : plages triées, recherche dichotomique

Les listes sont stockées sous forme d'`IpSet`. Chaque IP ou CIDR devient une plage `[start, end]` dans un unique espace de 128 bits : IPv4 y occupe le bloc IPv4-mapped `::ffff:0:0/96`, et les adresses clientes IPv4-mapped (`::ffff:203.0.113.9`) sont d'abord converties en IPv4. Les plages sont triées, celles qui se chevauchent ou se touchent sont fusionnées : une recherche se résume à une dichotomie, en `O(log n)`, que la liste compte dix entrées ou cent mille.

Syntaxe acceptée : `"192.0.2.7"` (hôte unique), `"10.0.0.0/8"`, `"2001:db8::/32"`. Les bits d'hôte au-delà du préfixe sont ignorés (`10.1.2.3/8` équivaut à `10.0.0.0/8`).

### Mises à jour à chaud

Les listes sont protégées par un verrou lecture-écriture partagé par tous les clones du filtre. Les requêtes prennent le verrou en lecture le temps d'une dichotomie. `replace_deny_list` et `replace_allow_list` reçoivent un ensemble construit au préalable, si bien que le verrou en écriture n'est tenu que le temps d'un échange ; `deny_now` et `allow_now` fusionnent leur réseau dans la liste sous le verrou. Les méthodes de construction (`allow`, `deny`, `try_allow`, `try_deny`, `allow_private`) fonctionnent en copie à l'écriture : le filtre qu'elles renvoient reçoit ses propres listes, et les clones créés auparavant restent inchangés. Terminez d'abord la configuration, puis gardez un clone comme poignée et confiez l'autre au bouclier.

## Démarrage rapide

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let shield = Shield::builder()
    .guard(IpFilter::new().deny(["203.0.113.0/24", "2001:db8:bad::/48"]))
    .build();

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(shield);
```

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `IpFilter::new()` | – | Filtre vide : tout le monde passe. |
| `.allow(networks)` | vide | Ajoute des IP ou CIDR à la liste d'autorisation. Panique sur une entrée invalide. |
| `.deny(networks)` | vide | Ajoute des IP ou CIDR à la liste de refus. Panique sur une entrée invalide. |
| `.try_allow(networks)` | – | Variante faillible de `allow`, renvoie `Result<IpFilter, InvalidNetwork>`. |
| `.try_deny(networks)` | – | Variante faillible de `deny`. |
| `.allow_private()` | – | Ajoute les plages privées, de bouclage, link-local et CGNAT à la liste d'autorisation. |
| `.only_paths(prefixes)` | tous les chemins | N'applique le filtre qu'à ces préfixes de chemin. |
| `.monitor()` | blocage | Signale les violations sans bloquer. |
| `.deny_now(network)` | – | Ajoute un réseau à la liste de refus à chaud (`Result`), pour tous les clones. |
| `.allow_now(network)` | – | Ajoute un réseau à la liste d'autorisation à chaud (`Result`), pour tous les clones. |
| `.replace_deny_list(set)` | – | Remplace toute la liste de refus. |
| `.replace_allow_list(set)` | – | Remplace toute la liste d'autorisation. |
| `.is_allowed(Option<IpAddr>)` | – | Évalue les listes pour une adresse. |

Un `IpSet` se construit avec `IpSet::parse(items)`, avec `str::parse` sur une liste séparée par des virgules ou des espaces, ou avec `IpSet::private_networks()` (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `100.64.0.0/10`, `::1/128`, `fc00::/7`, `fe80::/10`). Il propose `contains(ip)`, `len()` et `is_empty()`. Comme l'IPv4 réside dans la plage IPv4-mapped, un ensemble contenant `::/0` contient aussi toutes les adresses IPv4. Les erreurs d'analyse sont de type `securite::ip_filter::InvalidNetwork`, également exporté par le prélude.

## Exemples

### Panneau d'administration réservé au bureau et au VPN

```rust
use securite::prelude::*;

let shield = Shield::builder()
    .client_ip(ClientIpSource::cloudflare())
    .guard(
        IpFilter::new()
            .allow_private() // VPN and internal tools
            .allow(["198.51.100.10", "2001:db8:abcd::/48"]) // office
            .only_paths(["/admin", "/metrics"]),
    )
    .build();
```

Tout le monde accède au site public ; seuls les réseaux listés atteignent `/admin` et `/metrics`.

### Bloquer un réseau pendant un incident

```rust
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use securite::prelude::*;

async fn block(State(filter): State<IpFilter>, Path(cidr): Path<String>) -> StatusCode {
    // `cidr` arrives percent-decoded, e.g. "203.0.113.0/24" sent as 203.0.113.0%2F24.
    match filter.deny_now(&cidr) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

fn app() -> Router {
    let filter = IpFilter::new();
    let admin = IpFilter::new().allow_private().only_paths(["/admin"]);
    // Both guards are named "ip_filter": the second would replace the first in
    // one shield, so each one gets its own layer.
    Router::new()
        .route("/admin/block/{cidr}", post(block))
        .with_state(filter.clone())
        .layer(admin)
        .layer(Shield::builder().guard(filter).build())
}
```

### Rafraîchir une liste de refus depuis un flux

```rust
use std::time::Duration;

use securite::prelude::*;

async fn load_blocklist() -> std::io::Result<String> {
    tokio::fs::read_to_string("/etc/myapp/blocklist.txt").await
}

fn spawn_refresher(filter: IpFilter) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(600));
        loop {
            every.tick().await;
            let Ok(text) = load_blocklist().await else { continue };
            let entries = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'));
            match IpSet::parse(entries) {
                Ok(set) => filter.replace_deny_list(set),
                Err(e) => eprintln!("blocklist ignored: {e}"),
            }
        }
    });
}
```

Appelez `spawn_refresher(filter.clone())` et confiez `filter` au bouclier. Un fichier invalide est ignoré et la liste précédente reste active.

## Utilisation en couche autonome

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/metrics", get(|| async { "up 1" }))
    .layer(IpFilter::new().allow_private());
```

## En-têtes de réponse

`IpFilter` n'ajoute aucun en-tête particulier. Les clients bloqués reçoivent une réponse volontairement laconique ; l'adresse du client n'est inscrite que dans les détails d'audit de l'événement de sécurité (`ip=203.0.113.9`).

```text
HTTP/1.1 403 Forbidden
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Forbidden","status":403,"code":"ip_blocked","detail":"Access denied."}
```

## Pièges et conseils

* **Derrière un proxy, configurez `ShieldBuilder::client_ip`**. Sinon toutes les requêtes semblent venir du proxy : avec `allow_private()`, votre panneau d'administration est ouvert à tout Internet, et une règle de refus peut bloquer tout le monde. Avec des couches autonomes, placez `Shield::builder().client_ip(ClientIpSource::heroku()).build()` (ou la source de votre plateforme) en couche la plus externe, voir [IP du client](/docs/client-ip).
* **`::/0` couvre aussi toutes les adresses IPv4**, puisque IPv4 est projeté dans l'espace IPv6. `0.0.0.0/0` ne couvre que l'IPv4.
* **Les méthodes de construction fonctionnent en copie à l'écriture** : appeler `.allow()`, `.deny()`, `try_allow`, `try_deny` ou `allow_private()` sur un clone renvoie un filtre doté de ses propres listes et ne modifie jamais l'original. Seules `deny_now`, `allow_now`, `replace_deny_list` et `replace_allow_list` agissent sur les listes vivantes partagées par tous les clones : prenez donc votre poignée après le dernier appel de construction.
* Un seul `IpFilter` par bouclier : les gardes sont identifiés par leur nom, un second remplace donc le premier. Utilisez des couches séparées comme ci-dessus.
* Il n'existe pas de suppression d'une entrée isolée : reconstruisez la liste et appelez `replace_deny_list` ou `replace_allow_list`.
* `IpFilter` s'exécute en priorité 40, juste après `AutoBan` : les clients bloqués ne coûtent presque rien.

> **Astuce :** une liste d'autorisation IP est une seconde barrière, pas une authentification. Conservez l'[authentification](/docs/auth) sur les routes d'administration.

## Pages associées

* [Bannissement automatique](/docs/auto-ban)
* [Limitation de débit](/docs/rate-limit)
* [IP client derrière un proxy](/docs/client-ip)
* [Authentification](/docs/auth)
