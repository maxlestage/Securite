---
title: Événements de sécurité et statistiques
summary: Chaque blocage ou détection en mode surveillance devient un événement de sécurité structuré pour vos journaux, métriques, SIEM ou alertes, et des compteurs en direct peuvent être exposés en JSON.
category: integrity
order: 3
---

Bloquer les attaques ne fait que la moitié du travail : encore faut-il savoir ce qui est bloqué, par quel guard, depuis où, et si une nouvelle règle gêne de vrais utilisateurs. Chaque fois qu'un guard rejette une requête, ou l'aurait rejetée en mode surveillance, le shield émet un `SecurityEvent`, l'écrit via `tracing` et met à jour des compteurs en direct consultables à tout moment.

## Pourquoi c'est important

**A09:2021 Security Logging and Monitoring Failures** range parmi les faiblesses les plus courantes l'absence de journalisation des événements de sécurité, de seuils d'alerte et de détection en temps réel. Les événements décrits ci-dessous vous offrent d'emblée une piste d'audit structurée et à faible cardinalité, et le hook vous permet de l'acheminer là où votre équipe regarde déjà.

## Le `SecurityEvent`

| Champ | Type | Description |
|---|---|---|
| `guard` | `&'static str` | Nom du guard : `waf`, `rate_limit`, `auth`, `bot_blocker`… |
| `code` | `&'static str` | Code de rejet lisible par une machine : `waf_blocked`, `rate_limited`… |
| `status` | `StatusCode` | Statut renvoyé (ou qui l'aurait été en mode surveillance). |
| `enforced` | `bool` | `false` lorsque le guard fonctionne en mode surveillance. |
| `client_ip` | `Option<IpAddr>` | Adresse IP du client résolue, si elle est connue. |
| `method` | `&Method` | Méthode de la requête. |
| `path` | `&str` | Chemin de la requête, sans la chaîne de requête. |
| `request_id` | `Option<&str>` | Identifiant de requête, lorsqu'un guard `RequestId` est actif. |
| `message` | `&str` | Message envoyé au client. |
| `details` | `Option<&str>` | Détails réservés à l'audit, comme `score=8 rules=[143, 100] categories=sqli`. |

Un événement est émis pour chaque rejet par un guard du shield, en mode blocage comme en mode surveillance. Aucun événement n'est émis pour les requêtes autorisées, pour les courts-circuits bénins (réponses aux preflights CORS, redirections HTTPS), pour les rejets de `SignatureLayer` (écrits uniquement via `tracing`) ni pour les appels à `Waf::inspect_text` effectués dans vos handlers.

## Journalisation tracing intégrée

Par défaut, les événements sont écrits avec `tracing` sous la cible `securite` :

- au niveau `WARN` avec le message `request blocked` pour les rejets effectifs ;
- au niveau `INFO` avec le message `violation (monitor mode)` pour les détections en mode surveillance.

Chaque ligne porte les champs `guard`, `code`, `status`, `ip`, `method`, `path`, `request_id` et `details`. `AutoBan` journalise aussi `client banned` au niveau `WARN`, et `SignatureLayer` journalise `webhook signature rejected`.

```rust
// Requires tracing-subscriber with the "env-filter" feature.
tracing_subscriber::fmt()
    .with_env_filter("info,securite=info")
    .init();
```

```text
2026-10-10T08:12:44.913245Z  WARN securite: request blocked guard="waf" code="waf_blocked" status=403 ip=Some(203.0.113.7) method=GET path="/search" request_id="3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44" details="score=8 rules=[143, 100] categories=sqli"
```

```bash
# Blocked requests only
RUST_LOG=info,securite=warn ./my-service
# Blocked requests and monitor-mode findings
RUST_LOG=info,securite=info ./my-service
```

Appelez `.log_events(false)` sur le builder si vous préférez traiter les événements uniquement via votre hook.

## Le hook `on_event`

`ShieldBuilder::on_event` enregistre une fonction appelée de manière synchrone pour chaque événement. Branchez-y vos métriques, votre SIEM ou vos alertes.

### Compteur de métriques

Avec le crate `metrics` (exportateurs Prometheus, StatsD, OpenTelemetry…) :

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .on_event(|e| {
        metrics::counter!(
            "securite_events_total",
            "guard" => e.guard,
            "code" => e.code,
            "enforced" => if e.enforced { "true" } else { "false" }
        )
        .increment(1);
    })
    .build();
```

### Alertes

Le hook s'exécute sur le chemin de la requête : n'y bloquez jamais. Copiez ce dont vous avez besoin dans une valeur possédée et transmettez-la à une tâche de fond via un canal :

```rust
use std::net::IpAddr;

use securite::prelude::*;
use tokio::sync::mpsc;

#[derive(Debug)]
struct Alert {
    guard: &'static str,
    code: &'static str,
    ip: Option<IpAddr>,
    path: String,
    request_id: Option<String>,
    details: Option<String>,
}

let (tx, mut rx) = mpsc::channel::<Alert>(1024);

tokio::spawn(async move {
    while let Some(alert) = rx.recv().await {
        // Post to Slack, PagerDuty or your SIEM here.
        eprintln!("security alert: {alert:?}");
    }
});

let shield = ShieldBuilder::recommended()
    .on_event(move |e| {
        if e.enforced && matches!(e.guard, "waf" | "auth" | "ban") {
            // try_send never blocks: alerts are dropped if the queue is full.
            let _ = tx.try_send(Alert {
                guard: e.guard,
                code: e.code,
                ip: e.client_ip,
                path: e.path.to_owned(),
                request_id: e.request_id.map(str::to_owned),
                details: e.details.map(str::to_owned),
            });
        }
    })
    .build();
```

## Statistiques en direct

`Shield::stats()` renvoie un `StatsSnapshot`, copie instantanée de compteurs sans verrou :

| Élément | Type | Description |
|---|---|---|
| `total` | `u64` | Requêtes vues par le shield. |
| `blocked` | `u64` | Requêtes rejetées par un guard en mode blocage. |
| `monitored` | `u64` | Violations signalées par des guards en mode surveillance. |
| `by_guard` | `Vec<(&'static str, u64)>` | Violations par guard (bloquées et surveillées), dans l'ordre d'exécution. |
| `allowed()` | `u64` | `total` moins `blocked`. |
| `to_json()` | `String` | L'instantané sous forme d'objet JSON compact. |

### Exposer un point d'accès d'administration

Conservez un clone du shield (c'est un `Arc`) et servez l'instantané derrière une authentification :

```rust
use securite::prelude::*;
use vitesse::prelude::*;

async fn security_stats(req: Request) -> Response {
    res::send(req.state::<Shield>().stats().to_json())
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
}

let admin_token = std::env::var("ADMIN_TOKEN").expect("ADMIN_TOKEN must be set");
let shield = ShieldBuilder::recommended()
    .guard(Auth::bearer().token("ops", &admin_token).protect(["/admin"]))
    .build();

let mut app = App::new();
app.state(shield.clone());
app.middleware(shield);
app.get("/admin/security/stats", security_stats);
```

```json
{
  "total": 15230,
  "allowed": 15102,
  "blocked": 128,
  "monitored": 0,
  "by_guard": {
    "request_id": 0,
    "hygiene": 4,
    "method": 2,
    "body_limit": 0,
    "rate_limit": 61,
    "bot_blocker": 17,
    "waf": 39,
    "csrf": 1,
    "auth": 4,
    "security_headers": 0,
    "cookies": 0
  }
}
```

`to_json()` renvoie le même objet sur une seule ligne.

## Pièges et conseils

- Les compteurs vivent en mémoire, par shield et par processus : ils repartent de zéro à chaque déploiement et ne sont pas partagés entre instances. Utilisez le hook et votre système de métriques pour des chiffres consolidés et sur la durée.
- Une couche autonome construit son propre shield interne, dont vous ne pouvez pas lire les statistiques. Construisez un `Shield`, conservez-en un clone et enregistrez-y vos guards.
- `total` compte aussi les courts-circuits bénins comme les preflights CORS et les redirections HTTPS ; ils font partie de `allowed()`.
- N'utilisez jamais l'adresse IP du client ni le chemin comme étiquettes de métriques : leur cardinalité est illimitée et contrôlée par les attaquants. Contentez-vous de `guard`, `code` et `enforced`.
- Protégez le point d'accès des statistiques : il révèle à un attaquant quels guards sont actifs et lesquelles de ses tentatives aboutissent.
- Les `details` ne sont destinés qu'à vous. Ils ne sont jamais envoyés aux clients : ne les recopiez pas dans les réponses.

## Pages associées

- [Mode surveillance](/docs/monitor-mode)
- [Identifiants de requête](/docs/request-id)
- [Format des réponses d'erreur](/docs/error-format)
- [Pare-feu applicatif (WAF)](/docs/waf)
- [Authentification](/docs/auth)
