---
title: Métriques Prometheus
summary: Compte chaque requête et expose sur /metrics, au format texte Prometheus, le nombre de requêtes par méthode et par classe de statut, un histogramme de latence, les requêtes en cours et la durée de fonctionnement.
category: everyday
order: 6
---

`Metrics` fournit à votre application les quatre indicateurs par lesquels commence tout tableau de bord (trafic, erreurs, latence, saturation) et les expose sur `GET /metrics` au format texte Prometheus, lu par Prometheus, Grafana Agent, VictoriaMetrics, Datadog ou le collecteur OpenTelemetry.

## Ce qui est mesuré

```text
# TYPE http_requests_total counter
http_requests_total{method="GET",status="2xx"} 1027
http_requests_total{method="POST",status="4xx"} 3
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{le="0.001"} 812
http_request_duration_seconds_bucket{le="0.005"} 1001
…
http_request_duration_seconds_bucket{le="+Inf"} 1030
http_request_duration_seconds_sum 1.734
http_request_duration_seconds_count 1030
# TYPE http_requests_in_flight gauge
http_requests_in_flight 2
# TYPE process_uptime_seconds gauge
process_uptime_seconds 86400
```

| Métrique | Type | Labels |
|---|---|---|
| `http_requests_total` | counter | `method` (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `OTHER`), `status` (`1xx` … `5xx`) |
| `http_request_duration_seconds` | histogram | intervalles de 1 ms à 10 s |
| `http_requests_in_flight` | gauge | — |
| `process_uptime_seconds` | gauge | — |

Les labels forment un ensemble fixe d'au plus 40 séries : le chemin n'est volontairement **pas** un label, si bien qu'un attaquant ou un robot d'indexation ne peut pas créer des millions de séries. Le comptage coûte quelques additions atomiques par requête, sans verrou.

## Démarrage rapide

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Metrics::new());
app.get("/", |_req: Request| async { "home" });
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: my-app
    static_configs:
      - targets: ["my-app:3000"]
```

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `Metrics::new()` | `/metrics`, préfixe `http` | Crée le middleware. |
| `.path(path)` | `/metrics` | Chemin de l'endpoint. |
| `.prefix(prefix)` | `http` | Préfixe des noms de métriques, par exemple `shop_http` ; panique s'il est invalide. |
| `.handle()` | — | Un `MetricsHandle` pour lire les valeurs depuis votre code. |

```rust
use pratique::prelude::*;

let metrics = Metrics::new();
let numbers = metrics.handle();
// plus tard : numbers.total(), numbers.by_class(5), numbers.in_flight(), numbers.render()
```

## Garder l'endpoint privé

Quiconque peut atteindre `/metrics` voit votre trafic. Ajoutez-le après le `Shield` de Securite, avec un guard `Auth` ou `IpFilter` :

```rust
use pratique::prelude::*;
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(
    Shield::builder()
        .guard(Auth::bearer().token("prometheus", "long-random-token").protect(["/metrics"]))
        .build(),
);
app.middleware(Metrics::new());
```

## Pièges et conseils

- L'endpoint ne se compte pas lui-même : les collectes ne faussent pas les chiffres.
- Les durées s'arrêtent quand l'en-tête de la réponse est prêt, pas à la fin d'un corps en flux.
- Ajoutez `Metrics` tôt (en premier ou juste après `AccessLog`) pour que les réponses des autres middlewares (redirections, `304`, maintenance) soient elles aussi comptées.
- Chaque processus a ses propres compteurs ; Prometheus additionne les instances.

## Pages associées

- [Journaux d'accès](/docs/access-log)
- [Sondes de santé](/docs/health)
- [Authentification](/docs/auth)
