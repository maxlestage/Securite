---
title: Sondes de santé
summary: Répond à GET /health pour les répartiteurs de charge, Kubernetes et les outils de surveillance de disponibilité, au format application/health+json, avec des vérifications nommées qui transforment la réponse en 503.
category: everyday
order: 10
---

Les répartiteurs de charge, les orchestrateurs (Kubernetes, Nomad, Fly.io, Heroku…) et les outils de surveillance de disponibilité demandent régulièrement « es-tu en vie ? ». `Health` répond lui-même à cette question, avant vos routes : les sondes n'atteignent jamais vos handlers ni vos journaux.

## La réponse

```json
{
  "checks": {
    "database": [{ "status": "pass" }],
    "uptime": [{ "componentType": "system", "observedUnit": "s", "observedValue": 3600, "status": "pass" }]
  },
  "status": "pass",
  "version": "1.4.0"
}
```

Chaque vérification est une liste de mesures, comme le définit le format `application/health+json` ; la vérification `uptime` (nombre de secondes écoulées depuis le démarrage de l'application) est toujours présente.

- `200 OK` avec `"status":"pass"` lorsque toutes les vérifications réussissent ;
- `503 Service Unavailable` avec `"status":"fail"` dès que l'une d'elles échoue, pour que le répartiteur de charge cesse d'envoyer du trafic à cette instance.

Le type de contenu est `application/health+json` et la réponse n'est jamais mise en cache (`Cache-Control: no-store`). Seuls les `GET` et `HEAD` sur le chemin (avec ou sans `/` final) reçoivent une réponse ; tout le reste part vers vos routes.

## Démarrage rapide

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Health::new().version(env!("CARGO_PKG_VERSION")));
```

```bash
curl -i https://example.com/health
# HTTP/1.1 200 OK
# content-type: application/health+json
#
# {"checks":{"uptime":[{"componentType":"system","observedUnit":"s","observedValue":42,"status":"pass"}]},"status":"pass","version":"1.4.0"}
```

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `Health::new()` | `/health`, aucune vérification | Crée le middleware. |
| `.path(path)` | `/health` | Un autre chemin (`/healthz`, `/_health`…). |
| `.version(v)` | aucune | Version affichée dans la réponse. |
| `.check(name, f)` | aucune | Vérification nommée ; `f() == false` fait échouer la sonde. |

## Vérifications

Les vérifications s'exécutent à chaque sonde, de façon synchrone : gardez-les peu coûteuses. Le schéma habituel est un indicateur qu'une tâche en arrière-plan tient à jour :

```rust
use pratique::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use vitesse::prelude::*;

async fn ping_database() -> bool {
    true // par exemple `SELECT 1` avec un délai d'expiration court
}

let db_up = Arc::new(AtomicBool::new(true));

let flag = db_up.clone();
vitesse::tokio::spawn(async move {
    loop {
        let ok = ping_database().await;
        flag.store(ok, Ordering::Relaxed);
        vitesse::tokio::time::sleep(Duration::from_secs(5)).await;
    }
});

let mut app = App::new();
app.middleware(Health::new().check("database", move || db_up.load(Ordering::Relaxed)));
```

## Liveness et readiness

Kubernetes distingue « redémarre-moi » (liveness) de « ne m'envoie pas encore de trafic » (readiness). Utilisez deux instances sur deux chemins :

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Health::new().path("/livez"));
app.middleware(Health::new().path("/readyz").check("database", || true));
```

## Pièges et conseils

- Ajoutez `Health` avant le `Shield` de Securite si votre plateforme envoie ses sondes sans en-tête `Host` ou depuis une adresse que vos règles bloqueraient, et avant [Maintenance](/docs/maintenance) (ou autorisez son chemin avec `allow`) pour que les sondes continuent de fonctionner pendant la maintenance.
- Excluez le chemin de vos [journaux d'accès](/docs/access-log) : `.skip("/health")`.
- Ne faites pas dépendre la liveness de la base de données : une panne de celle-ci redémarrerait toutes les instances en boucle.

## Pages associées

- [Mode maintenance](/docs/maintenance)
- [Métriques Prometheus](/docs/metrics)
