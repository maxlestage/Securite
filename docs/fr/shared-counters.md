---
title: Compteurs partagés
summary: Une seule limite de tentatives de connexion pour toutes les instances de votre application, avec des compteurs dans Redis ou tout autre stockage, des clés hachées et un comportement fermé en cas de panne.
category: traffic
order: 8
---

Chaque instance d'une application compte dans sa propre mémoire : derrière un répartiteur de charge avec quatre instances, « 5 échecs par 15 minutes » devient 20. Un `CounterStore` sort les compteurs du processus (Redis, Memcached, une base de données) et `LoginThrottle::with_store` s'en sert.

## Menaces couvertes

- **Force brute distribuée** (CWE-307) : un attaquant répartit ses essais sur toutes les instances pour multiplier la limite.
- **Pannes du stockage** : quand le stockage répond une erreur, la clé est traitée comme verrouillée (échec fermé) ; casser Redis n'ouvre pas la porte.
- **Vie privée** : les clés arrivent dans le stockage sous la forme `securite:throttle:<sha-256>`, jamais comme adresses e-mail ou IP.

## Démarrage rapide

```rust
use std::sync::Arc;
use std::time::Duration;
use securite::throttle::LoginThrottle;

let store = Arc::new(MyRedisCounters::new(pool)); // implémente CounterStore
let throttle = LoginThrottle::with_store(5, Duration::from_secs(15 * 60), store);
// Même API qu'avant : attempt, check, hit, clear …
```

`MemoryCounterStore` implémente le trait en mémoire (tests, instance unique).

## Implémenter un stockage

Le modèle est un compteur à fenêtre fixe, que tout stockage sait faire de façon atomique :

```rust
use std::time::Duration;
use securite::counter::{CounterStore, StoreError, Window};

impl CounterStore for MyRedisCounters {
    fn increment(&self, key: &str, window: Duration) -> Result<Window, StoreError> {
        let mut c = self.pool.get().map_err(|_| StoreError)?;
        let (count, ttl): (u64, i64) = redis::pipe().atomic()
            .incr(key, 1)
            .cmd("PEXPIRE").arg(key).arg(window.as_millis() as u64).arg("NX").ignore()
            .cmd("PTTL").arg(key)
            .query(&mut *c).map_err(|_| StoreError)?;
        Ok(Window { count, resets_in: Duration::from_millis(ttl.max(1) as u64) })
    }
    fn get(&self, key: &str) -> Result<Option<Window>, StoreError> { /* GET + PTTL */ }
    fn delete(&self, key: &str) -> Result<(), StoreError> { /* DEL */ }
}
```

Les appels sont synchrones : utilisez un pool de connexions et des délais courts (quelques centaines de millisecondes), car un stockage lent ralentit les connexions.

## Pièges et conseils

- `PEXPIRE … NX` (Redis 7) ne pose la durée de vie que d'une nouvelle fenêtre ; sur les versions plus anciennes, posez-la quand `INCR` renvoie 1.
- Gardez le throttle en mémoire pour les déploiements à une instance : il est plus rapide et sans dépendance externe.
- La [limitation de débit](/docs/rate-limit) et l'[auto-ban](/docs/auto-ban) comptent toujours par instance.

## Pages liées

- [Limitation des tentatives de connexion](/docs/login-throttle)
- [Limitation de débit](/docs/rate-limit)
