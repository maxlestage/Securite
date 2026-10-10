---
title: Mode observation
summary: Faites tourner vos guards en simple signalement pour mesurer les faux positifs, puis passez au blocage en toute confiance ; la méthode sûre pour déployer un WAF ou une CSP stricte.
category: start
order: 7
---

Activer un WAF ou une Content-Security-Policy stricte devant une application existante comporte un risque : un seul faux positif peut bloquer une page de paiement ou une intégration partenaire. Le mode observation (`Mode::Monitor`) permet à un guard de signaler ce qu'il *aurait* bloqué tout en laissant passer le trafic : vous l'ajustez sur du trafic réel avant de l'appliquer.

## Blocage et observation

Chaque guard possède un `Mode` :

| Mode | Quand le guard détecte une violation |
|---|---|
| `Mode::Enforce` (par défaut) | La requête est rejetée, un événement `WARN` `request blocked` est journalisé, `blocked` est incrémenté |
| `Mode::Monitor` | La requête continue vers les guards suivants et votre handler, un événement `INFO` `violation (monitor mode)` est journalisé, `monitored` est incrémenté |

Dans les deux cas, le shield émet un `SecurityEvent` avec le même guard, le même code, le même statut et les mêmes détails ; seul son champ `enforced` diffère. Une violation observée ne neutralise pas les autres guards : un limiteur de débit en mode blocage continue de stopper les inondations pendant que le WAF est en observation.

## Guards compatibles

| Guard | `.monitor()` | Comportement en mode observation |
|---|---|---|
| `Waf` | Oui | Les attaques sont signalées avec leur score, les identifiants de règles et les catégories, puis atteignent le handler |
| `RateLimit` | Oui | Les requêtes hors quota passent ; les réponses affichent tout de même `RateLimit-Remaining: 0` |
| `ConcurrencyLimit` | Oui | Les requêtes simultanées excédentaires passent et sont signalées |
| `AutoBan` | Oui | Infractions et bannissements sont calculés et journalisés, mais les clients bannis ne sont pas bloqués |
| `IpFilter` | Oui | Les adresses refusées passent et sont signalées |
| `HostFilter` | Oui | Les valeurs de `Host` inconnues passent et sont signalées |
| `BotBlocker` | Oui | Les user agents reconnus passent et sont signalés |
| `Csrf` | Oui | Les requêtes intersites modifiant l'état passent et sont signalées |
| `SecurityHeaders` | Non | Utilisez plutôt une CSP en report-only (voir ci-dessous) |
| Autres guards intégrés | Non | `Auth`, `Hygiene`, `MethodFilter`, `BodyLimit`, `ContentTypeGuard`, `HttpsRedirect`, `Cors`, `RequestId` et `CookieHardening` appliquent toujours leurs règles |

`.monitor()` est une méthode de builder qui s'enchaîne avec le reste de la configuration : `Waf::new().paranoia(Paranoia::Medium).monitor()`. Vos propres guards adoptent ce mode en renvoyant `Mode::Monitor` depuis `mode()`, voir [Guards personnalisés](/docs/custom-guards).

## CSP en report-only

`ContentSecurityPolicy::report_only()` envoie `Content-Security-Policy-Report-Only` au lieu de l'en-tête bloquant. Les navigateurs signalent alors les violations sans rien bloquer :

```rust
use securite::headers::src;
use securite::prelude::*;

let csp = ContentSecurityPolicy::strict()
    .img_src([src::SELF, src::DATA, "https://images.example.com"])
    .report_uri(["/csp-reports"])
    .report_only();

let shield = ShieldBuilder::recommended()
    .guard(SecurityHeaders::new().csp(csp))
    .guard(Csrf::new().exempt("/csp-reports"))
    .build();
```

Les navigateurs envoient leurs rapports en `application/csp-report` ou `application/reports+json`. Exemptez l'endpoint de la protection CSRF comme ci-dessus et, si votre shield contient un `ContentTypeGuard`, autorisez ces types de médias ou ignorez le chemin avec `.skip("/csp-reports")`.

## Un déploiement progressif

1. **Observer.** Déployez le WAF avec `.monitor()` et la CSP avec `.report_only()`. Rien n'est encore bloqué.
2. **Attendre un trafic représentatif.** Un cycle d'activité complet, en général une à deux semaines, traitements par lots, clients mobiles et intégrations partenaires compris.
3. **Trier.** Chaque événement WAF observé porte des `details` du type `score=… rules=[…] categories=…`. Pour chaque faux positif, corrigez l'application, ignorez le chemin ou l'en-tête (`skip_paths`, `skip_headers`), désactivez la règle (`disable_rules`) ou relevez le seuil (`threshold`).
4. **Appliquer.** Retirez `.monitor()`, ou passez à la CSP bloquante, et conservez les alertes sur les événements. Activer d'abord le blocage sur une seule instance fait office de déploiement canari.
5. **Resserrer.** Augmentez le niveau de paranoïa ou restreignez la CSP, puis recommencez le cycle.

Une variable d'environnement permet de changer de mode sans toucher au code :

```rust
use securite::prelude::*;

// WAF_ENFORCE=1 switches from observation to blocking.
let enforce = std::env::var("WAF_ENFORCE").is_ok_and(|v| v == "1");

let waf = Waf::new()
    .paranoia(Paranoia::Medium)
    .disable_rules([119]) // "sleep(" matched legitimate search queries
    .skip_paths(["/webhooks"]);
let waf = if enforce { waf } else { waf.monitor() };

let shield = ShieldBuilder::recommended().guard(waf).build();
```

> **Attention :** Un guard en mode observation ne vous protège pas : les attaques atteignent vos handlers. Gardez des périodes d'observation courtes, laissez les autres guards en mode blocage et assurez-vous que quelqu'un lit réellement les rapports.

## Observer les violations

### Callback d'événements

`on_event` reçoit chaque événement ; `enforced` vaut `false` pour les violations observées :

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .guard(Waf::new().monitor())
    .on_event(|e| {
        if !e.enforced {
            eprintln!(
                "[monitor] {} {} {} {} would return {} ({})",
                e.guard,
                e.code,
                e.method,
                e.path,
                e.status,
                e.details.unwrap_or("-"),
            );
        }
    })
    .build();
```

### tracing

Avec `log_events` activé (c'est le cas par défaut), les événements sont écrits sous la cible `securite`, avec les champs `guard`, `code`, `status`, `ip`, `method`, `path`, `request_id` et `details`. Les violations observées sont journalisées au niveau `INFO`, les blocages au niveau `WARN` ; un filtre comme `RUST_LOG=securite=info` affiche les deux.

### Statistiques

`shield.stats()` compte les violations observées séparément des blocages :

```rust
let stats = shield.stats();
println!(
    "{} requests, {} blocked, {} would have been blocked",
    stats.total, stats.blocked, stats.monitored,
);
println!("{}", stats.to_json());
// {"total":1200,"allowed":1198,"blocked":2,"monitored":37,"by_guard":{"request_id":0,
//  "hygiene":0,"method":0,"body_limit":0,"rate_limit":2,"bot_blocker":0,"waf":37,
//  "csrf":0,"security_headers":0,"cookies":0}}
```

`by_guard` additionne, pour chaque guard, violations bloquées et observées. Les compteurs vivent en mémoire et repartent de zéro au redémarrage du processus : exportez-les régulièrement (voir [Événements et statistiques](/docs/events-stats)).

> **Astuce :** Les requêtes observées comptent comme `allowed`, puisqu'elles sont bel et bien passées. `monitored` correspond exactement au nombre de requêtes que le blocage aurait refusées, légitimes ou non : comparez-le aux attaques effectivement identifiées avant de basculer.
