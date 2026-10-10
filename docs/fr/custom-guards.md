---
title: Guards personnalisés
summary: Écrivez vos propres règles de sécurité en implémentant le trait Guard, rejetez les requêtes avec des erreurs structurées et enregistrez-les dans n'importe quel shield.
category: start
order: 6
---

Les guards intégrés couvrent les menaces génériques, mais votre application a ses propres règles : une fenêtre de maintenance, un réseau partenaire, une restriction aux heures ouvrées. Implémentez le trait `Guard` et votre règle profite de tout ce dont bénéficient les guards intégrés : ordonnancement, erreurs structurées, événements, statistiques et mode observation.

## Le trait Guard

```rust
pub trait Guard: Send + Sync + 'static {
    /// Stable, machine readable name (logs, events, stats, `without`).
    fn name(&self) -> &'static str;

    /// Execution order, lower runs first. Default: `priority::CUSTOM` (500).
    fn priority(&self) -> u16 { priority::CUSTOM }

    /// `Mode::Enforce` (default) or `Mode::Monitor`.
    fn mode(&self) -> Mode { Mode::Enforce }

    /// Inspect (and possibly modify) the request head. `Err` stops the pipeline.
    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        Ok(())
    }

    /// Decorate the response head (handler responses and rejections alike).
    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {}
}
```

Seul `name()` est obligatoire. Les modules `request` et `response` proviennent de la crate `http`, que securite réexporte : `use securite::http::{request::Parts, StatusCode};` fonctionne sans ajouter `http` à vos dépendances.

| Méthode | Rôle |
|---|---|
| `name` | Identifie le guard ; `.guard()` remplace tout guard portant le même nom |
| `priority` | Position dans le pipeline, voir les constantes dans [Shield et préréglages](/docs/shield-presets) |
| `mode` | Renvoyez `Mode::Monitor` pour signaler les violations sans bloquer |
| `on_request` | Examine la méthode, l'URI, les en-têtes et les extensions ; renvoyez `Err(Rejection)` pour bloquer |
| `on_response` | Ajoute ou retire des en-têtes de réponse ; appelé pour chaque réponse |

## Les rejets

| API | Effet |
|---|---|
| `Rejection::new(status, code, message)` | Rejet bloquant : journalisé, comptabilisé, rendu avec le format d'erreur du shield |
| `Rejection::respond(status, code)` | Court-circuit bénin (redirection, preflight) : corps vide, ni journalisé ni comptabilisé |
| `.with_header(name, value)` | Ajoute un en-tête de réponse comme `Retry-After` ou `WWW-Authenticate` |
| `.with_details(text)` | Détails réservés à l'audit, écrits dans les événements et les logs, jamais envoyés au client |

`code` est un identifiant court et stable, comme `maintenance`, repris dans le corps problem+json, les événements et les statistiques. `message` est affiché au client : restez générique et placez les valeurs détectées dans `details`.

## Le contexte de requête

`Context` est partagé par tous les guards pendant toute la durée d'une requête :

| Méthode | Description |
|---|---|
| `client_ip()` | Adresse résolue du client, `Option<IpAddr>` (voir [IP du client](/docs/client-ip)) |
| `method()`, `uri()`, `path()` | Ligne de requête telle que reçue par le shield |
| `request_id()` | Identifiant attribué par `RequestId`, qui s'exécute en premier |
| `rejected_by()` | Nom du guard qui a rejeté la requête, utile dans `on_response` |
| `blocked()` | Indique si un guard a bloqué la requête ; les courts-circuits bénins comme les preflights CORS ou les redirections HTTPS ne comptent pas |
| `started()` | `Instant` auquel le shield a commencé le traitement |
| `csp_nonce()` | Nonce CSP de la requête, lorsqu'il est activé |
| `add_set_cookie(value)` | Ajoute un en-tête `Set-Cookie` à la réponse finale |
| `hold(value)` | Garde une valeur en vie jusqu'à la production de l'en-tête de réponse, puis la libère |
| `extensions()`, `extensions_mut()` | Stockage typé réservé aux guards |
| `Context::new(method, uri, client_ip)` | Construit un contexte hors de tout shield, pour tester un guard unitairement |

## Exemple : mode maintenance

Ce guard répond `503 Service Unavailable` pendant la maintenance, sauf pour le réseau de l'équipe et le contrôle de santé, et peut être activé ou désactivé à chaud :

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use securite::http::header::{HeaderValue, RETRY_AFTER};
use securite::http::{StatusCode, request, response};
use securite::prelude::*;
use securite::priority;

/// Marker stored in the context when staff bypass maintenance.
#[derive(Clone)]
struct StaffBypass;

/// Answers `503` to everyone but staff while maintenance is on.
#[derive(Clone)]
pub struct Maintenance {
    enabled: Arc<AtomicBool>,
    staff: IpSet,
}

impl Maintenance {
    pub fn new(staff: IpSet) -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(false)),
            staff,
        }
    }

    /// Shared by every clone: flip it from an admin endpoint or a signal handler.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }
}

impl Guard for Maintenance {
    fn name(&self) -> &'static str {
        "maintenance"
    }

    // Right after the request id, before bans, rate limiting and the WAF.
    fn priority(&self) -> u16 {
        priority::REQUEST_ID + 5
    }

    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        if !self.enabled.load(Ordering::Relaxed) || req.uri.path() == "/health" {
            return Ok(());
        }
        if ctx.client_ip().is_some_and(|ip| self.staff.contains(ip)) {
            ctx.extensions_mut().insert(StaffBypass);
            return Ok(());
        }
        Err(Rejection::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "maintenance",
            "The service is under maintenance, please retry in a few minutes.",
        )
        .with_header(RETRY_AFTER, HeaderValue::from_static("600"))
        .with_details(format!("path={}", req.uri.path())))
    }

    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {
        if ctx.extensions().get::<StaffBypass>().is_some() {
            res.headers
                .insert("x-maintenance-bypass", HeaderValue::from_static("staff"));
        }
    }
}
```

### L'enregistrer

Conservez un clone du guard : tous les clones partagent le même indicateur.

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

let maintenance = Maintenance::new(
    IpSet::parse(["10.0.0.0/8", "192.0.2.0/24"]).expect("valid networks"),
);

let shield = ShieldBuilder::recommended()
    .guard(maintenance.clone())
    .build();

let app: Router = Router::new()
    .route("/", get(|| async { "Hello, secure world!" }))
    .route("/health", get(|| async { "ok" }))
    .layer(shield);

// Later, from wherever you kept the clone:
maintenance.set_enabled(true);
```

Les visiteurs reçoivent alors un corps problem+json avec `"code":"maintenance"` et un en-tête `Retry-After`, et chaque refus apparaît dans vos logs et vos statistiques. Si vous préférez tenir la maintenance à l'écart de la piste d'audit de sécurité, utilisez `Rejection::respond(StatusCode::SERVICE_UNAVAILABLE, "maintenance")`, silencieux et au corps vide.

## Retenir des ressources

`ctx.hold` lie une valeur à la durée de vie de la requête : elle est libérée lorsque l'en-tête de réponse est produit ou que la requête est annulée. C'est ainsi que la limite de concurrence rend ses permis. Ici, la valeur sert à repérer les réponses lentes :

```rust
use std::time::{Duration, Instant};

use securite::http::request;
use securite::{Context, Guard, Rejection};

/// Logs requests whose response head took more than one second.
struct SlowRequests;

struct Timer {
    path: String,
    started: Instant,
}

impl Drop for Timer {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        if elapsed > Duration::from_secs(1) {
            eprintln!("slow request: {} took {:?}", self.path, elapsed);
        }
    }
}

impl Guard for SlowRequests {
    fn name(&self) -> &'static str {
        "slow_requests"
    }

    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        ctx.hold(Timer {
            path: req.uri.path().to_owned(),
            started: Instant::now(),
        });
        Ok(())
    }
}
```

## Tester un guard

Un guard est une simple structure : appelez directement `on_request` avec des parties de requête et un contexte construit par `Context::new`, sans aucun serveur. Dans le fichier qui définit `Maintenance` :

```rust
#[cfg(test)]
mod tests {
    use securite::http::{Method, Request, StatusCode, Uri};
    use securite::prelude::*;

    use super::Maintenance;

    #[test]
    fn maintenance_blocks_visitors_but_not_staff() {
        let guard = Maintenance::new(IpSet::parse(["10.0.0.0/8"]).unwrap());
        guard.set_enabled(true);
        let (mut req, ()) = Request::get("/orders").body(()).unwrap().into_parts();

        // A visitor gets a 503.
        let visitor = Some("203.0.113.7".parse().unwrap());
        let mut ctx = Context::new(Method::GET, Uri::from_static("/orders"), visitor);
        let rejection = guard.on_request(&mut req, &mut ctx).unwrap_err();
        assert_eq!(rejection.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(rejection.code(), "maintenance");

        // Staff go through.
        let staff = Some("10.1.2.3".parse().unwrap());
        let mut ctx = Context::new(Method::GET, Uri::from_static("/orders"), staff);
        assert!(guard.on_request(&mut req, &mut ctx).is_ok());
    }
}
```

## Bonnes pratiques

- **Gardez vos guards synchrones et rapides.** Les guards s'exécutent sur chaque requête et ne peuvent pas faire `.await`. Évitez toute E/S bloquante : rafraîchissez plutôt un état partagé en arrière-plan (un `Arc<RwLock<…>>` ou un atomique, comme ci-dessus).
- **Choisissez un nom unique.** `.guard()` remplace un guard de même nom : appeler le vôtre `waf` retirerait silencieusement le WAF intégré.
- **Ne supposez pas que `on_request` a été appelé.** `on_response` l'est pour chaque réponse, y compris les rejets émis par des guards qui s'exécutent avant le vôtre. Vérifiez `ctx.rejected_by()` ou `ctx.blocked()` quand cela compte.
- **Transmettez les données aux handlers via la requête.** Insérez-les dans `req.extensions` et lisez-les avec l'extracteur `Extension<T>` d'axum ; `ctx.extensions_mut()` est réservé aux guards. Les valeurs stockées dans l'un ou l'autre doivent implémenter `Clone + Send + Sync`.
- **Aucun secret dans les messages.** Le message parvient au client ; `with_details` reste dans vos logs.
- **Déployez progressivement.** Renvoyez `Mode::Monitor` depuis `mode()` pour observer une nouvelle règle avant de l'appliquer, voir [Mode observation](/docs/monitor-mode).
