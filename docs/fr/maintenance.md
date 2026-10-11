---
title: Mode maintenance
summary: Répond à chaque requête par 503 Service Unavailable et Retry-After tant qu'un interrupteur est activé, en HTML, en JSON ou en texte, et laisse ouverts les chemins de votre choix.
category: everyday
order: 11
---

Pendant une migration de base de données ou un incident, mieux vaut annoncer « de retour dans dix minutes » que servir des erreurs. `Maintenance` s'en charge grâce à un interrupteur que vous actionnez pendant que l'application tourne, sans redéploiement.

## Fonctionnement

Tant que l'interrupteur est activé, chaque requête hors des chemins autorisés reçoit :

- `503 Service Unavailable`, le statut que les moteurs de recherche comprennent comme « temporaire, revenez plus tard » ;
- `Retry-After: <seconds>` s'il est configuré ;
- `Cache-Control: no-store`, pour que personne ne mette la page de maintenance en cache ;
- une page HTML pour les navigateurs (si vous en avez fourni une et que la requête accepte `text/html`), du JSON `{"error":"maintenance","message":"…"}` pour les clients qui acceptent le JSON, du texte brut sinon.

L'interrupteur est un indicateur atomique : le consulter ne coûte rien lorsque la maintenance est désactivée.

## Démarrage rapide

```rust
use pratique::prelude::*;
use std::time::Duration;
use vitesse::prelude::*;

let maintenance = Maintenance::new()
    .allow("/health")
    .allow("/admin")
    .retry_after(Duration::from_secs(600))
    .html("<!doctype html><title>Maintenance</title><h1>Back in a few minutes</h1>");
let switch = maintenance.switch();

let mut app = App::new();
app.middleware(maintenance);
app.post("/admin/maintenance", move |req: Request| {
    let switch = switch.clone();
    async move {
        switch.set(req.query("on").as_deref() == Some("1"));
        format!("maintenance: {}", switch.is_on())
    }
});
```

> **Attention :** protégez la route qui actionne l'interrupteur, par exemple avec l'[authentification](/docs/auth) de Securite.

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `Maintenance::new()` | désactivé | Crée le middleware. |
| `.enabled(true)` | `false` | Démarre en maintenance (par exemple d'après une variable d'environnement). |
| `.switch()` | — | Le `MaintenanceSwitch`, à conserver avant de confier le middleware à l'application. |
| `.allow(prefix)` | aucun | Préfixe de chemin toujours servi. Peut être appelé plusieurs fois. |
| `.retry_after(duration)` | aucun | `Retry-After`, en secondes entières. |
| `.message(text)` | une phrase générique | Texte des réponses en texte brut et en JSON. |
| `.html(page)` | aucune | Page affichée aux navigateurs. |

`MaintenanceSwitch` se clone à moindre coût et propose `on()`, `off()`, `set(bool)` et `is_on()`.

## Démarrer d'après l'environnement

```rust
use pratique::prelude::*;

let maintenance = Maintenance::new()
    .enabled(std::env::var("MAINTENANCE").as_deref() == Ok("1"))
    .allow("/health");
```

## Pièges et conseils

- Autorisez le chemin de votre sonde de santé, sinon votre orchestrateur croira les instances mortes et les redémarrera.
- Chaque processus a son propre interrupteur : avec plusieurs instances, actionnez-les tous (ou lisez un indicateur partagé dans une tâche en arrière-plan et appelez `set`).
- Gardez la page HTML autonome (styles en ligne, aucune ressource externe) : vos fichiers statiques peuvent eux aussi être indisponibles.

## Pages associées

- [Sondes de santé](/docs/health)
- [Authentification](/docs/auth)
