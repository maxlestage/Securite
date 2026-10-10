---
title: Filtre d'hôtes
summary: Une liste d'autorisation pour l'en-tête Host qui bloque l'empoisonnement de l'en-tête Host et les attaques par DNS rebinding.
category: access
order: 2
---

`HostFilter` ne laisse passer que les requêtes adressées à vos propres noms de domaine. Tout le reste (un `Host` forgé, une adresse IP brute, un domaine qui se contente de pointer vers votre serveur) est refusé avant d'atteindre votre code.

## La menace

L'en-tête `Host` est choisi par le client, et pourtant de nombreuses applications lui font confiance :

- **Empoisonnement des liens de réinitialisation** : une application qui construit des URL absolues à partir de `Host` (« cliquez ici pour réinitialiser votre mot de passe ») envoie à ses victimes un lien vers le domaine de l'attaquant, accompagné d'un jeton de réinitialisation valide.
- **Empoisonnement de cache web** : un cache qui n'inclut pas `Host` dans sa clé peut stocker une réponse générée pour un hôte forgé et la servir à tout le monde.
- **DNS rebinding** : une page malveillante fait pointer son propre domaine vers `127.0.0.1` ou une adresse interne. Le navigateur de la victime dialogue alors avec votre service local ou interne comme s'il était de même origine que la page de l'attaquant, en envoyant `Host: attacker.example`.
- **Scanners et mauvais routage** : les robots qui balaient des plages d'adresses envoient l'adresse IP brute comme hôte.

L'OWASP recense l'injection d'en-tête Host dans son Web Security Testing Guide (WSTG-INPV-17) ; elle relève généralement de la catégorie A05 Security Misconfiguration.

## Fonctionnement

Le guard s'exécute à la priorité 70, après les contrôles d'hygiène du protocole et juste avant la redirection HTTPS (75). Il prend l'hôte dans l'URI de la requête (requêtes en forme absolue et `:authority` HTTP/2) ou, à défaut, dans l'en-tête `Host`. Avant la comparaison, la valeur est passée en minuscules, son port est retiré, ainsi qu'un éventuel point final. Chaque règle est soit un nom exact, soit un motif `*.example.com`.

- Hôte autorisé : la requête poursuit son chemin.
- Hôte inconnu : `421 Misdirected Request`, code `invalid_host` ; la valeur rejetée est consignée dans les détails de l'événement, jamais renvoyée au client.
- Aucun hôte : `400 Bad Request`, code `missing_host`.

Les requêtes qui portent plusieurs en-têtes `Host` sont déjà rejetées par le guard `Hygiene` des presets.

| Règle | Correspond à | Ne correspond pas à |
|---|---|---|
| `example.com` | `example.com`, `EXAMPLE.com:443`, `example.com.` | `www.example.com`, `example.com.evil.com` |
| `*.example.com` | `api.example.com`, `a.b.example.com` | `example.com`, `evilexample.com` |
| `localhost` (via `allow_localhost`) | `localhost:3000` | `localhost.example.com` |

## Démarrage rapide

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    let shield = Shield::builder()
        .guard(HostFilter::new(["example.com", "*.example.com"]))
        .build();

    Router::new()
        .route("/", get(|| async { "hello" }))
        .layer(shield)
}
```

Le guard s'appelle `host`. Aucun preset ne l'inclut, car vous seul connaissez vos domaines.

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `HostFilter::new(hosts)` | — | Noms d'hôte autorisés, sans tenir compte du port. `*.example.com` couvre tous les sous-domaines, mais pas `example.com` lui-même. |
| `allow(hosts)` | — | Ajoute d'autres hôtes autorisés. |
| `allow_localhost()` | inactif | Accepte aussi `localhost`, `127.0.0.1` et `[::1]`. |
| `monitor()` | blocage | Journalise et signale les violations sans bloquer. |
| `is_allowed(&str)` | — | Indique si un hôte, avec ou sans port, est autorisé. |

## Exemples

### Production et développement local

```rust
use securite::prelude::*;

pub fn hosts(dev: bool) -> HostFilter {
    let hosts = HostFilter::new(["example.com", "*.example.com"]);
    if dev { hosts.allow_localhost() } else { hosts }
}
```

### Un outil local protégé contre le DNS rebinding

Tableaux de bord de développement, back-ends d'applications de bureau et outils d'administration liés à `127.0.0.1` sont les cibles favorites du DNS rebinding :

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn local_admin() -> Router {
    Router::new()
        .route("/", get(|| async { "local admin" }))
        .layer(HostFilter::new(["localhost", "127.0.0.1", "[::1]"]))
}
```

### Déploiement progressif en mode monitor

Avant de bloquer, identifiez les hôtes réellement utilisés par votre trafic :

```rust
use securite::prelude::*;

pub fn shield() -> Shield {
    Shield::builder()
        .guard(HostFilter::new(["example.com", "*.example.com"]).monitor())
        .on_event(|e| {
            if e.guard == "host" {
                eprintln!("unexpected host on {}: {:?}", e.path, e.details);
            }
        })
        .build()
}
```

### Sondes de santé adressées par IP

Les répartiteurs de charge et les sondes Kubernetes utilisent souvent l'adresse IP de l'instance comme hôte. Avec axum, les routes ajoutées après `.layer()` ne sont pas enveloppées par cette couche :

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "hello" }))
        .layer(Shield::builder().guard(HostFilter::new(["example.com"])).build())
        // Not behind the shield: probes using the pod IP as host still succeed.
        .route("/healthz", get(|| async { "ok" }))
}
```

## Utilisation comme couche autonome

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(SecurityHeaders::strict())
        .layer(HostFilter::new(["example.com"])) // outermost: runs first
}
```

## Pièges et conseils

> **Astuce :** au sein d'un même `Shield`, `HostFilter` s'exécute avant [HttpsRedirect](/docs/https-redirect), qui construit sa `Location` à partir de l'en-tête `Host` : ajoutez les deux au même shield et seuls des hôtes validés seront redirigés. Avec des couches autonomes, placez `HostFilter` à l'extérieur de `HttpsRedirect`.

- Un motif générique n'inclut pas le domaine racine : listez à la fois `example.com` et `*.example.com`.
- Les règles ignorent le port ; le filtre ne distingue pas `example.com:8080` de `example.com`.
- `X-Forwarded-Host` n'est pas vérifié. Si votre framework construit des URL à partir de cet en-tête, assurez-vous que votre proxy l'écrase.
- Ne construisez de toute façon jamais d'URL absolues à partir des en-têtes de la requête ; utilisez une URL de base configurée. Le filtre est un filet de sécurité, pas un substitut.
- Les sondes de santé par IP reçoivent un `421` : sortez-les du périmètre comme ci-dessus ou autorisez explicitement l'adresse.

> **Astuce :** `421 Misdirected Request` est le statut qu'attendent les clients HTTP/2 lorsqu'une connexion est réutilisée pour un hôte qu'elle ne sert pas ; les clients bien conçus réessaient alors sur une nouvelle connexion.

## Pages associées

- [Redirection HTTPS](/docs/https-redirect)
- [Protection CSRF](/docs/csrf)
- [CORS](/docs/cors)
- [En-têtes de sécurité](/docs/security-headers)
- [Hygiène HTTP](/docs/hygiene)
- [Mode monitor](/docs/monitor-mode)
