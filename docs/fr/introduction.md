---
title: Introduction
summary: Securite protège vos applications Vitesse, et tout service tower ou hyper, avec un seul middleware, le Shield, qui exécute des guards rapides sur chaque requête et durcit chaque réponse.
category: start
order: 1
---

`securite` est une boîte à outils de sécurité pour les services web Rust, écrite pour Vitesse et pour l'écosystème tower. Elle réunit les protections dont toute application exposée sur Internet a besoin (en-têtes de sécurité, limitation de débit, pare-feu applicatif, CSRF et CORS, filtrage IP, bannissement automatique, authentification, signatures de webhooks) derrière une seule couche, qui s'ajoute en une ligne.

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::recommended());
app.get("/", |_req: Request| async { "Hello, secure world!" });
```

## Pourquoi Securite

Aucun contrôle ne bloque à lui seul toutes les attaques. Securite applique le principe de **défense en profondeur** : plusieurs vérifications indépendantes et peu coûteuses, chacune fermant une catégorie de faiblesses différente, de sorte qu'une faille dans une couche soit couverte par la suivante. Une requête qui reste sous la limite de débit se heurte encore au WAF ; un script injecté malgré le WAF reste neutralisé par la Content-Security-Policy.

Les valeurs par défaut suivent les recommandations de l'OWASP (Secure Headers Project, Core Rule Set, aide-mémoire sur le CSRF et la gestion de session) et sont pensées pour la production telles quelles. Désactiver une protection est un choix explicite ; vous n'avez jamais à penser à l'activer.

| OWASP Top 10 (2021) | Contrôles dans Securite |
|---|---|
| A01 Broken Access Control | Filtre IP, filtre d'hôte, authentification, CSRF, CORS |
| A03 Injection | WAF, hygiène HTTP, liste d'autorisation des types de contenu, CSP |
| A05 Security Misconfiguration | En-têtes de sécurité, durcissement des cookies, filtre de méthodes, redirection HTTPS |
| A07 Identification and Authentication Failures | Limites de débit par route, bannissement automatique, vérification des identifiants en temps constant |
| A08 Software and Data Integrity Failures | Vérification des signatures de webhooks |
| A09 Security Logging and Monitoring Failures | Événements de sécurité, statistiques en direct, identifiants de requête |
| A10 Server-Side Request Forgery | Signatures SSRF du WAF |

## Le concept de Shield

`Shield` est le cœur de la crate : une couche tower unique qui exécute un pipeline de **guards**.

```text
request ─► request_id ─► hygiene ─► … ─► rate_limit ─► waf ─► csrf ─► handler
                 │ first rejection stops the pipeline             │
                 ▼                                                ▼
        rejection (problem+json)                         handler response
                 └───────────────────────┬────────────────────────┘
                                         ▼
           on_response: security headers, rate-limit headers, CORS,
                        hardened cookies, x-request-id …
```

### Un pipeline de guards synchrones

Chaque guard examine la requête sans son corps (méthode, URI, en-têtes, extensions), puis la laisse passer ou la rejette. Les guards sont synchrones et ne mettent jamais le corps en mémoire tampon, ce qui les rend extrêmement rapides. Ils s'exécutent par ordre de priorité croissant : les contrôles bon marché, comme les bannissements ou l'hygiène du protocole, passent avant le WAF. Le premier rejet l'emporte : votre handler n'est jamais appelé et le client reçoit une erreur structurée.

### Décoration des réponses

Dès qu'une réponse existe, qu'elle provienne de votre handler ou d'un rejet, chaque guard peut en compléter les en-têtes. C'est pourquoi les réponses d'erreur portent elles aussi les en-têtes de sécurité, les en-têtes de limitation de débit et l'identifiant de requête.

### Contexte partagé et événements

Les guards partagent un contexte propre à chaque requête (IP du client, identifiant de requête, nonce CSP…). Chaque violation produit un événement de sécurité, écrit avec `tracing` et transmis à votre propre callback. La page [Shield et préréglages](/docs/shield-presets) détaille l'ordre d'exécution.

## Middlewares

### Durcissement du navigateur

| Middleware | Rôle |
|---|---|
| [En-têtes de sécurité](/docs/security-headers) | CSP avec nonces, HSTS, COOP, CORP, COEP, Permissions-Policy ; suppression des en-têtes qui trahissent votre pile technique |
| [CORS](/docs/cors) | Partage de ressources entre origines strict, fondé sur une liste d'autorisation |
| [Cookies](/docs/cookies) | Ajoute `Secure`, `HttpOnly` et `SameSite` à chaque `Set-Cookie` |
| [Redirection HTTPS](/docs/https-redirect) | Redirection de HTTP vers HTTPS, compatible avec les proxys |

### Contrôle du trafic

| Middleware | Rôle |
|---|---|
| [Limitation de débit](/docs/rate-limit) | Limiteur GCRA par IP, en-tête, route ou global |
| [Limite de concurrence](/docs/concurrency-limit) | Plafonne les requêtes simultanées par client |
| [Bannissement automatique](/docs/auto-ban) | Bannissement à la fail2ban des clients qui accumulent les échecs |
| [Limite de taille du corps](/docs/body-limit) | Rejette les corps trop volumineux avant que votre handler ne les lise |
| [Hygiène HTTP](/docs/hygiene) | Contrôles contre le request smuggling, la traversée de répertoires et les anomalies de protocole |
| [Filtre de méthodes](/docs/method-filter) | Méthodes HTTP autorisées ; bloque les en-têtes de surcharge de méthode |

### Contrôle d'accès

| Middleware | Rôle |
|---|---|
| [Filtre IP](/docs/ip-filter) | Listes CIDR d'autorisation et de refus, modifiables à chaud |
| [Filtre d'hôte](/docs/host-filter) | Liste d'autorisation de `Host` contre le DNS rebinding et les attaques sur l'en-tête Host |
| [Authentification](/docs/auth) | Jeton Bearer, clé d'API et Basic, vérifiés en temps constant |
| [CSRF](/docs/csrf) | Vérification Fetch Metadata et, en option, jetons double-submit signés |
| [Type de contenu](/docs/content-type) | Liste d'autorisation des types de médias acceptés en requête |

### Détection des menaces

| Middleware | Rôle |
|---|---|
| [WAF](/docs/waf) | Pare-feu à score d'anomalie : SQLi, XSS, traversée de répertoires, RCE, Log4Shell, SSRF … |
| [Blocage des bots](/docs/bot-blocker) | Bloque les scanners et outils d'attaque connus |

### Intégrité et traçabilité

| Middleware | Rôle |
|---|---|
| [Identifiant de requête](/docs/request-id) | Identifiants de requête validés, pour les logs, les handlers et les réponses |
| [Signatures de webhooks](/docs/webhook-signatures) | Vérification HMAC pour GitHub, Stripe, Slack, Shopify … |
| [Événements et statistiques](/docs/events-stats) | Piste d'audit, intégration `tracing` et compteurs en direct |
| [Format des erreurs](/docs/error-format) | Corps d'erreur problem+json (RFC 9457), texte brut, vides ou personnalisés |

## Performances

Une sécurité qui ralentit l'application finit toujours désactivée : Securite est donc conçue pour la vitesse. Mesures réalisées avec criterion (`cargo bench -p securite`) :

| Benchmark | Durée |
|---|---|
| Pipeline recommandé complet, requête de navigateur réaliste | ~6 µs |
| Inspection d'une requête par le WAF | ~2 µs |
| Recherche dans un ensemble de 10 000 plages IP | ~3,4 ns |

Toutes les signatures du WAF sont compilées en un unique automate Aho-Corasick : le coût ne croît pas avec le nombre de règles. La crate est en `#![forbid(unsafe_code)]`, et les guards à état conservent leurs données dans des tables partitionnées et bornées, au hachage à clé aléatoire : des clés contrôlées par un attaquant ne peuvent ni épuiser la mémoire ni provoquer d'attaque par inondation de hachage (HashDoS).

## Compatibilité

`Shield` est un middleware Vitesse et implémente `tower::Layer` : il s'intègre donc partout où une couche tower est acceptée :

| Pile | Intégration |
|---|---|
| Vitesse | `app.middleware(shield)` ; le shield lit lui-même l'adresse de chaque connexion |
| hyper 1 | Enveloppez votre service avec `tower::ServiceBuilder` et insérez `PeerAddr` |
| tonic | `Server::builder().layer(shield)` |
| tower | `ServiceBuilder::new().layer(shield)` |

Chaque guard est aussi un middleware autonome, par exemple `app.middleware(Shield::from(Waf::new()))`. Poursuivez avec l'[installation](/docs/installation), puis le [démarrage rapide](/docs/quick-start).
