---
title: Shield et préréglages
summary: Le contenu de Shield::recommended(), strict() et api(), leur personnalisation avec ShieldBuilder et l'ordre exact dans lequel les guards s'exécutent.
category: start
order: 4
---

Un `Shield` est un pipeline de guards immuable et peu coûteux à cloner. Vous l'obtenez à partir d'un préréglage ou de `ShieldBuilder`, puis vous l'ajoutez à votre application avec `app.middleware()` (ou à un service tower avec `.layer()`). `Shield::recommended()` équivaut simplement à `ShieldBuilder::recommended().build()`, et il en va de même pour `strict()` et `api()`.

## Les trois préréglages

### Shield::recommended()

Une protection raisonnable pour les applications web et les API consommées par des navigateurs. Dix guards :

| Guard | Nom | Réglages |
|---|---|---|
| `RequestId::new()` | `request_id` | `x-request-id`, réutilise les identifiants entrants sûrs |
| `Hygiene::new()` | `hygiene` | URI de 8 Kio, 100 en-têtes, 32 Kio d'en-têtes, 256 paramètres de requête, ni segments `..` ni encodage invalide |
| `MethodFilter::new()` | `method` | `GET HEAD POST PUT PATCH DELETE OPTIONS`, en-têtes de surcharge de méthode refusés |
| `BodyLimit::new(2 * 1024 * 1024)` | `body_limit` | Fondée sur `Content-Length` |
| `RateLimit::new(Quota::per_second(20).burst(100))` | `rate_limit` | 20 req/s par IP, rafale de 100, IPv6 regroupé par /64 |
| `BotBlocker::new()` | `bot_blocker` | Liste intégrée de scanners (sqlmap, nikto, nuclei …) |
| `Waf::new()` | `waf` | Paranoïa `Low`, seuil 5, en-têtes inspectés |
| `Csrf::new()` | `csrf` | Contrôles Fetch Metadata et `Origin`, sans jeton |
| `SecurityHeaders::new()` | `security_headers` | CSP stricte limitée à l'origine, HSTS deux ans avec sous-domaines, `nosniff`, `DENY` … |
| `CookieHardening::new()` | `cookies` | `Secure; HttpOnly; SameSite=Lax` |

### Shield::strict()

Tout le contenu de `recommended()`, avec des limites plus serrées et quatre guards supplémentaires :

| Guard | Nom | Changement |
|---|---|---|
| `HttpsRedirect::new()` | `https_redirect` | Ajouté : `308` vers HTTPS, fait confiance à `X-Forwarded-Proto`, challenges ACME exemptés |
| `AutoBan::new()` | `ban` | Ajouté : 20 infractions en une minute (requêtes bloquées par un autre guard, réponses `401`, `403` ou `429`) déclenchent un bannissement de 15 min, doublé à chaque récidive jusqu'à 24 h |
| `BodyLimit::new(1024 * 1024)` | `body_limit` | Abaissée de 2 Mio à 1 Mio |
| `RateLimit::new(Quota::per_second(10).burst(40))` | `rate_limit` | 10 req/s par IP, rafale de 40 |
| `ConcurrencyLimit::per_ip(32)` | `concurrency` | Ajouté : 32 requêtes simultanées par IP |
| `Waf::new().paranoia(Paranoia::Medium)` | `waf` | Paranoïa `Medium` |
| `ContentTypeGuard::new()` | `content_type` | Ajouté : JSON, `application/*+json`, formulaires URL-encodés et multipart |
| `SecurityHeaders::strict()` | `security_headers` | Ajoute `Cross-Origin-Embedder-Policy: require-corp` et `Referrer-Policy: no-referrer` (sans HSTS `preload`) |
| `CookieHardening::new().same_site(SameSite::Strict)` | `cookies` | `SameSite=Strict` |

> **Astuce :** aucun préréglage n'envoie la directive HSTS `preload`, qui vaut consentement à l'inscription dans les listes de préchargement des navigateurs. Une fois que chaque sous-domaine sert du HTTPS, activez-la avec `.hsts(Some(Hsts { preload: true, ..Hsts::default() }))` sur `SecurityHeaders` (importez `securite::headers::Hsts`), voir [En-têtes de sécurité](/docs/security-headers).

### Shield::api()

Pensé pour les API JSON authentifiées par jetons plutôt que par cookies : il ne contient donc aucun guard CSRF.

| Guard | Nom | Réglages |
|---|---|---|
| `RequestId`, `Hygiene`, `MethodFilter` | `request_id`, `hygiene`, `method` | Comme dans `recommended()` |
| `BodyLimit::new(1024 * 1024)` | `body_limit` | 1 Mio |
| `RateLimit::new(Quota::per_second(20).burst(50))` | `rate_limit` | 20 req/s par IP, rafale de 50 |
| `BotBlocker::new()`, `Waf::new()` | `bot_blocker`, `waf` | Comme dans `recommended()` |
| `ContentTypeGuard::json()` | `content_type` | `application/json` et `application/*+json` uniquement |
| `SecurityHeaders::api()` | `security_headers` | CSP `default-src 'none'`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` |
| `CookieHardening::new()` | `cookies` | `Secure; HttpOnly; SameSite=Lax` |

## Le builder

`Shield::builder()` part d'un pipeline vide ; `ShieldBuilder::recommended()`, `strict()` et `api()` partent d'un préréglage.

| Méthode | Effet | Par défaut |
|---|---|---|
| `.guard(g)` | Ajoute un guard ; un guard de même `name()` est remplacé | — |
| `.without(name)` | Retire le guard portant ce nom | — |
| `.client_ip(source)` | Origine de l'IP du client, voir [IP du client](/docs/client-ip) | `ClientIpSource::Peer` |
| `.error_format(format)` | Rendu des rejets, voir [Format des erreurs](/docs/error-format) | `ErrorFormat::ProblemJson` |
| `.on_event(f)` | Callback appelé à chaque blocage ou violation observée | Aucun |
| `.log_events(bool)` | Écrit les événements avec `tracing` (cible `securite`) | `true` |
| `.build()` | Trie les guards par priorité et renvoie le `Shield` | — |

```rust
use securite::prelude::*;

let shield = ShieldBuilder::strict()
    // Behind Heroku's router.
    .client_ip(ClientIpSource::heroku())
    // Not in the preset: added.
    .guard(Cors::new().allow_origin("https://app.example.com"))
    // Same name as the preset's guard: replaced.
    .guard(BodyLimit::new(10 * 1024 * 1024))
    // Removed by name.
    .without("concurrency")
    .error_format(ErrorFormat::PlainText)
    .on_event(|e| {
        if e.enforced {
            eprintln!("[security] {} blocked {} {}", e.guard, e.method, e.path);
        }
    })
    .build();

assert_eq!(
    shield.guard_names(),
    [
        "request_id", "ban", "hygiene", "method", "https_redirect", "body_limit",
        "cors", "rate_limit", "bot_blocker", "waf", "csrf", "content_type",
        "security_headers", "cookies",
    ]
);
```

Comme `.guard()` remplace par nom, configurer un préréglage ne crée jamais de doublon : il y a toujours au plus un `rate_limit`, un `waf`, et ainsi de suite.

## Ordre d'exécution

`build()` trie les guards par priorité, la plus basse en premier ; à priorité égale, l'ordre d'insertion est conservé. Les constantes se trouvent dans `securite::priority` :

| Constante | Valeur | Guard | Nom |
|---|---|---|---|
| `REQUEST_ID` | 10 | `RequestId` | `request_id` |
| `BAN` | 30 | `AutoBan` | `ban` |
| `IP_FILTER` | 40 | `IpFilter` | `ip_filter` |
| `HYGIENE` | 50 | `Hygiene` | `hygiene` |
| `METHOD` | 60 | `MethodFilter` | `method` |
| `HOST` | 70 | `HostFilter` | `host` |
| `HTTPS_REDIRECT` | 75 | `HttpsRedirect` | `https_redirect` |
| `BODY_LIMIT` | 80 | `BodyLimit` | `body_limit` |
| `CORS` | 90 | `Cors` | `cors` |
| `RATE_LIMIT` | 100 | `RateLimit` | `rate_limit` |
| `CONCURRENCY` | 105 | `ConcurrencyLimit` | `concurrency` |
| `USER_AGENT` | 110 | `BotBlocker` | `bot_blocker` |
| `WAF` | 120 | `Waf` | `waf` |
| `CSRF` | 130 | `Csrf` | `csrf` |
| `AUTH` | 140 | `Auth` | `auth` |
| `CONTENT_TYPE` | 150 | `ContentTypeGuard` | `content_type` |
| `CUSTOM` | 500 | Vos propres guards (par défaut) | Au choix |
| `HEADERS` | 900 | `SecurityHeaders` | `security_headers` |
| `COOKIES` | 910 | `CookieHardening` | `cookies` |

Cet ordre est délibéré. L'identifiant de requête vient en premier pour que chaque événement en porte un. Les IP bannies ou filtrées sont écartées avant tout travail réel, les contrôles de protocole peu coûteux passent avant le WAF, la redirection HTTPS suit le filtre d'hôte pour que sa `Location` soit construite à partir d'un hôte validé, et la limitation de débit coupe les inondations avant l'inspection, plus onéreuse. La décoration des réponses suit le même ordre : les en-têtes de sécurité et le durcissement des cookies interviennent donc en dernier, sur la réponse finale. `shield.guard_names()` renvoie les noms dans l'ordre d'exécution.

## Guards autonomes

Chaque guard se convertit en `Shield` (et implémente `tower::Layer`) : une protection peut donc être utilisée seule.

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(SecurityHeaders::strict()));
app.middleware(Shield::from(RateLimit::per_minute(120)));
app.get("/", |_req: Request| async { "ok" });

let waf_only = Shield::from(Waf::new());
```

> **Attention :** Chaque guard autonome est un shield indépendant à un seul guard : il utilise le format d'erreur par défaut et tient ses propres statistiques. Il détermine l'IP du client à partir de l'adresse du pair TCP, sauf si un shield extérieur l'a déjà fait : derrière un proxy, placez `Shield::builder().client_ip(ClientIpSource::heroku()).build()` (ou la source de votre plateforme) en premier middleware, voir [IP du client](/docs/client-ip). Les shields ne décorent pas non plus les rejets des autres : le premier middleware ajouté est le plus externe, si bien que les réponses `429` ci-dessus ne portent aucun en-tête de sécurité. Préférez un `Shield` unique construit avec `.guard()`.

## Inspecter un shield

`shield.stats()` renvoie un `StatsSnapshot` avec les compteurs `total`, `blocked`, `monitored` et par guard, ainsi que `allowed()` et `to_json()`. En interne, un `Shield` est un `Arc` : clonez-le librement pour le partager entre votre routeur et un endpoint de métriques. Voir [Événements et statistiques](/docs/events-stats).
