---
title: Format des réponses d'erreur
summary: Choisissez comment les requêtes bloquées reçoivent leur réponse, du problem+json de la RFC 9457 au texte brut, au corps vide ou à votre propre rendu, sans rien divulguer des rouages internes.
category: integrity
order: 4
---

Lorsqu'un guard rejette une requête, le shield construit lui-même la réponse : vos handlers ne s'exécutent jamais. `ErrorFormat` décide de l'allure de cette réponse. Quel que soit le format, les rejets partagent le même durcissement : un message court et générique, aucun détail interne, `Cache-Control: no-store` et les mêmes en-têtes de sécurité que vos réponses habituelles.

## Pourquoi c'est important

- **A05:2021 Security Misconfiguration** et **CWE-209** (messages d'erreur contenant des informations sensibles) : des erreurs bavardes qui dévoilent des identifiants de règles, des versions ou des traces d'appels aident un attaquant à ajuster ses charges jusqu'à ce que l'une d'elles passe. Securite n'envoie qu'un message générique ; identifiants de règles et valeurs reconnues restent dans la piste d'audit.
- Des erreurs cohérentes et lisibles par une machine permettent aux clients d'une API de distinguer une limitation de débit d'un blocage du WAF ou d'un échec d'authentification sans analyser de texte.

## Les formats

| Variante | `Content-Type` | Corps |
|---|---|---|
| `ErrorFormat::ProblemJson` (par défaut) | `application/problem+json` | Détails de problème RFC 9457 |
| `ErrorFormat::PlainText` | `text/plain; charset=utf-8` | `403 Forbidden: <message>` |
| `ErrorFormat::Empty` | aucun | vide |
| `ErrorFormat::custom(f)` | le vôtre | ce que renvoie votre closure |

Choisissez-en un sur le builder ; le défaut est `ProblemJson` :

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .error_format(ErrorFormat::PlainText)
    .build();
```

| Méthode | Défaut | Description |
|---|---|---|
| `ShieldBuilder::error_format(ErrorFormat)` | `ErrorFormat::ProblemJson` | Mode de rendu des rejets. |
| `ErrorFormat::custom(f)` | — | Construit `ErrorFormat::Custom` à partir d'une closure `Fn(&Rejection, &Context) -> Response<Bytes>`. |

### ProblemJson

Le format par défaut suit la RFC 9457 (Problem Details for HTTP APIs), avec deux membres d'extension : `code`, le code de rejet lisible par une machine, et `request_id`, présent lorsqu'un guard `RequestId` est actif.

```text
HTTP/1.1 403 Forbidden
content-type: application/problem+json
cache-control: no-store
x-request-id: 3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44
x-content-type-options: nosniff
```

```json
{
  "type": "about:blank",
  "title": "Forbidden",
  "status": 403,
  "code": "waf_blocked",
  "detail": "Request blocked by the web application firewall.",
  "request_id": "3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44"
}
```

Le corps est envoyé sur une seule ligne ; `<` et `>` sont échappés en `\u003c` et `\u003e`.

### PlainText

```text
403 Forbidden: Request blocked by the web application firewall.
```

Pratique pour les petits services et les clients en ligne de commande.

### Empty

Uniquement le code de statut et les en-têtes, sans corps. À utiliser lorsque vous voulez en révéler le moins possible, ou lorsqu'un CDN ou un proxy inverse affiche ses propres pages d'erreur.

### Custom

Votre closure reçoit la `Rejection` et le `Context` de la requête, et renvoie une `http::Response<bytes::Bytes>` (`http` est réexporté sous `securite::http` ; ajoutez le crate `bytes` à vos dépendances ou utilisez la réexportation de Vitesse `vitesse::Bytes`). Une page HTML aux couleurs de votre site :

```rust
use bytes::Bytes;
use http::{header, Response};
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .error_format(ErrorFormat::custom(|rejection, ctx| {
        let body = format!(
            "<!doctype html><title>{status}</title><h1>{status}</h1><p>{message}</p><p>Reference: {id}</p>",
            status = rejection.status(),
            message = rejection.message(),
            id = ctx.request_id().unwrap_or("n/a"),
        );
        Response::builder()
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Bytes::from(body))
            .unwrap()
    }))
    .build();
```

Ou l'enveloppe d'erreur que les clients de votre API connaissent déjà, construite avec `serde_json` pour que chaque valeur soit correctement échappée :

```rust
use bytes::Bytes;
use http::{header, Response};
use securite::prelude::*;

let shield = ShieldBuilder::api()
    .error_format(ErrorFormat::custom(|rejection, ctx| {
        let body = serde_json::json!({
            "error": {
                "code": rejection.code(),
                "message": rejection.message(),
                "request_id": ctx.request_id(),
            }
        });
        Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Bytes::from(body.to_string()))
            .unwrap()
    }))
    .build();
```

`Rejection` expose `status()`, `code()`, `message()`, `details()`, `headers()` et `is_benign()`. `Context` expose `client_ip()`, `method()`, `uri()`, `path()`, `request_id()`, `rejected_by()`, `started()` et `csp_nonce()`.

> **Attention :** ne recopiez jamais `rejection.details()` dans la réponse. Les détails contiennent des identifiants de règles, des motifs reconnus et des adresses IP destinés uniquement à votre piste d'audit.

## Ce que reçoit chaque rejet

Après le rendu, quel que soit le format :

1. Le statut est celui du rejet, même si votre réponse personnalisée en utilisait un autre.
2. `Cache-Control: no-store` est positionné, afin qu'aucun navigateur ni cache partagé ne conserve une page d'erreur.
3. Les en-têtes portés par le rejet sont ajoutés : `Retry-After` pour les limitations de débit et les bannissements, `WWW-Authenticate` pour l'authentification, `Allow` pour les méthodes interdites.
4. Chaque guard décore la réponse comme d'habitude : en-têtes de sécurité, `X-Request-Id`, en-têtes `RateLimit-*`, en-têtes CORS, cookies durcis.

Codes de rejet courants :

| Guard | Statut | `code` |
|---|---|---|
| `waf` | 403 | `waf_blocked` |
| `bot_blocker` | 403 | `bot_blocked` |
| `auth` | 401 | `unauthorized` |
| `rate_limit` | 429 | `rate_limited` |
| `ban` | 403 | `banned` |
| `csrf` | 403 | `csrf_rejected`, `csrf_token_invalid` |
| `body_limit` | 413 | `body_too_large` |
| `method` | 405 | `method_not_allowed` |
| `content_type` | 415 | `unsupported_media_type` |
| `ip_filter` | 403 | `ip_blocked` |
| `host` | 421 | `invalid_host` |

## Réponses bénignes

Certains courts-circuits ne sont pas des attaques : un preflight CORS auquel on répond `204 No Content` (`cors_preflight`) ou une requête HTTP en clair redirigée avec `308 Permanent Redirect` (`https_redirect`). Ils sont créés avec `Rejection::respond(status, code)` et ont toujours un corps vide, quel que soit le format ; votre closure personnalisée n'est pas appelée. Ils ne reçoivent pas `Cache-Control: no-store`, ne sont ni journalisés ni comptés comme bloqués, et ne déclenchent pas `on_event`.

## Rejets de vos propres guards

Un guard personnalisé renvoie `Rejection::new(status, code, message)`. Le message est envoyé aux clients : gardez-le générique et n'y incluez jamais de saisie utilisateur ni de secret. Placez les diagnostics dans `.with_details(…)` et les en-têtes de réponse supplémentaires dans `.with_header(name, value)`.

## Guards autonomes

Un guard utilisé seul (`app.middleware(Shield::from(Waf::new()))`) construit un shield interne avec le format par défaut : ses rejets sont donc toujours en problem+json. Il en va de même pour `SignatureLayer`. Pour choisir le format, enregistrez vos guards dans un `Shield` construit avec `error_format`.

## Pièges et conseils

- Votre closure personnalisée s'exécute à chaque rejet, éventuellement en pleine attaque : gardez-la rapide, économe en allocations et sans entrées-sorties.
- Échappez tout ce que vous interpolez. Les messages intégrés sont statiques, mais ceux de vos propres guards ne le sont pas forcément.
- Si votre interface affiche les erreurs, montrez le `request_id` : il permet à votre support de retrouver l'événement exact dans les journaux.
- `ErrorFormat::Empty` complique le diagnostic pour les clients légitimes. Préférez `ProblemJson` pour les API et une page HTML personnalisée pour les sites web.

## Pages associées

- [Guards personnalisés](/docs/custom-guards)
- [Événements de sécurité et statistiques](/docs/events-stats)
- [Identifiants de requête](/docs/request-id)
- [Shield et préréglages](/docs/shield-presets)
