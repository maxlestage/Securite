---
title: Liste d'autorisation Content-Type
summary: Rejette les corps de requête dont le type de média n'est pas attendu, ce qui ferme la confusion de types, le CSRF par requêtes simples et les vecteurs XXE.
category: access
order: 5
---

`ContentTypeGuard` répond `415 Unsupported Media Type` lorsqu'un corps de requête est déclaré avec un type de média que vous n'avez pas autorisé. C'est un contrôle précoce et peu coûteux, qui élimine des familles entières de confusions d'analyse avant même l'exécution d'un handler.

## La menace

- **CSRF contre des points d'entrée JSON** : les navigateurs envoient `text/plain`, `application/x-www-form-urlencoded` et `multipart/form-data` en cross-site sans preflight CORS. Un handler qui analyse le corps brut comme du JSON, quel que soit son type déclaré, peut être piloté par un formulaire caché sur n'importe quel site.
- **XML External Entities (XXE)** : un point d'entrée qui négocie les formats peut transmettre le XML d'un attaquant à un analyseur XML, avec à la clé une divulgation de fichiers ou une SSRF.
- **Divergences d'analyse** : un WAF, un proxy et votre handler peuvent interpréter différemment un même corps lorsque son type est ambigu ou absent.

L'OWASP REST Security Cheat Sheet demande aux services de valider le `Content-Type` des requêtes ; voir aussi l'OWASP XXE Prevention Cheat Sheet, la catégorie A05 Security Misconfiguration de l'OWASP Top 10 2021 (qui a absorbé XXE) et l'OWASP API Security Top 10 2023 (API8 Security Misconfiguration).

## Fonctionnement

Le guard s'exécute à la priorité 150, après l'authentification. Il n'examine que les requêtes `POST`, `PUT`, `PATCH` et `DELETE` qui portent un corps, et dont le chemin n'est pas ignoré. Une requête porte un corps si elle a un `Content-Length` différent de `0` ou un en-tête `Transfer-Encoding` ; en HTTP/2 et HTTP/3, qui n'ont besoin d'aucun de ces en-têtes pour envoyer un corps, une requête sans `Content-Length` est supposée en porter un.

L'essence du type de média (la partie avant `;`, en minuscules) doit correspondre à une entrée autorisée :

- un type exact, comme `application/json` ;
- un sous-type générique, comme `text/*` (ou `*/*`, qui autorise tout) ;
- un suffixe de syntaxe structurée, comme `application/*+json`, qui couvre `application/problem+json` ou `application/merge-patch+json`.

Un `Content-Type` absent ou refusé donne un `415` avec le code `unsupported_media_type`. La valeur fautive n'est consignée que dans les détails de l'événement.

| `Content-Type` | `json()` | `new()` |
|---|---|---|
| `application/json; charset=utf-8` | autorisé | autorisé |
| `application/merge-patch+json` | autorisé | autorisé |
| `application/x-www-form-urlencoded` | 415 | autorisé |
| `multipart/form-data; boundary=x` | 415 | autorisé |
| `text/plain` | 415 | 415 |
| `application/xml` | 415 | 415 |
| absent | 415 | 415 |

## Démarrage rapide

```rust
use axum::{Router, routing::post};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/orders", post(|body: String| async move { body }))
        .layer(Shield::builder().guard(ContentTypeGuard::json()).build())
}
```

`Shield::api()` inclut `ContentTypeGuard::json()` et `Shield::strict()` inclut `ContentTypeGuard::new()`. Le guard s'appelle `content_type`.

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `ContentTypeGuard::new()` | JSON, `*+json`, formulaires URL-encoded et multipart | Adapté aux applications web. |
| `ContentTypeGuard::json()` | `application/json`, `application/*+json` | Adapté aux API JSON. |
| `allow(&str)` | — | Ajoute un type de média (`application/xml`, `text/csv`, `text/*`…). Peut être appelée plusieurs fois. |
| `skip(prefix)` | aucun | Préfixe de chemin non vérifié. Peut être appelée plusieurs fois. |
| `is_allowed(&str)` | — | Indique si une valeur de `Content-Type`, paramètres compris, est autorisée. |

## Exemples

### Application web avec import CSV et webhooks

```rust
use securite::prelude::*;

pub fn content_types() -> ContentTypeGuard {
    ContentTypeGuard::new()
        .allow("text/csv") // bulk import endpoint
        .skip("/webhooks") // third-party payloads, verified by signature
}
```

### Tester votre configuration

```rust
use securite::prelude::*;

#[test]
fn json_api_accepts_only_json() {
    let guard = ContentTypeGuard::json();
    assert!(guard.is_allowed("application/json; charset=utf-8"));
    assert!(guard.is_allowed("application/merge-patch+json"));
    assert!(!guard.is_allowed("text/plain"));
    assert!(!guard.is_allowed("application/xml"));
}
```

### Vérifier avec curl

```bash
curl -i -X POST https://api.example.com/orders \
  -H "Content-Type: text/plain" \
  --data '{"amount": 10}'
```

```text
HTTP/2 415
content-type: application/problem+json
cache-control: no-store
```

## Utilisation comme couche autonome

Appliquez le guard à un sous-routeur seulement, par exemple une API JSON montée à côté de pages HTML :

```rust
use axum::{Router, routing::{get, post}};
use securite::prelude::*;

pub fn app() -> Router {
    let api = Router::new()
        .route("/orders", post(|body: String| async move { body }))
        .layer(ContentTypeGuard::json());

    Router::new()
        .route("/", get(|| async { "home" }))
        .nest("/api", api)
}
```

Dans un routeur imbriqué, axum retire le préfixe de montage du chemin : les préfixes de `skip` sont donc relatifs à ce point de montage (`/orders`, et non `/api/orders`).

## Pièges et conseils

> **Attention :** en HTTP/2 et HTTP/3, un `POST`, `PUT`, `PATCH` ou `DELETE` sans `Content-Length` est vérifié comme s'il portait un corps : un corps envoyé en flux ne peut donc pas passer entre les mailles. Une telle requête sans corps, par exemple un `DELETE` envoyé sans `Content-Length: 0` ni `Content-Type`, reçoit `415` : faites envoyer `Content-Length: 0` par le client ou ignorez le chemin.

- **Défense en profondeur** : les extracteurs `Json` et `Form` d'axum vérifient déjà le type de contenu, mais pas `String`, `Bytes` ni les extracteurs personnalisés. Le guard les protège tous d'un coup.
- `allow()` ne fait qu'ajouter des types. Pour en accepter moins que `new()`, partez de `json()` et ajoutez ce dont vous avez besoin.
- `*/*` ou un `text/*` trop large réduit la protection à néant ; autorisez des types précis.
- Les corps des requêtes `GET` ne sont pas vérifiés ; ceux des requêtes `DELETE` le sont.
- Les envois multipart sont acceptés dans leur ensemble ; le type de chaque partie et de chaque fichier doit encore être validé dans votre code.

> **Astuce :** une API exclusivement JSON associée à un [CORS](/docs/cors) strict oblige toute écriture cross-site à passer par un preflight, ce qui complète efficacement la [protection CSRF](/docs/csrf).

## Pages associées

- [Protection CSRF](/docs/csrf)
- [CORS](/docs/cors)
- [Filtre d'hôtes](/docs/host-filter)
- [En-têtes de sécurité](/docs/security-headers)
- [Limite de taille du corps](/docs/body-limit)
- [Signatures de webhooks](/docs/webhook-signatures)
