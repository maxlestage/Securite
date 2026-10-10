---
title: Durcissement des cookies
summary: Ajoute les attributs Secure, HttpOnly et SameSite manquants à chaque en-tête Set-Cookie, y compris pour les cookies posés par des crates que vous ne contrôlez pas.
category: browser
order: 3
---

`CookieHardening` réécrit les en-têtes `Set-Cookie` de vos réponses pour que chaque cookie reçoive `Secure`, `HttpOnly` et `SameSite`, quel que soit le handler, la bibliothèque de sessions ou la crate OAuth qui l'a créé. Les attributs déjà présents ne sont jamais modifiés.

## La menace

Un cookie de session est un identifiant au porteur : qui le détient devient l'utilisateur. Chaque attribut manquant ouvre une voie connue pour le voler ou en abuser :

- sans `HttpOnly`, une seule faille XSS suffit pour lire `document.cookie` et exfiltrer la session ;
- sans `Secure`, le cookie circule en clair dans toute requête HTTP, y compris une requête provoquée par un attaquant sur un Wi-Fi public ;
- sans `SameSite`, le navigateur joint le cookie aux requêtes cross-site, ce qui est la cause première du CSRF.

Ces faiblesses relèvent de la catégorie A07 Identification and Authentication Failures de l'OWASP Top 10 2021. L'OWASP Session Management Cheat Sheet exige les trois attributs, et le test WSTG-SESS-02 les vérifie. On les oublie facilement, car les cookies sont posés à de nombreux endroits ; ce guard les corrige en un seul.

## Fonctionnement

Le guard intervient sur la réponse, à la priorité 910, après tous les autres, et réécrit chaque valeur `Set-Cookie` :

- `Secure` est ajouté s'il est absent. Il l'est toujours pour les cookies `SameSite=None` et pour les cookies préfixés `__Host-` ou `__Secure-`, même en mode développement, car les navigateurs les refusent sinon.
- `HttpOnly` est ajouté s'il est absent, sauf si le nom du cookie figure dans `readable_by_js` ou si `no_http_only()` est activé.
- `SameSite=<défaut>` n'est ajouté que si le cookie n'a pas d'attribut `SameSite`.
- Les autres attributs (`Path`, `Domain`, `Max-Age`, `Partitioned`…) restent intacts, et les valeurs qui ne sont pas de l'UTF-8 valide sont transmises telles quelles.

Les cookies ajoutés par d'autres guards, comme le cookie de jeton [CSRF](/docs/csrf), sont eux aussi durcis.

| Posé par l'application | Envoyé au navigateur (valeurs par défaut) |
|---|---|
| `sid=abc` | `sid=abc; Secure; HttpOnly; SameSite=Lax` |
| `sid=abc; Path=/;` | `sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax` |
| `sid=abc; secure; HTTPONLY; SameSite=Strict` | inchangé |

## Démarrage rapide

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/login", get(|| async { ([("set-cookie", "sid=abc; Path=/")], "welcome") }))
        .layer(Shield::builder().guard(CookieHardening::new()).build())
}
```

`Shield::recommended()` et `Shield::api()` incluent déjà `CookieHardening::new()` ; `Shield::strict()` utilise `SameSite::Strict`. Le guard s'appelle `cookies`.

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `CookieHardening::new()` | `Secure; HttpOnly; SameSite=Lax` | Valeurs recommandées. |
| `same_site(SameSite)` | `SameSite::Lax` | Valeur `SameSite` ajoutée aux cookies qui n'en ont pas. |
| `readable_by_js(names)` | aucun | Noms des cookies qui doivent rester lisibles par JavaScript (sans `HttpOnly`). Peut être appelée plusieurs fois. |
| `no_http_only()` | `HttpOnly` ajouté | N'ajoute jamais `HttpOnly`. |
| `insecure_dev()` | `Secure` ajouté | N'ajoute pas `Secure`, uniquement pour le développement local en HTTP simple. |
| `harden(&str)` | — | Renvoie la version durcie d'une valeur `Set-Cookie` ; pratique dans les tests unitaires. |

### Valeurs de SameSite

| Valeur | Cookie envoyé avec | Usage typique |
|---|---|---|
| `SameSite::Strict` | les requêtes same-site uniquement | back-offices d'administration, opérations bancaires |
| `SameSite::Lax` | les requêtes same-site et les navigations `GET` de premier niveau venant d'autres sites | cookies de session de la plupart des sites |
| `SameSite::None` | toutes les requêtes (`Secure` est imposé) | widgets intégrés, SSO cross-site |

## Exemples

### Sessions strictes pour un back-office

```rust
use securite::prelude::*;

pub fn shield() -> Shield {
    Shield::builder()
        .guard(SecurityHeaders::new())
        .guard(CookieHardening::new().same_site(SameSite::Strict))
        .build()
}
```

### Cookies lus par JavaScript

Une préférence de thème ou le cookie `XSRF-TOKEN` d'un framework doivent rester lisibles par les scripts ; tous les autres cookies conservent `HttpOnly` :

```rust
use securite::prelude::*;

pub fn cookies() -> CookieHardening {
    CookieHardening::new().readable_by_js(["theme", "XSRF-TOKEN"])
}
```

### Développement local en HTTP simple

```rust
use securite::prelude::*;

pub fn cookies(dev: bool) -> CookieHardening {
    let cookies = CookieHardening::new();
    if dev { cookies.insecure_dev() } else { cookies }
}
```

### Tester vos cookies

```rust
use securite::prelude::*;

#[test]
fn session_cookie_is_hardened() {
    let hardening = CookieHardening::new();
    assert_eq!(
        hardening.harden("sid=abc; Path=/"),
        "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
    );
}
```

## Utilisation comme couche autonome

Le guard ne voit que les en-têtes `Set-Cookie` présents au moment où la réponse le traverse. Avec axum, le dernier appel à `.layer()` est le plus externe : ajoutez-le donc après les couches qui posent des cookies.

```rust
use axum::{Router, routing::post};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/login", post(|| async { ([("set-cookie", "sid=abc; Path=/")], "ok") }))
        // .layer(session_layer)       // sets the session cookie
        .layer(CookieHardening::new()) // outer layer: sees the final Set-Cookie headers
}
```

La même règle vaut pour un `Shield` : il doit envelopper votre middleware de sessions.

## Pièges et conseils

> **Attention :** `insecure_dev()` ne doit jamais atteindre la production. Faites-le dépendre de votre configuration, pas d'un indicateur codé en dur.

- **`SameSite=Strict` et liens entrants** : un utilisateur qui suit un lien depuis un e-mail ou un autre site arrive sans le cookie et semble déconnecté sur cette première page. `Lax` est le bon choix par défaut pour les cookies de session ; réservez `Strict` aux cookies sensibles.
- **SameSite ne suffit pas contre le CSRF** : il ne couvre pas les attaques venant de sous-domaines voisins, considérés comme « same-site », et `Lax` autorise toujours les navigations `GET` de premier niveau. Gardez le guard [CSRF](/docs/csrf) actif.
- **Préfixe `__Host-`** : les navigateurs exigent aussi `Path=/` et l'absence d'attribut `Domain`. Le guard ajoute `Secure` mais ne peut pas deviner le reste ; définissez-les dans votre code.
- **Développement local** : les navigateurs basés sur Chromium et Firefox acceptent les cookies `Secure` sur `http://localhost`. `insecure_dev()` sert surtout lorsque vous testez en HTTP simple sur une adresse du réseau local ou un nom d'hôte personnalisé.
- **Périmètre** : les cookies écrits par JavaScript (`document.cookie`) ou ajoutés par un reverse proxy ne passent jamais par le guard.
- `HttpOnly` empêche le vol du cookie, pas la XSS elle-même ; associez-le à une [CSP](/docs/security-headers) stricte.

> **Astuce :** `readable_by_js` compare les noms de cookies de façon exacte et sensible à la casse, comme les navigateurs.

## Pages associées

- [Protection CSRF](/docs/csrf)
- [En-têtes de sécurité](/docs/security-headers)
- [Redirection HTTPS](/docs/https-redirect)
- [CORS](/docs/cors)
