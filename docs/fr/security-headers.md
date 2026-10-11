---
title: En-têtes de sécurité
summary: Les en-têtes de réponse à la Helmet, avec une Content-Security-Policy stricte (nonces ou empreintes), HSTS, l'isolation cross-origin et la suppression des empreintes serveur.
category: browser
order: 1
---

`SecurityHeaders` ajoute à chaque réponse les en-têtes recommandés par l'[OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/), y compris aux réponses d'erreur produites par les autres guards. Il fournit aussi un builder typé pour la `Content-Security-Policy`, avec des nonces par requête et des empreintes pour les scripts inline. Tous les presets de `Shield` l'incluent.

## La menace

Un navigateur fait tout ce que vos réponses lui permettent. Sans consigne explicite, il exécute les scripts injectés, laisse d'autres sites encadrer vos pages, devine les types de contenu et se rabat sur le HTTP en clair. Ces en-têtes ferment ces portes :

- **Cross-site scripting** (OWASP Top 10 2021 A03 Injection) : une CSP stricte empêche l'exécution des scripts injectés, même lorsqu'un défaut d'échappement passe entre les mailles.
- **Clickjacking** : `frame-ancestors 'none'` et `X-Frame-Options: DENY` interdisent l'intégration dans une frame.
- **Détection du type MIME** : `X-Content-Type-Options: nosniff`.
- **Rétrogradation de protocole et SSL stripping** (A02 Cryptographic Failures) : `Strict-Transport-Security`.
- **Fuites cross-origin et canaux auxiliaires de type Spectre** : COOP, CORP et, en option, COEP isolent votre origine.
- **Prise d'empreinte** : `Server`, `X-Powered-By` et les en-têtes similaires sont supprimés.

L'absence de ces en-têtes est l'une des constatations les plus fréquentes de la catégorie A05 Security Misconfiguration.

## Fonctionnement

Le guard a la priorité 900 : il s'exécute après les guards bloquants. À l'aller, il n'intervient que si les nonces sont activés : il tire 128 bits du générateur aléatoire cryptographique du système, les encode en base64url et les dépose dans l'extension de requête `CspNonce`. Au retour, il :

1. supprime `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version` et `X-Runtime` ;
2. ajoute chaque en-tête configuré **uniquement si le handler ne l'a pas déjà défini** (sauf avec `overwrite(true)`) ;
3. écrit la CSP en y substituant le nonce. Si un guard exécuté plus tôt a rejeté la requête, aucun nonce n'a été tiré : la politique est alors envoyée complète, sans la source de nonce, jamais tronquée.

La politique est générée et validée une seule fois, à la construction du guard : une valeur invalide provoque une panique au démarrage, jamais pendant une requête.

## Démarrage rapide

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "Hello" }))
        .layer(Shield::builder().guard(SecurityHeaders::new()).build())
}
```

Ajouter un guard portant le même nom remplace l'existant : durcir un preset tient donc en une ligne.

```rust
use securite::prelude::*;

pub fn shield() -> Shield {
    ShieldBuilder::recommended()
        .guard(SecurityHeaders::strict()) // replaces the preset's SecurityHeaders::new()
        .build()
}
```

## En-têtes par défaut

| En-tête | `new()` | `strict()` | `api()` |
|---|---|---|---|
| `Content-Security-Policy` | `ContentSecurityPolicy::strict()` | identique | `ContentSecurityPolicy::api()` |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | identique | identique |
| `X-Content-Type-Options` | `nosniff` | identique | identique |
| `X-Frame-Options` | `DENY` | identique | identique |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | `no-referrer` | `no-referrer` |
| `Permissions-Policy` | désactive 15 fonctionnalités (voir ci-dessous) | identique | identique |
| `Cross-Origin-Opener-Policy` | `same-origin` | identique | identique |
| `Cross-Origin-Resource-Policy` | `same-origin` | identique | identique |
| `Cross-Origin-Embedder-Policy` | non envoyé | `require-corp` | non envoyé |
| `Origin-Agent-Cluster` | `?1` | identique | identique |
| `X-DNS-Prefetch-Control` | `off` | identique | identique |
| `X-Download-Options` | `noopen` | identique | identique |
| `X-Permitted-Cross-Domain-Policies` | `none` | identique | identique |
| `X-XSS-Protection` | `0` (l'ancien filtre XSS est nuisible) | identique | identique |
| `Cache-Control` | non envoyé | non envoyé | `no-store` |

La `Permissions-Policy` par défaut attribue une liste vide à `accelerometer`, `autoplay`, `camera`, `display-capture`, `encrypted-media`, `geolocation`, `gyroscope`, `magnetometer`, `microphone`, `midi`, `payment`, `picture-in-picture`, `screen-wake-lock`, `usb` et `xr-spatial-tracking`. `publickey-credentials-get` n'est pas restreint : les passkeys (connexion WebAuthn) fonctionnent par défaut.

`ContentSecurityPolicy::strict()` produit `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests`. `ContentSecurityPolicy::api()` produit `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`.

## Configuration

### SecurityHeaders

| Méthode | Défaut | Description |
|---|---|---|
| `new()` / `strict()` / `api()` | — | Presets décrits ci-dessus. |
| `csp(policy)` / `content_security_policy(policy)` | `ContentSecurityPolicy::strict()` | Définit la CSP. Accepte une politique ou une `Option`. |
| `hsts(Option<Hsts>)` | `Hsts::default()` | Configure HSTS ; `None` le retire. |
| `frame_options(&str)` | `DENY` | `X-Frame-Options` (`DENY` ou `SAMEORIGIN`). |
| `referrer_policy(&str)` | `strict-origin-when-cross-origin` | `Referrer-Policy`. |
| `permissions_policy(&str)` | voir ci-dessus | `Permissions-Policy`. |
| `cross_origin_opener_policy(&str)` | `same-origin` | COOP. |
| `cross_origin_resource_policy(&str)` | `same-origin` | CORP (`same-origin`, `same-site`, `cross-origin`). |
| `cross_origin_embedder_policy(&str)` | non envoyé | COEP (`require-corp`, `credentialless`). |
| `cache_control(&str)` | non envoyé | `Cache-Control`. |
| `set(name, value)` | — | Définit ou remplace n'importe quel en-tête. Panique si le nom ou la valeur est invalide. |
| `unset(name)` | — | Retire un en-tête configuré ; `unset("content-security-policy")` désactive la CSP. |
| `overwrite(bool)` | `false` | Avec `true`, remplace les en-têtes déjà définis par les handlers. |
| `keep_fingerprinting_headers()` | en-têtes supprimés | Conserve `Server`, `X-Powered-By` et consorts. |
| `policy()` | — | Renvoie la CSP configurée, s'il y en a une. |

### ContentSecurityPolicy

| Méthode | Défaut | Description |
|---|---|---|
| `new()` | vide | Politique vide. |
| `strict()` / `api()` | — | Presets décrits ci-dessus. |
| `default_src`, `script_src`, `script_src_elem`, `script_src_attr`, `style_src`, `style_src_elem`, `style_src_attr`, `img_src`, `font_src`, `connect_src`, `media_src`, `object_src`, `frame_src`, `child_src`, `worker_src`, `manifest_src`, `frame_ancestors`, `base_uri`, `form_action`, `sandbox`, `report_to`, `report_uri` | selon le preset | Définissent (remplacent) la directive correspondante avec les sources fournies. |
| `directive(name, sources)` | — | Définit ou remplace n'importe quelle directive. |
| `add_sources(name, sources)` | — | Ajoute des sources à une directive, en la créant si besoin. Le nom est normalisé (espaces retirés, minuscules). |
| `remove_directive(name)` | — | Retire une directive, par exemple `upgrade-insecure-requests` pour le développement en HTTP simple. |
| `upgrade_insecure_requests()` | actif dans `strict()` | Ajoute `upgrade-insecure-requests`. |
| `require_trusted_types()` | inactif | Ajoute `require-trusted-types-for 'script'` (XSS côté DOM). |
| `with_nonce()` | inactif | Nonce neuf à chaque requête, ajouté à `script-src`, `script-src-elem` et `style-src`. En l'absence de `script-src`, en ajoute un composé des sources de `default-src` et du nonce. |
| `report_only()` | inactif | Envoie `Content-Security-Policy-Report-Only` à la place. |
| `hashes_for_inline_scripts(html)` | — | Renvoie les sources `'sha256-…'` de chaque `<script>` inline de `html`. |
| `hashes_for_inline_styles(html)` | — | Idem pour les éléments `<style>` inline. |

Les mots-clés de source se trouvent dans `securite::headers::src` : `SELF`, `NONE`, `UNSAFE_INLINE`, `UNSAFE_EVAL`, `WASM_UNSAFE_EVAL`, `STRICT_DYNAMIC`, `UNSAFE_HASHES`, `DATA`, `BLOB` et `HTTPS`. Les chaînes simples comme `"https://cdn.example.com"` fonctionnent aussi. Une source contenant `;`, `,` ou un caractère de contrôle provoque une panique, ce qui exclut toute injection d'en-tête. `policy.to_string()` affiche la valeur générée.

### Hsts

`securite::headers::Hsts` est une simple structure aux champs publics : `max_age` (deux ans par défaut), `include_subdomains` (`true` par défaut) et `preload` (`false` par défaut). Aucun preset n'active `preload`, pas même `strict()` ; activez-le explicitement :

```rust
use securite::headers::Hsts;
use securite::prelude::*;

pub fn headers() -> SecurityHeaders {
    // Only once the domain and every sub-domain are HTTPS only.
    SecurityHeaders::strict().hsts(Some(Hsts { preload: true, ..Hsts::default() }))
}
```

## Exemples

### Nonces dans des pages rendues côté serveur

```rust
use axum::{Extension, Router, response::Html, routing::get};
use securite::prelude::*;

async fn index(Extension(CspNonce(nonce)): Extension<CspNonce>) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<script nonce="{nonce}">console.log("runs: it carries the nonce");</script>
<script>console.log("blocked: no nonce");</script>"#
    ))
}

pub fn app() -> Router {
    let headers = SecurityHeaders::new().csp(ContentSecurityPolicy::strict().with_nonce());
    Router::new()
        .route("/", get(index))
        .layer(Shield::builder().guard(headers).build())
}
```

### Empreintes pour les applications monopage

Vite et les bundlers similaires injectent un script d'amorçage inline dans `index.html`, et les front-ends Rust rendus par le serveur en écrivent un pour démarrer leur bundle WebAssembly (ce site, construit avec [active](https://maxlestage.github.io/Active/), autorise ainsi son chargeur et l'enregistrement de son service worker). Calculez son empreinte au démarrage et gardez un `script-src` strict :

```rust
use axum::{Router, response::Html, routing::get};
use securite::headers::src;
use securite::prelude::*;

pub fn spa(index_html: String) -> Router {
    let csp = ContentSecurityPolicy::strict()
        .add_sources("script-src", ContentSecurityPolicy::hashes_for_inline_scripts(&index_html))
        .add_sources("script-src", [src::WASM_UNSAFE_EVAL]); // Rust/WASM front-ends
    Router::new()
        .route("/", get(move || async move { Html(index_html) }))
        .layer(SecurityHeaders::new().csp(csp))
}
```

### Une politique strict-dynamic

C'est la politique à base de nonce que recommandent les bonnes pratiques actuelles. Les navigateurs qui comprennent les nonces ignorent `https:` et `'unsafe-inline'`, qui ne servent que de solution de repli pour les anciens navigateurs :

```rust
use securite::headers::src;
use securite::prelude::*;

pub fn policy() -> ContentSecurityPolicy {
    ContentSecurityPolicy::new()
        .script_src([src::STRICT_DYNAMIC, src::HTTPS, src::UNSAFE_INLINE])
        .object_src([src::NONE])
        .base_uri([src::NONE])
        .frame_ancestors([src::NONE])
        .with_nonce()
}
```

### Déploiement en mode report-only et Trusted Types

```rust
use securite::prelude::*;

pub fn rollout() -> SecurityHeaders {
    SecurityHeaders::new()
        .csp(
            ContentSecurityPolicy::strict()
                .require_trusted_types()
                .report_to(["csp"])
                .report_only(),
        )
        .set("reporting-endpoints", r#"csp="https://example.com/csp-reports""#)
}
```

Collectez les violations pendant quelques jours, corrigez-les, puis retirez `report_only()`.

### Assouplir un en-tête sur une seule route

Par défaut, les en-têtes définis par un handler l'emportent ; une route peut donc faire exception :

```rust
use axum::response::{Html, IntoResponse};

// This widget may be framed by a partner site; CSP frame-ancestors overrides X-Frame-Options.
pub async fn widget() -> impl IntoResponse {
    (
        [("content-security-policy", "default-src 'self'; frame-ancestors https://partner.example.com")],
        Html("<p>Embeddable widget</p>"),
    )
}
```

### HSTS sur mesure et développement local

```rust
use std::time::Duration;

use securite::headers::Hsts;
use securite::prelude::*;

pub fn headers(dev: bool) -> SecurityHeaders {
    if dev {
        // Plain-HTTP local development: no HSTS, no upgrade-insecure-requests.
        return SecurityHeaders::new()
            .hsts(None)
            .csp(ContentSecurityPolicy::strict().remove_directive("upgrade-insecure-requests"));
    }
    SecurityHeaders::new().hsts(Some(Hsts {
        max_age: Duration::from_secs(31_536_000), // one year
        include_subdomains: true,
        preload: false,
    }))
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
}
```

## Pièges et conseils

> **Attention :** `preload` est difficile à annuler. Dès qu'un domaine sert cette directive, il peut être soumis à la liste de préchargement HSTS des navigateurs, et tous ses sous-domaines deviennent alors accessibles uniquement en HTTPS pendant des mois. Aucun preset ne l'envoie : ne l'activez qu'en connaissance de cause, comme indiqué dans la section Hsts ci-dessus.

- **Médias et paiements** : la `Permissions-Policy` par défaut désactive aussi pour vos propres pages `encrypted-media`, `autoplay` et `payment` ; les passkeys (`publickey-credentials-get`) ne sont pas restreintes. Remplacez-la, par exemple avec `permissions_policy("camera=(), microphone=(), geolocation=(), payment=(self)")`.
- **Frames** : pour autoriser l'intégration par vos propres pages, modifiez les deux en-têtes : `.frame_options("SAMEORIGIN")` et `frame_ancestors([src::SELF])` dans la CSP.
- **Ressources publiques** : CORP `same-origin` empêche les autres sites d'intégrer vos images ou vos polices. Un hôte de ressources publiques a besoin de `cross_origin_resource_policy("cross-origin")`.
- **COEP** : `require-corp`, présent dans `strict()`, bloque les ressources cross-origin qui ne l'acceptent pas via CORP ou CORS. `credentialless` est une alternative plus souple.
- **Nonces** : `with_nonce()` ajoute aussi le nonce à `style-src`, où `'unsafe-inline'` est alors ignoré. Les attributs `style="…"` inline nécessitent `style_src_attr([src::UNSAFE_INLINE])`. Si la politique n'a pas de `script-src`, `with_nonce()` en ajoute un composé des sources de `default-src` et du nonce (`script-src 'self' 'nonce-…'` après `default-src 'self'`) : les fichiers de script de la même origine continuent donc de se charger.
- **Cache** : ne laissez jamais un cache partagé stocker une page HTML portant un nonce. Le HTML statique doit plutôt utiliser des empreintes.
- **Extension absente** : extraire `Extension<CspNonce>` sans `with_nonce()` fait répondre 500 par axum.
- **HTTP en clair** : `upgrade-insecure-requests` casse les sous-ressources d'un site servi en HTTP simple, par exemple sur une adresse du réseau local. Retirez-la dans ce cas avec `ContentSecurityPolicy::strict().remove_directive("upgrade-insecure-requests")`, comme dans l'exemple de développement local ci-dessus.
- **Écrasement** : par défaut, les en-têtes des handlers l'emportent. Utilisez `.overwrite(true)` si aucune route ne doit pouvoir affaiblir la politique.
- **Proxys** : les en-têtes d'empreinte ne sont retirés que des réponses qui traversent la couche ; un reverse proxy peut ajouter son propre en-tête `Server`.

> **Astuce :** déployez toujours une modification de CSP d'abord avec `report_only()`, puis appliquez-la.

## Pages associées

- [CORS](/docs/cors)
- [Durcissement des cookies](/docs/cookies)
- [Redirection HTTPS](/docs/https-redirect)
- [Protection CSRF](/docs/csrf)
- [Shield et presets](/docs/shield-presets)
