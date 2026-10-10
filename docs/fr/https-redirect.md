---
title: Redirection HTTPS
summary: Redirige les requêtes HTTP en clair vers HTTPS avec un code 308, en tenant compte des proxys qui terminent TLS comme Heroku, Render, AWS ALB ou Cloudflare.
category: browser
order: 4
---

`HttpsRedirect` renvoie chaque requête HTTP en clair vers son équivalent `https://` avec un `308 Permanent Redirect`. Il lit le schéma d'origine dans l'URI de la requête ou dans les en-têtes posés par votre proxy de terminaison TLS, et ne touche pas au développement local.

## La menace

En HTTP simple, quiconque se trouve sur le chemin réseau (Wi-Fi public, routeur compromis, fournisseur d'accès) peut lire et modifier le trafic : identifiants, cookies de session, pages et téléchargements. Un attaquant actif peut aussi maintenir sa victime en HTTP indéfiniment (« SSL stripping »). C'est la catégorie A02 Cryptographic Failures de l'OWASP Top 10 2021 ; les cheat sheets OWASP Transport Layer Security et HTTP Strict Transport Security, ainsi que le test WSTG-CONF-07, traitent le sujet.

Une redirection seule ne suffit pas, puisque la première requête part toujours en clair. Le dispositif robuste est le suivant :

1. `HttpsRedirect` fait passer en HTTPS les visiteurs arrivés en HTTP ;
2. [HSTS](/docs/security-headers), envoyé sur les réponses HTTPS, impose au navigateur d'utiliser directement HTTPS lors des visites suivantes ;
3. en option, le préchargement HSTS supprime jusqu'à la toute première requête HTTP.

## Fonctionnement

Le guard s'exécute à la priorité 75, après le bannissement, le filtrage IP, l'hygiène et le filtrage des méthodes, et juste après `HostFilter` (70) : lorsque les deux figurent dans le même shield, la redirection n'est construite qu'à partir d'un hôte validé. Il passe toujours avant la limitation de débit et le WAF. Il détermine le schéma dans cet ordre :

1. le schéma de l'URI de la requête, si celle-ci utilise une URI absolue ;
2. si `trust_forwarded_proto` est activé (par défaut), la valeur la plus à droite de `X-Forwarded-Proto`, celle qu'a écrite le proxy le plus proche, selon le même modèle de confiance que `ClientIpSource::XForwardedFor` ;
3. sinon, le paramètre `proto=` de l'en-tête standard `Forwarded` ;
4. si aucune de ces informations n'est disponible, le schéma est inconnu et **rien ne se passe**, ce qui préserve le développement local.

Si la requête est en HTTP simple et que son chemin n'est pas exempté, le shield répond `308 Permanent Redirect` avec `Location: https://<hôte><chemin>?<requête>`. L'hôte provient de l'URI ou de l'en-tête `Host`, sans son port. Contrairement à `301` et `302`, un `308` conserve la méthode et le corps. La redirection est un court-circuit bénin : corps vide, non journalisée comme une attaque, non comptée comme un blocage. Un hôte absent ou malformé donne `400 Bad Request` avec le code `https_required`.

`/.well-known/acme-challenge/` est exempté par défaut, afin que la validation HTTP-01 de Let's Encrypt continue de fonctionner.

## Démarrage rapide

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    let shield = Shield::builder()
        .guard(HttpsRedirect::new())
        .guard(SecurityHeaders::new()) // HSTS for the following visits
        .build();

    Router::new()
        .route("/", get(|| async { "secure" }))
        .layer(shield)
}
```

`Shield::strict()` inclut déjà `HttpsRedirect::new()`. Le guard s'appelle `https_redirect`.

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `HttpsRedirect::new()` | fait confiance aux en-têtes du proxy, exempte ACME | Configuration recommandée. |
| `trust_forwarded_proto(bool)` | `true` | Lit `X-Forwarded-Proto` (valeur la plus à droite) et `Forwarded`. Avec `false`, seule une URI de requête absolue peut révéler le schéma. |
| `exempt(prefix)` | `/.well-known/acme-challenge/` | Ajoute un préfixe de chemin jamais redirigé. Peut être appelée plusieurs fois. |

Les préfixes respectent les limites de segment : `/health` couvre `/health` et `/health/live`, mais pas `/healthz`. La barre oblique initiale est ajoutée si elle manque.

## Exemples

### Derrière un PaaS ou un répartiteur de charge

Heroku, Render, Fly.io, AWS ALB et Cloudflare terminent TLS et positionnent `X-Forwarded-Proto`. Les sondes de santé passent souvent en HTTP simple : exemptez-les.

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    let shield = Shield::builder()
        .client_ip(ClientIpSource::heroku())
        .guard(HttpsRedirect::new().exempt("/health"))
        .guard(SecurityHeaders::new())
        .build();

    Router::new()
        .route("/", get(|| async { "secure" }))
        .route("/health", get(|| async { "ok" }))
        .layer(shield)
}
```

### Vérifier la redirection avec curl

```bash
curl -i http://127.0.0.1:3000/path?x=1 \
  -H "Host: example.com" \
  -H "X-Forwarded-Proto: http"
```

```text
HTTP/1.1 308 Permanent Redirect
location: https://example.com/path?x=1
```

### Terminer TLS dans votre propre processus

Si l'application sert elle-même HTTPS et n'écoute sur le port 80 que pour rediriger, les requêtes reçues sur ce port ne portent aucune information de schéma. Marquez-les comme HTTP simple avant le passage du shield, et ajoutez `HostFilter` au même shield pour que l'hôte soit validé avant la redirection :

```rust
use axum::{Router, extract::Request, http::{HeaderValue, StatusCode}, middleware::map_request};
use securite::prelude::*;

async fn mark_plain_http(mut req: Request) -> Request {
    req.headers_mut()
        .insert("x-forwarded-proto", HeaderValue::from_static("http"));
    req
}

// Served on port 80 only; the real application listens on 443.
pub fn port_80_app() -> Router {
    let shield = Shield::builder()
        .guard(HostFilter::new(["example.com", "www.example.com"])) // priority 70
        .guard(HttpsRedirect::new()) // priority 75: only sees allowed hosts
        .build();

    Router::new()
        .fallback(|| async { StatusCode::NOT_FOUND }) // reached by exempt paths only
        .layer(shield)
        .layer(map_request(mark_plain_http)) // outermost: runs first
}
```

## Utilisation comme couche autonome

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(HttpsRedirect::new())
}
```

## Pièges et conseils

> **Astuce :** la `Location` est construite à partir de l'en-tête `Host`, et un `308` peut être mis en cache. Ajoutez [HostFilter](/docs/host-filter) au même `Shield` : il s'exécute à la priorité 70, avant `HttpsRedirect` (75), si bien qu'un hôte falsifié est refusé avec `421` au lieu d'être redirigé. Avec des couches autonomes, placez `HostFilter` à l'extérieur de `HttpsRedirect`.

- **Pas de schéma, pas de redirection** : si ni l'URI ni un en-tête de proxy ne révèlent le schéma, le guard ne fait rien. Vérifiez-le en préproduction avec la commande curl ci-dessus.
- **Faites confiance au proxy, pas au client** : `X-Forwarded-Proto` n'est fiable que si votre proxy le renseigne. Le guard lit la valeur la plus à droite, écrite par le proxy le plus proche de votre application : une valeur placée à sa gauche par le client est ignorée. Avec `trust_forwarded_proto(false)`, un serveur sans proxy ne redirige que les requêtes à URI absolue.
- **Proxys en chaîne** : quand plusieurs proxys ajoutent chacun une valeur à `X-Forwarded-Proto`, la plus à droite ne décrit que le dernier saut. Si ce saut est en HTTP simple, toutes les requêtes sont redirigées : faites en sorte que le proxy le plus proche de votre application transmette le schéma du client au lieu d'ajouter le sien.
- **Ports** : la redirection vise toujours le port HTTPS par défaut, 443.
- **API** : un client qui suit la redirection a déjà envoyé son jeton en clair. Pour une API pure, mieux vaut ne pas écouter en HTTP du tout.
- **Sondes de santé** : un répartiteur de charge qui sonde en HTTP recevrait un `308` et déclarerait l'instance défaillante ; exemptez leur chemin.

> **Astuce :** combinez la redirection avec le HSTS de [SecurityHeaders](/docs/security-headers) et les cookies sécurisés de [CookieHardening](/docs/cookies) : ensemble, ils tiennent les sessions à l'écart du HTTP en clair.

## Pages associées

- [En-têtes de sécurité](/docs/security-headers)
- [Filtre d'hôtes](/docs/host-filter)
- [Durcissement des cookies](/docs/cookies)
- [IP du client](/docs/client-ip)
