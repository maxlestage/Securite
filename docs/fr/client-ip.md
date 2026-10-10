---
title: IP du client
summary: Comment le shield retrouve la véritable adresse du client derrière proxys et CDN, pourquoi il lit X-Forwarded-For par la droite, et comment utiliser cette adresse dans vos handlers.
category: start
order: 5
---

La limitation de débit, les limites de concurrence, le bannissement automatique, le filtrage IP et la piste d'audit reposent tous sur l'identité du client. Une erreur coûte cher dans les deux sens : faites confiance au mauvais en-tête et un attaquant choisit sa propre IP pour échapper aux bannissements ; ignorez le proxy et tous vos visiteurs partagent son adresse, donc sa limite de débit.

## Sources

Le shield résout l'adresse une fois par requête, selon la `ClientIpSource` définie avec `ShieldBuilder::client_ip` :

| Variante | Lit | À utiliser quand |
|---|---|---|
| `Peer` (par défaut) | L'adresse du pair TCP | L'application est exposée directement, sans proxy |
| `XForwardedFor { trusted_hops }` | L'entrée la plus à droite de `X-Forwarded-For`, en sautant `trusted_hops` proxys supplémentaires | Vos proxys complètent `X-Forwarded-For` |
| `Forwarded { trusted_hops }` | Le `for=` le plus à droite de l'en-tête `Forwarded` (RFC 7239) | Vos proxys émettent l'en-tête standard |
| `Header(name)` | Un en-tête contenant une seule IP, posé par votre frontal | CDN comme Cloudflare ou Akamai |

### Raccourcis

| Raccourci | Équivalent | Plateforme |
|---|---|---|
| `ClientIpSource::heroku()` | `XForwardedFor { trusted_hops: 0 }` | Heroku, Render, AWS ALB, un Nginx unique |
| `ClientIpSource::cloudflare()` | `Header("cf-connecting-ip")` | Cloudflare |
| `ClientIpSource::fly()` | `Header("fly-client-ip")` | Fly.io |
| `ClientIpSource::x_real_ip()` | `Header("x-real-ip")` | Nginx avec `proxy_set_header X-Real-IP $remote_addr;` |

```rust
use securite::prelude::*;

// Heroku router, or any single proxy appending to X-Forwarded-For.
let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::heroku())
    .build();

// A CDN and a load balancer, both appending to X-Forwarded-For.
let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::XForwardedFor { trusted_hops: 1 })
    .build();

// Akamai, or any edge that sets a single-IP header.
// (axum::http re-exports the http crate.)
let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::Header(
        axum::http::HeaderName::from_static("true-client-ip"),
    ))
    .build();
```

## Pourquoi l'entrée la plus à droite de X-Forwarded-For

Chaque proxy *ajoute* l'adresse depuis laquelle il a reçu la connexion. Tout ce qui se trouve à gauche figurait déjà dans la requête lorsqu'elle a atteint votre proxy, et peut donc avoir été écrit par le client. Supposons qu'un visiteur situé en `203.0.113.50` envoie un en-tête falsifié :

```text
X-Forwarded-For: 6.6.6.6                  ← sent by the client (forged)
X-Forwarded-For: 6.6.6.6, 203.0.113.50    ← after your proxy appended the peer
```

La valeur la plus à gauche, `6.6.6.6`, est contrôlée par l'attaquant ; la plus à droite, `203.0.113.50`, a été écrite par une infrastructure de confiance. `ClientIpSource::heroku()` résout donc `203.0.113.50`. Les bibliothèques qui retiennent la valeur la plus à gauche permettent à n'importe qui d'échapper aux bannissements et aux limites de débit avec un simple en-tête.

### trusted_hops

Dans une chaîne de plusieurs proxys, chacun ajoute une entrée. `trusted_hops` indique le nombre de proxys de confiance *supplémentaires* à sauter en partant de la droite :

| `X-Forwarded-For` | `trusted_hops` | Adresse résolue |
|---|---|---|
| `6.6.6.6, 1.2.3.4, 5.6.7.8` | `0` | `5.6.7.8` |
| `6.6.6.6, 1.2.3.4, 5.6.7.8` | `1` | `1.2.3.4` |
| `6.6.6.6, 1.2.3.4, 5.6.7.8` | `5` | Trop peu d'entrées : pair TCP |

Plusieurs lignes d'en-tête sont traitées comme une seule liste séparée par des virgules. Les entrées peuvent comporter un port (`1.2.3.4:5678`, `[2001:db8::1]:443`), et les adresses IPv6 mappées IPv4 comme `::ffff:1.2.3.4` sont ramenées à IPv4. `Forwarded` fonctionne de la même façon : à partir de `for=192.0.2.43, for="[2001:db8:cafe::17]:4711"`, `Forwarded { trusted_hops: 0 }` résout `2001:db8:cafe::17`.

## Risques d'usurpation

> **Attention :** Ne faites confiance à un en-tête de transfert que si votre application est joignable **exclusivement** à travers le proxy qui le pose. Si l'origine est aussi accessible directement (IP publique, URL `*.herokuapp.com` qui contourne votre CDN), un attaquant peut envoyer l'en-tête lui-même et choisir n'importe quelle adresse. Verrouillez l'origine avec un pare-feu, un réseau privé ou l'authentification d'origine proposée par votre CDN.

Les en-têtes à IP unique comme `CF-Connecting-IP` sont les plus exposés : leur valeur est reprise telle quelle, ils ne sont donc sûrs que si chaque requête passe par le frontal qui les écrase.

## Regroupement IPv6

Les FAI attribuent généralement à chaque abonné un `/64` IPv6 entier, soit 2^64 adresses. Compter chaque adresse séparément permettrait à un seul attaquant de faire défiler des milliards d'identités. Le limiteur de débit, la limite de concurrence et le bannissement automatique regroupent donc les clients IPv6 par `/64` ; les adresses IPv4 sont utilisées telles quelles. Le limiteur de débit permet de changer le préfixe :

```rust
use securite::prelude::*;

// Some ISPs delegate a /56 per customer.
let limiter = RateLimit::per_second(20).burst(100).ipv6_prefix(56);
```

La fonction `securite::ip::mask` applique le même regroupement dans votre propre code.

## Utiliser l'adresse dans les handlers

Le shield insère une extension `ClientIp` dans chaque requête dont il a résolu l'adresse. Elle contient l'adresse complète, et non le groupe `/64` :

```rust
use axum::{Extension, Router, routing::get};
use securite::prelude::*;

async fn whoami(ip: Option<Extension<ClientIp>>) -> String {
    match ip {
        Some(Extension(ClientIp(ip))) => format!("your address: {ip}"),
        None => "unknown address".to_owned(),
    }
}

let app: Router = Router::new()
    .route("/whoami", get(whoami))
    .layer(Shield::recommended());
```

Dans un [guard personnalisé](/docs/custom-guards), lisez-la avec `ctx.client_ip()`.

## Shields imbriqués et couches autonomes

Quand une requête porte déjà une extension `ClientIp`, posée par un shield extérieur, le shield réutilise cette adresse au lieu de la résoudre à nouveau. Les shields intérieurs et les couches autonomes s'accordent donc avec le plus externe. Pour utiliser des couches autonomes derrière un proxy, ajoutez en couche la plus externe un shield sans guard qui se contente de résoudre l'adresse :

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(RateLimit::per_minute(120))
    .layer(AutoBan::new())
    // Outermost (last `.layer()` call): resolves the client IP once,
    // and the layers added before it reuse its `ClientIp`.
    .layer(Shield::builder().client_ip(ClientIpSource::heroku()).build());
```

> **Attention :** seul compte le réglage `client_ip` du shield le plus externe. S'il conserve la source par défaut `Peer`, chaque shield intérieur réutilise l'adresse du proxy résolue par celui-ci, quel que soit son propre réglage : configurez la source sur le shield le plus externe.

## Solutions de repli

Quand l'en-tête configuré est absent, mal formé ou contient trop peu d'entrées, le shield se rabat sur l'adresse du pair TCP. Celle-ci est cherchée, dans l'ordre, dans `ConnectInfo<SocketAddr>` d'axum (avec la feature `axum`), dans une extension `PeerAddr` et dans une extension `SocketAddr` brute.

Quand aucune adresse n'est trouvée, le shield journalise une seule fois un avertissement (cible `securite`) recommandant `into_make_service_with_connect_info::<SocketAddr>()` avec axum ou une extension `PeerAddr` avec hyper, et les guards se dégradent ainsi :

| Guard | Comportement sans IP client |
|---|---|
| `RateLimit` (par IP) | Toutes ces requêtes partagent un seul seau global |
| `AutoBan`, `ConcurrencyLimit` | Ignorés |
| `IpFilter` | Refus si une liste d'autorisation est configurée, accès accordé sinon |
| Événements de sécurité | `client_ip` vaut `None` |

> **Astuce :** Ajoutez le handler `whoami` ci-dessus pendant le déploiement et appelez-le à travers votre véritable infrastructure. S'il affiche l'adresse d'un proxy ou `unknown address`, corrigez la source avant la mise en production.
