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
// (securite::http réexporte la crate http.)
let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::Header(
        securite::http::HeaderName::from_static("true-client-ip"),
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

### Proxies de confiance

Quand l'origine ne peut pas être complètement verrouillée, indiquez au shield les réseaux où vivent vos proxies. Un en-tête de transfert n'est alors cru que si le pair TCP appartient à l'un d'eux, comme le `trust proxy` d'Express, le `TrustProxies` de Laravel ou les recommandations de Django sur `X-Forwarded-For` :

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::XForwardedFor { trusted_hops: 0 })
    // Votre répartiteur de charge, votre ingress ou les plages de votre CDN.
    .trusted_proxies(["10.0.0.0/8", "fd00::/8"])
    .build();
```

Avec un ensemble de confiance :

- une requête venant d'une adresse **hors** de l'ensemble est résolue en son pair TCP, quels que soient ses en-têtes : un client qui atteint l'origine directement ne peut pas usurper son adresse ;
- `X-Forwarded-For` et `Forwarded` sont lus depuis la droite **en sautant chaque proxy de confiance**, et la première adresse non fiable est le client (`trusted_hops` est alors ignoré : l'ensemble décrit la chaîne). Si tous les sauts sont de confiance, le plus à gauche est retenu ; une entrée illisible arrête le parcours au dernier saut de confiance ;
- un en-tête à IP unique (`CF-Connecting-IP`, `X-Real-IP` …) n'est utilisé que si le pair est de confiance ;
- sans adresse de pair connue, aucun en-tête n'est cru.

| Pair | `X-Forwarded-For` | Confiance | Résultat |
|---|---|---|---|
| `10.0.0.1` | `6.6.6.6, 203.0.113.9, 10.1.2.3` | `10.0.0.0/8` | `203.0.113.9` |
| `198.51.100.7` | `1.2.3.4` | `10.0.0.0/8` | `198.51.100.7` (en-tête ignoré) |
| `10.0.0.1` | `10.1.1.1, 10.2.2.2` | `10.0.0.0/8` | `10.1.1.1` |

`try_trusted_proxies` renvoie une erreur au lieu de paniquer, pour des réseaux lus dans la configuration, et `ClientIpSource::resolve_trusted` expose la même logique à votre propre code.

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
use securite::prelude::*;
use vitesse::prelude::*;

async fn whoami(req: Request) -> String {
    match req.get::<ClientIp>() {
        Some(ClientIp(ip)) => format!("your address: {ip}"),
        None => "unknown address".to_owned(),
    }
}

let mut app = App::new();
app.middleware(Shield::recommended());
app.get("/whoami", whoami);
```

Dans un [guard personnalisé](/docs/custom-guards), lisez-la avec `ctx.client_ip()`.

## Shields imbriqués et guards autonomes

Quand une requête porte déjà une extension `ClientIp`, posée par un shield extérieur, le shield réutilise cette adresse au lieu de la résoudre à nouveau. Les shields intérieurs et les guards autonomes s'accordent donc avec le plus externe. Pour utiliser des guards autonomes derrière un proxy, ajoutez en premier middleware un shield sans guard qui se contente de résoudre l'adresse :

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
// Le plus externe (premier middleware ajouté) : il détermine l'IP du client une fois,
// et les middlewares ajoutés après lui réutilisent son `ClientIp`.
app.middleware(Shield::builder().client_ip(ClientIpSource::heroku()).build());
app.middleware(Shield::from(AutoBan::new()));
app.middleware(Shield::from(RateLimit::per_minute(120)));
app.get("/", |_req: Request| async { "hello" });
```

> **Attention :** seul compte le réglage `client_ip` du shield le plus externe. S'il conserve la source par défaut `Peer`, chaque shield intérieur réutilise l'adresse du proxy résolue par celui-ci, quel que soit son propre réglage : configurez la source sur le shield le plus externe.

## Solutions de repli

Quand l'en-tête configuré est absent, mal formé ou contient trop peu d'entrées, le shield se rabat sur l'adresse du pair TCP. Celle-ci est l'adresse de la connexion, que Vitesse fournit au shield ; dans un service tower, elle est cherchée dans une extension `PeerAddr`, puis dans une extension `SocketAddr` brute.

Quand aucune adresse n'est trouvée (un service tower sans `PeerAddr`), le shield journalise une seule fois un avertissement (cible `securite`) recommandant une extension `PeerAddr`, et les guards se dégradent ainsi :

| Guard | Comportement sans IP client |
|---|---|
| `RateLimit` (par IP) | Toutes ces requêtes partagent un seul seau global |
| `AutoBan`, `ConcurrencyLimit` | Ignorés |
| `IpFilter` | Refus si une liste d'autorisation est configurée, accès accordé sinon |
| Événements de sécurité | `client_ip` vaut `None` |

> **Astuce :** Ajoutez le handler `whoami` ci-dessus pendant le déploiement et appelez-le à travers votre véritable infrastructure. S'il affiche l'adresse d'un proxy ou `unknown address`, corrigez la source avant la mise en production.
