---
title: Démarrage rapide
summary: Protégez une application Vitesse avec Shield::recommended(), observez les en-têtes ajoutés, voyez-le bloquer une injection SQL, puis adaptez le préréglage.
category: start
order: 3
---

En cinq minutes, vous allez placer une application Vitesse derrière le shield recommandé, constater ce qui change dans les échanges HTTP et ajuster le préréglage à vos besoins.

## Créer le projet

```bash
cargo new secure-app
cd secure-app
cargo add securite vitesse
```

## Ajouter le shield

Remplacez le contenu de `src/main.rs` par :

```rust
use securite::prelude::*;
use vitesse::prelude::*;

fn main() -> std::io::Result<()> {
    let mut app = App::new();
    // Security headers, WAF, rate limiting, CSRF, request ids …
    app.middleware(Shield::recommended());
    app.get("/", |_req: Request| async { "Hello, secure world!" });

    println!("listening on http://127.0.0.1:3000");
    app.run("127.0.0.1:3000")
}
```

Deux détails comptent. Les middlewares globaux s'exécutent avant le routage, pour chaque requête, dans l'ordre où ils ont été ajoutés : le shield vient en premier pour tout voir. L'adresse de chaque connexion parvient d'elle-même au shield, indispensable aux guards qui travaillent par IP (voir [Installation](/docs/installation)).

## Lancer l'application

```bash
cargo run
```

## Une requête normale

```bash
curl -i http://127.0.0.1:3000/
```

```text
HTTP/1.1 200 OK
content-type: text/plain; charset=utf-8
content-length: 20
x-request-id: 3f6c2a1e-8b4d-4e7a-9c15-2d0f6b8a7e43
ratelimit-limit: 100
ratelimit-remaining: 99
ratelimit-reset: 1
strict-transport-security: max-age=63072000; includeSubDomains
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: accelerometer=(), autoplay=(), camera=(), …
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
origin-agent-cluster: ?1
x-dns-prefetch-control: off
x-download-options: noopen
x-permitted-cross-domain-policies: none
x-xss-protection: 0
content-security-policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests

Hello, secure world!
```

Votre handler n'a pas changé, et pourtant la réponse est désormais durcie :

| En-tête | Ajouté par | Protection |
|---|---|---|
| `x-request-id` | `request_id` | Relie la réponse aux logs et aux événements de sécurité |
| `ratelimit-*` | `rate_limit` | Indique au client son quota restant (20 req/s, rafale de 100) |
| `content-security-policy` | `security_headers` | Bloque les scripts injectés, les plugins et l'intégration dans un cadre (XSS, clickjacking) |
| `strict-transport-security` | `security_headers` | Impose HTTPS pendant deux ans, sous-domaines compris |
| `cross-origin-*` | `security_headers` | Isole votre origine des documents provenant d'autres origines |

Les en-têtes qui trahissent votre pile technique, comme `Server` ou `X-Powered-By`, sont supprimés.

## Une attaque bloquée

Envoyez maintenant une injection SQL classique dans la chaîne de requête :

```bash
curl -i "http://127.0.0.1:3000/?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"
```

```text
HTTP/1.1 403 Forbidden
content-type: application/problem+json
cache-control: no-store
x-request-id: 9a1d4c7b-2e3f-4a5b-8c6d-0e1f2a3b4c5d
ratelimit-limit: 100
ratelimit-remaining: 99
ratelimit-reset: 1
x-content-type-options: nosniff
x-frame-options: DENY
…
```

Le corps suit la RFC 9457 (mis en forme ici pour plus de lisibilité) :

```json
{
  "type": "about:blank",
  "title": "Forbidden",
  "status": 403,
  "code": "waf_blocked",
  "detail": "Request blocked by the web application firewall.",
  "request_id": "9a1d4c7b-2e3f-4a5b-8c6d-0e1f2a3b4c5d"
}
```

Le handler ne s'est jamais exécuté. Le client reçoit un `code` stable et le `request_id`, mais rien sur les règles déclenchées : ces détails ne partent que dans vos logs. Les rejets sont marqués `no-store` et reçoivent malgré tout l'ensemble des en-têtes de sécurité.

### Le voir dans les logs

Les requêtes bloquées sont écrites avec `tracing` sous la cible `securite`. Ajoutez un subscriber (`cargo add tracing-subscriber`) et appelez `tracing_subscriber::fmt::init();` au début de `main` :

```text
WARN securite: request blocked guard="waf" code="waf_blocked" status=403 ip=Some(127.0.0.1) method=GET path="/" request_id="9a1d4c7b-2e3f-4a5b-8c6d-0e1f2a3b4c5d" details="score=… rules=[…] categories=sqli"
```

## Personnaliser le préréglage

`ShieldBuilder::recommended()` renvoie le même préréglage sous forme de builder. `.guard()` ajoute un guard, ou remplace celui qui porte le même nom ; `.without()` en retire un :

```rust
use std::time::Duration;

use securite::prelude::*;
use vitesse::prelude::*;

let shield = ShieldBuilder::recommended()
    // Same name as the preset's limiter ("rate_limit"): it replaces it.
    .guard(
        RateLimit::new(Quota::per_second(20).burst(100))
            .route_methods("/login", [Method::POST], Quota::per_minute(5))
            .skip_paths(["/health"]),
    )
    // Not in the preset: it is added.
    .guard(AutoBan::new().max_strikes(10).ban_for(Duration::from_secs(600)))
    // Token-authenticated API without cookies: CSRF protection is not needed.
    .without("csrf")
    .build();

println!("{:?}", shield.guard_names());
// ["request_id", "ban", "hygiene", "method", "body_limit", "rate_limit",
// "bot_blocker", "waf", "security_headers", "cookies"]

let mut app = App::new();
app.middleware(shield);
app.get("/", |_req: Request| async { "Hello, secure world!" });
app.get("/health", |_req: Request| async { "ok" });
```

> **Attention :** Ne retirez `csrf` que si aucun endpoint modifiant l'état ne s'appuie sur des cookies ou d'autres identifiants transmis automatiquement. Les navigateurs joignent les cookies aux requêtes intersites ; c'est la protection CSRF qui empêche un autre site de s'en servir.

> **Astuce :** `CookieHardening` ajoute `Secure` à chaque cookie. Les navigateurs acceptent les cookies sécurisés sur `http://localhost` ; sur un autre hôte de développement en HTTP simple, utilisez `CookieHardening::new().insecure_dev()`, et jamais en production.

## Pour aller plus loin

- [Shield et préréglages](/docs/shield-presets) : le contenu de chaque préréglage et l'ordre d'exécution des guards.
- [IP du client](/docs/client-ip) : lecture indispensable avant tout déploiement derrière un proxy.
- [Mode observation](/docs/monitor-mode) : déployer le WAF ou une CSP plus stricte sans casser la production.
