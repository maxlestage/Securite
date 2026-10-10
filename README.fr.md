<div align="center">

# 🛡️ securite

**Des middlewares de sécurité natifs pour Rust : rapides, faciles et complets.**

[![CI](https://github.com/maxlestage/Securite/actions/workflows/ci.yml/badge.svg)](https://github.com/maxlestage/Securite/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/securite.svg)](https://crates.io/crates/securite)
[![docs.rs](https://img.shields.io/docsrs/securite)](https://docs.rs/securite)
![unsafe interdit](https://img.shields.io/badge/unsafe-interdit-success)

[English](README.md) · **Français** · [Español](README.es.md)

[![Déployer sur Heroku](https://www.herokucdn.com/deploy/button.svg)](https://www.heroku.com/deploy?template=https://github.com/maxlestage/Securite)

</div>

---

Ce dépôt contient :

| Dossier | Contenu |
|---|---|
| [`crates/securite`](crates/securite) | La **crate `securite`** (prête pour crates.io) : 19 middlewares de sécurité pour tower / axum / hyper / tonic |
| [`site`](site) | Le **site de présentation** : Yew + WebAssembly, animé, FR / EN / ES, documentation classée par catégories, playground d'attaques en direct |
| [`server`](server) | Le serveur axum qui héberge le site — protégé par `securite` lui-même |
| [`docs`](docs) | La **documentation** (32 pages × 3 langues), compilée dans le site |
| [`Dockerfile`](Dockerfile), [`heroku.yml`](heroku.yml), [`app.json`](app.json) | Image conteneur et **déploiement Heroku en un geste** |
| [`.github/workflows`](.github/workflows) | CI, **merge automatique sur master**, déploiement Heroku, publication crates.io |

## La crate en 10 secondes

```bash
cargo add securite
```

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app = Router::new()
    .route("/", get(|| async { "Bonjour, monde sécurisé !" }))
    .layer(Shield::recommended()); // en-têtes, WAF, rate limit, CSRF, request ids…
```

| Catégorie | Middlewares |
|---|---|
| Durcissement navigateur | `SecurityHeaders` (CSP avec nonces et hashes, HSTS, COOP/CORP/COEP…), `Cors`, `CookieHardening`, `HttpsRedirect` |
| Contrôle du trafic | `RateLimit` (GCRA), `ConcurrencyLimit`, `AutoBan`, `BodyLimit`, `Hygiene`, `MethodFilter` |
| Contrôle d'accès | `IpFilter`, `HostFilter`, `Auth`, `Csrf`, `ContentTypeGuard` |
| Détection des menaces | `Waf` (SQLi, XSS, RCE, Log4Shell, SSRF, NoSQLi, SSTI, scanners), `BotBlocker` |
| Intégrité & traçabilité | `RequestId`, `SignatureLayer` (webhooks GitHub / Stripe / Slack / Shopify), événements et statistiques |

≈ 6 µs pour tout le pipeline recommandé · `#![forbid(unsafe_code)]` · MSRV 1.85.
Lisez le [README de la crate](crates/securite/README.md) et la [documentation](docs/fr/introduction.md).

## Déployer depuis votre téléphone (sans ordinateur)

**Option A — en un geste.** Touchez le bouton *Deploy to Heroku* ci-dessus,
choisissez un nom d'application, touchez *Deploy app*. Heroku construit
l'image Docker à partir de `heroku.yml` (≈ 10–15 min la première fois) et
démarre le site.

**Option B — déploiement automatique à chaque merge.**

1. Heroku (navigateur mobile) → *Account settings* → *API Key* → *Reveal* → copier.
2. GitHub (navigateur mobile) → ce dépôt → *Settings* → *Secrets and
   variables* → *Actions* → ajouter `HEROKU_API_KEY` et `HEROKU_APP_NAME`.
3. C'est tout : chaque push fusionné sur `master` est déployé par
   [`deploy.yml`](.github/workflows/deploy.yml) (l'application est créée si
   besoin). Lancement manuel : application GitHub → *Actions* → *Deploy to
   Heroku* → *Run workflow*.

Guide complet : [docs/fr/heroku-from-phone.md](docs/fr/heroku-from-phone.md).

## Toujours fusionné sur master

Chaque branche poussée sur GitHub lance la CI (fmt, clippy, tests, docs,
MSRV, build WebAssembly) puis est **fusionnée automatiquement sur `master` si
tout est vert** ([`auto-merge.yml`](.github/workflows/auto-merge.yml)), ce
qui déclenche ensuite le déploiement Heroku. Nommez une branche `wip/...`
pour l'exclure.

## Publier la crate sur crates.io (depuis le téléphone)

1. crates.io → *Account settings* → *API Tokens* → nouveau jeton (droit de publication).
2. GitHub → *Settings* → *Secrets and variables* → *Actions* → ajouter
   `CARGO_REGISTRY_TOKEN`.
3. Application GitHub → *Actions* → *Publish crate* → *Run workflow*
   (décochez *dry run*), ou poussez un tag `v0.1.0`.

## Développement local

```bash
# crate
cargo test --workspace

# site (prérequis : rustup target add wasm32-unknown-unknown ; cargo install trunk wasm-bindgen-cli)
cd site && trunk build --release && cd ..
DIST_DIR=site/dist cargo run -p securite-server   # http://localhost:8080

# ou avec rechargement à chaud : lancez le serveur puis `trunk serve` dans site/ (http://localhost:8081)
```

## Licence

Double licence [MIT](LICENSE-MIT) ou [Apache-2.0](LICENSE-APACHE).
Signaler une faille : voir [SECURITY.md](SECURITY.md).
