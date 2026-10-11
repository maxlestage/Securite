<div align="center">

# 🛡️ Securite

**Des middlewares de sécurité natifs pour Rust : rapides, faciles et complets.**

[![crates.io](https://img.shields.io/crates/v/securite.svg)](https://crates.io/crates/securite)
[![docs.rs](https://img.shields.io/docsrs/securite)](https://docs.rs/securite)
![unsafe interdit](https://img.shields.io/badge/unsafe-interdit-success)

[English](README.md) · **Français** · [Español](README.es.md)

</div>

---

Ce dépôt contient :

| Dossier | Contenu |
|---|---|
| [`crates/securite`](crates/securite) | La **crate `securite`** (prête pour crates.io) : 19 middlewares de sécurité pour Vitesse, et pour tower / hyper / tonic |
| [`crates/pratique`](crates/pratique) | La **crate `pratique`** : 13 middlewares Vitesse du quotidien sans rapport avec la sécurité (ETag, Cache-Control, cache de réponses, access logs, métriques Prometheus, temps de réponse, slash final, redirections, health checks, mode maintenance, en-têtes, langue, dépréciation d'API) |
| [`site`](site) | Le **site de présentation**, écrit avec [Active](https://maxlestage.github.io/Active/) : pages rendues par le serveur avec un SEO complet, îlots WebAssembly, animé, FR / EN / ES, documentation classée par catégories, playground d'attaques en direct, PWA installable qui fonctionne hors ligne |
| [`server`](server) | Le serveur Vitesse qui rend et héberge le site et l'API du playground — protégé par `securite` lui-même |
| [`docs`](docs) | La **documentation** (47 pages × 3 langues), compilée dans le site |
| [`Dockerfile`](Dockerfile), [`heroku.yml`](heroku.yml), [`app.json`](app.json) | Image conteneur et **déploiement Heroku en un geste** |
| [`.github/workflows`](.github/workflows) | CI, **merge automatique sur master**, déploiement Heroku, publication crates.io |

## La crate en 10 secondes

```bash
cargo add securite --git https://github.com/maxlestage/Securite
```

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::recommended()); // en-têtes, WAF, rate limit, CSRF, request ids…
app.get("/", |_req: Request| async { "Hello, secure world!" });
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

**Option A — en un geste.** Ouvrez `https://heroku.com/deploy?template=https://github.com/maxlestage/Securite` sur votre téléphone, choisissez un nom d'application, touchez
*Deploy app*. Heroku construit
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

## GitHub Pages (hébergement statique gratuit)

[`pages.yml`](.github/workflows/pages.yml) publie le site sur
**https://maxlestage.github.io/Securite/** après chaque fusion sur `master`,
sous forme de fichiers statiques exportés par le serveur (`securite-server
export`), avec une CSP stricte en balise `<meta>` (scripts inline autorisés par
hash), un manifeste d'application web et un service worker hors ligne.
Configuration unique depuis le téléphone : dépôt → *Settings* →
*Pages* → *Source* : **GitHub Actions**, puis *Actions* → *Deploy to GitHub
Pages* → *Run workflow*. Le playground d'attaques en direct a besoin du
serveur (Heroku ou Docker). Guide : [docs/fr/github-pages.md](docs/fr/github-pages.md).

## Toujours fusionné sur master

Chaque branche poussée sur GitHub lance la CI (fmt, clippy, tests, docs,
MSRV, bundle WebAssembly, export statique) puis est **fusionnée automatiquement sur `master` si
tout est vert** ([`auto-merge.yml`](.github/workflows/auto-merge.yml)), ce
qui déclenche ensuite le déploiement Heroku. Les pull requests Dependabot
sont fusionnées de la même façon dès que leur CI est verte
([`dependabot-auto-merge.yml`](.github/workflows/dependabot-auto-merge.yml)).
Nommez une branche `wip/...` pour l'exclure.

## Publier la crate sur crates.io (depuis le téléphone)

1. crates.io → *Account settings* → *API Tokens* → nouveau jeton (droit de publication).
2. GitHub → *Settings* → *Secrets and variables* → *Actions* → ajouter
   `CARGO_REGISTRY_TOKEN`.
3. Application GitHub → *Actions* → *Publish crate* → *Run workflow*
   (décochez *dry run*), ou poussez un tag `v0.1.0`.

## Développement local

```bash
# crate, site et serveur
cargo test --workspace

# site : le bundle navigateur (prérequis : rustup target add wasm32-unknown-unknown ;
# cargo install wasm-bindgen-cli --version 0.2.129), puis le serveur
cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release
wasm-bindgen --target web --no-typescript --out-dir site/pkg target/wasm32-unknown-unknown/wasm-release/securite_site.wasm
cargo run -p securite-server   # http://localhost:8080

# la copie statique pour GitHub Pages
BASE_PATH=/Securite cargo run -p securite-server -- export dist
```

## Licence

Securite est un logiciel propriétaire : © 2026 Maxime Nathan Lestage, tous
droits réservés. Ce n'est pas un logiciel open source. Le code source est
publié sur crates.io et GitHub pour pouvoir être lu, audité et compilé, et
vous pouvez l'utiliser librement comme dépendance de vos propres programmes,
y compris commerciaux. Le modifier ou redistribuer son code source demande
l'accord écrit de l'auteur. Conditions complètes : [LICENSE](LICENSE).
Signaler une faille : voir [SECURITY.md](SECURITY.md).

Les contributions (code, documentation, idées) sont les bienvenues et
rejoignent le projet aux mêmes conditions : en soumettre une, c'est en céder
les droits à l'auteur, comme l'indique la licence.

## Crédits

Conçu et développé par Maxime Nathan Lestage,
au sein d'une même famille de projets Rust : [Active](https://maxlestage.github.io/Active/), [Vitesse](https://maxlestage.github.io/Vitesse/), [Securite](https://maxlestage.github.io/Securite/), [Memoire](https://maxlestage.github.io/Memoire/), [Paquets](https://maxlestage.github.io/Paquets/), [FerroSwift](https://maxlestage.github.io/FerroSwift/) et [Solidify](https://maxlestage.github.io/Solidify/).
