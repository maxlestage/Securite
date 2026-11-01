<div align="center">

[![Securite : protégez vos API Rust contre le XSS, l'injection SQL et les robots](https://raw.githubusercontent.com/maxlestage/Securite/master/site/static/og-image.jpg)](https://securite-2db4c1994be7.herokuapp.com/)

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
| [`crates/securite`](crates/securite) | La **crate `securite`** (prête pour crates.io) : 23 middlewares de sécurité pour Vitesse, et pour tower / hyper / tonic, plus le hachage et la politique des mots de passe, la limitation des connexions, les autorisations et le contrôle d'accès, les sessions, JWT / JWKS, le chiffrement, les URL signées, TOTP, les rapports CSP et security.txt |
| [`crates/pratique`](crates/pratique) | La **crate `pratique`** : 14 middlewares Vitesse du quotidien sans rapport avec la sécurité (ETag, Cache-Control, cache de réponses, access logs, métriques Prometheus, temps de réponse, slash final, redirections, health checks, mode maintenance, en-têtes, langue, dépréciation d'API, `Idempotency-Key`) |
| [`site`](site) | Le **site de présentation**, écrit avec [Active](https://active-c1883a966650.herokuapp.com/) : pages rendues par le serveur avec un SEO complet, îlots WebAssembly, animé, FR / EN / ES, documentation classée par catégories, playground d'attaques en direct, PWA installable qui fonctionne hors ligne |
| [`server`](server) | Le serveur Vitesse qui rend et héberge le site et l'API du playground — protégé par `securite` lui-même |
| [`docs`](docs) | La **documentation** (52 pages × 3 langues), compilée dans le site |
| [`RustConfig`](RustConfig), [`Procfile`](Procfile), [`heroku-build.sh`](heroku-build.sh), [`app.json`](app.json) | **Déploiement Heroku en un geste** avec le buildpack Rust (`emk/rust`) |
| [`Dockerfile`](Dockerfile), [`heroku.yml`](heroku.yml) | Image conteneur (Docker, ou la stack container de Heroku) |
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
*Deploy app*. Heroku compile le site avec le
[buildpack emk/rust](https://elements.heroku.com/buildpacks/emk/heroku-buildpack-rust)
sur la stack `heroku-26`, comme l'indiquent `RustConfig`, `heroku-build.sh` et `Procfile`
(≈ 10–15 min la première fois), puis le démarre.

**Option B — déploiement automatique à chaque merge.**

1. Heroku (navigateur mobile) → *Account settings* → *API Key* → *Reveal* → copier.
2. GitHub (navigateur mobile) → ce dépôt → *Settings* → *Secrets and
   variables* → *Actions* → ajouter `HEROKU_API_KEY` et `HEROKU_APP_NAME`.
3. C'est tout : chaque push fusionné sur `master` est déployé par
   [`deploy.yml`](.github/workflows/deploy.yml) (l'application est créée si
   besoin). Lancement manuel : application GitHub → *Actions* → *Deploy to
   Heroku* → *Run workflow*. Il utilise lui aussi le buildpack ; donnez la valeur
   `docker` à la variable de dépôt `HEROKU_BUILD` pour construire plutôt le
   `Dockerfile` (`heroku.yml`).

Depuis un ordinateur : `heroku create --stack heroku-26 --buildpack emk/rust`,
puis `git push heroku master:main`.

Guide complet : [docs/fr/heroku-from-phone.md](docs/fr/heroku-from-phone.md).

## Site

Le site est servi uniquement par Heroku, à l'adresse **https://securite-2db4c1994be7.herokuapp.com/** : GitHub
n'héberge que le code. Le serveur sait toujours l'exporter en fichiers statiques
(`securite-server export`), ce que la CI vérifie à chaque push.

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
3. Changez la version dans `crates/securite/Cargo.toml`, écrivez sa section
   dans `CHANGELOG.md` et poussez. Une fois la CI de `master` au vert,
   *Publish crate* pose le tag de la version (`v0.1.0`), crée la release GitHub
   avec cette section pour notes et publie la crate. Sans le secret, ou tant que
   `vitesse` n'est pas sur crates.io, la publication attend : plus tard,
   application GitHub → *Actions* → *Publish crate* → *Run workflow* (décochez
   *dry run*).

## Développement local

```bash
# crate, site et serveur
cargo test --workspace

# site : le bundle navigateur (prérequis : rustup target add wasm32-unknown-unknown ;
# cargo install wasm-bindgen-cli --version 0.2.129), puis le serveur
cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release
wasm-bindgen --target web --no-typescript --out-dir site/pkg target/wasm32-unknown-unknown/wasm-release/securite_site.wasm
cargo run -p securite-server   # http://localhost:8080

# tout le site en fichiers statiques (vérifié par la CI, publié nulle part)
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
au sein d'une même famille de projets Rust : [Active](https://active-c1883a966650.herokuapp.com/), [Vitesse](https://vitesse-f16135654c3d.herokuapp.com/), [Securite](https://securite-2db4c1994be7.herokuapp.com/), [Memoire](https://memoire-7f4525f1fdaf.herokuapp.com/) et [Paquets](https://paquets-90dfc06b6fea.herokuapp.com/).
