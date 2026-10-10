---
title: Image Docker
summary: Comment le Dockerfile multi-étapes construit le site et son serveur, comment lancer l'image en local ou sur n'importe quelle plateforme de conteneurs, et comment développer sans Docker.
category: deploy
order: 3
---

Le `Dockerfile` à la racine du dépôt construit ce site : des pages rendues par le serveur avec [active](https://github.com/maxlestage/Active) et des îlots WebAssembly, servis par un serveur axum qui se protège lui-même avec `securite`. Heroku construit la même image pour vous (voir [Déployer sur Heroku depuis votre téléphone](/docs/heroku-from-phone)) ; les commandes de cette page demandent un ordinateur ou un terminal dans le cloud.

## Les deux étapes

### build

Basée sur `rust:1-slim-bookworm` avec la cible `wasm32-unknown-unknown`.

* Installe wasm-bindgen `0.2.129` (argument de build `WASM_BINDGEN_VERSION`) à partir du binaire précompilé publié sur GitHub. Si le téléchargement échoue, elle se rabat sur `cargo install --locked` de la même version, plus lent.
* Copie les manifestes de l'espace de travail et `crates/`, avec des sources provisoires pour `server/` et `site/`, et lance `cargo fetch --locked` : la couche des dépendances reste en cache tant que `Cargo.lock` ne change pas.
* Copie `server/`, `site/` et `docs/` (le `build.rs` du site compile ces pages dans le serveur), puis construit le bundle navigateur (`cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release`, puis `wasm-bindgen --target web --no-typescript --out-dir site/pkg …`) et le serveur (`cargo build --release --locked -p securite-server`). Le profil release utilise la LTO « thin », une seule unité de génération de code et un binaire dépouillé de ses symboles ; le profil `wasm-release` optimise le bundle pour la taille.

### runtime

Basée sur `debian:bookworm-slim`, elle ne contient que `/app/securite-server`, les fichiers statiques de `/app/site/static` (feuille de style, icônes) et le bundle navigateur de `/app/site/pkg`. Elle s'exécute sous l'utilisateur système non root `app` (uid `10001`, sans répertoire personnel, shell `nologin`), définit `SITE_DIR=/app/site`, `RUST_LOG=info` et `PORT=8080`, et expose le port 8080.

`.dockerignore` réduit le contexte de build : `.git`, `.github`, `target`, `site/pkg`, `dist` et les fichiers Markdown sont exclus, sauf `docs/**/*.md` et `crates/securite/README.md`.

> **Attention :** la CLI wasm-bindgen doit correspondre exactement à la crate `wasm-bindgen`. Pour la mettre à jour, changez `0.2.129` dans `site/Cargo.toml` et dans l'argument `WASM_BINDGEN_VERSION` du `Dockerfile`, puis lancez `cargo update -p wasm-bindgen` : les workflows lisent la version dans `Cargo.lock`.

## Construire et lancer

```bash
docker build -t securite-site .
docker run -p 8080:8080 -e SECURITE_ENV=development securite-site
```

Ouvrez ensuite `http://localhost:8080`. Le mode développement permet de rester en HTTP simple : le mode production envoie HSTS et `upgrade-insecure-requests`, qui cassent `http://localhost`.

> **Astuce :** le binaire wasm-bindgen téléchargé est compilé pour x86_64. Si l'étape `wasm-bindgen --version` échoue sur une machine ARM, ajoutez `--platform linux/amd64` à `docker build`.

## Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `PORT` | `8080` | Port d'écoute sur `0.0.0.0`. Heroku, Render et Railway le définissent. |
| `SITE_DIR` | `/app/site` dans l'image, le dossier `site/` sinon | Contient `static/` et `pkg/`. Sans `pkg/`, le serveur journalise un avertissement : les pages fonctionnent, sans leurs animations ni leurs îlots. |
| `BASE_PATH` | vide | Chemin sous lequel vit le site derrière un proxy, par exemple `/securite` : chaque lien commence par lui. |
| `SITE_URL` | déduite de chaque requête | Adresse publique, pour les URL canoniques, `sitemap.xml` et Open Graph. |
| `SECURITE_ENV` | `production` si `DYNO` est défini, `development` sinon | `production` active la redirection HTTPS (sauf `/api/health`), HSTS, `upgrade-insecure-requests` et `ClientIpSource::heroku()`. Toute autre valeur signifie développement, avec `ClientIpSource::Peer`. |
| `RUST_LOG` | `info` | Filtre `tracing` ; les événements de sécurité utilisent la cible `securite`. |

## Ce que fait le serveur

Chaque page est rendue par le serveur avec active, en français, en anglais et en espagnol : `/` redirige vers `/fr/`, `/en/` ou `/es/` selon `Accept-Language`, puis viennent `/{lang}/`, `/{lang}/docs/`, `/{lang}/docs/{slug}/` et `/{lang}/playground/` ; les adresses de la version précédente (`/docs/waf`, `/playground`) sont redirigées. `/manifest.webmanifest` et `/sw.js` font du site une application installable qui fonctionne hors ligne, `/sitemap.xml` et `/robots.txt` aident les moteurs de recherche, `/static/` et `/pkg/` servent les fichiers (en cache pendant un an quand ils sont versionnés). `/api/health` répond `ok`, `/api/stats` renvoie les compteurs du bouclier en JSON, et `/api/demo` renvoie la charge envoyée par le playground quand le WAF la laisse passer.

| Garde | Réglage |
|---|---|
| `MethodFilter` | `GET`, `HEAD` et `OPTIONS` uniquement |
| `BodyLimit` | 16 Kio |
| `RateLimit` | 30 requêtes par seconde et par IP, rafale de 150 ; `/api/demo` 60 par minute, rafale de 20 |
| `ConcurrencyLimit` | 64 requêtes simultanées par IP |
| `AutoBan` | 30 pénalités, `/api/demo` ignoré |
| `SecurityHeaders` | CSP stricte : les scripts inline (chargeur WebAssembly, enregistrement du service worker) et le style inline d'active autorisés par hash, `'wasm-unsafe-eval'`, `worker-src` et `manifest-src` limités à `'self'` ; COEP `require-corp`, HSTS en production |
| `HttpsRedirect` | Production uniquement, `/api/health` exempté |
| `RequestId`, `Hygiene`, `BotBlocker`, `Waf`, `Csrf`, `CookieHardening` | Valeurs par défaut |

## L'exécuter n'importe où

L'image écoute sur `$PORT` et journalise sur la sortie standard : n'importe quelle plateforme de conteneurs convient. Derrière du HTTPS, définissez `SECURITE_ENV=production` et vérifiez que la source d'IP client correspond au proxy, voir [IP du client](/docs/client-ip). Le site utilise `ClientIpSource::heroku()` en production ; pour un autre proxy, modifiez l'appel `.client_ip(...)` dans `server/src/app.rs`.

| Plateforme | Déploiement | Source d'IP client |
|---|---|---|
| Fly.io | `fly launch` détecte le `Dockerfile` ; gardez `internal_port = 8080` | `ClientIpSource::fly()` |
| Render | Web Service avec le runtime Docker ; Render définit `PORT` | `ClientIpSource::heroku()` |
| Railway | Déploiement depuis le dépôt GitHub ; Railway définit `PORT` | `ClientIpSource::x_real_ip()` |
| Kubernetes | Deployment, Service et Ingress | `XForwardedFor { trusted_hops }`, un saut par proxy supplémentaire |

Sur Kubernetes, l'image respecte déjà un contexte de sécurité restreint :

```yaml
containers:
  - name: securite-site
    image: registry.example.com/securite-site:latest
    ports:
      - containerPort: 8080
    env:
      - name: SECURITE_ENV
        value: production
    readinessProbe:
      httpGet:
        path: /api/health
        port: 8080
    securityContext:
      runAsNonRoot: true
      runAsUser: 10001
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
```

> **Astuce :** avant la mise en ligne, envoyez une attaque depuis le playground en passant par le vrai proxy et lisez le champ `ip=` de la ligne `request blocked` : il doit afficher votre propre adresse, pas celle du proxy.

## Développer en local sans Docker

Installez les outils une fois :

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --locked --version 0.2.129
```

Construisez le bundle navigateur, puis lancez le serveur comme en production, avec tous les en-têtes du bouclier :

```bash
# Depuis la racine du dépôt
cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release
wasm-bindgen --target web --no-typescript --out-dir site/pkg target/wasm32-unknown-unknown/wasm-release/securite_site.wasm
cargo run -p securite-server   # http://localhost:8080
```

Les pages, les textes et la documentation sont compilés dans le serveur : après une modification, relancez `cargo run -p securite-server`. Ne reconstruisez le bundle que si les îlots ou les animations de page changent (`site/src/islands.rs`, `site/src/client/`).

La copie statique publiée sur GitHub Pages vient du même code (voir [Déployer sur GitHub Pages](/docs/github-pages)) :

```bash
BASE_PATH=/Securite SITE_URL=https://maxlestage.github.io/Securite cargo run -p securite-server -- export dist
```

## Pages associées

* [Déployer sur Heroku depuis votre téléphone](/docs/heroku-from-phone)
* [IP du client](/docs/client-ip)
* [En-têtes de sécurité](/docs/security-headers)
* [CI et fusion automatique](/docs/ci-auto-merge)
