---
title: Image Docker
summary: Comment le Dockerfile multi-étapes construit le site et son serveur, comment lancer l'image en local ou sur n'importe quelle plateforme de conteneurs, et comment développer sans Docker.
category: deploy
order: 2
---

Le `Dockerfile` à la racine du dépôt construit ce site : un front-end Yew + WebAssembly servi par un serveur axum qui se protège lui-même avec `securite`. Heroku construit la même image pour vous (voir [Déployer sur Heroku depuis votre téléphone](/docs/heroku-from-phone)) ; les commandes de cette page demandent un ordinateur ou un terminal dans le cloud.

## Les trois étapes

### site

Basée sur `rust:1-slim-bookworm` avec la cible `wasm32-unknown-unknown`.

* Installe Trunk `0.21.14` et wasm-bindgen `0.2.129` (arguments de build `TRUNK_VERSION` et `WASM_BINDGEN_VERSION`) à partir des binaires précompilés publiés sur GitHub. Si un téléchargement échoue, elle se rabat sur `cargo install --locked` de la même version, plus lent.
* Copie seuls `site/Cargo.toml` et `site/Cargo.lock` et lance `cargo fetch --locked` avec un `main.rs` provisoire : la couche des dépendances reste en cache tant que le fichier de verrouillage ne change pas.
* Copie `docs/` (le `build.rs` du site compile ces pages) et `site/`, puis lance `trunk build --release --offline` : tout a été téléchargé auparavant, aucun accès réseau n'est nécessaire.

### server

Basée sur `rust:1-slim-bookworm`, elle copie l'espace de travail (`Cargo.toml`, `Cargo.lock`, `crates/`, `server/`) et lance `cargo build --release --locked -p securite-server`. Le profil release utilise la LTO « thin », une seule unité de génération de code et un binaire dépouillé de ses symboles.

### runtime

Basée sur `debian:bookworm-slim`, elle ne contient que `/app/securite-server` et les fichiers statiques de `/app/dist`. Elle s'exécute sous l'utilisateur système non root `app` (uid `10001`, sans répertoire personnel, shell `nologin`), définit `DIST_DIR=/app/dist`, `RUST_LOG=info` et `PORT=8080`, et expose le port 8080.

`.dockerignore` réduit le contexte de build : `.git`, `.github`, `target`, `site/target`, `site/dist` et les fichiers Markdown sont exclus, sauf `docs/**/*.md` et `crates/securite/README.md`.

> **Attention :** la CLI wasm-bindgen doit correspondre exactement à la crate `wasm-bindgen`. Pour la mettre à jour, changez `0.2.129` à quatre endroits à la fois : `site/Cargo.toml`, la section `[tools]` de `site/Trunk.toml`, l'argument `WASM_BINDGEN_VERSION` et le job `site` de `ci.yml`.

## Construire et lancer

```bash
docker build -t securite-site .
docker run -p 8080:8080 -e SECURITE_ENV=development securite-site
```

Ouvrez ensuite `http://localhost:8080`. Le mode développement permet de rester en HTTP simple : le mode production envoie HSTS et `upgrade-insecure-requests`, qui cassent `http://localhost`.

> **Astuce :** les binaires Trunk et wasm-bindgen téléchargés sont compilés pour x86_64. Si l'étape `trunk --version` échoue sur une machine ARM, ajoutez `--platform linux/amd64` à `docker build`.

## Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `PORT` | `8080` | Port d'écoute sur `0.0.0.0`. Heroku, Render et Railway le définissent. |
| `DIST_DIR` | `/app/dist` dans l'image, `dist` sinon | Sortie de `trunk build`. Sans `index.html`, le serveur journalise un avertissement et sert une page provisoire. |
| `SECURITE_ENV` | `production` si `DYNO` est défini, `development` sinon | `production` active la redirection HTTPS (sauf `/api/health`), HSTS, `upgrade-insecure-requests` et `ClientIpSource::heroku()`. Toute autre valeur signifie développement, avec `ClientIpSource::Peer`. |
| `RUST_LOG` | `info` | Filtre `tracing` ; les événements de sécurité utilisent la cible `securite`. |

## Ce que fait le serveur

`/api/health` répond `ok`, `/api/stats` renvoie les compteurs du bouclier en JSON, et `/api/demo` renvoie la charge envoyée par le playground quand le WAF la laisse passer. Tout autre chemin sert un fichier statique ou retombe sur `index.html`.

| Garde | Réglage |
|---|---|
| `MethodFilter` | `GET`, `HEAD` et `OPTIONS` uniquement |
| `BodyLimit` | 16 Kio |
| `RateLimit` | 30 requêtes par seconde et par IP, rafale de 150 ; `/api/demo` 60 par minute, rafale de 20 |
| `ConcurrencyLimit` | 64 requêtes simultanées par IP |
| `AutoBan` | 30 pénalités, `/api/demo` ignoré |
| `SecurityHeaders` | CSP stricte autorisant le script inline de Trunk par hash et `'wasm-unsafe-eval'`, COEP `require-corp`, HSTS en production |
| `HttpsRedirect` | Production uniquement, `/api/health` exempté |
| `RequestId`, `Hygiene`, `BotBlocker`, `Waf`, `Csrf`, `CookieHardening` | Valeurs par défaut |

## L'exécuter n'importe où

L'image écoute sur `$PORT` et journalise sur la sortie standard : n'importe quelle plateforme de conteneurs convient. Derrière du HTTPS, définissez `SECURITE_ENV=production` et vérifiez que la source d'IP client correspond au proxy, voir [IP du client](/docs/client-ip). Le site utilise `ClientIpSource::heroku()` en production ; pour un autre proxy, modifiez l'appel `.client_ip(...)` dans `server/src/main.rs`.

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
cargo install trunk --locked --version 0.21.14
cargo install wasm-bindgen-cli --locked --version 0.2.129
```

Pour lancer le site comme en production, avec tous les en-têtes du bouclier :

```bash
# From the repository root
(cd site && trunk build --release)
DIST_DIR=site/dist cargo run -p securite-server
```

Pour le rechargement à chaud, laissez tourner le serveur pour l'API et lancez Trunk dans `site/` :

```bash
# Terminal 1, repository root: API on http://localhost:8080
DIST_DIR=site/dist cargo run -p securite-server

# Terminal 2: site with live reload on http://127.0.0.1:8081
cd site
trunk serve
```

`site/Trunk.toml` relaie les requêtes `/api/` vers `http://127.0.0.1:8080/api/` : le playground et les compteurs continuent de fonctionner. Les pages servies par `trunk serve` ne portent pas les en-têtes du bouclier : vérifiez-les sur le port 8080.

## Pages associées

* [Déployer sur Heroku depuis votre téléphone](/docs/heroku-from-phone)
* [IP du client](/docs/client-ip)
* [En-têtes de sécurité](/docs/security-headers)
* [CI et fusion automatique](/docs/ci-auto-merge)
