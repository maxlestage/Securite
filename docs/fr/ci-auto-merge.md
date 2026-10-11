---
title: CI et fusion automatique
summary: Ce que vérifie le workflow de CI, comment chaque branche au vert est fusionnée dans master puis déployée automatiquement, et comment gérer exclusions, conflits et mises à jour Dependabot depuis un téléphone.
category: deploy
order: 5
---

Trois workflows s'enchaînent pour qu'une branche poussée depuis n'importe où, téléphone compris, soit testée, fusionnée et déployée sans le moindre clic :

```text
push to feature/x
  -> Auto-merge: CI (crate, MSRV, website)
  -> green: merge --no-ff into master as github-actions[bot]
  -> Deploy to Heroku (workflow_run): build, release, smoke test /api/health
```

## Le workflow de CI

`.github/workflows/ci.yml` s'exécute à chaque push sur `master`, sur les pull requests, quand Auto-merge l'appelle, et à la main. Ses trois jobs tournent en parallèle :

| Job | Vérifications |
|---|---|
| Crate · fmt, clippy, tests, docs, package | `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo doc -p securite --no-deps` avec `RUSTDOCFLAGS=-D warnings`, `cargo publish -p securite --dry-run` |
| Crate · MSRV 1.85 | `cargo check -p securite --all-features` avec Rust 1.85 |
| Website · Active + WebAssembly | `cargo clippy -p securite-site --lib --target wasm32-unknown-unknown -- -D warnings`, le bundle navigateur (`cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release`, puis `wasm-bindgen`, l'outil précompilé de la version verrouillée dans `Cargo.lock`), le serveur en release et l'export statique pour GitHub Pages (`securite-server export dist` avec `BASE_PATH=/Securite`) |

Les avertissements sont des erreurs : un lint clippy ou un lien de documentation cassé fait échouer l'exécution. Les mêmes vérifications sur un ordinateur :

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc -p securite --no-deps
cargo publish -p securite --dry-run
cargo clippy -p securite-site --lib --target wasm32-unknown-unknown -- -D warnings
cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release
wasm-bindgen --target web --no-typescript --out-dir site/pkg target/wasm32-unknown-unknown/wasm-release/securite_site.wasm
BASE_PATH=/Securite cargo run --release -p securite-server -- export dist
```

## Le workflow de fusion automatique

`.github/workflows/auto-merge.yml` s'exécute à chaque push de branche, sauf sur `master`, `main`, `wip/**` et `dependabot/**` :

1. Il appelle le workflow de CI sur le commit poussé.
2. Quand tous les jobs sont au vert, le job **Merge into master** récupère `master` et y fusionne ce commit précis avec `git merge --no-ff` sous l'identité `github-actions[bot]`, avec le message `Merge branch '<branch>' into master (auto-merge)`, puis pousse `master`. Si le commit est déjà dans `master`, il ne fait rien.
3. Sa réussite lance **Deploy to Heroku** via `workflow_run`. Un push effectué avec le jeton du workflow ne déclenche pas d'autres workflows, d'où ce lien explicite (voir [Déployer sur Heroku depuis votre téléphone](/docs/heroku-from-phone)).

Un nouveau push sur la même branche annule l'exécution en cours, et les fusions dans `master` passent une par une. Une pull request ouverte depuis la branche est automatiquement marquée comme fusionnée. La branche, elle, reste : supprimez-la depuis la page **Branches** quand vous n'en avez plus besoin.

> **Attention :** le résultat de la fusion n'est pas retesté avant le push lui-même. Le workflow de déploiement relance en revanche toute la CI sur `master` et ne déploie sur Heroku que si elle est verte : une mauvaise fusion n'atteint jamais la production. Quand deux branches modifient le même code, gardez-les courtes et à jour avec `master`.

### Depuis un téléphone

Modifiez un fichier sur github.com, choisissez **Create a new branch for this commit**, puis **Propose changes**. Ce push suffit à lancer la chaîne : inutile de créer la pull request que GitHub propose, et si vous la créez, elle est marquée comme fusionnée dès que la fusion aboutit.

### Exclure une branche

Nommez la branche `wip/...`, par exemple `wip/nouvelles-regles-waf`. Rien n'est fusionné, et aucune CI ne tourne non plus, puisque la CI ne se lance d'elle-même que pour `master` et les pull requests. Ouvrez une pull request pour obtenir les vérifications, puis fusionnez-la depuis l'application GitHub quand vous êtes prêt.

## Prérequis

* **Settings** → **Actions** → **General** → **Workflow permissions** → **Read and write permissions** → **Save**. Le workflow demande `contents: write` pour pousser `master` ; si l'option est grisée, une règle de l'organisation la restreint.
* Si `master` est protégée par une règle de protection de branche ou un ruleset, cette règle doit laisser `github-actions` pousser directement, par exemple via sa liste de contournement. Une règle qui exige des pull requests ou des vérifications d'état rejette le push, et le job de fusion échoue.

## Conflits de fusion

Quand `master` a modifié les mêmes lignes, `git merge` s'arrête, le job échoue et rien n'est poussé. Intégrez `master` dans votre branche, résolvez, puis poussez de nouveau : la fusion automatique réessaie d'elle-même. Depuis un téléphone, ouvrez une pull request depuis la branche ; si GitHub propose **Resolve conflicts**, corrigez les marqueurs dans l'éditeur web (le mode « version pour ordinateur » aide), puis **Mark as resolved** et **Commit merge**. Ce commit arrive sur votre branche et relance la chaîne.

> **Astuce :** pour n'être prévenu qu'en cas d'échec, ouvrez github.com → votre avatar → **Settings** → **Notifications**, puis sous **Actions** cochez **Only notify for failed workflows**.

## Dependabot

`.github/dependabot.yml` cherche des mises à jour chaque semaine à deux endroits : l'espace de travail Cargo (`/`, site compris) et les versions des GitHub Actions. Chaque mise à jour ouvre une pull request sur une branche `dependabot/...`, **elle aussi fusionnée automatiquement sur `master`** :

1. La CI s'exécute sur la pull request.
2. Quand elle est verte, `.github/workflows/dependabot-auto-merge.yml` fusionne exactement le commit testé (`gh pr merge --match-head-commit`). Il ne récupère jamais le code de la pull request et n'agit que sur les pull requests ouvertes par `dependabot[bot]`.
3. Le déploiement Heroku suit, après un nouveau passage de la CI sur `master`.

Une CI rouge laisse la pull request ouverte : lisez la vérification en échec depuis l'application GitHub, puis fermez la pull request ou corrigez `master`. Les pull requests venant de forks ne sont jamais fusionnées automatiquement : personne d'extérieur au dépôt ne peut pousser du code sur `master`.

`wasm-bindgen` est volontairement exclu de Dependabot : il doit correspondre exactement à son outil en ligne de commande, voir [Image Docker](/docs/docker).

## Pages associées

* [Déployer sur Heroku depuis votre téléphone](/docs/heroku-from-phone)
* [Publier la crate sur crates.io](/docs/publish-crates-io)
* [Image Docker](/docs/docker)
