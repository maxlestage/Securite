---
title: Publier la crate sur crates.io
summary: Publiez une nouvelle version de la crate securite depuis votre téléphone avec un jeton crates.io, un secret GitHub et le workflow Publish crate, puis gérez vos versions sans risque.
category: deploy
order: 4
---

La crate `securite`, dans `crates/securite`, est prête pour crates.io. La publication s'exécute dans GitHub Actions (`.github/workflows/publish.yml`) : un téléphone suffit.

## Ce qui est déjà en place

| Élément | Valeur |
|---|---|
| Métadonnées | `description`, `keywords`, `categories`, `homepage`, `repository`, `documentation` (docs.rs) et `readme` dans `crates/securite/Cargo.toml` ; `rust-version` (1.85) hérité de l'espace de travail |
| Licence | Propriétaire : `license-file = "LICENSE"`, héritée de l'espace de travail ; cargo copie le fichier dans le paquet |
| README | `crates/securite/README.md`, affiché sur la page crates.io |
| docs.rs | `[package.metadata.docs.rs]` compile avec toutes les fonctionnalités et `--cfg docsrs` |
| Vérification du paquet | La CI lance `cargo publish -p securite --dry-run` à chaque push : les problèmes d'empaquetage apparaissent bien avant le jour de la sortie |

## Configuration initiale

### Créer un jeton crates.io

1. Dans le navigateur mobile, connectez-vous à [crates.io](https://crates.io) avec votre compte GitHub.
2. Ouvrez **Account Settings** et vérifiez votre adresse e-mail : crates.io refuse les publications sans elle.
3. **API Tokens** → **New Token**. Donnez-lui un nom et une date d'expiration, cochez les portées `publish-new` (nécessaire pour le tout premier envoi) et `publish-update`, et limitez-le à la crate `securite`.
4. Copiez le jeton : il n'est affiché qu'une seule fois.

### L'enregistrer dans GitHub

L'application GitHub ne permet pas de modifier les secrets, utilisez donc le navigateur mobile : dépôt → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**, nom `CARGO_REGISTRY_TOKEN`, collez le jeton, **Add secret**.

## Publier une version

### Depuis l'onglet Actions

1. Application GitHub → dépôt → **Actions** → **Publish crate** → **Run workflow**.
2. Gardez la branche `master` et **décochez** *Dry run (package and verify only)*, puis lancez l'exécution.
3. Le job lance `cargo test -p securite`, puis `cargo publish -p securite`.

Si la case reste cochée, ce qui est le cas par défaut, le workflow se contente de `cargo publish --dry-run` : une répétition sans risque avant le vrai envoi.

### Depuis une étiquette de version

Dans le navigateur mobile : **Releases** → **Draft a new release** → **Choose a tag**, saisissez `v0.1.0` et choisissez **Create new tag on publish**, cible `master`, rédigez les notes, **Publish release**. La nouvelle étiquette déclenche le workflow, qui vérifie qu'elle vaut `v` suivi de la version de la crate et échoue dans le cas contraire. Une étiquette publie toujours pour de vrai.

Quelques minutes après l'envoi, docs.rs génère la documentation sur [docs.rs/securite](https://docs.rs/securite).

## Liste de contrôle de sortie

1. Augmentez `version` dans `crates/securite/Cargo.toml` en suivant le versionnage sémantique.
2. Reportez la même version sur l'entrée `securite` du `Cargo.lock` racine (la ligne qui suit `name = "securite"`). Le build Docker utilise `--locked` et échoue si le fichier de verrouillage n'est pas à jour.
3. Décrivez les changements dans `CHANGELOG.md` à la racine du dépôt (format Keep a Changelog) : le pied de page du site pointe vers lui.
4. Commitez sur une branche et laissez la [CI et la fusion automatique](/docs/ci-auto-merge) l'amener dans `master`.
5. Publiez avec une étiquette de version, ou depuis l'onglet Actions.

```toml
[package]
name = "securite"
version = "0.1.1"
```

Avant la 1.0, Cargo considère le numéro mineur comme celui des changements incompatibles :

```text
0.1.0 -> 0.1.1   bug fix or compatible addition
0.1.1 -> 0.2.0   breaking change (renamed type, removed method, raised MSRV)
0.9.3 -> 1.0.0   stable API, then 1.x.y follows the usual major.minor.patch rules
```

> **Astuce :** relever la version minimale de Rust prise en charge (1.85 aujourd'hui) mérite au moins une version mineure. Modifiez ensemble `rust-version` dans le `Cargo.toml` racine et le job `msrv` de `ci.yml`.

## Ce qui est irréversible

* **Les noms de crate sont définitifs** : une fois `securite` publiée, le nom est lié à votre compte. Choisissez avec soin le nom de toute future crate.
* **Les versions sont immuables** : impossible de publier un autre contenu sous le même numéro. Une erreur se corrige par une nouvelle version.
* **Le yank** retire une version défectueuse des nouvelles résolutions de dépendances, tandis que les fichiers `Cargo.lock` existants continuent de fonctionner. Il faut un terminal et un jeton doté de la portée `yank`, par exemple dans un GitHub Codespace ouvert dans le navigateur :

```bash
cargo login
cargo yank securite@0.1.1
# Changed your mind
cargo yank securite@0.1.1 --undo
```

> **Attention :** ne commitez jamais le jeton et ne le collez jamais dans une issue ou un journal. En cas de fuite, révoquez-le dans **API Tokens** sur crates.io, créez-en un nouveau et mettez à jour le secret `CARGO_REGISTRY_TOKEN`.

## Pages associées

* [CI et fusion automatique](/docs/ci-auto-merge)
* [Installation](/docs/installation)
