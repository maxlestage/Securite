---
title: Publish the crate on crates.io
summary: Release a new version of the Securite crate by pushing its version and changelog: the Publish crate workflow tags it, creates the GitHub release and publishes it on crates.io, from your phone, and you manage versions safely.
category: deploy
order: 4
---

The `securite` crate in `crates/securite` is ready for crates.io. Publishing runs in GitHub Actions (`.github/workflows/publish.yml`) and starts on its own when a new version reaches `master`, so a phone is enough.

## What is already in place

| Item | Value |
|---|---|
| Metadata | `description`, `keywords`, `categories`, `homepage`, `repository`, `documentation` (docs.rs) and `readme` in `crates/securite/Cargo.toml`; `rust-version` (1.85) inherited from the workspace |
| License | Proprietary: `license-file = "LICENSE"`, inherited from the workspace; cargo copies the file into the package |
| README | `crates/securite/README.md`, shown on the crates.io page |
| docs.rs | `[package.metadata.docs.rs]` builds with every feature and `--cfg docsrs` |
| Package check | CI runs `cargo publish -p securite --dry-run` on every push, so packaging problems show up long before release day |

## One-time setup

### Create a crates.io token

1. In the mobile browser, sign in at [crates.io](https://crates.io) with your GitHub account.
2. Open **Account Settings** and verify your e-mail address: crates.io refuses uploads without it.
3. **API Tokens** → **New Token**. Give it a name and an expiration date, tick the scopes `publish-new` (needed for the very first upload) and `publish-update`, and restrict it to the crate `securite`.
4. Copy the token: it is shown only once.

### Store it in GitHub

The GitHub mobile app cannot edit secrets, so use the mobile browser: repository → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**, name `CARGO_REGISTRY_TOKEN`, paste the token, **Add secret**.

## Publish a version

### Automatically, from master

Change the version, write its section in `CHANGELOG.md`, push (see the checklist below). Nothing else to fill in: once CI is green on a push to `master`, the **Publish crate** workflow reads the version of `securite` and, if it has no tag yet:

1. tags the commit `v` followed by the version (`v0.1.0` for `0.1.0`);
2. creates the GitHub release of that tag, with the `## [0.1.0]` section of `CHANGELOG.md` as notes (GitHub's generated notes when there is no such section);
3. runs `cargo test -p securite`, then `cargo publish -p securite`.

A version that already has its tag is left alone, so ordinary pushes publish nothing. Without the `CARGO_REGISTRY_TOKEN` secret, or while `vitesse` (a dependency of the default `vitesse` feature) is not on crates.io yet, the tag and the release are still made and the publication is postponed: the run ends with a notice, and you publish later from the Actions tab.

### From the Actions tab

1. GitHub app → repository → **Actions** → **Publish crate** → **Run workflow**.
2. Keep the `master` branch and **untick** *Dry run (package and verify only)*, then start the run.
3. The job runs `cargo test -p securite`, then `cargo publish -p securite`.

Left ticked, which is the default, the workflow only runs `cargo publish --dry-run`: a safe rehearsal before the real upload.

Use it for a postponed publication, once the secret is in place or `vitesse` is online.

### From a tag

Pushing a tag `v0.1.0` yourself still starts the workflow, which checks that the tag equals `v` followed by the crate version and fails otherwise. A tag always publishes for real. The automatic release usually makes this unnecessary.

A few minutes after the upload, docs.rs builds the documentation at [docs.rs/securite](https://docs.rs/securite).

## Release checklist

1. Bump `version` in `crates/securite/Cargo.toml`, following semantic versioning.
2. Set the same version on the `securite` entry of the root `Cargo.lock` (the line after `name = "securite"`). The Docker build uses `--locked` and fails when the lockfile is out of date.
3. Describe the changes in `CHANGELOG.md` at the repository root (Keep a Changelog format), under a `## [0.1.1]` heading: this section becomes the notes of the GitHub release. The website footer links to the file.
4. Commit on a branch and let [CI and auto-merge](/docs/ci-auto-merge) bring it into `master`.
5. Nothing more: once CI is green on `master`, the workflow tags `v0.1.1`, creates the release and publishes the crate.

```toml
[package]
name = "securite"
version = "0.1.1"
```

Before 1.0, Cargo treats the minor number as the breaking one:

```text
0.1.0 -> 0.1.1   bug fix or compatible addition
0.1.1 -> 0.2.0   breaking change (renamed type, removed method, raised MSRV)
0.9.3 -> 1.0.0   stable API, then 1.x.y follows the usual major.minor.patch rules
```

> **Tip:** raising the minimum supported Rust version (1.85 today) deserves at least a minor bump. Change `rust-version` in the root `Cargo.toml` and the `msrv` job of `ci.yml` together.

## What you cannot undo

* **Crate names are permanent**: once `securite` is published, the name is tied to your account. Pick names carefully for any future crate.
* **Versions are immutable**: you can never upload different content under the same number. A mistake means a new version.
* **Yanking** hides a broken version from new dependency resolutions, while existing `Cargo.lock` files keep working. It needs a terminal and a token with the `yank` scope, for example in a GitHub Codespace opened in the browser:

```bash
cargo login
cargo yank securite@0.1.1
# Changed your mind
cargo yank securite@0.1.1 --undo
```

> **Warning:** never commit the token or paste it into an issue or a log. If it leaks, revoke it under **API Tokens** on crates.io, create a new one and update the `CARGO_REGISTRY_TOKEN` secret.

## Related pages

* [CI and auto-merge](/docs/ci-auto-merge)
* [Installation](/docs/installation)
