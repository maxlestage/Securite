# Publishing on crates.io

Securite is published on [crates.io](https://crates.io/crates/securite) as the `securite`
crate, under its [proprietary license](LICENSE): the source is visible there so that it can
be audited and built, and anyone may depend on it.

## One release = one version bump

1. Bump `version` in [`crates/securite/Cargo.toml`](crates/securite/Cargo.toml), write its
   `## [X.Y.Z]` section in [`CHANGELOG.md`](CHANGELOG.md) and commit.
2. Push to `master`. That is all.

Once CI is green on `master`, the [`publish.yml`](.github/workflows/publish.yml) workflow
sees a version without a tag: it tags it `vX.Y.Z`, creates the GitHub release with that
version's CHANGELOG section as notes (GitHub's generated notes if there is none), runs the
tests and publishes the crate. Without the `CARGO_REGISTRY_TOKEN` secret, or while `vitesse`
is not on crates.io yet, the tag and the release are still made and the publication is
postponed: open **Actions → Publish crate → Run workflow** later and uncheck *dry run*.
Pushing a tag `vX.Y.Z` by hand still publishes too (the workflow checks that the tag matches
the version). It all works from the GitHub app on a phone; nothing is installed locally.
Started by hand, it is a dry run by default (the package is built and checked, nothing is
uploaded). The full guide: [`docs/en/publish-crates-io.md`](docs/en/publish-crates-io.md).

## One-time setup

- A crates.io account with a verified e-mail address.
- A token from [crates.io/settings/tokens](https://crates.io/settings/tokens) with the scopes
  **publish-new** and **publish-update**, saved as the repository secret
  `CARGO_REGISTRY_TOKEN` (GitHub → Settings → Secrets and variables → Actions).

## From a computer

```sh
cargo login                            # paste the token, once
cargo publish -p securite --dry-run    # packages and builds exactly what would be uploaded
cargo publish -p securite
```

## The ecosystem, in order

The five projects by Maxime Nathan Lestage depend on each other through crates.io, so they
are published in this order, each one after the previous one is online:

1. **Active** — `active`
2. **Vitesse** — `vitesse`
3. **Securite** — `securite` (this repository)
4. **Memoire** — `memoire-orm-derive`, then `memoire-orm`
5. **Paquets** — `paquets-macros`, then `paquets` (depends on the four above)
