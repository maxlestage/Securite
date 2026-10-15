---
title: CI and auto-merge
summary: What the CI workflow checks, how every green branch is merged into master and deployed automatically, and how to handle opt-outs, conflicts and Dependabot updates from a phone.
category: deploy
order: 4
---

Three workflows chain together so that a branch pushed from anywhere, a phone included, ends up tested, merged and deployed without a single click:

```text
push to feature/x
  -> Auto-merge: CI (crate, MSRV, website)
  -> green: merge --no-ff into master as github-actions[bot]
  -> Deploy to Heroku (workflow_run): build, release, smoke test /api/health
```

## The CI workflow

`.github/workflows/ci.yml` runs on pushes to `master`, on pull requests, when Auto-merge calls it, and by hand. Its three jobs run in parallel:

| Job | Checks |
|---|---|
| Crate · fmt, clippy, tests, docs, package | `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo doc -p securite --no-deps` with `RUSTDOCFLAGS=-D warnings`, `cargo publish -p securite --dry-run` |
| Crate · MSRV 1.85 | `cargo check -p securite --all-features` with Rust 1.85 |
| Website · Active + WebAssembly | `cargo clippy -p securite-site --lib --target wasm32-unknown-unknown -- -D warnings`, the browser bundle (`cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release`, then `wasm-bindgen`, the prebuilt tool of the version locked in `Cargo.lock`), the release server and the static export of the site (`securite-server export dist` with `BASE_PATH=/Securite`) |

Warnings are errors: a clippy lint or a broken doc link fails the run. The same checks on a computer:

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

## The auto-merge workflow

`.github/workflows/auto-merge.yml` runs on every branch push except `master`, `main`, `wip/**` and `dependabot/**`:

1. It calls the CI workflow on the pushed commit.
2. When every job is green, the **Merge into master** job checks out `master` and merges that exact commit with `git merge --no-ff` as `github-actions[bot]`, with the message `Merge branch '<branch>' into master (auto-merge)`, then pushes `master`. If the commit is already in `master`, it does nothing.
3. Its success starts **Deploy to Heroku** through `workflow_run`. A push made with the workflow token does not trigger other workflows, hence this explicit link (see [Deploy to Heroku from your phone](/docs/heroku-from-phone)).

A new push to the same branch cancels the run in progress, and merges into `master` are queued one at a time. An open pull request from the branch is marked as merged automatically. The branch itself stays: delete it from the **Branches** page when you no longer need it.

> **Warning:** the merge result is not tested again before the push itself. The deploy workflow, however, re-runs the whole CI on `master` and only ships to Heroku when it is green, so a bad merge never reaches production. When two branches change the same code, keep them short-lived and up to date with `master`.

### From a phone

Edit a file on github.com, choose **Create a new branch for this commit**, then **Propose changes**. That push alone starts the chain: you do not need to create the pull request GitHub suggests, and if you do, it is marked as merged once the merge lands.

### Opting out

Name the branch `wip/...`, for example `wip/new-waf-rules`. Nothing is merged, and no CI runs either, since CI only runs on its own for `master` and pull requests. Open a pull request to get the checks, then merge it from the GitHub app when you are ready.

## Requirements

* **Settings** → **Actions** → **General** → **Workflow permissions** → **Read and write permissions** → **Save**. The workflow asks for `contents: write` to push `master`; if the option is greyed out, an organization policy restricts it.
* If `master` is protected by a branch protection rule or a ruleset, that rule must let `github-actions` push directly, for example through its bypass list. A rule that requires pull requests or status checks rejects the push and the merge job fails.

## Merge conflicts

When `master` changed the same lines, `git merge` stops, the job fails and nothing is pushed. Bring `master` into your branch, resolve, and push again: auto-merge retries on its own. From a phone, open a pull request from the branch; if GitHub offers **Resolve conflicts**, fix the markers in the web editor (desktop site mode helps), then **Mark as resolved** and **Commit merge**. That commit lands on your branch and restarts the chain.

> **Tip:** to hear about failures only, open github.com → your avatar → **Settings** → **Notifications**, and under **Actions** tick **Only notify for failed workflows**.

## Dependabot

`.github/dependabot.yml` looks for updates every week in two places: the Cargo workspace (`/`, the website included) and the GitHub Actions versions. Each update opens a pull request on a `dependabot/...` branch, and **it is merged into `master` automatically** too:

1. The CI runs on the pull request.
2. When it is green, `.github/workflows/dependabot-auto-merge.yml` merges exactly the commit that was tested (`gh pr merge --match-head-commit`). It never checks out the pull request code and only acts on pull requests opened by `dependabot[bot]`.
3. The Heroku deploy follows, after the CI has run once more on `master`.

A red CI leaves the pull request open: read the failing check from the GitHub app, then close the pull request or fix `master`. Pull requests from forks are never merged automatically, so nobody outside the repository can push code to `master`.

`wasm-bindgen` is excluded from Dependabot on purpose: it must match its command-line tool exactly, see [Docker image](/docs/docker).

## Related pages

* [Deploy to Heroku from your phone](/docs/heroku-from-phone)
* [Publish the crate on crates.io](/docs/publish-crates-io)
* [Docker image](/docs/docker)
