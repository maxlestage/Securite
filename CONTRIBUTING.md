# Contributing

Thanks for helping make Rust services safer!

1. Fork and create a branch (`feat/my-change`). Pushing a branch runs CI and,
   on the main repository, **auto-merges it into `master` when green**. Use a
   `wip/...` branch name to opt out.
2. Before pushing:

   ```bash
   cargo fmt --all
   cargo clippy --workspace --all-targets -- -D warnings
   cargo clippy -p securite-site --lib --target wasm32-unknown-unknown -- -D warnings
   cargo test --workspace
   ```

   The website (`site/`, written with [active](https://maxlestage.github.io/Active/))
   is rendered by `server/`. To see it, build the browser bundle, then run the server
   (needs `rustup target add wasm32-unknown-unknown` and
   `cargo install wasm-bindgen-cli --version 0.2.129`):

   ```bash
   cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release
   wasm-bindgen --target web --no-typescript --out-dir site/pkg target/wasm32-unknown-unknown/wasm-release/securite_site.wasm
   cargo run -p securite-server   # http://localhost:8080
   BASE_PATH=/Securite cargo run -p securite-server -- export dist   # GitHub Pages copy
   ```

   Texts live in `site/src/i18n.rs` (French, English, Spanish), pages in
   `site/src/render/pages.rs`, interactive parts in `site/src/islands.rs` and the
   animations in `site/src/client/`.

3. Documentation lives in `docs/{en,fr,es}` (see `docs/FORMAT.md`): please
   update the three languages.
4. New WAF rules need a test with the payload **and** a false-positive test.

securite is proprietary software by Maxime Nathan Lestage (see [LICENSE](LICENSE)).
By contributing you assign the rights in your contribution to the author, as
section 3 of the license states; contributions are welcome under those terms.
