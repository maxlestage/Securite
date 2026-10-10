# Contributing

Thanks for helping make Rust services safer!

1. Fork and create a branch (`feat/my-change`). Pushing a branch runs CI and,
   on the main repository, **auto-merges it into `master` when green**. Use a
   `wip/...` branch name to opt out.
2. Before pushing:

   ```bash
   cargo fmt --all
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   (cd site && cargo fmt && cargo clippy --target wasm32-unknown-unknown -- -D warnings)
   ```

3. Documentation lives in `docs/{en,fr,es}` (see `docs/FORMAT.md`): please
   update the three languages.
4. New WAF rules need a test with the payload **and** a false-positive test.

By contributing you agree that your work is dual licensed under MIT and
Apache-2.0.
