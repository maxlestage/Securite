#!/usr/bin/env bash
# Builds the server and the islands (WebAssembly), as the
# Dockerfile does: run on Heroku by RustConfig once the emk/rust buildpack has
# installed Rust. Works by hand too, from the repository: ./heroku-build.sh
# The Procfile starts target/release/securite-server.
set -euo pipefail
cd "$(dirname "$0")"
# On Heroku, Cargo builds into the buildpack's cache (CARGO_TARGET_DIR).
target="${CARGO_TARGET_DIR:-target}"

echo "-----> Building the server"
cargo build --release --locked -p securite-server
mkdir -p target/release
if [ "$target" != target ]; then
  cp "$target/release/securite-server" target/release/
fi
echo "       target/release/securite-server ready"

echo "-----> Building the islands (WebAssembly)"
rustup target add wasm32-unknown-unknown
cargo build --locked -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release

# wasm-bindgen must be the version of Cargo.lock: a prebuilt binary, or compiled
# if it cannot be downloaded.
version=$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/^version = "\(.*\)"$/\1/p')
bin="$target/wasm-bindgen-$version"
if [ ! -x "$bin/wasm-bindgen" ]; then
  mkdir -p "$bin"
  curl -sSfL "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${version}/wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz" \
    | tar -xz --strip-components=1 -C "$bin" \
    || cargo install wasm-bindgen-cli --version "$version" --locked --root "$bin" --bin wasm-bindgen
  [ -x "$bin/wasm-bindgen" ] || mv "$bin/bin/wasm-bindgen" "$bin/"
fi
"$bin/wasm-bindgen" --target web --no-typescript --out-dir site/pkg \
  "$target/wasm32-unknown-unknown/wasm-release/securite_site.wasm"
echo "       islands ready in site/pkg"
