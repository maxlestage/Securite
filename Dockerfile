# syntax=docker/dockerfile:1
#
# securite website — multi-stage image
#   1. build   : the browser bundle (active islands compiled to WebAssembly, then
#                wasm-bindgen) and the axum server protected by the securite crate,
#                which renders the pages with active
#   2. runtime : small Debian image, non-root user
#
# Used by `docker build .`, Heroku (heroku.yml / Deploy button) and the
# GitHub Actions deploy workflow. The server listens on $PORT (Heroku sets it).

# Must match the wasm-bindgen crate in Cargo.lock.
ARG WASM_BINDGEN_VERSION=0.2.129

# ---------------------------------------------------------------------------
FROM rust:1-slim-bookworm AS build
ARG WASM_BINDGEN_VERSION
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown
# Prebuilt binary from the GitHub release, falling back to crates.io.
RUN curl -fsSL "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/wasm-bindgen-${WASM_BINDGEN_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
      | tar -xzf - --strip-components=1 -C /usr/local/cargo/bin \
 || cargo install wasm-bindgen-cli --locked --version "${WASM_BINDGEN_VERSION}"
RUN wasm-bindgen --version

WORKDIR /build
# Dependencies first (better layer caching): the website crates with placeholder sources.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY server/Cargo.toml server/
COPY site/Cargo.toml site/
RUN mkdir -p server/src site/src \
 && touch site/src/lib.rs \
 && echo "fn main() {}" > server/src/main.rs \
 && cargo fetch --locked \
 && rm -rf server/src site/src
COPY server server
COPY site site
# The documentation pages are compiled into the server by site/build.rs.
COPY docs docs
RUN cargo build --locked -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release \
 && wasm-bindgen --target web --no-typescript --out-dir site/pkg target/wasm32-unknown-unknown/wasm-release/securite_site.wasm \
 && cargo build --locked --release -p securite-server

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
COPY --from=build /build/target/release/securite-server /app/securite-server
COPY --from=build /build/site/static /app/site/static
COPY --from=build /build/site/pkg /app/site/pkg
ENV SITE_DIR=/app/site \
    RUST_LOG=info \
    PORT=8080
USER 10001
EXPOSE 8080
CMD ["/app/securite-server"]
