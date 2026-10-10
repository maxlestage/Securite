# syntax=docker/dockerfile:1
#
# securite website — multi-stage image
#   1. site    : Yew + WebAssembly front-end built with Trunk
#   2. server  : axum server protected by the securite crate
#   3. runtime : small Debian image, non-root user
#
# Used by `docker build .`, Heroku (heroku.yml / Deploy button) and the
# GitHub Actions deploy workflow. The server listens on $PORT (Heroku sets it).

ARG TRUNK_VERSION=0.21.14
ARG WASM_BINDGEN_VERSION=0.2.129

# ---------------------------------------------------------------------------
FROM rust:1-slim-bookworm AS site
ARG TRUNK_VERSION
ARG WASM_BINDGEN_VERSION
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown
# Prebuilt binaries from GitHub releases, falling back to crates.io.
RUN curl -fsSL "https://github.com/trunk-rs/trunk/releases/download/v${TRUNK_VERSION}/trunk-x86_64-unknown-linux-gnu.tar.gz" \
      | tar -xzf - -C /usr/local/cargo/bin \
 || cargo install trunk --locked --version "${TRUNK_VERSION}"
RUN curl -fsSL "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/wasm-bindgen-${WASM_BINDGEN_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
      | tar -xzf - -C /tmp \
 && mv "/tmp/wasm-bindgen-${WASM_BINDGEN_VERSION}-x86_64-unknown-linux-musl/wasm-bindgen" /usr/local/cargo/bin/ \
 || cargo install wasm-bindgen-cli --locked --version "${WASM_BINDGEN_VERSION}"
RUN trunk --version && wasm-bindgen --version

WORKDIR /build/site
# Dependencies first (better layer caching).
COPY site/Cargo.toml site/Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo fetch --locked && rm -rf src
COPY docs /build/docs
COPY site /build/site
RUN trunk build --release --offline

# ---------------------------------------------------------------------------
FROM rust:1-slim-bookworm AS server
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY server ./server
RUN cargo build --release --locked -p securite-server

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
COPY --from=server /build/target/release/securite-server /app/securite-server
COPY --from=site /build/site/dist /app/dist
ENV DIST_DIR=/app/dist \
    RUST_LOG=info \
    PORT=8080
USER 10001
EXPOSE 8080
CMD ["/app/securite-server"]
