#!/usr/bin/env bash
# Produces a standalone `dist/encrypt` CLI binary.
#
# The CLI is not a containerized component: only the web encrypter ships as an
# image. This script just gets you a binary. If cargo is installed it builds
# natively; otherwise it borrows a throwaway rust container as a compiler and
# emits a statically linked musl binary that runs on any Linux with no runtime
# dependency on Docker.
#
#   ./scripts/build-cli.sh

set -euo pipefail

PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$PROJECT/dist"
RUST_IMAGE="${RUST_IMAGE:-rust:1-slim-bookworm}"
CARGO_CACHE_VOLUME="${CARGO_CACHE_VOLUME:-encrypt-cargo-cache}"

mkdir -p "$OUT_DIR"

if command -v cargo >/dev/null 2>&1; then
    printf 'Building with the local cargo toolchain\n'
    cargo build --release --locked --no-default-features --features cli --bin encrypt
    cp "$PROJECT/target/release/encrypt" "$OUT_DIR/encrypt"
else
    if ! command -v docker >/dev/null 2>&1; then
        printf 'Neither cargo nor docker is available; install one of them.\n' >&2
        exit 1
    fi

    printf 'No local cargo; compiling a static binary inside %s\n' "$RUST_IMAGE"
    docker volume create "$CARGO_CACHE_VOLUME" >/dev/null

    docker run --rm \
        -v "$PROJECT:/src:ro" \
        -v "$OUT_DIR:/out" \
        -v "$CARGO_CACHE_VOLUME:/usr/local/cargo/registry" \
        -e HOST_UID="$(id -u)" \
        -e HOST_GID="$(id -g)" \
        "$RUST_IMAGE" sh -c '
            set -e
            mkdir -p /build
            cp /src/Cargo.toml /src/Cargo.lock /build/
            cp -r /src/src /build/src
            cd /build
            rustup target add x86_64-unknown-linux-musl >/dev/null
            cargo build --release --locked --no-default-features --features cli \
                --bin encrypt --target x86_64-unknown-linux-musl
            cp target/x86_64-unknown-linux-musl/release/encrypt /out/encrypt
            chown "$HOST_UID:$HOST_GID" /out/encrypt
        '
fi

chmod +x "$OUT_DIR/encrypt"
printf '\n%s\n' "$OUT_DIR/encrypt"
"$OUT_DIR/encrypt" 2>&1 | head -3 || true
