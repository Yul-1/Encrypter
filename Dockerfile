# syntax=docker/dockerfile:1

# Only the web encrypter is containerized. The CLI is a standalone binary:
# build it with `cargo build --release` or `./scripts/build-cli.sh`, which
# needs Docker only as a compiler and produces a binary with no runtime
# dependency on it.
#
# The service is built without the "cli" feature, so the filesystem module
# (secure deletion, directory recursion) is not linked into it at all.

ARG RUST_IMAGE=rust:1-slim-bookworm

FROM ${RUST_IMAGE} AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# The target dir is a cache mount, so the artifact is copied out in the same layer
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --release --locked --no-default-features --features web --bin encrypt-web \
 && mkdir -p /out \
 && cp target/release/encrypt-web /out/


# Distroless: no shell, no package manager, non-root by default
FROM gcr.io/distroless/cc-debian12:nonroot AS web
COPY --from=builder /out/encrypt-web /usr/local/bin/encrypt-web
USER 65532:65532
ENV ENCRYPT_WEB_BIND=0.0.0.0:8080 \
    ENCRYPT_WEB_MAX_UPLOAD_MB=64 \
    ENCRYPT_WEB_CONCURRENCY=2
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/encrypt-web", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/encrypt-web"]
