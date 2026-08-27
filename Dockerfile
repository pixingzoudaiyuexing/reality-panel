# ---- Build stage for the React frontend ----
FROM node:20-alpine AS frontend-build
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund || npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- Build stage for the Rust workspace (panel only) ----
# v1.2: panel and node release on independent tracks. Each image compiles ONLY
# its own crate (panel-build / node-build), so a panel-only release does not
# compile relay-node and a node-only release does not compile relay-panel. The
# runtime stages copy only their own binary.
FROM rust:1-bookworm AS panel-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY crates/ ./crates/
COPY scripts/relay-node-bootstrap.sh ./scripts/relay-node-bootstrap.sh
COPY scripts/relay-node-manual-bootstrap.sh ./scripts/relay-node-manual-bootstrap.sh
RUN cargo build --release -p relay-panel

# ---- Build stage for the Rust workspace (node only) ----
FROM rust:1-bookworm AS node-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY crates/ ./crates/
RUN cargo build --release -p relay-node && \
    sed -n 's/^version = "\([^"]*\)"/\1/p' crates/node/Cargo.toml | head -n1 > /app/node-version

# ---- Panel runtime ----
FROM debian:bookworm-slim AS panel
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=panel-build /app/target/release/relay-panel /app/relay-panel
COPY --from=frontend-build /frontend/dist /app/public
# Local/source builds provide the host-architecture artifact in the same
# canonical layout used by release images. Production multi-arch images use
# the panel-release stage below, which supplies both architectures.
ARG TARGETARCH
RUN install -d -m 0755 /app/node-assets/${TARGETARCH}
COPY --from=node-build /app/target/release/relay-node /tmp/relay-node
COPY --from=node-build /app/node-version /tmp/node-version
RUN install -m 0755 /tmp/relay-node /app/node-assets/${TARGETARCH}/relay-node && \
    sha256sum /app/node-assets/${TARGETARCH}/relay-node | awk '{print $1}' > /tmp/node-sha && \
    printf '{"version":"%s","sha256":"%s","size":%s}\n' "$(cat /tmp/node-version)" "$(cat /tmp/node-sha)" "$(wc -c < /app/node-assets/${TARGETARCH}/relay-node)" > /app/node-assets/${TARGETARCH}/metadata.json && \
    chmod 0644 /app/node-assets/${TARGETARCH}/metadata.json
VOLUME ["/app/data"]
EXPOSE 18888
ENV DATABASE_URL="sqlite:/app/data/data.db?mode=rwc" \
    LISTEN="0.0.0.0:18888" \
    PUBLIC_DIR="/app/public"
CMD ["./relay-panel"]

# ---- Node runtime ----
FROM debian:bookworm-slim AS node
# v1.0.5: iproute2 provides the `ip` command used to resolve an interface's
# IPv4 address when OUTBOUND_INTERFACE is set. Without it, multi-NIC egress
# selection by interface name would fail. ca-certificates is for HTTPS to the
# panel.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=node-build /app/target/release/relay-node /app/relay-node
# ENTRYPOINT (not CMD) so `docker run image --version` appends the flag to the
# binary instead of replacing it. With CMD, `docker run image --version` tries
# to execute "--version" as a program (the release verify job hit this).
ENTRYPOINT ["./relay-node"]

# ---- Panel release image (used by docker-release.yml for multi-arch publishing) ----
# v1.3: panel and node release on independent tracks. This stage produces a
# panel image from a pre-compiled binary + pre-built frontend (both supplied by
# the CI job, not baked into the image). Unlike the build-time `panel` stage,
# it accepts the binary from any host architecture, so the same Dockerfile can
# produce `linux/amd64` and `linux/arm64` images from their respective native
# runners without QEMU or cross-compilation toolchains.
FROM debian:bookworm-slim AS panel-release
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY release-dist/panel/relay-panel /app/relay-panel
RUN chmod +x /app/relay-panel
COPY release-dist/frontend /app/public
COPY release-dist/node-assets /app/node-assets
RUN for arch in amd64 arm64; do \
      test -s "/app/node-assets/$arch/relay-node"; \
      test -s "/app/node-assets/$arch/metadata.json"; \
      sha=$(sed -n 's/.*"sha256":"\([0-9A-Fa-f]\{64\}\)".*/\1/p' "/app/node-assets/$arch/metadata.json"); \
      size=$(sed -n 's/.*"size":\([0-9]\{1,\}\).*/\1/p' "/app/node-assets/$arch/metadata.json"); \
      test -n "$sha"; \
      test "$size" = "$(wc -c < /app/node-assets/$arch/relay-node)"; \
      printf '%s  %s\n' "$sha" "/app/node-assets/$arch/relay-node" | sha256sum -c -; \
    done && \
    find /app/node-assets -type f -name relay-node -exec chmod 0755 {} + && \
    find /app/node-assets -type f -name metadata.json -exec chmod 0644 {} +
VOLUME ["/app/data"]
EXPOSE 18888
ENV DATABASE_URL="sqlite:/app/data/data.db?mode=rwc" \
    LISTEN="0.0.0.0:18888" \
    PUBLIC_DIR="/app/public"
CMD ["./relay-panel"]
