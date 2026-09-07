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
RUN apt-get -o Acquire::Retries=5 update && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY crates/ ./crates/
RUN cargo build --release -p relay-panel

# ---- Build stage for the Rust workspace (node only) ----
FROM rust:1-bookworm AS node-build
RUN apt-get -o Acquire::Retries=5 update && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY crates/ ./crates/
RUN cargo build --release -p relay-node

# ---- Panel runtime ----
FROM debian:bookworm-slim AS panel
ARG OCI_VERSION=dev
ARG OCI_REVISION=unknown
LABEL org.opencontainers.image.version=$OCI_VERSION \
      org.opencontainers.image.revision=$OCI_REVISION \
      org.opencontainers.image.source="https://github.com/MoeShinX/relay-panel"
RUN apt-get -o Acquire::Retries=5 update && \
    apt-get -o Acquire::Retries=5 install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=panel-build /app/target/release/relay-panel /app/relay-panel
COPY --from=frontend-build /frontend/dist /app/public
VOLUME ["/app/data"]
EXPOSE 18888
ENV DATABASE_URL="sqlite:/app/data/data.db?mode=rwc" \
    LISTEN="0.0.0.0:18888" \
    PUBLIC_DIR="/app/public"
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
    CMD curl --fail --silent --show-error http://127.0.0.1:18888/api/v1/health >/dev/null || exit 1
CMD ["./relay-panel"]

# ---- Node runtime ----
FROM debian:bookworm-slim AS node
ARG OCI_VERSION=dev
ARG OCI_REVISION=unknown
LABEL org.opencontainers.image.version=$OCI_VERSION \
      org.opencontainers.image.revision=$OCI_REVISION \
      org.opencontainers.image.source="https://github.com/MoeShinX/relay-panel"
# v1.0.5: iproute2 provides the `ip` command used to resolve an interface's
# IPv4 address when OUTBOUND_INTERFACE is set. Without it, multi-NIC egress
# selection by interface name would fail. ca-certificates is for HTTPS to the
# panel.
RUN apt-get -o Acquire::Retries=5 update && \
    apt-get -o Acquire::Retries=5 install -y --no-install-recommends ca-certificates iproute2 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV RELAY_BUILD_VERSION=$OCI_VERSION
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
RUN apt-get -o Acquire::Retries=5 update && \
    apt-get -o Acquire::Retries=5 install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY release-dist/panel/relay-panel /app/relay-panel
RUN chmod +x /app/relay-panel
COPY release-dist/frontend /app/public
VOLUME ["/app/data"]
EXPOSE 18888
ENV DATABASE_URL="sqlite:/app/data/data.db?mode=rwc" \
    LISTEN="0.0.0.0:18888" \
    PUBLIC_DIR="/app/public"
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
    CMD curl --fail --silent --show-error http://127.0.0.1:18888/api/v1/health >/dev/null || exit 1
CMD ["./relay-panel"]
