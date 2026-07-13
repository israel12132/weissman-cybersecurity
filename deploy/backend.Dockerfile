# Production API + async job worker binaries (workspace build).
# `fingerprint_engine serve` was removed — use `weissman-server` (see fingerprint_engine/src/main.rs).
# Build: docker compose build backend
#
# OT/ICS critical-infra engines: enabled via `high_risk_engines` on the fingerprint_engine
# dependency in weissman-server / weissman-worker Cargo.toml (transitive for this build).
#
# Compile-time paths (include_str!, workspace members) — ALL must be COPY'd before cargo build:
#   Cargo.toml/Cargo.lock · fuzz_core · fingerprint_engine · backend · crates · scripts · shared
#
# Native deps: openssl-sys, aws-lc-sys (rustls), hwlocality→hwloc+libudev, libsqlite3-sys (sqlx), ring.
FROM rust:1.91-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    git \
    ninja-build \
    pkg-config \
    perl \
    libssl-dev \
    libhwloc-dev \
    libudev-dev \
    zlib1g-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY fuzz_core ./fuzz_core
COPY fingerprint_engine ./fingerprint_engine
COPY backend ./backend
COPY crates ./crates
COPY scripts ./scripts
COPY shared ./shared
RUN cargo build -p weissman-server -p weissman-worker -p weissman-agent \
    --release --locked

FROM debian:bookworm-slim AS runtime
# git + patch are runtime deps of the auto-heal verification sandbox: it shells out
# to `git clone`/`git diff` (to capture the applied fix) and `patch` (to apply the diff).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 postgresql-client xmlsec1 libhwloc15 libudev1 curl procps git patch \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/false -u 65532 weissman \
    && mkdir -p /srv/bin/agents/linux-x86_64-gnu /srv/bin/agents/linux-aarch64-gnu
COPY --from=build /build/target/release/weissman-server /usr/local/bin/weissman-server
COPY --from=build /build/target/release/weissman-worker /usr/local/bin/weissman-worker
COPY --from=build /build/target/release/weissman-agent /srv/bin/agents/linux-x86_64-gnu/weissman-agent
COPY --from=build /build/target/release/weissman-agent /srv/bin/agents/linux-aarch64-gnu/weissman-agent
RUN chmod 755 /srv/bin/agents/linux-x86_64-gnu/weissman-agent \
    /srv/bin/agents/linux-aarch64-gnu/weissman-agent
# No-tx migration pre-runner reads SQL from disk at runtime (compile-time CARGO_MANIFEST_DIR is /build/...).
COPY --from=build /build/crates/weissman-db/migrations /srv/migrations
ENV WEISSMAN_MIGRATIONS_DIR=/srv/migrations
ENV WEISSMAN_AGENT_BIN_DIR=/srv/bin/agents
USER weissman
WORKDIR /srv
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/weissman-server"]
