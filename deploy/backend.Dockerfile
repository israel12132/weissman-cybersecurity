# Production API + async job worker binaries (workspace build).
# `fingerprint_engine serve` was removed — use `weissman-server` (see fingerprint_engine/src/main.rs).
# Build: docker compose build backend
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
RUN cargo build -p weissman-server -p weissman-worker --release --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 postgresql-client xmlsec1 libhwloc15 libudev1 curl procps \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/false -u 65532 weissman
COPY --from=build /build/target/release/weissman-server /usr/local/bin/weissman-server
COPY --from=build /build/target/release/weissman-worker /usr/local/bin/weissman-worker
USER weissman
WORKDIR /srv
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/weissman-server"]
