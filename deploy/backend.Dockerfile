# Production API + async job worker binaries (workspace build).
# `fingerprint_engine serve` was removed — use `weissman-server` (see fingerprint_engine/src/main.rs).
# Build: docker compose -f docker-compose.build.yml build backend
#
# OT/ICS critical-infra engines: enabled via `high_risk_engines` on the fingerprint_engine
# dependency in weissman-server / weissman-worker Cargo.toml (transitive for this build).
#
# Compile-time paths (include_str!, workspace members) — ALL must be COPY'd before cargo build:
#   Cargo.toml/Cargo.lock · fuzz_core · fingerprint_engine · backend · crates · scripts · shared
#
# Native deps: openssl-sys, aws-lc-sys (rustls), hwlocality→hwloc+libudev,
# libsqlite3-sys (sqlx), ring, tss-esapi-sys (weissman-agent linux-gnu).
FROM rust:1.91-bookworm AS build
# Resilient apt: By-Hash fetches indices by content hash (avoids the mirror mid-sync
# "Hash Sum mismatch"), Retries handles transient CDN blips, No-Cache defeats stale proxies.
RUN printf 'Acquire::Retries "5";\nAcquire::By-Hash "yes";\nAcquire::http::No-Cache "true";\n' > /etc/apt/apt.conf.d/99resilient
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
    libtss2-dev \
    && rm -rf /var/lib/apt/lists/*
# tss-esapi-sys probes tss2-sys / tss2-esys / tss2-mu / tss2-tctildr via pkg-config.
# libtss2-dev on bookworm pulls those .so files; stage the ESAPI + device-TCTI
# sonames for the slim runtime so the gnu agent ELF can load (DT_NEEDED) without
# apt-installing the esys runtime package in debian:bookworm-slim (Depends:
# tpm-udev → udev). FAPI is not copied — the agent never links it.
RUN mkdir -p /opt/tss-runtime \
    && find /usr/lib /lib \( \
         -name 'libtss2-esys.so*' \
         -o -name 'libtss2-sys.so*' \
         -o -name 'libtss2-mu.so*' \
         -o -name 'libtss2-tctildr.so*' \
         -o -name 'libtss2-tcti-device.so*' \
       \) -exec cp -aL {} /opt/tss-runtime/ \; \
    && test -n "$(ls -A /opt/tss-runtime)"
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY fuzz_core ./fuzz_core
COPY fingerprint_engine ./fingerprint_engine
COPY backend ./backend
COPY crates ./crates
COPY scripts ./scripts
COPY shared ./shared
# Fat LTO on the full ~250-crate workspace (Cargo.toml [profile.release]) OOM-kills
# standard CI/build runners at link time. Scope the image build to thin LTO —
# near-identical runtime performance, dramatically lower peak build memory — and
# bound parallelism so the optimized (opt-level 3) compiles don't spike RAM. This
# keeps the workspace release profile (fat) intact for anyone who builds with the
# memory headroom; the shipped image just builds reliably here.
#
# ARG (not a hardcoded ENV) so CI can pass --build-arg. Previously CI sent
# CARGO_PROFILE_RELEASE_LTO=false and CODEGEN_UNITS=16 but the Dockerfile never
# declared ARG, so rustc still linked thin-LTO + codegen-units=1 and the runner
# died with exit 143 mid-link.
ARG CARGO_PROFILE_RELEASE_LTO=thin
ARG CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
ENV CARGO_PROFILE_RELEASE_LTO=$CARGO_PROFILE_RELEASE_LTO \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=$CARGO_PROFILE_RELEASE_CODEGEN_UNITS \
    CARGO_BUILD_JOBS=2 \
    CARGO_NET_RETRY=10 \
    CARGO_HTTP_MULTIPLEXING=false \
    CARGO_NET_GIT_FETCH_WITH_CLI=true
# CARGO_HTTP_MULTIPLEXING=false avoids the crates.io HTTP/2 "SSL_ERROR_SYSCALL / Failed
# sending data to the peer" fetch failures on flaky networks; retries + git-CLI add resilience.
RUN cargo build -p weissman-server -p weissman-worker -p weissman-agent \
    --release --locked

FROM debian:bookworm-slim AS runtime
# BuildKit sets TARGETARCH (amd64/arm64); the classic builder does not, so fall back to
# the runtime image's own dpkg architecture. Either way this resolves to the ONE
# architecture this image was actually compiled for.
ARG TARGETARCH
RUN printf 'Acquire::Retries "5";\nAcquire::By-Hash "yes";\nAcquire::http::No-Cache "true";\n' > /etc/apt/apt.conf.d/99resilient
# git + patch are runtime deps of the auto-heal verification sandbox: it shells out
# to `git clone`/`git diff` (to capture the applied fix) and `patch` (to apply the diff).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 postgresql-client xmlsec1 libhwloc15 libudev1 curl procps git patch \
    && rm -rf /var/lib/apt/lists/*
# TSS runtime for the in-image gnu weissman-agent (served from /srv/bin/agents).
# Copied from the builder — do not apt-install the esys runtime package here (udev).
COPY --from=build /opt/tss-runtime /usr/lib/weissman-tss
RUN echo /usr/lib/weissman-tss > /etc/ld.so.conf.d/weissman-tss.conf && ldconfig
RUN useradd -r -s /bin/false -u 65532 weissman
COPY --from=build /build/target/release/weissman-server /usr/local/bin/weissman-server
COPY --from=build /build/target/release/weissman-worker /usr/local/bin/weissman-worker
# weissman-agent is compiled natively for THIS image's architecture only. Publishing the
# same ELF under a second, foreign platform directory handed ARM endpoints an x86-64
# binary ("Exec format error" on first run), so install it solely under the directory
# that matches the build architecture. /install/binaries/<other-arch>/weissman-agent then
# returns the handler's clean 404 instead of a binary that cannot execute.
# Multi-arch: `docker buildx build --platform linux/amd64,linux/arm64`, or pre-populate
# /srv/bin/agents with scripts/package_agent_binaries.sh (cross-compiles all 4 targets).
COPY --from=build /build/target/release/weissman-agent /tmp/weissman-agent
RUN set -eu; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
      amd64) platform=linux-x86_64-gnu ;; \
      arm64) platform=linux-aarch64-gnu ;; \
      *) echo "backend.Dockerfile: unsupported agent architecture '$arch'" >&2; exit 1 ;; \
    esac; \
    mkdir -p "/srv/bin/agents/$platform"; \
    mv /tmp/weissman-agent "/srv/bin/agents/$platform/weissman-agent"; \
    chmod 755 "/srv/bin/agents/$platform/weissman-agent"
# No-tx migration pre-runner reads SQL from disk at runtime (compile-time CARGO_MANIFEST_DIR is /build/...).
COPY --from=build /build/crates/weissman-db/migrations /srv/migrations
ENV WEISSMAN_MIGRATIONS_DIR=/srv/migrations
ENV WEISSMAN_AGENT_BIN_DIR=/srv/bin/agents
USER weissman
WORKDIR /srv
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/weissman-server"]
