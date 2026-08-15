# Production: WASM crates + Vite build + Nginx gateway (static SPA + /api /ws → backend)
#
# Build context MUST include (repo root):
#   frontend/ · scripts/ · backend/ · fingerprint_engine/ · shared/
#   Cargo workspace (for weissman-ast-cap + weissman-ui-provenance WASM)
#
# Stage 1 — Rust WASM (ast-cap, ui-provenance)
FROM rust:1.91-bookworm AS wasm-build
# Resilient apt (By-Hash avoids "Hash Sum mismatch" on mid-sync mirrors; + retries/no-cache).
RUN printf 'Acquire::Retries "5";\nAcquire::By-Hash "yes";\nAcquire::http::No-Cache "true";\n' > /etc/apt/apt.conf.d/99resilient
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY fuzz_core ./fuzz_core
COPY fingerprint_engine ./fingerprint_engine
COPY backend ./backend
COPY crates ./crates
COPY shared ./shared
COPY scripts ./scripts
COPY frontend/package.json frontend/package-lock.json* ./frontend/
RUN mkdir -p frontend/src/wasm
# Cargo network resilience (flaky networks: crates.io HTTP/2 SSL_ERROR_SYSCALL fetch fails).
ENV CARGO_NET_RETRY=10 \
    CARGO_HTTP_MULTIPLEXING=false \
    CARGO_NET_GIT_FETCH_WITH_CLI=true
    # Pin the CLI to the wasm-bindgen crate version in Cargo.lock (0.2.122). An unpinned
    # `cargo install` picks the latest, which mismatches the compiled .wasm's schema and
    # fails the build ("schema version mismatch") — a classic non-reproducible-build trap.
RUN rustup target add wasm32-unknown-unknown \
    && cargo install wasm-bindgen-cli --locked --version 0.2.122 \
    && bash scripts/build-ui-provenance-wasm.sh \
    && bash scripts/build-ast-cap-wasm.sh

# Stage 2 — Vite production bundle (engine param defs + SPA)
FROM node:22-bookworm-slim AS vite-build
# Lockfile is generated with npm 11; bookworm-slim ships npm 10 — align before `npm ci`.
RUN npm install -g npm@11.12.1
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./frontend/
# npm network resilience for flaky registries (more retries, longer backoff).
RUN npm config set fetch-retries 5 \
    && npm config set fetch-retry-factor 3 \
    && npm config set fetch-retry-mintimeout 20000 \
    && npm config set fetch-retry-maxtimeout 120000
RUN cd frontend && npm ci --ignore-scripts
COPY frontend ./frontend
COPY scripts ./scripts
COPY backend ./backend
COPY fingerprint_engine ./fingerprint_engine
COPY shared ./shared
COPY --from=wasm-build /build/frontend/src/wasm ./frontend/src/wasm
WORKDIR /build/frontend
# Run the SAME gates `npm run build` runs, not just vite. The image previously invoked
# `npx vite build` directly, skipping verify-import-cycles and verify-provider-wiring — so a
# production image could be built from a tree those checks would have rejected, and only CI
# (which does run `npm run build`) would ever notice. An image build that is weaker than the
# CI build is a gap you find in production.
#
# Both are offline: verify-provider-wiring is pure node, and verify-import-cycles now resolves
# madge from node_modules (exact-pinned devDependency) instead of fetching it with `npx --yes`.
RUN node ../scripts/generate_engine_param_defs.mjs \
 && node ../scripts/verify-import-cycles.mjs \
 && node ../scripts/verify-provider-wiring.mjs \
 && npx vite build

# Stage 3 — Nginx gateway (non-root, :8080 inside → :80 on host)
FROM nginxinc/nginx-unprivileged:1.29-alpine
USER root
RUN apk add --no-cache curl
COPY deploy/nginx-gateway.conf          /etc/nginx/conf.d/default.conf
COPY deploy/nginx-security-headers.inc  /etc/nginx/conf.d/security-headers.inc
COPY --from=vite-build /build/frontend/dist /usr/share/nginx/html/command-center
COPY deploy/public                      /usr/share/nginx/html/public
USER 101
EXPOSE 8080
