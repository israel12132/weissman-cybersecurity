# Production: WASM crates + Vite build + Nginx gateway (static SPA + /api /ws → backend)
#
# Build context MUST include (repo root):
#   frontend/ · scripts/ · backend/ · fingerprint_engine/ · shared/
#   Cargo workspace (for weissman-ast-cap + weissman-ui-provenance WASM)
#
# Stage 1 — Rust WASM (ast-cap, ui-provenance)
FROM rust:1.91-bookworm AS wasm-build
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
RUN rustup target add wasm32-unknown-unknown \
    && cargo install wasm-bindgen-cli --locked \
    && bash scripts/build-ui-provenance-wasm.sh \
    && bash scripts/build-ast-cap-wasm.sh

# Stage 2 — Vite production bundle (engine param defs + SPA)
FROM node:22-bookworm-slim AS vite-build
# Lockfile is generated with npm 11; bookworm-slim ships npm 10 — align before `npm ci`.
RUN npm install -g npm@11.12.1
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./frontend/
RUN cd frontend && npm ci --ignore-scripts
COPY frontend ./frontend
COPY scripts ./scripts
COPY backend ./backend
COPY fingerprint_engine ./fingerprint_engine
COPY shared ./shared
COPY --from=wasm-build /build/frontend/src/wasm ./frontend/src/wasm
WORKDIR /build/frontend
RUN node ../scripts/generate_engine_param_defs.mjs && npx vite build

# Stage 3 — Nginx gateway (non-root, :8080 inside → :80 on host)
FROM nginxinc/nginx-unprivileged:1.31-alpine
USER root
RUN apk add --no-cache curl
COPY deploy/nginx-gateway.conf          /etc/nginx/conf.d/default.conf
COPY deploy/nginx-security-headers.inc  /etc/nginx/conf.d/security-headers.inc
COPY --from=vite-build /build/frontend/dist /usr/share/nginx/html/command-center
COPY deploy/public                      /usr/share/nginx/html/public
USER 101
EXPOSE 8080
