# Weissman OAST listener (out-of-band interaction correlation).
# Workspace members must all exist even when building a single crate.
FROM rust:1.91-bookworm AS build
RUN printf 'Acquire::Retries "5";\nAcquire::By-Hash "yes";\nAcquire::http::No-Cache "true";\n' > /etc/apt/apt.conf.d/99resilient
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY fuzz_core ./fuzz_core
COPY fingerprint_engine ./fingerprint_engine
COPY backend ./backend
COPY crates ./crates
COPY shared ./shared
ENV CARGO_NET_RETRY=10 \
    CARGO_HTTP_MULTIPLEXING=false \
    CARGO_NET_GIT_FETCH_WITH_CLI=true
RUN cargo build -p weissman-oast-server --release --locked

FROM debian:bookworm-slim AS runtime
RUN printf 'Acquire::Retries "5";\nAcquire::By-Hash "yes";\nAcquire::http::No-Cache "true";\n' > /etc/apt/apt.conf.d/99resilient
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/false -u 65533 oast
COPY --from=build /build/target/release/weissman-oast-server /usr/local/bin/weissman-oast-server
USER oast
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/weissman-oast-server"]
