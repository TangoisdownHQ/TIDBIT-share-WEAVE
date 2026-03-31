FROM rust:1.90-bookworm AS builder

WORKDIR /app

COPY backend-rs/Cargo.toml backend-rs/Cargo.lock ./backend-rs/
RUN mkdir -p backend-rs/src && printf 'fn main() {}\n' > backend-rs/src/main.rs
RUN cd backend-rs && cargo build --release

COPY backend-rs ./backend-rs
RUN cd backend-rs && cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && useradd --system --create-home --uid 10001 tidbit \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/backend-rs

COPY --from=builder /app/backend-rs/target/release/tidbit /usr/local/bin/tidbit
COPY --from=builder /app/backend-rs/web ./web
COPY --from=builder /app/backend-rs/migrations ./migrations

RUN chown -R tidbit:tidbit /app/backend-rs

USER tidbit

ENV PORT=4100

EXPOSE 4100

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

CMD ["tidbit", "server"]
