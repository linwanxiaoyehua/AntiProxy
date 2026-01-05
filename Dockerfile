# syntax=docker/dockerfile:1

FROM rust:1.83-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config ca-certificates libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY web ./web
COPY web_config.json ./web_config.json

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/anti-proxy /app/anti-proxy
COPY --from=builder /app/web /app/web
COPY --from=builder /app/web_config.json /app/web_config.json

RUN mkdir -p /root/.anti-proxy \
    && sed \
      -e 's/"enabled": false/"enabled": true/' \
      -e 's/"allow_lan_access": false/"allow_lan_access": true/' \
      /app/web_config.json \
      > /root/.anti-proxy/web_config.json

EXPOSE 8045

ENV RUST_LOG=info
ENV ANTI_PROXY_ALLOW_LAN=1
ENV ANTI_PROXY_BIND=0.0.0.0
ENV ANTI_PROXY_PUBLIC_URL=http://127.0.0.1:8045

CMD ["/app/anti-proxy"]
