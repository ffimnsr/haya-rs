# syntax=docker/dockerfile:1.7

FROM docker.io/library/rust:slim-bookworm AS builder

WORKDIR /src

ENV CARGO_HOME=/usr/local/cargo

RUN apt-get update \
  && apt-get install --yes --no-install-recommends \
    ca-certificates \
    libssl-dev \
    pkg-config \
  && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY templates ./templates

RUN --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/usr/local/cargo/git \
  --mount=type=cache,target=/src/target \
  cargo build --locked --release \
  && cp target/release/haya /tmp/haya

FROM gcr.io/distroless/base-debian12:nonroot

WORKDIR /app

ENV PORT=9999
ENV HAYA_PID_FILE=/tmp/haya.pid

COPY --from=builder /tmp/haya /usr/local/bin/haya
COPY --from=builder /src/migrations ./migrations
COPY --from=builder /src/templates ./templates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/lib/x86_64-linux-gnu/libssl.so.3 /usr/lib/x86_64-linux-gnu/libssl.so.3
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3
COPY --from=builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/libgcc_s.so.1
COPY --from=builder /lib/x86_64-linux-gnu/libz.so.1 /lib/x86_64-linux-gnu/libz.so.1

EXPOSE 9999

ENTRYPOINT ["/usr/local/bin/haya"]
