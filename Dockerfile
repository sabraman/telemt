# syntax=docker/dockerfile:1

# ==========================
# Stage 1: Build
# ==========================
FROM rust:1.88-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Depcache
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Build
COPY . .
RUN cargo build --release && strip target/release/telemt

# ==========================
# Stage 2: Compress (strip + UPX)
# ==========================
FROM debian:12-slim AS minimal

RUN apt-get update && apt-get install -y --no-install-recommends \
    upx \
    binutils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/telemt /telemt

RUN strip /telemt || true
RUN upx --best --lzma /telemt || true

# ==========================
# Stage 3: Debug base
# ==========================
FROM debian:12-slim AS debug-base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    curl \
    iproute2 \
    busybox \
    && rm -rf /var/lib/apt/lists/*

# ==========================
# Stage 4: Debug image
# ==========================
FROM debug-base AS debug

WORKDIR /app

COPY --from=minimal /telemt /app/telemt
COPY config.toml /app/config.toml

USER root

EXPOSE 443
EXPOSE 9090
EXPOSE 9091

ENTRYPOINT ["/app/telemt"]
CMD ["config.toml"]

# ==========================
# Stage 5: Production (distroless)
# ==========================
FROM gcr.io/distroless/base-debian12 AS prod

WORKDIR /app

COPY --from=minimal /telemt /app/telemt
COPY config.toml /app/config.toml

# TLS + timezone + shell
COPY --from=debug-base /etc/ssl/certs /etc/ssl/certs
COPY --from=debug-base /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=debug-base /bin/busybox /bin/busybox

RUN ["/bin/busybox", "--install", "-s", "/bin"]

# distroless user
USER nonroot:nonroot

EXPOSE 443
EXPOSE 9090
EXPOSE 9091

ENTRYPOINT ["/app/telemt"]
CMD ["config.toml"]
