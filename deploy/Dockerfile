# syntax=docker/dockerfile:1
# Multi-stage build for QuickTunnel: minimal, secure, statically linked binary

FROM rust:1.80-alpine AS builder

WORKDIR /usr/src/quicktunnel

# Install build dependencies
RUN apk add --no-cache musl-dev perl make pkgconfig gcc

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY crates/qt-proto/Cargo.toml crates/qt-proto/
COPY crates/qt-mux/Cargo.toml crates/qt-mux/
COPY crates/qt-server/Cargo.toml crates/qt-server/
COPY crates/qt-client/Cargo.toml crates/qt-client/
COPY crates/qt-inspector-ui/Cargo.toml crates/qt-inspector-ui/
COPY crates/quicktunnel/Cargo.toml crates/quicktunnel/
COPY fuzz/Cargo.toml fuzz/

# Copy all source trees
COPY . .

# Build statically linked release binary
RUN RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --package quicktunnel

# Final minimal scratch runtime container
FROM alpine:3.20 AS runtime

RUN apk add --no-cache ca-certificates tzdata libcap \
    && addgroup -S quicktunnel && adduser -S quicktunnel -G quicktunnel

WORKDIR /app

# Copy binary from builder
COPY --from=builder /usr/src/quicktunnel/target/release/quicktunnel /usr/local/bin/quicktunnel

# Grant binary permission to bind to low ports (80/443) without running as root
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/quicktunnel

USER quicktunnel

# Control port (7000), HTTP visitor port (80), Web Inspector (4040)
EXPOSE 7000 80 4040

ENTRYPOINT ["quicktunnel"]
CMD ["server", "--control-bind", "0.0.0.0:7000", "--http-bind", "0.0.0.0:80", "--domain", "tunnel.local"]
