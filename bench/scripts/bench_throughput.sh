#!/usr/bin/env bash
# QuickTunnel Bulk Throughput Benchmark Script
# Measures raw single-stream and multi-stream TCP throughput over QuickTunnel using iperf3.

set -euo pipefail

CONTROL_PORT=7200
TCP_PORT=20500
SECRET="bench-token-$(openssl rand -hex 16 2>/dev/null || echo '0123456789abcdef0123456789abcdef')"
DURATION=5

echo "=== QuickTunnel Throughput Benchmark ==="

# Check iperf3
if ! command -v iperf3 &>/dev/null; then
    echo "iperf3 is required for bulk throughput tests. Install via 'sudo apt/dnf/pacman install iperf3'."
    exit 1
fi

# Build release binary
cargo build --release --package quicktunnel

# 1. Start local iperf3 server
iperf3 -s -p 5201 &
IPERF_PID=$!
sleep 1

# 2. Start quicktunnel server
./target/release/quicktunnel server \
    --control-bind 127.0.0.1:${CONTROL_PORT} \
    --http-bind 127.0.0.1:8888 \
    --tcp-port-range 20500-20510 \
    --secret "${SECRET}" &
SERVER_PID=$!
sleep 1

# 3. Start quicktunnel client in TCP mode forwarding 5201
./target/release/quicktunnel client \
    --to 127.0.0.1:${CONTROL_PORT} \
    --local 5201 \
    --mode tcp \
    --remote-port ${TCP_PORT} \
    --secret "${SECRET}" &
CLIENT_PID=$!
sleep 2

cleanup() {
    echo "Cleaning up processes..."
    kill ${CLIENT_PID} ${SERVER_PID} ${IPERF_PID} 2>/dev/null || true
}
trap cleanup EXIT

echo "--> Running single-stream throughput test (10s)..."
iperf3 -c 127.0.0.1 -p ${TCP_PORT} -t ${DURATION}

echo "--> Running 8 parallel streams throughput test (10s)..."
iperf3 -c 127.0.0.1 -p ${TCP_PORT} -P 8 -t ${DURATION}

echo "=== Benchmark Complete ==="
