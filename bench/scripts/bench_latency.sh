#!/usr/bin/env bash
# QuickTunnel HTTP Latency and Concurrency Benchmark Script
# Uses wrk or hey to measure p50, p90, p99, and p99.9 latency under load.

set -euo pipefail

CONTROL_PORT=7210
HTTP_PORT=8890
LOCAL_PORT=3344
SECRET="bench-latency-token"

echo "=== QuickTunnel Latency & Concurrency Benchmark ==="

# Build release
cargo build --release --package quicktunnel

# Start minimal echo backend (Node.js if available, otherwise python3)
if command -v node &>/dev/null; then
    node -e "
    const http = require('http');
    const s = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': '2' });
        res.end('ok');
    });
    s.listen(${LOCAL_PORT}, '127.0.0.1');
    " &
    BACKEND_PID=$!
else
    python3 -c "
    from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
    class H(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'ok')
            self.wfile.flush()
        def log_message(self, *args): pass
    s = ThreadingHTTPServer(('127.0.0.1', ${LOCAL_PORT}), H)
    s.serve_forever()
    " &
    BACKEND_PID=$!
fi

# Start server
./target/release/quicktunnel server \
    --control-bind 127.0.0.1:${CONTROL_PORT} \
    --http-bind 127.0.0.1:${HTTP_PORT} \
    --domain bench.local \
    --secret "${SECRET}" &
SERVER_PID=$!
sleep 1

# Start client
./target/release/quicktunnel client \
    --to 127.0.0.1:${CONTROL_PORT} \
    --local ${LOCAL_PORT} \
    --subdomain echo \
    --secret "${SECRET}" \
    --no-inspect &
CLIENT_PID=$!
sleep 2

cleanup() {
    kill ${CLIENT_PID} ${SERVER_PID} ${BACKEND_PID} 2>/dev/null || true
}
trap cleanup EXIT

TARGET_URL="http://127.0.0.1:${HTTP_PORT}/"
HOST_HEADER="Host: echo.bench.local"

if command -v wrk &>/dev/null; then
    echo "--> Running wrk benchmark (100 concurrency, 10s)..."
    wrk -t4 -c100 -d10s -H "${HOST_HEADER}" "${TARGET_URL}"
elif command -v hey &>/dev/null; then
    echo "--> Running hey benchmark (100 concurrency, 10,000 requests)..."
    hey -n 10000 -c 100 -H "${HOST_HEADER}" "${TARGET_URL}"
elif command -v ab &>/dev/null; then
    echo "--> Running ApacheBench (ab) benchmark (20 concurrency, 2,000 requests, keep-alive)..."
    ab -k -n 2000 -c 20 -H "${HOST_HEADER}" "${TARGET_URL}"
else
    echo "Neither wrk nor hey found. Running curl 1000 requests sequential benchmark..."
    time for i in $(seq 1 1000); do
        curl -s -H "${HOST_HEADER}" "${TARGET_URL}" >/dev/null
    done
fi

echo "=== Benchmark Complete ==="
