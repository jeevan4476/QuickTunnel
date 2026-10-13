#!/usr/bin/env bash
# QuickTunnel DRR Scheduler Fairness Benchmark Script
# Measures small-request latency under concurrent bulk background load to prove
# absence of Head-of-Line (HoL) blocking.

set -euo pipefail

CONTROL_PORT=7215
HTTP_PORT=8895
LOCAL_PORT=3348
SECRET="bench-fairness-token"

echo "=== QuickTunnel DRR Scheduler Fairness Benchmark ==="

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

# Run fairness probe script with target ports
TARGET_URL="http://127.0.0.1:${HTTP_PORT}/" python3 bench/scripts/fairness.py
