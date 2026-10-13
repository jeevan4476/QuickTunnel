# QuickTunnel Benchmarking Plan & Performance Suite

This directory contains the micro-benchmarks, end-to-end load generation scripts, and methodology for evaluating QuickTunnel's throughput, latency, concurrency, and multiplexer fairness as specified in §18 of `quicktunnel-technical-design.md`.

---

## 1. Benchmark Suites

### A. Criterion Micro-Benchmarks (`bench/benches/`)
Measures nanosecond-level protocol and framing primitives in isolation:
- **`framing`**:
  - `frame_encode`: Serializing fixed 12-byte header + payload at 64B, 1 KiB, and 16 KiB frame sizes.
  - `frame_decode`: Streaming `FrameAssembler` decoding throughput and CRC32C validation.
  - `header_decode`: Decoding fixed 12-byte QTP header struct from byte slices.
- **`mux`**:
  - `flow_control`: Send/receive credit window consumption and replenishment.
  - `in_memory_mux_transfer`: Full bi-directional stream transfer over Tokio duplex pipes.

**Run Criterion benchmarks:**
```bash
cargo bench --package qt-bench
```

---

### B. End-to-End Bulk Throughput (`bench/scripts/bench_throughput.sh`)
Measures maximum network throughput using `iperf3` over a TCP-mode reverse tunnel:
- **Single Stream Throughput**: Tests single-connection maximum bandwidth.
- **Parallel Scaling**: Tests 8 to 32 parallel streams (`iperf3 -P 8`) through the multiplexer session.

**Run throughput benchmark:**
```bash
chmod +x bench/scripts/bench_throughput.sh
./bench/scripts/bench_throughput.sh
```

---

### C. Request Latency & Concurrency (`bench/scripts/bench_latency.sh`)
Measures latency overhead added by the QTP multiplexer and proxy hops using `wrk` or `hey`:
- Concurrency levels: 10, 50, 100, 500, 1000 concurrent client streams.
- Metrics recorded: p50, p90, p99, and p99.9 latency distributions.

**Run latency benchmark:**
```bash
chmod +x bench/scripts/bench_latency.sh
./bench/scripts/bench_latency.sh
```

---

### D. DRR Multiplexer Fairness (`bench/scripts/fairness.py`)
Validates that QuickTunnel's Deficit Round-Robin (DRR) scheduler (§6.4) prevents head-of-line blocking:
- Compares small-request round-trip latency on an idle tunnel vs. under 8 saturated bulk transfers.
- Ensures small-packet p95 latency remains bounded under full connection saturation.

**Run fairness benchmark:**
```bash
python3 bench/scripts/fairness.py
```

---

## 2. Profiling & Flamegraphs

To generate CPU flamegraphs and identify hot paths:

```bash
# Install cargo-flamegraph
cargo install flamegraph

# Run quicktunnel server under perf/dtrace sampling
cargo flamegraph --bin quicktunnel -- server --control-bind 0.0.0.0:7000 --secret test
```

The resulting `flamegraph.svg` can be opened in any browser to inspect instruction and allocation profiles.
