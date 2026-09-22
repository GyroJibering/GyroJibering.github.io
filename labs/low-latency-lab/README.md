# Low-latency C++ lab

This directory contains the executable code used by the four blog posts dated
2026-09-22. It is intentionally small enough to audit: no queue or benchmark
dependency is hidden behind a library.

## What is here

- `include/ll/spsc_queue.hpp`: bounded, allocation-free SPSC queue with a
  documented acquire/release proof.
- `include/ll/bounded_mpmc_queue.hpp`: bounded MPMC ring with per-slot sequence
  numbers. It uses no mutex but does **not** claim the formal lock-free progress
  guarantee.
- `include/ll/market.hpp`: fixed-depth order book and messages carrying market,
  decision, and order sequence numbers.
- `src/trading_loop.cpp`: feed -> book -> strategy -> order-entry pipeline.
- `src/benchmark.cpp`: separate latency and throughput experiments. The latency
  experiment permits only one message in flight.
- `src/mpmc_benchmark.cpp`: 1P/1C, 2P/2C, and 4P/4C contention experiment.
- `src/journal_demo.cpp`: Linux-only single-writer `mmap` journal with per-record
  commit markers, checksums, and an `eventfd`-driven background flusher.
- `tests/stress.cpp`: million-message ordering, loss/duplicate, and sequence-gap
  checks.

## Build and run

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel
./build-release/stress
./build-release/benchmark
./build-release/mpmc_benchmark
./build-release/trading_loop
./build-release/journal_demo market.journal   # Linux only
```

For Linux counter sampling and a call graph:

```bash
./scripts/perf.sh
```

Run benchmarks on an otherwise idle machine. Keep the CPU governor, affinity,
SMT placement, compiler, and binary fixed when comparing changes. `RDTSC`
reports TSC ticks, not necessarily core clock cycles; `perf stat` supplies the
hardware `cycles` and `instructions` counters.

## Deliberate limits

This is a learning system, not an exchange gateway. It omits protocol decoding,
snapshot recovery, NUMA placement, kernel bypass, production risk limits, order
session recovery, and formal linearizability verification. The journal's
`MS_ASYNC` flush is an asynchronous writeback request; only the final `MS_SYNC`
waits for completion. Checksums detect torn records during recovery but cannot
make ordinary storage power-loss atomic.
