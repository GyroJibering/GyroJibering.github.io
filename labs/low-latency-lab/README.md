# Low-latency lab: contracts, counterexamples and measurements

C++20 / x86-64. This is a set of research artifacts, not a production trading
engine. Four articles under `_posts/2026-09-22-*` explain the contracts and
separate implemented behavior from proposed extensions.

## Build

Linux / Windows with CMake and a C++20 toolchain:

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel
ctest --test-dir build-release --output-on-failure
```

On multi-config generators use `--config Release` and `ctest -C Release`.
Tests use always-enabled checks; they do not disappear under NDEBUG.

This session used Zig 0.15.2's Clang 20.1.2 directly on Windows:

```powershell
zig c++ -std=c++20 -O3 -Wall -Wextra -Wpedantic -pthread -Iinclude tests/research.cpp -o build-zig/research.exe
zig c++ -std=c++20 -O3 -Wall -Wextra -Wpedantic -pthread -Iinclude tests/stress.cpp -o build-zig/stress.exe
zig c++ -std=c++20 -O3 -Wall -Wextra -Wpedantic -pthread -Iinclude src/trading_loop.cpp -o build-zig/trading_loop.exe
zig c++ -std=c++20 -O3 -Wall -Wextra -Wpedantic -pthread -Iinclude src/benchmark.cpp -o build-zig/benchmark.exe
zig c++ -std=c++20 -O1 -g -fsanitize=undefined -fno-sanitize-recover=all -pthread -Iinclude tests/research.cpp -o build-zig/research-ubsan.exe
```

Create `build-zig` before these commands. The Linux-only journal was cross-compiled:

```bash
zig c++ -target x86_64-linux-gnu -std=c++20 -O3 -Wall -Wextra -Wpedantic -pthread -Iinclude src/journal_demo.cpp -o build-zig/journal_demo
```

CMake is supplied for reproduction; it was not available on this session's host.
Direct compiler builds and Windows tests were actually run. Cross-compilation
is not a Linux runtime test.

## Evidence and boundaries

| Artifact | Actual claim |
|---|---|
| `include/ll/spsc_queue.hpp` | SPSC only; nothrow element operations; acquire/release publication and slot recycling; safe destruction requires quiescence |
| `include/ll/bounded_mpmc_queue.hpp` | Bounded no-mutex ring; false means next slot unavailable; does not implement a strict-empty lock-free FIFO contract |
| `tests/research.cpp` | Deterministic reservation hole; full/empty and counter-wrap boundaries; book quarantine/snapshot behavior; seeded differential book; byte-level journal fault injection |
| `tests/stress.cpp` | One million SPSC ordered messages and 4P/4C exact set verification |
| `src/trading_loop.cpp` | Synthetic single-stream pipeline, not transport recovery/risk/session implementation |
| `include/ll/journal_format.hpp` | Versioned little-endian bytes, CRC32C, offline valid-prefix recovery |
| `src/journal_demo.cpp` | Linux single-writer mmap with MS_SYNC worker, separate published/durable watermarks; runtime untested here |
| `src/benchmark.cpp` | Same-origin serialized-TSC RTT; checked topology/affinity; equal-quota throughput with mutex comparison |

Queue-owned storage is allocation-free; arbitrary T may still allocate or block.
Finite MPMC tags require bounded observation age. The book never silently drops
deep levels: capacity failure latches quarantine.

## Benchmark

```bash
./build-release/benchmark all
./build-release/benchmark spsc
./build-release/benchmark mpmc
bash scripts/perf.sh
```

RTT is two SPSC queues with one request in flight. It includes a conservative
CPUID/RDTSC/CPUID timestamp framework; the empty framework is separately printed.
Do not divide RTT by two or subtract percentiles to claim single-call latency.
The implementation is x86-specific; the Windows path supports one processor
group. CPU affinity errors abort the experiment.

The throughput workload uses 16-byte id/inverse messages and 1024 usable slots.
Each consumer completes a fixed quota; no per-message shared completion counter.
Thread-local checksums are verified after joins. They supplement, not replace,
the stress test's exact set check. Trials are fixed-work and short; no claim of
open-loop saturation, fairness or stable maximum arrival rate is made.

The final benchmark ran without concurrent builds/tests dispatched by this task.
The desktop OS remained active; no core isolation, fixed-frequency guarantee,
scheduler traces or PMU evidence is claimed. See `results/RESEARCH.md`.

## Journal (Linux runtime required)

```bash
./build-release/journal_demo create /tmp/unique-journal.bin
./build-release/journal_demo recover /tmp/unique-journal.bin
```

create refuses existing files (O_EXCL). Use a new path for another run.
append returns a published sequence, not a durable acknowledgement.
Explicit close joins the worker, reports sync errors, and returns the durable
watermark. A destructor alone does not report persistence failures.

The scanner reads a quiescent file and stops at the first invalid/truncated
record. It does not skip corruption, perform append-reopen, authenticate data,
or prove power-loss atomicity. The Windows tests mutate byte streams; they are
not filesystem crash tests.

No live exchange connection, order submission, credentials or account data are
used. Network feed recovery, per-subscriber broadcast, order admission epochs,
risk reservations and venue reconciliation are analyzed in the articles but
not implemented in the synthetic pipeline.
