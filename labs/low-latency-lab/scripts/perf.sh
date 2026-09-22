#!/usr/bin/env bash
set -euo pipefail

build_dir="${1:-build-release}"
cmake -S . -B "$build_dir" -DCMAKE_BUILD_TYPE=Release
cmake --build "$build_dir" --parallel

"$build_dir/stress"
"$build_dir/research"
# The benchmark discovers allowed CPU topology and checks every affinity call.
# Whole-process counters include setup and multiple trials, not just queue ops.
perf stat -r 10 -e cycles:u,instructions:u -- "$build_dir/benchmark" mpmc
perf stat -r 10 -e context-switches,cpu-migrations,page-faults -- \
  "$build_dir/benchmark" mpmc
perf record -g --call-graph dwarf -o "$build_dir/perf.data" \
  "$build_dir/trading_loop"
perf report -i "$build_dir/perf.data"
