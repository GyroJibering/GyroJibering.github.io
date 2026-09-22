#!/usr/bin/env bash
set -euo pipefail

build_dir="${1:-build-release}"
cmake -S . -B "$build_dir" -DCMAKE_BUILD_TYPE=Release
cmake --build "$build_dir" --parallel

"$build_dir/stress"
taskset -c 2,3 "$build_dir/benchmark"
perf stat -r 10 -e cycles,instructions,branches,branch-misses,cache-references,cache-misses \
  taskset -c 2,3 "$build_dir/benchmark"
perf record -g --call-graph dwarf -o "$build_dir/perf.data" \
  taskset -c 2,3 "$build_dir/trading_loop"
perf report -i "$build_dir/perf.data"
