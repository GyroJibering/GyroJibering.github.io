#include "ll/latency.hpp"
#include "ll/spsc_queue.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <thread>
#include <vector>

namespace {

inline void spin_hint() noexcept {
#if defined(__x86_64__) || defined(_M_X64)
  _mm_pause();
#else
  std::this_thread::yield();
#endif
}

void latency_test() {
  constexpr std::size_t warmup = 20'000;
  constexpr std::size_t measured = 200'000;
  ll::SpscQueue<std::uint64_t, 1024> queue;
  std::atomic<std::size_t> acknowledged{0};
  std::vector<std::uint64_t> cycles;
  cycles.reserve(measured);

  std::thread consumer([&] {
    (void)ll::pin_current_thread(3);
    std::uint64_t sent_tsc{};
    for (std::size_t i = 0; i < warmup + measured; ++i) {
      while (!queue.try_pop(sent_tsc)) spin_hint();
      const auto elapsed = ll::tsc_stop() - sent_tsc;
      if (i >= warmup) cycles.push_back(elapsed);
      acknowledged.store(i + 1, std::memory_order_release);
    }
  });

  (void)ll::pin_current_thread(2);
  for (std::size_t i = 0; i < warmup + measured; ++i) {
    const auto start = ll::tsc_start();
    while (!queue.try_push(start)) spin_hint();
    while (acknowledged.load(std::memory_order_acquire) != i + 1) spin_hint();
  }
  consumer.join();

  const auto stats = ll::percentiles(std::move(cycles));
  std::cout << "SPSC one-way handoff (TSC ticks, one message in flight)\n"
            << "min=" << stats.min << " p50=" << stats.p50
            << " p99=" << stats.p99 << " p99.9=" << stats.p999
            << " max=" << stats.max << '\n';
}

void throughput_test() {
  constexpr std::size_t warmup = 100'000;
  constexpr std::size_t measured = 5'000'000;
  ll::SpscQueue<std::uint64_t, 4096> queue;
  std::thread consumer([&] {
    (void)ll::pin_current_thread(3);
    std::uint64_t value{};
    for (std::size_t i = 0; i < warmup + measured; ++i) {
      while (!queue.try_pop(value)) spin_hint();
    }
  });

  (void)ll::pin_current_thread(2);
  const auto wall_start = std::chrono::steady_clock::now();
  for (std::size_t i = 0; i < warmup + measured; ++i) {
    while (!queue.try_push(i)) spin_hint();
  }
  consumer.join();
  const auto seconds = std::chrono::duration<double>(
                           std::chrono::steady_clock::now() - wall_start)
                           .count();
  std::cout << std::fixed << std::setprecision(2)
            << "SPSC sustained throughput=" << (warmup + measured) / seconds / 1e6
            << " Mmsg/s\n";
}

}  // namespace

int main() {
  latency_test();
  throughput_test();
}
