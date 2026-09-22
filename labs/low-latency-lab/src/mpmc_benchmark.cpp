#include "ll/bounded_mpmc_queue.hpp"
#include "ll/latency.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
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

double run(std::size_t producer_count, std::size_t consumer_count) {
  constexpr std::uint64_t per_producer = 1'000'000;
  ll::BoundedMpmcQueue<std::uint64_t, 65536> queue;
  const auto total = per_producer * producer_count;
  std::atomic<std::size_t> ready{0};
  std::atomic<bool> go{false};
  std::atomic<std::uint64_t> consumed{0};
  std::vector<std::thread> workers;

  for (std::size_t p = 0; p < producer_count; ++p) {
    workers.emplace_back([&, p] {
      (void)ll::pin_current_thread(static_cast<unsigned>(p));
      ready.fetch_add(1, std::memory_order_release);
      while (!go.load(std::memory_order_acquire)) spin_hint();
      for (std::uint64_t i = 0; i < per_producer; ++i) {
        const auto value = (static_cast<std::uint64_t>(p) << 48U) | i;
        while (!queue.try_push(value)) spin_hint();
      }
    });
  }
  for (std::size_t c = 0; c < consumer_count; ++c) {
    workers.emplace_back([&, c] {
      (void)ll::pin_current_thread(static_cast<unsigned>(6 + c));
      ready.fetch_add(1, std::memory_order_release);
      while (!go.load(std::memory_order_acquire)) spin_hint();
      std::uint64_t value{};
      while (consumed.load(std::memory_order_relaxed) < total) {
        if (queue.try_pop(value)) {
          consumed.fetch_add(1, std::memory_order_relaxed);
        } else {
          spin_hint();
        }
      }
    });
  }

  while (ready.load(std::memory_order_acquire) != workers.size()) spin_hint();
  const auto start = std::chrono::steady_clock::now();
  go.store(true, std::memory_order_release);
  for (auto& worker : workers) worker.join();
  return total / std::chrono::duration<double>(
                     std::chrono::steady_clock::now() - start)
                     .count() /
         1e6;
}

}  // namespace

int main() {
  std::cout << std::fixed << std::setprecision(2);
  for (const auto [producers, consumers] :
       {std::pair{1U, 1U}, std::pair{2U, 2U}, std::pair{4U, 4U}}) {
    std::cout << producers << "P/" << consumers << "C: "
              << run(producers, consumers) << " Mmsg/s\n";
  }
}
