#include "ll/bounded_mpmc_queue.hpp"
#include "ll/market.hpp"
#include "ll/spsc_queue.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

namespace {

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "FAILED: " << message << '\n';
    std::abort();
  }
}

void test_spsc() {
  constexpr std::uint64_t count = 1'000'000;
  ll::SpscQueue<std::uint64_t, 1024> queue;
  std::thread producer([&] {
    for (std::uint64_t i = 0; i < count; ++i) {
      while (!queue.try_push(i)) std::this_thread::yield();
    }
  });
  for (std::uint64_t expected = 0; expected < count; ++expected) {
    std::uint64_t value{};
    while (!queue.try_pop(value)) std::this_thread::yield();
    require(value == expected, "SPSC order mismatch");
  }
  producer.join();
  std::cout << "spsc: strict order OK (" << count << " messages)\n";
}

void test_mpmc() {
  constexpr std::size_t producers = 4;
  constexpr std::size_t consumers = 4;
  constexpr std::uint64_t per_producer = 250'000;
  constexpr std::uint64_t total = producers * per_producer;
  ll::BoundedMpmcQueue<std::uint64_t, 4096> queue;
  std::atomic<std::uint64_t> consumed{0};
  std::vector<std::uint64_t> output(total);
  std::vector<std::thread> threads;

  for (std::size_t p = 0; p < producers; ++p) {
    threads.emplace_back([&, p] {
      const auto begin = p * per_producer;
      for (std::uint64_t i = 0; i < per_producer; ++i) {
        while (!queue.try_push(begin + i)) std::this_thread::yield();
      }
    });
  }
  for (std::size_t c = 0; c < consumers; ++c) {
    threads.emplace_back([&] {
      for (;;) {
        auto ticket = consumed.fetch_add(1, std::memory_order_relaxed);
        if (ticket >= total) break;
        std::uint64_t value{};
        while (!queue.try_pop(value)) std::this_thread::yield();
        output[ticket] = value;
      }
    });
  }
  for (auto& thread : threads) thread.join();
  std::sort(output.begin(), output.end());
  for (std::uint64_t i = 0; i < total; ++i) {
    require(output[i] == i, "MPMC loss or duplicate");
  }
  std::cout << "mpmc: no loss/duplicate OK (" << total << " messages)\n";
}

void test_book_sequences() {
  ll::OrderBook<8> book;
  require(book.apply({1, 10, 100, 5, ll::Side::bid}) == ll::BookResult::applied,
          "first book update rejected");
  require(book.apply({2, 11, 102, 4, ll::Side::ask}) == ll::BookResult::applied,
          "second book update rejected");
  require(book.apply({2, 12, 101, 3, ll::Side::bid}) == ll::BookResult::stale,
          "stale update not detected");
  require(book.apply({4, 13, 103, 2, ll::Side::ask}) == ll::BookResult::gap,
          "sequence gap not detected");
  const auto top = book.top();
  require(top.market_sequence == 2 && top.bid_price == 100 && top.ask_price == 102,
          "top of book mismatch");
  std::cout << "book: stale/gap detection OK\n";
}

}  // namespace

int main() {
  test_spsc();
  test_mpmc();
  test_book_sequences();
}
