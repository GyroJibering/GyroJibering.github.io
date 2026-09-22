#include "ll/latency.hpp"
#include "ll/market.hpp"
#include "ll/spsc_queue.hpp"

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <thread>

int main() {
  constexpr std::uint64_t update_count = 1'000'000;
  ll::SpscQueue<ll::MarketUpdate, 4096> feed_to_book;
  ll::SpscQueue<ll::TopOfBook, 4096> book_to_strategy;
  ll::SpscQueue<ll::OrderIntent, 4096> strategy_to_orders;
  std::atomic<bool> feed_done{false};
  std::atomic<bool> book_done{false};
  std::atomic<bool> strategy_done{false};
  std::atomic<std::uint64_t> gap_count{0};
  std::uint64_t sent_orders = 0;

  std::thread feed([&] {
    for (std::uint64_t seq = 1; seq <= update_count; ++seq) {
      ll::MarketUpdate update{seq,
                              ll::tsc_start(),
                              (seq & 1U) ? 100'00 : 100'02,
                              10,
                              (seq & 1U) ? ll::Side::bid : ll::Side::ask};
      while (!feed_to_book.try_push(update)) std::this_thread::yield();
    }
    feed_done.store(true, std::memory_order_release);
  });

  std::thread book_thread([&] {
    ll::OrderBook<16> book;
    ll::MarketUpdate update{};
    while (!feed_done.load(std::memory_order_acquire) || !feed_to_book.empty()) {
      if (!feed_to_book.try_pop(update)) {
        std::this_thread::yield();
        continue;
      }
      const auto result = book.apply(update);
      if (result == ll::BookResult::gap) {
        gap_count.fetch_add(1, std::memory_order_relaxed);
        continue;  // production code would stop publication and request recovery
      }
      if (result == ll::BookResult::applied && update.side == ll::Side::ask) {
        auto top = book.top();
        while (!book_to_strategy.try_push(top)) std::this_thread::yield();
      }
    }
    book_done.store(true, std::memory_order_release);
  });

  std::thread strategy([&] {
    ll::TopOfBook top{};
    std::uint64_t decision_seq = 0;
    std::uint64_t previous_market_seq = 0;
    while (!book_done.load(std::memory_order_acquire) || !book_to_strategy.empty()) {
      if (!book_to_strategy.try_pop(top)) {
        std::this_thread::yield();
        continue;
      }
      if (top.market_sequence <= previous_market_seq) std::abort();
      previous_market_seq = top.market_sequence;
      if (top.ask_price > top.bid_price) {
        ll::OrderIntent intent{++decision_seq, top.market_sequence,
                               top.bid_price, 1, ll::Side::bid};
        while (!strategy_to_orders.try_push(intent)) std::this_thread::yield();
      }
    }
    strategy_done.store(true, std::memory_order_release);
  });

  std::thread order_gateway([&] {
    ll::OrderIntent intent{};
    std::uint64_t order_seq = 0;
    std::uint64_t previous_decision_seq = 0;
    while (!strategy_done.load(std::memory_order_acquire) ||
           !strategy_to_orders.empty()) {
      if (!strategy_to_orders.try_pop(intent)) {
        std::this_thread::yield();
        continue;
      }
      if (intent.decision_sequence != previous_decision_seq + 1) std::abort();
      previous_decision_seq = intent.decision_sequence;
      const ll::NewOrder order{++order_seq, intent.decision_sequence,
                               intent.market_sequence, intent.price_ticks,
                               intent.quantity, intent.side};
      (void)order;  // encode and send on a real order-entry session here
      ++sent_orders;
    }
  });

  feed.join();
  book_thread.join();
  strategy.join();
  order_gateway.join();

  std::cout << "updates=" << update_count << " gaps=" << gap_count.load()
            << " orders=" << sent_orders << '\n';
  if (gap_count.load() != 0 || sent_orders != update_count / 2) return 1;
}
