#include "ll/spsc_queue.hpp"
#include "ll/bounded_mpmc_queue.hpp"
#include "ll/market.hpp"
#include "ll/journal_format.hpp"
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <sstream>
#include <thread>

void check(bool value, const char* message) {
  if (!value) { std::cerr << "FAIL: " << message << '\n'; std::abort(); }
}

template<class Queue>
void wraps(const char* label) {
  for (auto initial : {std::size_t{0},
       (std::size_t{1} << 63) - 8, std::numeric_limits<std::size_t>::max() - 7}) {
    Queue q(initial);
    std::uint64_t out = 0;
    for (std::uint64_t lap = 0; lap != 1000; ++lap) {
      check(!q.try_pop(out), "empty");
      for (std::uint64_t j = 0; j != 4; ++j) check(q.try_push(lap * 4 + j), "fill");
      check(!q.try_push(0), "full");
      for (std::uint64_t j = 0; j != 4; ++j) {
        check(q.try_pop(out) && out == lap * 4 + j, "wrap FIFO");
      }
    }
  }
  std::cout << label << ": sign-boundary and unsigned-wrap OK\n";
}

// Pauses *inside* construction: in the MPMC implementation reservation CAS
// has completed, but sequence publication has not. No scheduler luck required.
struct PausedValue {
  std::uint64_t id{};
  PausedValue() noexcept = default;
  PausedValue(std::uint64_t n, std::atomic<bool>* entered,
              std::atomic<bool>* resume) noexcept : id(n) {
    if (entered) {
      entered->store(true, std::memory_order_release);
      while (!resume->load(std::memory_order_acquire)) std::this_thread::yield();
    }
  }
};

void reservation_hole() {
  ll::BoundedMpmcQueue<PausedValue, 4> q;
  std::atomic<bool> entered{false}, resume{false};
  std::thread p0([&] { check(q.try_emplace(0, &entered, &resume), "reserve zero"); });
  while (!entered.load(std::memory_order_acquire)) std::this_thread::yield();
  check(q.try_emplace(1, nullptr, nullptr), "later enqueue completed");
  PausedValue value;
  check(!q.try_pop(value), "reserved head must not be read");
  std::cout << "hole: enqueue(1) completed, later pop returned false\n";
  resume.store(true, std::memory_order_release);
  p0.join();
  check(q.try_pop(value) && value.id == 0, "resume head");
  check(q.try_pop(value) && value.id == 1, "resume successor");
}

void book_failure_cases() {
  ll::OrderBook<2> q;
  check(q.apply({1,0,100,1,ll::Side::bid}) == ll::BookResult::applied,"bid100");
  check(q.apply({2,0,99,1,ll::Side::bid}) == ll::BookResult::applied,"bid99");
  check(q.apply({3,0,98,1,ll::Side::bid}) == ll::BookResult::capacity,"retain tail");
  check(!q.top().valid,"overflow invalidates tradability");
  check(q.apply({3,0,100,0,ll::Side::bid}) == ll::BookResult::quarantined,"latch");
  const ll::MarketUpdate snapshot[] = {{0,0,98,1,ll::Side::bid},
                                     {0,0,102,2,ll::Side::ask}};
  check(q.install_snapshot(10, snapshot),"snapshot recovery");
  check(q.top().valid && q.expected_sequence()==11,"snapshot watermark");
  check(q.apply({12,0,99,1,ll::Side::bid}) == ll::BookResult::gap,"gap");
  check(q.apply({11,0,99,1,ll::Side::bid}) == ll::BookResult::quarantined,"no late heal");
  const ll::MarketUpdate bad[] = {{0,0,98,1,ll::Side::bid},
                                {0,0,98,2,ll::Side::bid}};
  check(!q.install_snapshot(12,bad),"duplicate snapshot");
  check(q.expected_sequence()==11 && !q.top().valid,"snapshot atomicity");
  std::cout << "book: overflow, gap latch, snapshot transaction OK\n";
}

void differential_book() {
  ll::OrderBook<32> q;
  std::map<std::int64_t,std::int32_t> bids,asks;
  std::mt19937 rng(20260922);
  for (std::uint64_t i=1; i<=100000; ++i) {
    auto side = rng()%2 ? ll::Side::bid : ll::Side::ask;
    const std::int64_t price=(side==ll::Side::bid ? 1000:1100)+rng()%24;
    const auto qty=static_cast<std::int32_t>(rng()%8);
    auto& reference=side==ll::Side::bid ? bids:asks;
    if (qty==0) reference.erase(price); else reference[price]=qty;
    check(q.apply({i,0,price,qty,side})==ll::BookResult::applied,"differential apply");
    auto top=q.top();
    check(top.bid_price==(bids.empty()?0:bids.rbegin()->first),"best bid");
    check(top.ask_price==(asks.empty()?0:asks.begin()->first),"best ask");
    check(top.bid_quantity==(bids.empty()?0:bids.rbegin()->second),"bid qty");
    check(top.ask_quantity==(asks.empty()?0:asks.begin()->second),"ask qty");
  }
  std::cout << "book: 100000 seeded updates match std::map reference\n";
}

void journal_faults() {
  using namespace ll::journal;
  const auto h=header(4);
  std::string bytes(reinterpret_cast<const char*>(h.data()),64);
  for(unsigned i=1;i<=4;++i) {
    const auto b=record(i,1,"test payload");
    bytes.append(reinterpret_cast<const char*>(b.data()),64);
  }
  std::istringstream valid(bytes);
  check(recover(valid).records==4,"valid journal");
  // Every truncation byte boundary: no partial record is accepted.
  for(std::size_t cut=64;cut<=bytes.size();++cut) {
    std::istringstream input(bytes.substr(0,cut));
    check(recover(input).records==(cut-64)/64,"truncation prefix");
  }
  // Every single-bit corruption of the third record: the scanner must stop
  // after record 2, even though record 4 remains perfectly valid.
  for(std::size_t bit=0;bit<512;++bit) {
    auto corrupt=bytes;
    corrupt[64+2*64+bit/8]^=static_cast<char>(1U<<(bit%8));
    std::istringstream input(corrupt);
    check(recover(input).records==2,"corrupted prefix");
  }
  const auto text=std::string_view("123456789");
  check(crc32c(std::as_bytes(std::span(text.data(),text.size())))==0xe3069283U,"CRC32C test vector");
  std::cout<<"journal codec: 257 truncations + 512 bit flips + CRC32C vector OK\n";
}

int main() {
  // Fail rather than hang forever if a concurrency regression prevents progress.
  std::atomic<bool> done{false};
  std::thread watchdog([&] {
    for(int i=0;i<300 && !done.load();++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (!done.load()) { std::cerr<<"test timeout\n"; std::abort(); }
  });
  wraps<ll::SpscQueue<std::uint64_t,4>>("spsc");
  wraps<ll::BoundedMpmcQueue<std::uint64_t,4>>("mpmc");
  reservation_hole();
  book_failure_cases();
  differential_book();
  journal_faults();
  done.store(true);
  watchdog.join();
}
