#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ll {

enum class Side : std::uint8_t { bid, ask };

struct MarketUpdate {
  std::uint64_t sequence{};
  std::uint64_t receive_tsc{};
  std::int64_t price_ticks{};
  std::int32_t quantity{};  // absolute quantity; zero deletes the level
  Side side{};
};

struct TopOfBook {
  std::uint64_t market_sequence{};
  std::uint64_t receive_tsc{};
  std::int64_t bid_price{};
  std::int32_t bid_quantity{};
  std::int64_t ask_price{};
  std::int32_t ask_quantity{};
};

struct OrderIntent {
  std::uint64_t decision_sequence{};
  std::uint64_t market_sequence{};
  std::int64_t price_ticks{};
  std::int32_t quantity{};
  Side side{};
};

struct NewOrder {
  std::uint64_t order_sequence{};
  std::uint64_t decision_sequence{};
  std::uint64_t market_sequence{};
  std::int64_t price_ticks{};
  std::int32_t quantity{};
  Side side{};
};

enum class BookResult { applied, stale, gap };

template <bool IsBid, std::size_t Depth>
class FixedBookSide {
 public:
  struct Level {
    std::int64_t price{};
    std::int32_t quantity{};
  };

  void update(std::int64_t price, std::int32_t quantity) {
    std::size_t found = size_;
    for (std::size_t i = 0; i < size_; ++i) {
      if (levels_[i].price == price) {
        found = i;
        break;
      }
    }
    if (found < size_) erase(found);
    if (quantity == 0) return;

    std::size_t pos = 0;
    while (pos < size_ && better(levels_[pos].price, price)) ++pos;
    if (pos == Depth) return;
    const auto new_size = size_ < Depth ? size_ + 1 : size_;
    for (std::size_t i = new_size - 1; i > pos; --i) levels_[i] = levels_[i - 1];
    levels_[pos] = {price, quantity};
    size_ = new_size;
  }

  [[nodiscard]] const Level* best() const noexcept {
    return size_ == 0 ? nullptr : &levels_[0];
  }

 private:
  static bool better(std::int64_t lhs, std::int64_t rhs) noexcept {
    if constexpr (IsBid) return lhs > rhs;
    return lhs < rhs;
  }

  void erase(std::size_t pos) noexcept {
    for (std::size_t i = pos + 1; i < size_; ++i) levels_[i - 1] = levels_[i];
    --size_;
  }

  std::array<Level, Depth> levels_{};
  std::size_t size_{0};
};

template <std::size_t Depth>
class OrderBook {
 public:
  BookResult apply(const MarketUpdate& update) {
    if (update.sequence < expected_sequence_) return BookResult::stale;
    if (update.sequence > expected_sequence_) return BookResult::gap;
    if (update.side == Side::bid) {
      bids_.update(update.price_ticks, update.quantity);
    } else {
      asks_.update(update.price_ticks, update.quantity);
    }
    ++expected_sequence_;
    last_receive_tsc_ = update.receive_tsc;
    return BookResult::applied;
  }

  [[nodiscard]] TopOfBook top() const noexcept {
    TopOfBook out{};
    out.market_sequence = expected_sequence_ - 1;
    out.receive_tsc = last_receive_tsc_;
    if (const auto* bid = bids_.best()) {
      out.bid_price = bid->price;
      out.bid_quantity = bid->quantity;
    }
    if (const auto* ask = asks_.best()) {
      out.ask_price = ask->price;
      out.ask_quantity = ask->quantity;
    }
    return out;
  }

  [[nodiscard]] std::uint64_t expected_sequence() const noexcept {
    return expected_sequence_;
  }

 private:
  std::uint64_t expected_sequence_{1};
  std::uint64_t last_receive_tsc_{0};
  FixedBookSide<true, Depth> bids_{};
  FixedBookSide<false, Depth> asks_{};
};

}  // namespace ll
