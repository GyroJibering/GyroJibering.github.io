#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <limits>

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
  bool valid{};
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

enum class BookResult { applied, stale, gap, invalid, capacity, quarantined };

template <bool IsBid, std::size_t Depth>
class FixedBookSide {
  static_assert(Depth > 0);
 public:
  struct Level {
    std::int64_t price{};
    std::int32_t quantity{};
  };

  bool update(std::int64_t price, std::int32_t quantity) {
    std::size_t found = size_;
    for (std::size_t i = 0; i < size_; ++i) {
      if (levels_[i].price == price) {
        found = i;
        break;
      }
    }
    // Retain every known level. Silently truncating the tail would corrupt
    // future best-price queries after deleting a better level.
    if (found == size_ && quantity != 0 && size_ == Depth) return false;
    if (found < size_) erase(found);
    if (quantity == 0) return true;

    std::size_t pos = 0;
    while (pos < size_ && better(levels_[pos].price, price)) ++pos;
    const auto new_size = size_ < Depth ? size_ + 1 : size_;
    for (std::size_t i = new_size - 1; i > pos; --i) levels_[i] = levels_[i - 1];
    levels_[pos] = {price, quantity};
    size_ = new_size;
    return true;
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
    if (quarantined_) return BookResult::quarantined;
    if (update.sequence < expected_sequence_) return BookResult::stale;
    if (update.sequence > expected_sequence_) {
      quarantined_ = true;
      return BookResult::gap;
    }
    if (update.price_ticks <= 0 || update.quantity < 0 ||
        (update.side != Side::bid && update.side != Side::ask) ||
        update.sequence == std::numeric_limits<std::uint64_t>::max()) {
      quarantined_ = true;
      return BookResult::invalid;
    }
    const bool accepted = update.side == Side::bid
        ? bids_.update(update.price_ticks, update.quantity)
        : asks_.update(update.price_ticks, update.quantity);
    if (!accepted) {
      quarantined_ = true;
      return BookResult::capacity;
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
    out.valid = !quarantined_ && out.bid_quantity > 0 && out.ask_quantity > 0 &&
                out.bid_price < out.ask_price;
    return out;
  }

  // A complete snapshot of this single-instrument synthetic stream. The
  // transport sequencer, session identity and buffered replay live upstream.
  // Validate on a staging book so a malformed snapshot never partially commits.
  bool install_snapshot(std::uint64_t sequence,
                        std::span<const MarketUpdate> levels) {
    if (sequence == std::numeric_limits<std::uint64_t>::max() ||
        sequence < expected_sequence_ - 1) return false;
    OrderBook staged;
    for (const auto& level : levels) {
      if (level.price_ticks <= 0 || level.quantity <= 0 ||
          (level.side != Side::bid && level.side != Side::ask)) return false;
      // Duplicate prices in a snapshot are rejected, not interpreted as deltas.
      for (const auto& other : levels) {
        if (&other == &level) break;
        if (other.side == level.side && other.price_ticks == level.price_ticks)
          return false;
      }
      const bool ok = level.side == Side::bid
          ? staged.bids_.update(level.price_ticks, level.quantity)
          : staged.asks_.update(level.price_ticks, level.quantity);
      if (!ok) return false;
    }
    staged.expected_sequence_ = sequence + 1;
    *this = staged;
    return true;
  }

  [[nodiscard]] std::uint64_t expected_sequence() const noexcept {
    return expected_sequence_;
  }

 private:
  std::uint64_t expected_sequence_{1};
  std::uint64_t last_receive_tsc_{0};
  FixedBookSide<true, Depth> bids_{};
  FixedBookSide<false, Depth> asks_{};
  bool quarantined_{false};
};

}  // namespace ll
