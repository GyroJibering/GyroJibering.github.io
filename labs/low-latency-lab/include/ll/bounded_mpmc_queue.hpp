#pragma once

#include <array>
#include <atomic>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <limits>
#include <type_traits>
#include <utility>

namespace ll {

// Dmitry Vyukov's bounded MPMC ring pattern. It is allocation-free and uses
// no mutexes, but it is not lock-free in the formal progress-guarantee sense:
// a thread preempted after claiming a position can temporarily block progress
// at that position. Generation tags distinguish laps only while no participant
// retains an observation across an entire counter period (finite-tag ABA).
// Modular ahead/behind comparisons additionally require observation age below
// half the counter period. false from try_pop means unavailable, not empty.
template <typename T, std::size_t Capacity>
class BoundedMpmcQueue {
  static_assert(Capacity >= 2 && (Capacity & (Capacity - 1)) == 0,
                "Capacity must be a power of two");
  static_assert(std::numeric_limits<std::size_t>::digits == 64);
  static_assert(std::atomic<std::size_t>::is_always_lock_free);
  static_assert(Capacity < (std::size_t{1} << 63));
  static_assert(std::is_nothrow_move_assignable_v<T>);
  static_assert(std::is_nothrow_destructible_v<T>);

  struct Cell {
    std::atomic<std::size_t> sequence{0};
    std::optional<T> value{};
  };

 public:
  explicit BoundedMpmcQueue(std::size_t initial = 0) {
    for (std::size_t i = 0; i < Capacity; ++i) {
      const auto logical = initial + i;
      cells_[logical & mask].sequence.store(logical, std::memory_order_relaxed);
    }
    enqueue_pos_.value.store(initial, std::memory_order_relaxed);
    dequeue_pos_.value.store(initial, std::memory_order_relaxed);
  }

  BoundedMpmcQueue(const BoundedMpmcQueue&) = delete;
  BoundedMpmcQueue& operator=(const BoundedMpmcQueue&) = delete;

  template <typename... Args>
    requires std::is_nothrow_constructible_v<T, Args...>
  bool try_emplace(Args&&... args) noexcept {
    auto pos = enqueue_pos_.value.load(std::memory_order_relaxed);
    Cell* cell;
    for (;;) {
      cell = &cells_[pos & mask];
      const auto seq = cell->sequence.load(std::memory_order_acquire);
      // Unsigned modular subtraction avoids signed overflow at INT64_MAX.
      const auto diff = seq - pos;
      if (diff == 0) {
        if (enqueue_pos_.value.compare_exchange_weak(
                pos, pos + 1, std::memory_order_relaxed,
                std::memory_order_relaxed)) {
          break;
        }
      } else if (diff > std::numeric_limits<std::size_t>::max() / 2) {
        return false;
      } else {
        pos = enqueue_pos_.value.load(std::memory_order_relaxed);
      }
    }

    cell->value.emplace(std::forward<Args>(args)...);
    cell->sequence.store(pos + 1, std::memory_order_release);
    return true;
  }

  bool try_push(const T& value) { return try_emplace(value); }
  bool try_push(T&& value) { return try_emplace(std::move(value)); }

  // false means the next position is not ready, not necessarily abstract empty.
  bool try_pop(T& out) noexcept {
    auto pos = dequeue_pos_.value.load(std::memory_order_relaxed);
    Cell* cell;
    for (;;) {
      cell = &cells_[pos & mask];
      const auto seq = cell->sequence.load(std::memory_order_acquire);
      const auto diff = seq - (pos + 1);
      if (diff == 0) {
        if (dequeue_pos_.value.compare_exchange_weak(
                pos, pos + 1, std::memory_order_relaxed,
                std::memory_order_relaxed)) {
          break;
        }
      } else if (diff > std::numeric_limits<std::size_t>::max() / 2) {
        return false;
      } else {
        pos = dequeue_pos_.value.load(std::memory_order_relaxed);
      }
    }

    out = std::move(*cell->value);
    cell->value.reset();
    cell->sequence.store(pos + Capacity, std::memory_order_release);
    return true;
  }

 private:
  static constexpr std::size_t mask = Capacity - 1;
  struct alignas(64) Cursor {
    std::atomic<std::size_t> value{0};
  };

  std::array<Cell, Capacity> cells_{};
  Cursor enqueue_pos_{};
  Cursor dequeue_pos_{};
};

}  // namespace ll
