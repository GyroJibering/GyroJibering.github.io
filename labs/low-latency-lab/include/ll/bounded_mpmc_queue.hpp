#pragma once

#include <array>
#include <atomic>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>

namespace ll {

// Dmitry Vyukov's bounded MPMC ring pattern. It is allocation-free and uses
// no mutexes, but it is not lock-free in the formal progress-guarantee sense:
// a thread preempted after claiming a position can temporarily block progress
// at that position. The per-cell sequence prevents ABA across ring laps.
template <typename T, std::size_t Capacity>
class BoundedMpmcQueue {
  static_assert(Capacity >= 2 && (Capacity & (Capacity - 1)) == 0,
                "Capacity must be a power of two");

  struct Cell {
    std::atomic<std::size_t> sequence{0};
    std::optional<T> value{};
  };

 public:
  BoundedMpmcQueue() {
    for (std::size_t i = 0; i < Capacity; ++i) {
      cells_[i].sequence.store(i, std::memory_order_relaxed);
    }
  }

  BoundedMpmcQueue(const BoundedMpmcQueue&) = delete;
  BoundedMpmcQueue& operator=(const BoundedMpmcQueue&) = delete;

  template <typename... Args>
    requires std::constructible_from<T, Args...>
  bool try_emplace(Args&&... args) {
    auto pos = enqueue_pos_.value.load(std::memory_order_relaxed);
    Cell* cell;
    for (;;) {
      cell = &cells_[pos & mask];
      const auto seq = cell->sequence.load(std::memory_order_acquire);
      const auto diff = static_cast<std::intptr_t>(seq) -
                        static_cast<std::intptr_t>(pos);
      if (diff == 0) {
        if (enqueue_pos_.value.compare_exchange_weak(
                pos, pos + 1, std::memory_order_relaxed,
                std::memory_order_relaxed)) {
          break;
        }
      } else if (diff < 0) {
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

  bool try_pop(T& out) {
    auto pos = dequeue_pos_.value.load(std::memory_order_relaxed);
    Cell* cell;
    for (;;) {
      cell = &cells_[pos & mask];
      const auto seq = cell->sequence.load(std::memory_order_acquire);
      const auto diff = static_cast<std::intptr_t>(seq) -
                        static_cast<std::intptr_t>(pos + 1);
      if (diff == 0) {
        if (dequeue_pos_.value.compare_exchange_weak(
                pos, pos + 1, std::memory_order_relaxed,
                std::memory_order_relaxed)) {
          break;
        }
      } else if (diff < 0) {
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
