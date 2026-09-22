#pragma once

#include <array>
#include <atomic>
#include <concepts>
#include <cstddef>
#include <optional>
#include <utility>

namespace ll {

// A bounded queue for exactly one producer and one consumer.
// Capacity must be a power of two. All Capacity slots are usable.
template <typename T, std::size_t Capacity>
class SpscQueue {
  static_assert(Capacity >= 2 && (Capacity & (Capacity - 1)) == 0,
                "Capacity must be a power of two");

 public:
  SpscQueue() = default;
  SpscQueue(const SpscQueue&) = delete;
  SpscQueue& operator=(const SpscQueue&) = delete;

  template <typename... Args>
    requires std::constructible_from<T, Args...>
  bool try_emplace(Args&&... args) {
    const auto tail = tail_.value.load(std::memory_order_relaxed);
    if (tail - producer_cached_head_ == Capacity) {
      producer_cached_head_ = head_.value.load(std::memory_order_acquire);
      if (tail - producer_cached_head_ == Capacity) return false;
    }

    slots_[tail & mask].emplace(std::forward<Args>(args)...);
    tail_.value.store(tail + 1, std::memory_order_release);
    return true;
  }

  bool try_push(const T& value) { return try_emplace(value); }
  bool try_push(T&& value) { return try_emplace(std::move(value)); }

  bool try_pop(T& out) {
    const auto head = head_.value.load(std::memory_order_relaxed);
    if (head == consumer_cached_tail_) {
      consumer_cached_tail_ = tail_.value.load(std::memory_order_acquire);
      if (head == consumer_cached_tail_) return false;
    }

    auto& slot = slots_[head & mask];
    out = std::move(*slot);
    slot.reset();
    head_.value.store(head + 1, std::memory_order_release);
    return true;
  }

  [[nodiscard]] bool empty() const {
    return head_.value.load(std::memory_order_acquire) ==
           tail_.value.load(std::memory_order_acquire);
  }

 private:
  static constexpr std::size_t mask = Capacity - 1;
  struct alignas(64) Cursor {
    std::atomic<std::size_t> value{0};
  };

  std::array<std::optional<T>, Capacity> slots_{};
  Cursor head_{};  // written by the consumer
  Cursor tail_{};  // written by the producer
  alignas(64) std::size_t producer_cached_head_{0};
  alignas(64) std::size_t consumer_cached_tail_{0};
};

}  // namespace ll
