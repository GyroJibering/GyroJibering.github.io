#if !defined(__linux__)
#error "journal_demo requires Linux"
#endif

#include "ll/latency.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>

namespace {

constexpr std::uint64_t journal_magic = 0x4759524f4a4e4c31ULL;  // GYROJNL1

struct alignas(4096) JournalHeader {
  std::uint64_t magic{};
  std::uint64_t version{};
  std::uint64_t capacity{};
  std::uint64_t record_size{};
  std::array<std::byte, 4096 - 32> padding{};
};
static_assert(sizeof(JournalHeader) == 4096);

struct alignas(64) JournalRecord {
  std::uint64_t committed_sequence{};
  std::uint64_t tsc{};
  std::uint64_t stream_sequence{};
  std::uint32_t type{};
  std::uint32_t length{};
  std::uint64_t checksum{};
  std::array<char, 24> payload{};
};
static_assert(sizeof(JournalRecord) == 64);
static_assert(std::atomic_ref<std::uint64_t>::is_always_lock_free,
              "journal commit marker must be lock-free on this target");

std::uint64_t checksum(const JournalRecord& record) noexcept {
  std::uint64_t hash = 1469598103934665603ULL;
  const auto mix = [&](const void* data, std::size_t size) {
    const auto* bytes = static_cast<const unsigned char*>(data);
    for (std::size_t i = 0; i < size; ++i) {
      hash ^= bytes[i];
      hash *= 1099511628211ULL;
    }
  };
  mix(&record.tsc, sizeof(record.tsc));
  mix(&record.stream_sequence, sizeof(record.stream_sequence));
  mix(&record.type, sizeof(record.type));
  mix(&record.length, sizeof(record.length));
  mix(record.payload.data(), record.payload.size());
  return hash;
}

class MmapJournal {
 public:
  MmapJournal(const char* path, std::size_t capacity,
              std::size_t flush_batch = 4096)
      : capacity_(capacity), flush_batch_(flush_batch) {
    mapped_bytes_ = sizeof(JournalHeader) + capacity * sizeof(JournalRecord);
    fd_ = ::open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd_ == -1 || ::ftruncate(fd_, static_cast<off_t>(mapped_bytes_)) == -1) {
      throw std::runtime_error("open/ftruncate failed: " +
                               std::string(std::strerror(errno)));
    }
    mapping_ = ::mmap(nullptr, mapped_bytes_, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd_, 0);
    if (mapping_ == MAP_FAILED) {
      throw std::runtime_error("mmap failed: " +
                               std::string(std::strerror(errno)));
    }
    header_ = static_cast<JournalHeader*>(mapping_);
    records_ = reinterpret_cast<JournalRecord*>(header_ + 1);
    std::construct_at(header_,
                      JournalHeader{journal_magic, 1, capacity_,
                                    sizeof(JournalRecord)});
    // mmap returns raw storage. Explicitly start every record lifetime; this
    // also pre-faults the mapping before the latency-sensitive append loop.
    for (std::size_t i = 0; i < capacity_; ++i) {
      std::construct_at(records_ + i);
    }
    notify_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (notify_fd_ == -1) throw std::runtime_error("eventfd failed");
    flusher_ = std::thread([this] { flush_loop(); });
  }

  MmapJournal(const MmapJournal&) = delete;
  MmapJournal& operator=(const MmapJournal&) = delete;

  ~MmapJournal() {
    stop_.store(true, std::memory_order_release);
    signal_flusher();
    if (flusher_.joinable()) flusher_.join();
    if (mapping_ != MAP_FAILED) {
      ::msync(mapping_, mapped_bytes_, MS_SYNC);
      ::munmap(mapping_, mapped_bytes_);
    }
    if (notify_fd_ != -1) ::close(notify_fd_);
    if (fd_ != -1) ::close(fd_);
  }

  // Single-writer hot path. A multi-producer caller should feed one journal
  // writer through per-producer SPSC queues so records have one total order.
  bool append(std::uint64_t stream_sequence, std::uint32_t type,
              std::string_view payload) {
    if (next_ >= capacity_ || payload.size() > JournalRecord{}.payload.size()) {
      return false;
    }
    auto& record = records_[next_];
    record.tsc = ll::tsc_start();
    record.stream_sequence = stream_sequence;
    record.type = type;
    record.length = static_cast<std::uint32_t>(payload.size());
    record.payload.fill('\0');
    std::memcpy(record.payload.data(), payload.data(), payload.size());
    record.checksum = checksum(record);

    const auto commit = next_ + 1;
    std::atomic_ref(record.committed_sequence)
        .store(commit, std::memory_order_release);
    ++next_;
    committed_.store(commit, std::memory_order_release);
    if (commit % flush_batch_ == 0) signal_flusher();
    return true;
  }

  [[nodiscard]] std::size_t recoverable_records() {
    std::size_t count = 0;
    for (; count < capacity_; ++count) {
      auto& record = records_[count];
      const auto committed =
          std::atomic_ref(record.committed_sequence).load(std::memory_order_acquire);
      if (committed != count + 1 || record.checksum != checksum(record)) break;
    }
    return count;
  }

 private:
  void signal_flusher() noexcept {
    if (flush_pending_.exchange(true, std::memory_order_acq_rel)) return;
    const std::uint64_t one = 1;
    const auto ignored = ::write(notify_fd_, &one, sizeof(one));
    (void)ignored;
  }

  void flush_loop() noexcept {
    std::uint64_t flushed = 0;
    while (!stop_.load(std::memory_order_acquire)) {
      pollfd descriptor{notify_fd_, POLLIN, 0};
      (void)::poll(&descriptor, 1, 100);
      std::uint64_t signals{};
      while (::read(notify_fd_, &signals, sizeof(signals)) == sizeof(signals)) {
      }
      const auto target = committed_.load(std::memory_order_acquire);
      if (target != flushed) {
        (void)::msync(mapping_, mapped_bytes_, MS_ASYNC);
        flushed = target;
      }
      flush_pending_.store(false, std::memory_order_release);
      if (committed_.load(std::memory_order_acquire) - flushed >= flush_batch_) {
        signal_flusher();
      }
    }
  }

  int fd_{-1};
  int notify_fd_{-1};
  void* mapping_{MAP_FAILED};
  std::size_t mapped_bytes_{};
  std::size_t capacity_{};
  std::size_t flush_batch_{};
  std::size_t next_{0};
  JournalHeader* header_{};
  JournalRecord* records_{};
  std::atomic<std::uint64_t> committed_{0};
  std::atomic<bool> flush_pending_{false};
  std::atomic<bool> stop_{false};
  std::thread flusher_{};
};

}  // namespace

int main(int argc, char** argv) {
  const char* path = argc > 1 ? argv[1] : "market.journal";
  constexpr std::size_t count = 1'000'000;
  MmapJournal journal(path, count);
  const auto start = std::chrono::steady_clock::now();
  for (std::size_t i = 1; i <= count; ++i) {
    if (!journal.append(i, 1, "BID 10000 10")) return 1;
  }
  const auto seconds = std::chrono::duration<double>(
                           std::chrono::steady_clock::now() - start)
                           .count();
  std::cout << "records=" << journal.recoverable_records()
            << " append_rate=" << count / seconds / 1e6 << " Mrec/s\n";
}
