#pragma once

#include <algorithm>
#include <cstdint>
#include <vector>

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#endif
#endif
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace ll {

inline bool pin_current_thread(unsigned cpu) noexcept {
#if defined(_WIN32)
  if(cpu >= sizeof(std::uintptr_t)*8) return false;
  return ::SetThreadAffinityMask(::GetCurrentThread(),
                                 std::uintptr_t{1} << cpu) != 0;
#elif defined(__linux__)
  if(cpu >= CPU_SETSIZE) return false;
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  return ::pthread_setaffinity_np(::pthread_self(), sizeof(set), &set) == 0;
#else
  (void)cpu;
  return false;
#endif
}

inline std::uint64_t tsc_start() noexcept {
#if defined(_MSC_VER)
  _ReadWriteBarrier();
  _mm_lfence();
  const auto t = __rdtsc();
  _mm_lfence();
  return t;
#elif defined(__x86_64__) || defined(__i386__)
  _mm_lfence();
  const auto t = __rdtsc();
  _mm_lfence();
  return t;
#else
  return 0;
#endif
}

inline std::uint64_t tsc_stop() noexcept {
#if defined(_MSC_VER)
  unsigned aux = 0;
  const auto t = __rdtscp(&aux);
  _mm_lfence();
  _ReadWriteBarrier();
  return t;
#elif defined(__x86_64__) || defined(__i386__)
  unsigned aux = 0;
  const auto t = __rdtscp(&aux);
  _mm_lfence();
  return t;
#else
  return 0;
#endif
}

struct Percentiles {
  std::uint64_t min{};
  std::uint64_t p50{};
  std::uint64_t p99{};
  std::uint64_t p999{};
  std::uint64_t max{};
};

inline Percentiles percentiles(std::vector<std::uint64_t> samples) {
  std::sort(samples.begin(), samples.end());
  const auto at = [&](double q) {
    const auto i = static_cast<std::size_t>(q * (samples.size() - 1));
    return samples[i];
  };
  return {samples.front(), at(0.50), at(0.99), at(0.999), samples.back()};
}

}  // namespace ll
