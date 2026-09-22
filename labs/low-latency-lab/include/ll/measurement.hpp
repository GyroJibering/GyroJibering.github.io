#pragma once
#include "latency.hpp"
#include <atomic>
#include <array>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#if !defined(_MSC_VER)
#include <cpuid.h>
#endif
namespace ll::measurement {
inline void spin() { _mm_pause(); }
inline void pin(unsigned cpu) {
  if(!pin_current_thread(cpu)) {
    std::cerr<<"affinity failed for CPU "<<cpu<<'\n';std::abort();
  }
}
inline void cpuid(unsigned leaf, unsigned& a,unsigned& b,unsigned& c,unsigned& d) {
#if defined(_MSC_VER)
  int regs[4]; __cpuid(regs,static_cast<int>(leaf));
  a=regs[0];b=regs[1];c=regs[2];d=regs[3];
#else
  __cpuid_count(leaf,0,a,b,c,d);
#endif
}
// Deliberately conservative serialized timestamps on the *same* origin CPU.
// Both surrounding CPUIDs and compiler barriers are measured in the empty
// bracket. More expensive than LFENCE; avoids assuming AMD LFENCE MSR state.
inline std::uint64_t stamp() {
  std::atomic_signal_fence(std::memory_order_seq_cst);
#if defined(_MSC_VER)
  int regs[4]; __cpuid(regs,0);
#else
  unsigned a,b,c,d;
  __asm__ __volatile__("cpuid" : "=a"(a),"=b"(b),"=c"(c),"=d"(d) : "0"(0),"2"(0) : "memory");
#endif
  const auto t=__rdtsc();
#if defined(_MSC_VER)
  __cpuid(regs,0);
#else
  __asm__ __volatile__("cpuid" : "=a"(a),"=b"(b),"=c"(c),"=d"(d) : "0"(0),"2"(0) : "memory");
#endif
  std::atomic_signal_fence(std::memory_order_seq_cst);
  return t;
}
struct Core { int package; int core; std::vector<unsigned> cpus; };
inline std::vector<Core> topology() {
  std::vector<Core> result;
#ifdef _WIN32
  DWORD bytes=0;
  GetLogicalProcessorInformationEx(RelationProcessorCore,nullptr,&bytes);
  if(!bytes) throw std::runtime_error("topology unavailable");
  std::vector<std::byte> buffer(bytes);
  auto* base=reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data());
  if(!GetLogicalProcessorInformationEx(RelationProcessorCore,base,&bytes))
    throw std::runtime_error("topology query failed");
  for(DWORD off=0;off<bytes;) {
    auto* item=reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data()+off);
    if(item->Processor.GroupCount!=1 || item->Processor.GroupMask[0].Group!=0)
      throw std::runtime_error("benchmark supports one Windows processor group");
    Core core{0,static_cast<int>(result.size()),{}};
    const auto mask=item->Processor.GroupMask[0].Mask;
    for(unsigned i=0;i<sizeof(mask)*8;++i) if(mask&(KAFFINITY{1}<<i)) core.cpus.push_back(i);
    result.push_back(core); off+=item->Size;
  }
#else
  cpu_set_t allowed; CPU_ZERO(&allowed);
  if(pthread_getaffinity_np(pthread_self(),sizeof(allowed),&allowed))
    throw std::runtime_error("affinity query failed");
  for(unsigned cpu=0;cpu<CPU_SETSIZE;++cpu) if(CPU_ISSET(cpu,&allowed)) {
    const auto path="/sys/devices/system/cpu/cpu"+std::to_string(cpu)+"/topology/";
    int pkg=-1,id=-1;
    std::ifstream(path+"physical_package_id")>>pkg;
    std::ifstream(path+"core_id")>>id;
    if(pkg<0||id<0) throw std::runtime_error("topology unavailable");
    auto found=result.end();
    for(auto it=result.begin();it!=result.end();++it)
      if(it->package==pkg && it->core==id) {found=it;break;}
    if(found==result.end()) result.push_back({pkg,id,{cpu}}); else found->cpus.push_back(cpu);
  }
#endif
  return result;
}
inline void print_environment(const std::vector<Core>& cores) {
  unsigned a,b,c,d; cpuid(0x80000000,a,b,c,d);
  const unsigned maxleaf=a;
  if(maxleaf>=0x80000004) {
    std::array<unsigned,12> brand{};
    for(unsigned i=0;i<3;++i) cpuid(0x80000002+i,brand[4*i],brand[4*i+1],brand[4*i+2],brand[4*i+3]);
    const auto name=std::string(reinterpret_cast<char*>(brand.data()),48);
    std::cout<<"cpu="<<name.c_str()<<'\n';
  }
  if(maxleaf>=0x80000007) {cpuid(0x80000007,a,b,c,d);std::cout<<"invariant_tsc="<<bool(d&(1U<<8))<<'\n';}
  cpuid(1,a,b,c,d);
  std::cout<<"hypervisor_present="<<bool(c&(1U<<31))<<'\n';
#ifdef _MSC_VER
  std::cout<<"msvc="<<_MSC_VER<<'\n';
#else
  std::cout<<"compiler="<<__VERSION__<<"\n";
#endif
  for(auto& core:cores) {
    std::cout<<"core="<<core.package<<":"<<core.core<<" logical=";
    for(auto cpu:core.cpus)std::cout<<cpu<<",";
    std::cout<<'\n';
  }
}
} // namespace ll::measurement
