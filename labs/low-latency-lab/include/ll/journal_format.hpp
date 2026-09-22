#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string_view>

namespace ll::journal {
using Block = std::array<std::byte,64>;
inline constexpr std::uint64_t magic=0x324c4e4a4f525947ULL;
inline constexpr std::uint64_t commit_magic=0xa91d3b6e42f087c5ULL;
inline void put(std::span<std::byte> bytes,std::size_t at,std::uint64_t n,int width) {
  for(int i=0;i<width;++i) bytes[at+i]=std::byte((n>>(8*i))&255);
}
inline std::uint64_t get(std::span<const std::byte> b,std::size_t at,int width) {
  std::uint64_t n=0;
  for(int i=0;i<width;++i) n|=std::uint64_t(std::to_integer<unsigned>(b[at+i]))<<(8*i);
  return n;
}
inline std::uint32_t crc32c(std::span<const std::byte> bytes) {
  std::uint32_t crc=~std::uint32_t{0};
  for(auto b:bytes) {
    crc^=std::to_integer<unsigned>(b);
    for(int i=0;i<8;++i) crc=(crc>>1)^(0x82f63b78U & (0U-(crc&1U)));
  }
  return ~crc;
}
inline Block header(std::uint64_t capacity) {
  Block b{}; put(b,0,magic,8); put(b,8,2,4); put(b,12,64,4); put(b,16,capacity,8);
  put(b,48,crc32c(std::span(b).first(48)),4);
  return b;
}
inline bool valid_header(const Block& b) {
  return get(b,0,8)==magic && get(b,8,4)==2 && get(b,12,4)==64 &&
         get(b,16,8)>0 && get(b,48,4)==crc32c(std::span(b).first(48));
}
inline Block record(std::uint64_t seq,std::uint32_t type,std::string_view payload) {
  if(payload.size()>32 || seq==0) throw std::invalid_argument("record bounds");
  Block b{};
  put(b,0,seq,8); put(b,8,type,4); put(b,12,payload.size(),4);
  std::memcpy(b.data()+16,payload.data(),payload.size());
  put(b,48,crc32c(std::span(b).first(48)),4);
  put(b,56,commit_magic^seq,8);
  return b;
}
inline bool valid_record(const Block& b,std::uint64_t expected) {
  return get(b,0,8)==expected && get(b,12,4)<=32 && get(b,52,4)==0 &&
         get(b,56,8)==(commit_magic^expected) &&
         get(b,48,4)==crc32c(std::span(b).first(48));
}
struct Recovery { std::uint64_t records{}; bool invalid_tail{}; };
// Offline scan only: writer must have exited or quiesced. Reading mutable
// records concurrently via ifstream is not a substitute for synchronization.
inline Recovery recover(std::istream& input) {
  Block b{};
  if(!input.read(reinterpret_cast<char*>(b.data()),b.size()) || !valid_header(b))
    throw std::runtime_error("invalid/truncated journal header");
  const auto capacity=get(b,16,8);
  Recovery r;
  for(std::uint64_t i=1;i<=capacity;++i) {
    if(!input.read(reinterpret_cast<char*>(b.data()),b.size())) {
      r.invalid_tail=true; break;
    }
    if(!valid_record(b,i)) { r.invalid_tail=true; break; }
    ++r.records;
  }
  return r;
}
} // namespace ll::journal
