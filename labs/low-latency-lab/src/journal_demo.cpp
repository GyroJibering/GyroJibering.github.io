#if !defined(__linux__)
#error "journal_demo requires Linux"
#endif
#include "ll/journal_format.hpp"
#include <atomic>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <system_error>
#include <thread>
#include <unistd.h>

namespace {
class Journal {
 public:
  Journal(const char* path,std::size_t capacity):capacity_(capacity) {
    if(capacity==0 || capacity>(std::numeric_limits<std::size_t>::max()-64)/64)
      throw std::invalid_argument("capacity");
    bytes_=64+64*capacity;
    try {
      fd_=::open(path,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
      if(fd_<0) fail("create exclusively");
      // Allocate backing blocks at setup; ENOSPC is reported before append.
      const int allocation=::posix_fallocate(fd_,0,static_cast<off_t>(bytes_));
      if(allocation) throw std::system_error(allocation,std::generic_category(),"fallocate");
      mapping_=::mmap(nullptr,bytes_,PROT_READ|PROT_WRITE,MAP_SHARED,fd_,0);
      if(mapping_==MAP_FAILED) fail("mmap");
      std::memset(mapping_,0,bytes_); // setup cost, not part of append timing
      const auto header=ll::journal::header(capacity);
      std::memcpy(mapping_,header.data(),64);
      if(::msync(mapping_,64,MS_SYNC)<0 || ::fsync(fd_)<0) fail("header sync");
      auto parent=std::filesystem::path(path).parent_path();
      if(parent.empty()) parent=".";
      const int directory=::open(parent.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
      if(directory<0) fail("open directory");
      const int synced=::fsync(directory), saved=errno;
      ::close(directory);
      if(synced<0) throw std::system_error(saved,std::generic_category(),"directory sync");
      event_=::eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
      if(event_<0) fail("eventfd");
      worker_=std::thread([this]{ flush_loop(); });
    } catch(...) { cleanup(); throw; }
  }
  Journal(const Journal&)=delete;
  Journal& operator=(const Journal&)=delete;
  ~Journal() { stop(); cleanup(); }

  // Exactly one writer. Returns a *published* sequence, never a durable ACK.
  std::uint64_t append(std::uint32_t type,std::string_view payload) {
    if(closed_ || next_==capacity_) throw std::runtime_error("closed/full journal");
    check_error();
    const auto b=ll::journal::record(next_+1,type,payload);
    // The mapped bytes are immutable after publication. No in-place rewriting,
    // no atomic_ref on persistent C++ objects, no concurrent recovery scanner.
    std::memcpy(static_cast<std::byte*>(mapping_)+64+next_*64,b.data(),64);
    published_.store(++next_,std::memory_order_release);
    if(next_%4096==0) notify();
    return next_;
  }
  std::uint64_t close() {
    stop(); check_error();
    return durable_.load(std::memory_order_acquire);
  }
 private:
  [[noreturn]] static void fail(const char* what) {
    throw std::system_error(errno,std::generic_category(),what);
  }
  void check_error() {
    if(const int e=error_.load(std::memory_order_acquire))
      throw std::system_error(e,std::generic_category(),"journal worker");
  }
  void notify() noexcept {
    const std::uint64_t one=1;
    for(;;) {
      if(::write(event_,&one,sizeof(one))==sizeof(one)) return;
      if(errno==EINTR) continue;
      if(errno!=EAGAIN) error_.store(errno,std::memory_order_release);
      return; // EAGAIN means a notification is already pending
    }
  }
  void flush_loop() noexcept {
    for(;;) {
      pollfd p{event_,POLLIN,0};
      const int ready=::poll(&p,1,50);
      if(ready<0 && errno!=EINTR) {error_.store(errno);return;}
      std::uint64_t count=0;
      while(::read(event_,&count,sizeof(count))<0 && errno==EINTR) {}
      // Read stop first: acquiring the final stop publication also orders the
      // final published watermark. Reading target first could lose the tail.
      const bool stopping=stop_.load(std::memory_order_acquire);
      const auto target=published_.load(std::memory_order_acquire);
      if(target>durable_.load(std::memory_order_relaxed)) {
        if(::msync(mapping_,64+target*64,MS_SYNC)<0) {error_.store(errno);return;}
        durable_.store(target,std::memory_order_release);
      }
      if(stopping) return;
    }
  }
  void stop() noexcept {
    if(closed_) return;
    closed_=true;
    stop_.store(true,std::memory_order_release);
    if(event_>=0) notify();
    if(worker_.joinable()) worker_.join();
  }
  void cleanup() noexcept {
    if(mapping_!=MAP_FAILED) ::munmap(mapping_,bytes_);
    if(event_>=0) ::close(event_);
    if(fd_>=0) ::close(fd_);
  }
  int fd_{-1},event_{-1};
  void* mapping_{MAP_FAILED};
  std::size_t capacity_,bytes_{},next_{};
  bool closed_{false};
  std::atomic<bool> stop_{false};
  std::atomic<int> error_{0};
  std::atomic<std::uint64_t> published_{0},durable_{0};
  std::thread worker_;
};
}

int main(int argc,char** argv) try {
  if(argc!=3) {std::cerr<<"usage: journal_demo create|recover PATH\n";return 2;}
  if(std::string_view(argv[1])=="recover") {
    std::ifstream file(argv[2],std::ios::binary);
    const auto r=ll::journal::recover(file);
    std::cout<<"valid_prefix="<<r.records<<" stopped_at_invalid_tail="<<r.invalid_tail<<'\n';
  } else if(std::string_view(argv[1])=="create") {
    Journal j(argv[2],1000000);
    const auto start=std::chrono::steady_clock::now();
    for(int i=0;i<1000000;++i) j.append(1,"BID 10000 10");
    const auto appended=std::chrono::steady_clock::now();
    const auto durable=j.close();
    const auto synced=std::chrono::steady_clock::now();
    std::cout<<"published=1000000 durable="<<durable
      <<" append_seconds="<<std::chrono::duration<double>(appended-start).count()
      <<" including_close_seconds="<<std::chrono::duration<double>(synced-start).count()<<'\n';
  } else return 2;
} catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
