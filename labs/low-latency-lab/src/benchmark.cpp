#include "ll/spsc_queue.hpp"
#include "ll/bounded_mpmc_queue.hpp"
#include "ll/measurement.hpp"
#include <chrono>
#include <iomanip>
#include <memory>
#include <mutex>
#include <string_view>
#include <thread>

namespace m=ll::measurement;
using Clock=std::chrono::steady_clock;
struct Message {std::uint64_t id{}, inverse{};};
inline Message message(std::uint64_t id) {return {id,~id};}
constexpr std::size_t n=1000000;
constexpr std::size_t warm=20000;

template<std::size_t Capacity>
class MutexQueue {
  std::array<Message,Capacity> slots_{};
  std::mutex mutex_;
  std::size_t head_=0,tail_=0;
 public:
  bool try_push(Message x) {
    std::lock_guard lock(mutex_);
    if(tail_-head_==Capacity) return false;
    slots_[tail_++&(Capacity-1)]=x;return true;
  }
  bool try_pop(Message& x) {
    std::lock_guard lock(mutex_);
    if(tail_==head_) return false;
    x=slots_[head_++&(Capacity-1)];return true;
  }
};
struct alignas(64) Stats {std::uint64_t sum{},count{},retries{};};

template<class Queue>
void throughput(const char* name,unsigned count,const std::vector<unsigned>& cpus,int rep) {
  const auto total=n*count;
  auto queue=std::make_unique<Queue>();
  std::vector<std::thread> threads;
  std::vector<Stats> stats(count);
  std::atomic<unsigned> ready{0},finished{0};
  std::atomic<bool> go{false};
  for(unsigned p=0;p<count;++p) threads.emplace_back([&,p]{
    m::pin(cpus[p]);ready.fetch_add(1,std::memory_order_release);
    while(!go.load(std::memory_order_acquire)) m::spin();
    for(std::size_t i=0;i<n;++i) {
      const auto value=message(p*n+i);
      while(!queue->try_push(value)) m::spin();
    }
    finished.fetch_add(1,std::memory_order_release);
    finished.notify_one();
  });
  for(unsigned c=0;c<count;++c) threads.emplace_back([&,c]{
    m::pin(cpus[count+c]);ready.fetch_add(1,std::memory_order_release);
    while(!go.load(std::memory_order_acquire)) m::spin();
    Message value;
    // Equal finite quotas: termination has no per-message global RMW.
    // This is a fixed-work benchmark, not a fairness or open-loop-load test.
    while(stats[c].count<n) {
      if(queue->try_pop(value)) {
        if(value.inverse!=~value.id) std::abort();
        stats[c].sum+=value.id;++stats[c].count;
      } else {++stats[c].retries;m::spin();}
    }
    finished.fetch_add(1,std::memory_order_release);
    finished.notify_one();
  });
  while(ready.load(std::memory_order_acquire)!=count*2) m::spin();
  const auto start=Clock::now();go.store(true,std::memory_order_release);
  for(auto f=finished.load(std::memory_order_acquire);f!=count*2;
      f=finished.load(std::memory_order_acquire)) finished.wait(f,std::memory_order_acquire);
  const auto seconds=std::chrono::duration<double>(Clock::now()-start).count();
  for(auto& t:threads)t.join();
  std::uint64_t sum=0,retries=0;
  for(auto s:stats){sum+=s.sum;retries+=s.retries;}
  if(sum!=total*(total-1)/2) std::abort();
  std::cout<<"throughput,"<<name<<",rep="<<rep<<",P="<<count<<",C="<<count
    <<",messages="<<total<<",seconds="<<seconds<<",Mmsg_s="<<total/seconds/1e6
    <<",sum="<<sum<<",empty_retries="<<retries<<",cpus=";
  for(unsigned i=0;i<count*2;++i)std::cout<<cpus[i]<<":";
  std::cout<<'\n';
}

void roundtrip(unsigned producer,unsigned consumer,int rep) {
  ll::SpscQueue<Message,1024> request,reply;
  std::vector<std::uint64_t> samples; samples.reserve(n);
  std::atomic<bool> ready{false};
  std::thread responder([&]{
    m::pin(consumer);ready.store(true,std::memory_order_release);
    Message value;
    for(std::size_t i=0;i<n+warm;++i){
      while(!request.try_pop(value))m::spin();
      while(!reply.try_push(value))m::spin();
    }
  });
  m::pin(producer);
  while(!ready.load(std::memory_order_acquire))m::spin();
  Message value;
  for(std::size_t i=0;i<n+warm;++i) {
    const auto begin=m::stamp();
    while(!request.try_push(message(i)))m::spin();
    while(!reply.try_pop(value))m::spin();
    const auto end=m::stamp();
    if(value.id!=i||value.inverse!=~i)std::abort();
    if(i>=warm)samples.push_back(end-begin);
  }
  responder.join();
  const auto s=ll::percentiles(std::move(samples));
  std::cout<<"RTT_TSC,rep="<<rep<<",cpus="<<producer<<":"<<consumer
    <<",samples="<<n<<",min="<<s.min<<",p50="<<s.p50<<",p99="<<s.p99
    <<",p999="<<s.p999<<",max="<<s.max<<'\n';
}

int main(int argc,char** argv) try {
  const auto cores=m::topology();m::print_environment(cores);
  if(cores.size()<2)throw std::runtime_error("need two physical cores");
  const std::string_view mode=argc>1?argv[1]:"all";
  std::vector<unsigned> cpus;
  for(auto& c:cores)cpus.push_back(c.cpus[0]);
  for(auto& c:cores)for(std::size_t i=1;i<c.cpus.size();++i)cpus.push_back(c.cpus[i]);
  if(mode=="all"||mode=="spsc") {
    m::pin(cpus[0]);
    std::vector<std::uint64_t> empty;empty.reserve(n);
    for(std::size_t i=0;i<n;++i){auto a=m::stamp();auto b=m::stamp();empty.push_back(b-a);}
    const auto e=ll::percentiles(empty);
    std::cout<<"empty_bracket_TSC,p50="<<e.p50<<",p99="<<e.p99<<",max="<<e.max<<'\n';
    auto a=m::stamp();auto begin=Clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto end=Clock::now();auto b=m::stamp();
    std::cout<<"TSC_MHz_estimate="<<(b-a)/std::chrono::duration<double>(end-begin).count()/1e6<<'\n';
    for(int rep=0;rep<5;++rep) {
      roundtrip(cpus[0],cpus[1],rep);
      throughput<ll::SpscQueue<Message,1024>>("spsc1024",1,cpus,rep);
      if(cores[0].cpus.size()>1) roundtrip(cpus[0],cores[0].cpus[1],rep);
    }
  }
  if(mode=="all"||mode=="mpmc") {
    // A separate warm-up run, then rotate order to reduce consistent bias.
    throughput<ll::BoundedMpmcQueue<Message,1024>>("warmup_mpmc",1,cpus,-1);
    for(int rep=0;rep<5;++rep)for(unsigned count:{1U,2U,4U}) {
      if(cpus.size()<count*2)continue;
      if(rep%2==0)throughput<MutexQueue<1024>>("mutex1024",count,cpus,rep);
      throughput<ll::BoundedMpmcQueue<Message,1024>>("mpmc1024",count,cpus,rep);
      if(rep%2!=0)throughput<MutexQueue<1024>>("mutex1024",count,cpus,rep);
    }
  }
} catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
