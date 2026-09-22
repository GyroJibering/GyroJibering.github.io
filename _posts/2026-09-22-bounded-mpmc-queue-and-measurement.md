---
layout: post
title: "MPMC 的 reservation hole：一个可复现的反例，以及如何测错一条队列"
date: 2026-09-22 00:20 +0800
categories: [C++, 低延迟]
tags: [MPMC, 线性化, CAS, 性能测量, perf]
permalink: /blog/bounded-mpmc-queue-and-measurement/
toc: true
---

一条有界 MPMC 队列可以同时具备以下性质：payload 访问没有数据竞争，正常运行时不丢消息，所有协调都使用原子操作，而且一个已经完成的 enqueue 之后，另一个线程的 dequeue 仍然返回 false。

如果 false 被业务解释为“队列为空”，问题已经不只是性能，而是 API 与抽象 FIFO 语义不一致。

本文用一个确定性执行复现这种情况，再讨论它如何影响进展保证、通知机制和基准设计。研究对象是[本仓库的 Vyukov 风格有界环](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/include/ll/bounded_mpmc_queue.hpp)。算法作者将它归为 causal FIFO，并明确指出它不满足通常意义的 lock-free；这个限制是设计出发点，而不是代码审查中的附带备注。[原始说明](https://sites.google.com/site/1024cores/home/lock-free-algorithms/queues/bounded-mpmc-queue)

## 1. 两种状态不能压缩成一个 tail

MPMC 中，生产者首先竞争一个逻辑位置，之后才在该位置构造元素。至少有两种不同状态：

```text
reserved：某个生产者获得了独占写权限
published：元素已构造完成，消费者可以读取
```

全局 enqueue_pos 分配 reservation，每槽位 sequence 表示 publication 和复用代际。对容量 N、逻辑位置 p：

| sequence 值 | 对当前 p 的含义 |
|---|---|
| p | 这一代槽位可写 |
| p + 1 | 这一代元素已发布 |
| p + N | 消费者已释放，下一轮可写 |

生产者先 acquire 检查 sequence，再通过 relaxed CAS 推进 enqueue_pos，最后构造 payload、release 写 sequence。消费者执行对应协议，并在移动和析构之后 release 写 p + N。

这与 SPSC 的差别在于：所有权转移前增加了多个线程的竞争。全局游标的 CAS 决定谁获得位置；槽位 sequence 上的 acquire/release 决定什么时候允许触碰普通对象。

成功的 CAS 不发布 payload，因为 payload 此时还不存在。给这个 CAS 加 acq_rel 或 seq_cst 都不能发布未来的普通写。

## 2. 一个不依赖“多跑几次”的 reservation hole

测试使用一个 noexcept 构造函数，在原子门闩上等待：

```cpp
PausedValue(id, entered, resume) noexcept {
    entered->store(true, release);
    while (!resume->load(acquire)) { /* wait */ }
}
```

将它传给 try_emplace 后，等待发生在 reservation CAS 已成功、sequence 尚未发布的位置。测试线程等 entered，然后让第二个生产者完成 enqueue，最后调用 pop。

[research.cpp 的 reservation_hole 测试](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/tests/research.cpp) 实际得到：

```text
hole: enqueue(1) completed, later pop returned false
```

执行历史如下：

```text
时间       P0                         P1                      C
t0         认领位置 0
t1         在构造函数中暂停
t2                                    认领位置 1
t3                                    发布 1，enqueue 返回
t4                                                            调用 pop
t5                                                            位置 0 未发布，返回 false
t6         恢复，发布 0
t7                                                            依次取得 0、1
```

测试最后恢复 P0，验证消费顺序是 0 然后 1。这说明实现没有读未构造对象，也没有永久丢掉位置 1；问题在于 t5 的失败含义。

### 为什么不能称 t5 为线性化的 empty

假定队列初始为空，P1 的 enqueue 已经在 C 调用 pop 前完成。无论如何安排与之重叠的 P0：

- 若把 P0 放在 P1 前，队列至少有 0、1；
- 若把 P0 放在 P1 后，队列至少有 1；
- 即使不把仍未完成的 P0 纳入当前历史，P1 的元素仍然存在。

因此无法把 t5 的“空”放到 pop 调用与返回之间的任何时刻，同时保持普通 FIFO 的顺序语义。

本 API 应把 false 解释为“当前队首位置不可消费”。它可以意味着抽象空，也可以意味着前驱尚未发布。消费者重试是协议的一部分。若上层代码要求严格 empty 结果，就需要换算法或改变 API，不能靠换 memory_order 补救。

### 为什么“操作迅速返回 false”也不解决进展问题

确实，每次 try_pop 都可能迅速失败。但如果评价对象是能够成功传递已入队元素的 FIFO，那么在 P0 永久暂停时，消费者无法消费 P1，其他生产者最终也会耗尽环容量。

因此讨论 lock-free 时必须绑定操作规范。一个函数在循环里快速返回“暂不可用”，不能自动证明它实现了普通 lock-free FIFO。CAS 次数、系统成功推进以及单个线程是否饥饿，是不同层面的性质。

## 3. 通知与计数信号量为何容易配错

考虑业务层采用：

```text
生产者：enqueue 成功后 sem_post
消费者：sem_wait 后只 pop 一次
```

P1 的 enqueue 完成并 post，消费者获得一次令牌，但由于位置 0 的 hole，pop 失败。如果它丢掉这个令牌，回去等待，那么 P0 恢复时只再增加一个令牌。消费者取得 0 后，位置 1 仍留在队列里，却可能再没有通知。

这不是“随机丢唤醒”，而是把“完成了一个 enqueue”与“当前队首一定可读”错误地等同。

可选修正包括：获得令牌后保留对消费工作的责任并持续重试；用正确的事件计数/条件协议将“有变化”与“可消费数量”分开；或改用符合所需语义的队列。无论哪一种，都要重新分析停顿、CPU 占用和关闭行为。

作者也给出过相同类型的信号量失败历史，见 [Vyukov 对该问题的答复](https://groups.google.com/g/lock-free/c/Wg9F-EwYfF8)。这里的测试把核心依赖关系直接放进了本仓库的实现。

## 4. 泛型异常会把暂时的 hole 变成永久 hole

早期实现只要求 T 可构造。问题是：

```text
CAS 成功认领 p
    -> T 的构造函数抛异常
    -> sequence 永远不会变成 p + 1
```

同样，消费者在取得 dequeue_pos 后，如果移动赋值抛异常，sequence 也可能永远不回到可复用状态。

修订后对 emplace 要求 is_nothrow_constructible，对移动赋值和析构要求 noexcept。它牺牲泛型范围，换取协议完整性。若必须支持可抛异常类型，需要一个明确的取消/跳过状态，而且消费者、恢复逻辑、通知逻辑都要理解它；这已经是另一个算法。

noexcept 不代表执行时间有界。测试里的等待构造函数就不抛异常，却能无限等待。本文不会据此承诺任意 T 的进展性质。

## 5. sequence 不是无限期的 ABA 护身符

旧实现直接进行：

```cpp
intptr_t diff = intptr_t(sequence) - intptr_t(position);
```

当两个值跨越有符号边界时，即使真实逻辑距离只有一个槽位，有符号减法也可能溢出。修订版先做无符号减法：

```cpp
size_t diff = sequence - expected;
if (diff == 0) { /* current generation */ }
else if (diff > SIZE_MAX / 2) { /* behind */ }
else { /* ahead; reload position */ }
```

这个比较仍然有假设：相关观察的逻辑距离小于半个计数器周期。它消除了有符号溢出，没有消除有限标签的全部问题。

尤其在 MPMC 中，一个线程可以在读取 sequence 后停顿，其他线程继续推进。占用量始终不超过 N，并不限制这个线程所持观察的年龄。如果它暂停整个计数器周期，旧标签可能与新标签相同。64 位让这种执行在通常吞吐下极不现实，但数学上的 ABA 可能性不会凭位宽自动消失。

研究测试从 2^63 − 8 和 2^64 − 8 启动小环，检查符号边界和无符号回绕；它不声称模拟了“一个线程暂停完整 2^64 次全局推进”的情况。

## 6. 对第一版性能结论的更正

第一版有两个关键混杂因素：

1. CPU 2 与 3 实际属于同一个物理核心的 SMT 同胞，没有确认拓扑就称为跨核交接；
2. MPMC 消费者每条消息都操作一个全局 consumed.fetch_add，测试工具自身增加了一个共享 RMW 热点。

此外，单向延迟由生产者和消费者分别读 TSC，相减前没有验证不同执行上下文的时钟偏移；SPSC 吞吐实验没有在输出里保留 payload 校验结果；max 尖峰也没有调度跟踪就被直接归因为中断。

因此旧表保留为历史记录，但不再用于证明“队列延迟为 154 ticks”或“下降主要由 CAS 引起”。后者最多是需要 PMU/调度证据检验的假设。

## 7. 修订实验具体测量什么

[benchmark.cpp](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/src/benchmark.cpp) 把问题拆成两项。

### A. 两条 SPSC 的请求—应答 RTT

请求和响应使用不同 SPSC。生产者发出编号，消费者原样返回，生产者验证后再发下一条。开始与结束时间都在同一个、已成功绑定的发起线程上读取。

这测量的是：

```text
请求 push + 消费者等待/处理 + 响应 push + 发起者等待 + 计时扰动
```

它不是单次 push 耗时，也不能直接除以二成为单向延迟。两边执行路径不对称，轮询行为会受到对方速度影响。

为了不依赖未核实的 AMD LFENCE 配置，计时采用保守的 CPUID / RDTSC / CPUID 边界，并加入编译器屏障。一个真实遇到的错误是：最初直接使用 CPUID 头文件宏，返回寄存器未被使用，优化后序列化指令可能被删除。修订为带 memory clobber 的 volatile 汇编，并检查生成的汇编中 RDTSC 两侧确实存在 CPUID。

这套计时器很重，因此同时测空框架，不从结果中简单减掉某个常数。Intel 指令约束可查 [SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)；AMD 对 LFENCE dispatch serialization 的说明见[其技术材料](https://docs.amd.com/api/khub/documents/vbhMWnxkkda5Mz6LirjB_Q/content)。语言层屏障与处理器执行序列化也不能相互替代。

### B. 固定工作量的队列传递

每个生产者发送 100 万条 16 字节消息：

```cpp
struct Message { uint64_t id; uint64_t inverse; };
```

消费者检查 inverse == ~id，累计本线程的数量与 id 和，全部结束后验证总和。独立压力测试仍使用精确集合比较，因为总和相等本身不能排除所有丢失/重复组合。

结束条件改为每消费者固定配额；ready/go 只在试验边界同步，finished 每线程只修改一次，控制线程等待时休眠。热路径不再进行逐消息全局计数。分配、队列构造、线程创建和绑核在计时区间外完成；测试包含轮询、消息校验和结束协调成本。

对照组是同容量固定数组加 std::mutex，成功失败接口保持可比，MPMC 与 mutex 的执行先后每轮交替。它不是针对最佳阻塞队列的排名：没有比较 condition_variable、批处理、NUMA 分区或经过调优的工业库。

## 8. 本机实测：先看实验条件，再看数字

环境为 Windows、Ryzen 5 9600X、6 个物理核心/12 个逻辑处理器，Zig 0.15.2 所带 Clang 20.1.2，C++20、-O3。CPUID 报告 invariant TSC，hypervisor-present 位为 0；这两个标志不等于经过完整的时钟校准或平台认证。

拓扑查询得到：

```text
物理核心   0      1      2      3      4       5
逻辑 CPU  0/1    2/3    4/5    6/7    8/9    10/11
```

亲和性失败会终止实验，不能悄悄回退。RTT 每轮丢弃前 2 万次，保留 100 万次，共五轮。最终原始输出见 [revised-benchmark.txt](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/results/revised-benchmark.txt)。

| 放置方式 | 五轮 p50 | 五轮 p99 | 五轮 p99.9 |
|---|---|---|---|
| 不同物理核心，0 ↔ 2 | 624 / 624 / 624 / 663 / 624 | 780 / 741 / 780 / 780 / 780 | 819 / 819 / 819 / 819 / 1092 |
| SMT 同胞，0 ↔ 1 | 351 / 351 / 351 / 351 / 351 | 468 / 468 / 468 / 468 / 468 | 468 / 468 / 468 / 507 / 468 |

单位都是 TSC ticks，包含计时器。空框架 p50 与 p99 均为 195 ticks，其成本已经与 SMT RTT 同量级。粗略估计 TSC 为 3892.81 MHz，只能作为同一次会话的换算参考。

不采用“p99(RTT) − p99(empty)”作为修正值。一般情况下，两个分布之差的分位数不等于分位数之差；CPUID 还会改变流水线状态，观测并非被测系统之外的一项独立常量。

吞吐实验容量统一为 1024，单位 Mmsg/s：

| 算法与线程数 | 五轮结果 | 中位数 |
|---|---|---:|
| SPSC 1P/1C | 134.90 / 122.82 / 115.64 / 122.43 / 120.53 | 122.43 |
| MPMC 1P/1C | 78.73 / 81.62 / 83.59 / 76.85 / 94.37 | 81.62 |
| Mutex 1P/1C | 16.05 / 17.91 / 17.24 / 17.25 / 17.51 | 17.25 |
| MPMC 2P/2C | 18.51 / 26.51 / 19.45 / 19.18 / 19.02 | 19.18 |
| Mutex 2P/2C | 16.47 / 16.17 / 20.28 / 14.85 / 15.01 | 16.17 |
| MPMC 4P/4C | 18.86 / 18.57 / 18.72 / 17.48 / 18.79 | 18.72 |
| Mutex 4P/4C | 13.67 / 13.79 / 13.60 / 13.71 / 13.33 | 13.67 |

2P/2C 使用 0、2、4、6，位于四个不同物理核心。4P/4C 的放置为生产者 0/2/4/6、消费者 8/10/1/3；8 个工作线程超过物理核心数，因此部分线程使用 SMT。这不是纯粹的“只增加线程数”实验，不能画一条曲线就归因为 CAS 扩展性。

数值能支持的窄结论是：在这个固定工作量、容量与布局下，MPMC 对比 mutex 的优势随并发度变化；SPSC 1P/1C 在该实现中更快。它不能证明最佳算法、生产系统 p99、最大稳定到达率，或高负载下公平性。

单次 SPSC 吞吐区间仅约 7–9 ms，也限制了稳态结论。五轮 min/max 保留了波动，没有足够证据给出统计显著性或夸大的置信区间。

## 9. 为什么仍需要 perf，而不是更多小数位

跨核心 cache line 迁移、CAS 重试、分支、线程调度都可能影响结果。当前实验没有分别测量它们，因而不把任何一个写成已证实的主因。

在 Linux 上，应先用独立阶段收集：

```bash
perf stat -r 10 -e cycles:u,instructions:u -- ./build/benchmark mpmc
perf stat -r 10 -e context-switches,cpu-migrations,page-faults -- ./build/benchmark mpmc
perf record -g --call-graph dwarf -- ./build/trading_loop
perf report
```

这些命令的整进程统计包含初始化、多个小实验和汇总工作。要给“每条消息的 PMU cycles”下结论，需要把单一负载拆成独立运行阶段，或者在 ready/go 周围启停 counters；不能直接用整进程 cycles 除以其中一轮的消息数。

同时记录 enabled/running 时间，避免多事件 multiplex 后的缩放值被当作精确计数。cycles 与 instructions 的比值可描述执行效率，却不能独自区分缓存瓶颈和分支瓶颈。[perf stat 的事件与缩放说明](https://man7.org/linux/man-pages/man1/perf-stat.1.html)

当前机器没有可用 Linux 运行环境，所以这些是后续取证命令，没有对应的本机 PMU 结果。现有长尾的原因也保持未定：仅凭 TSC 尖峰不能区分抢占、中断或其他平台干扰。

## 10. 这个实验改变了哪些设计判断

MPMC 的吸引力在于连接关系灵活，但它同时带来 reservation/publication 分离、失败语义、有限代际、通知协议和竞争行为。业务能否接受这些条件，比最快一轮的吞吐数字更重要。

对于行情至策略的固定拓扑，单写者加每订阅者 SPSC 往往能缩小证明范围；对于真正需要多对多分摊工作的系统，MPMC 仍有价值。无论采用哪种结构，都应先明确“false 的业务含义”“停顿线程影响谁”“测试计入了哪些额外共享状态”。

完整环境、编译命令、测试结果与未验证项见[实验记录](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/results/RESEARCH.md)。
