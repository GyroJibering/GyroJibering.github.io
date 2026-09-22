---
layout: post
title: "MPMC 环形队列：sequence、CAS 争用与“无锁”术语陷阱"
date: 2026-09-22 00:20 +0800
categories: [C++, 低延迟]
tags: [MPMC, CAS, rdtsc, perf, benchmark]
permalink: /blog/bounded-mpmc-queue-and-measurement/
toc: true
---

SPSC 简单，是因为槽位所有权天然一对一。把它改成多生产者、多消费者后，真正困难的不是把两个游标换成 CAS，而是回答三个问题：谁拿到了位置、这一圈的槽位处于什么状态、线程中途暂停时系统还能否前进。

这篇实现并测量一个 Vyukov 风格的有界 MPMC 环。先给结论：它无互斥、无热路径分配、通常很快，但作者对原算法的描述很谨慎——它并不满足严格意义的 lock-free 进展保证。工程文章若只因看到 CAS 就称它为“严格无锁”，是在混淆实现手段与性质。

## 每个槽位为什么需要 sequence

只有全局 `enqueue_pos` 和 `dequeue_pos` 不够。环复用后，同一个数组下标会先后代表位置 `i`、`i + N`、`i + 2N`；一个布尔 `ready` 无法区分是哪一圈，容易出现 ABA。

容量为 `N` 时，逻辑位置 `p` 对应 `cell[p & (N - 1)]`：

| 状态 | `cell.sequence` |
|---|---:|
| 第一次可由生产者 `p` 认领 | `p` |
| 生产者已发布，可由消费者 `p` 读取 | `p + 1` |
| 消费完成，可供下一圈生产者使用 | `p + N` |

生产者流程：

```cpp
pos = enqueue_pos.load(relaxed);
cell = cells[pos & mask];
seq = cell.sequence.load(acquire);

if (seq == pos && enqueue_pos.compare_exchange_weak(pos, pos + 1, relaxed)) {
    cell.value.emplace(value);
    cell.sequence.store(pos + 1, release);
}
```

消费者等待 `seq == pos + 1`，拿到 `dequeue_pos` 后读取并析构元素，最后 `sequence.store(pos + N, release)`。

sequence 同时承担三件事：标识代际、传递元素可见性、传递槽位可复用性。全局游标上的 CAS 只负责分配逻辑位置，不负责发布 payload，所以 CAS 使用 relaxed 仍可以成立；真正的发布边在每槽位 sequence 上。

## 线性化点不能随口指定

生产者成功 CAS 只是**预留**了位置，此时消费者还不能读；发布发生在 sequence 的 release store。消费者的 acquire 读到它之后，payload 才可见。

这带来一个重要现象：生产者 A 先拿到位置 10 后被抢占，生产者 B 可以完成位置 11，但消费者面对位置 10 仍不能越过这个洞。FIFO 顺序保住了，整体进展却依赖 A 恢复运行。

因此本实现的准确描述是：

- bounded MPMC ring；
- 操作不使用 mutex，热路径不分配；
- 每次位置竞争通过 CAS；
- **不宣称正式的 lock-free progress guarantee**。

Lock-free 要求系统整体在有限步骤内持续有操作完成，单个线程可以饥饿；wait-free 进一步要求每个操作都有步数上界。代码里没有锁，不自动推出其中任何一个性质。

如果业务真的要求在任意参与线程停顿时保持全局进展，需要选择经过相应证明的算法，同时处理动态节点的安全回收，例如 hazard pointers 或 epoch reclamation。那部分复杂度不会因为 API 名叫 `ConcurrentQueue` 而消失。

## 正确性测试检查什么

本实验启动 4 个生产者和 4 个消费者。每个生产者写入不重叠的整数区间，共 100 万条；消费结果排序后必须精确等于 `[0, 1000000)`。

这同时检查：

- 没有丢元素；
- 没有重复消费；
- 没有读到未发布或上一圈的数据；
- 环多次回绕仍正确。

测试在当前主机通过。但这不是线性化证明，也没有覆盖所有调度。进一步应加入 ThreadSanitizer、随机暂停、不同容量、计数器回绕模拟，以及 ARM 主机测试。

## `rdtsc` 到底测了什么

`RDTSC` 读取的是时间戳计数器，不等同于当前核心实际执行的 cycles。现代 x86 常见 invariant TSC 以近似恒定频率运行，而 DVFS 会改变核心频率。要测硬件 cycles，使用 PMU 和 `perf stat`；要测非常短的时间区间，可以用 TSC，但必须处理乱序。

本实验使用：

```text
开始：LFENCE; RDTSC; LFENCE
结束：RDTSCP; LFENCE
```

`RDTSCP` 会等待此前指令执行和此前 load 全局可见，但它不是完整序列化屏障，后续指令仍需约束。围栏本身也有成本，所以先测空框架开销，并保持被测区间明显长于计时开销。

另一个大坑是协调：如果发送时间写进队列后生产者继续灌数据，测到的是服务时间加排队时间。延迟实验只允许一条消息在途；吞吐实验批量运行，用 `steady_clock` 统计总量，二者不混用。

## 本机结果与争用曲线

Ryzen 5 9600X、Zig clang C++20 `-O3`，每个生产者 100 万条，三次结果：

| 并发度 | 第 1 次 | 第 2 次 | 第 3 次 |
|---|---:|---:|---:|
| 1P / 1C | 50.50 | 49.65 | 49.72 Mmsg/s |
| 2P / 2C | 41.22 | 41.51 | 41.28 Mmsg/s |
| 4P / 4C | 19.27 | 19.28 | 19.50 Mmsg/s |

线程增加，吞吐反而下降。原因并不神秘：所有生产者争 `enqueue_pos`，所有消费者争 `dequeue_pos`，CAS 失败和缓存行所有权转移增加；测试中的全局消费计数器本身也构成额外热点。这组结果不是算法排名，而是一个提醒：**MPMC 提供连接拓扑的灵活性，却可能把争用集中到两个 cache line。**

低延迟流水线如果拓扑允许，多个 SPSC 通常更容易推理和扩展：每个生产者拥有独立通道，由单线程按确定规则合并。只有业务语义确实是“任意生产者交给任意消费者”时，MPMC 才值得支付这笔成本。

## 用 `perf` 把“慢”拆开

仓库中的 `scripts/perf.sh` 固定 CPU 后执行：

```bash
perf stat -r 10 \
  -e cycles,instructions,branches,branch-misses,cache-references,cache-misses \
  taskset -c 2,3 ./build-release/benchmark

perf record -g --call-graph dwarf \
  taskset -c 2,3 ./build-release/trading_loop
perf report
```

至少同时看：

- `cycles` 与 `instructions`：区分代码量和停顿；
- IPC：低 IPC 可能来自内存、分支或前端瓶颈，不能单独下结论；
- cache misses：观察工作集和跨核共享；
- branch misses：CAS 重试路径和空/满分支是否变得不可预测；
- context switches、CPU migrations：尾延迟是否来自调度；
- counter running percentage：事件过多被 multiplex 后，缩放值是否可信。

当前会话是 Windows，无法伪造 Linux `perf` 数字，所以仓库只保存了本机 `rdtsc`/吞吐数据；脚本留给 Linux 裸机复现。跨机器比较前必须固定编译器、优化级别、CPU governor、NUMA 节点、SMT 配对和绑核方案。

## 这次复习留下的原则

1. CAS 成功不等于 payload 已发布；找真正的发布点。
2. sequence number 往往既解决代际，也承载内存同步。
3. “没有 mutex”“non-blocking API”“lock-free progress”是三件事。
4. 平均吞吐不能代表 p99.9 延迟，吞吐实验也不能充当延迟实验。
5. MPMC 是语义选择，不是 SPSC 的自动升级版。

## 参考资料

- Dmitry Vyukov, [Bounded MPMC queue](https://sites.google.com/site/1024cores/home/lock-free-algorithms/queues/bounded-mpmc-queue)
- Anthony Williams, [C++ Concurrency in Action 配套代码](https://github.com/anthonywilliams/ccia_code_samples)
- Intel, [Intel 64 and IA-32 Architectures Software Developer's Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- Linux, [`perf stat` manual](https://man7.org/linux/man-pages/man1/perf-stat.1.html)
- [本实验 MPMC 实现](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/include/ll/bounded_mpmc_queue.hpp)
