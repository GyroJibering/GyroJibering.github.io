---
layout: post
title: "从 happens-before 到一条可证明安全的 SPSC 队列"
date: 2026-09-22 00:10 +0800
categories: [C++, 并发]
tags: [内存模型, 无锁编程, SPSC, acquire-release]
permalink: /blog/cpp-memory-model-and-spsc-queue/
toc: true
---

这是低延迟 C++ 实验的第一篇。我重新沿着《C++ Concurrency in Action》第二版第 5、7、8、11 章走了一遍，但目标不是背诵六种 `memory_order`，而是回答一个更严格的问题：我能否手写一条 SPSC 队列，并为每一次普通内存访问找到明确的 happens-before 路径？

完整实现和压力测试在 [`labs/low-latency-lab`](https://github.com/GyroJibering/GyroJibering.github.io/tree/main/labs/low-latency-lab)。

## 先把四种“顺序”分开

并发代码难读，经常不是因为指令太多，而是把不同层面的顺序混成了一种“看起来先后”。

1. **sequenced-before**：同一线程里，C++ 抽象机规定的求值先后。
2. **modification order**：每一个原子对象各自拥有一条修改全序；不存在自动覆盖所有原子的全局顺序。
3. **synchronizes-with**：某个 acquire 读到了 release 发布的值时，两者之间建立同步边。
4. **happens-before**：由 sequenced-before、synchronizes-with 及其传递闭包组成。

普通对象允许跨线程访问的关键不是“它最终会进缓存”，而是冲突访问之间是否存在 happens-before。没有这条边，至少一方又是写，就是 data race，程序行为未定义。

《C++ Concurrency in Action》第 5 章最值得反复看的不是 API 表，而是这个推理方式：**原子变量经常只是门铃，真正要传递的是门铃之前写入的普通数据。**

## 六种内存序如何落到工程选择

| 内存序 | 我在本实验中的理解与用途 |
|---|---|
| `relaxed` | 保证该原子读写不可撕裂并遵守它自己的 modification order，但不发布其他内存；用于线程私有游标的原子读 |
| `release` | 本线程此前的普通写不能越过它；用来发布“元素可读”或“槽位可复用” |
| `acquire` | 读到对应 release 后，本线程后续访问可以看到发布前的写 |
| `acq_rel` | 读改写同时承担 acquire 和 release；常用于竞争游标的 CAS |
| `seq_cst` | 在额外约束下参与单一总序，最容易推理，但不能修复数据竞争 |
| `consume` | 实际实现长期按 acquire 处理；这组代码不使用它 |

`relaxed` 不是“不安全模式”。如果一个游标只有当前线程写，而且当前读取不承担跨线程发布职责，relaxed 正合适。反过来，随手把一切改成 `seq_cst` 虽可能掩盖推理缺口，却不会让两个线程并发写同一个普通对象变得合法。

## 队列的三个不变量

队列容量是 2 的幂，`head` 和 `tail` 使用单调递增计数器，数组下标才做 `& (Capacity - 1)`：

```text
[head, tail)       已发布、尚未消费
tail - head == 0   空
tail - head == N   满
index              counter & (N - 1)
```

三个不变量决定了实现：

- 只有生产者写 `tail`，只有消费者写 `head`；
- 生产者在发布 `tail` 之前构造元素；
- 消费者在发布 `head` 之前读取并销毁元素。

核心代码只有两条对称路径：

```cpp
// producer
auto tail = tail_.load(std::memory_order_relaxed);
auto head = head_.load(std::memory_order_acquire); // 满时才刷新缓存
slots_[tail & mask].emplace(value);
tail_.store(tail + 1, std::memory_order_release);

// consumer
auto head = head_.load(std::memory_order_relaxed);
auto tail = tail_.load(std::memory_order_acquire); // 空时才刷新缓存
out = std::move(*slots_[head & mask]);
slots_[head & mask].reset();
head_.store(head + 1, std::memory_order_release);
```

实际代码缓存了对端游标，因此队列明显不满或不空时无需碰对端的 cache line。

## 为什么元素访问没有 data race

只说“acquire/release 配对”还不够，要分别证明发布和回收。

### 生产者把元素交给消费者

```text
构造 slot[p]                              读取 slot[p]
     | sequenced-before                       ^
tail.store(p+1, release) --sync-with--> tail.load(acquire)
```

消费者只有在 acquire 观察到 `tail >= p + 1` 后才读槽位。构造槽位 sequenced-before release，release synchronizes-with acquire，acquire 又 sequenced-before 读取槽位，所以构造 happens-before 读取。

### 消费者把槽位还给生产者

```text
读取并 reset slot[p]                      再次构造 slot[p]
          | sequenced-before                    ^
head.store(p+1, release) --sync-with--> head.load(acquire)
```

生产者只有在 acquire 看到消费者前进后才复用该槽位。因此上一次对象生命周期的结束 happens-before 下一次 `emplace`。

两条边缺一不可。只在 `tail` 上同步能保证消费者看见新元素，却不能保证生产者不会覆盖仍在读取的旧元素。

## 为什么自己的游标可以 relaxed

生产者是 `tail` 的唯一写者。它读取自己的 `tail` 只是为了确定下一位置，这次读取不负责接收其他线程发布的数据。同理，消费者读取自己的 `head` 也不承担同步。因此这两次 load 可以 relaxed。

跨线程读取对端游标则不同：

- 消费者 acquire `tail`，接收元素构造结果；
- 生产者 acquire `head`，接收元素析构结果。

判断内存序的办法不是从语法开始，而是先问：**这次原子操作要为哪些普通访问建立哪条边？**

## 缓存行和对象生命周期

`head` 与 `tail` 分别由不同核心频繁写。如果它们在同一缓存行，MESI 所有权会在核心间来回弹跳，这就是 false sharing。本实现给两者独立的 64 字节对齐区域。64 是常见工程值，不是 C++ 对所有机器的承诺；生产环境应结合目标硬件验证。

槽位使用 `std::optional<T>` 管理对象生命周期，避免默认构造全部 `T`，也避免直接对未构造存储做赋值。代价是每槽位多一个 engaged 状态；如果极致压缩布局，可以改为 placement new，但必须保留同样的构造、读取、析构顺序。

计数器最终会无符号回绕。这里利用无符号模运算，并假设生产者不可能领先消费者超过计数空间的一半；64 位计数在现实运行期足够，但这是依赖条件，不该从证明里消失。

## 我实际踩到的测量坑

第一版基准让生产者不断灌入，消费者读取每个元素里携带的 TSC。结果 p50 超过 58 万 ticks。队列没有突然慢几个数量级，测量包含了元素在队列里的等待时间。

修正后，延迟实验一次只允许一条在途消息，吞吐实验则不做逐消息计时。绑核运行五次，当前 Ryzen 5 9600X 主机得到：

```text
p50:   154, 154, 154, 154, 154 TSC ticks
p99:   193, 193, 193, 193, 193 TSC ticks
p99.9: 232, 193, 232, 193, 232 TSC ticks
吞吐:  505.28, 497.38, 489.36, 489.09, 470.74 Mmsg/s
```

最大值仍到 9 万至 38 万 ticks，因为 Windows 调度、抢占和中断没有消失。低延迟系统不能只报平均值，更不能从一台机器的结果外推到另一台机器。

压力测试连续传递 100 万个递增整数并逐个检查，严格顺序通过。它能发现很多实现错误，但测试通过不等于内存模型证明成立；在 x86 上“碰巧工作”的 relaxed 错误可能到 ARM 才暴露。

## 复习后的检查清单

- 先写清每个共享状态由谁写、由谁读；
- 为每次普通内存跨线程交接画出 happens-before；
- release 放在数据写完之后，acquire 放在读取数据之前；
- 区分安全性、线性化点和进展保证；
- 把对象生命周期也纳入证明；
- 分开测延迟、排队时间与吞吐；
- 报 p50/p99/p99.9/max，并保存机器、编译器、绑核信息。

## 参考资料

- Anthony Williams, [C++ Concurrency in Action, Second Edition](https://www.manning.com/books/c-plus-plus-concurrency-in-action-second-edition)，第 5、7、8、11 章
- [C++ working draft: order and consistency](https://eel.is/c++draft/atomics.order)
- [C++ working draft: multi-threaded executions and data races](https://eel.is/c++draft/basic.exec)
- [本系列 SPSC 完整实现](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/include/ll/spsc_queue.hpp)
