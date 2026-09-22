---
layout: post
title: "SPSC 的正确性边界：从对象生命周期、游标缓存到计数器回绕"
date: 2026-09-22 00:10 +0800
categories: [C++, 并发]
tags: [内存模型, SPSC, happens-before, 正确性证明]
permalink: /blog/cpp-memory-model-and-spsc-queue/
toc: true
---

考虑一个看似简单的问题：生产者在普通数组里写入一个对象，消费者在另一个核心上读取，为什么不需要给对象本身加锁？

“因为索引用了原子变量”不是答案。索引的原子性只保护索引。要保护数组元素，必须证明元素的构造、读取、析构、下一轮构造之间存在正确的顺序；还要解释缓存过期的索引为什么不会破坏这个顺序，以及计数器回绕后证明是否仍成立。

本文只研究一条有界 SPSC 环。推理对象是[仓库中的实际实现](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/include/ll/spsc_queue.hpp)，语言版本固定为 C++20。阅读路径来自《C++ Concurrency in Action》第二版第 5 章的内存模型、第 7 章的数据结构设计和第 11 章的测试方法；下文的证明与反例针对本实现，不是对书中算法的转述。

本系列另外三篇分别讨论 [MPMC 的反例与测量](/blog/bounded-mpmc-queue-and-measurement/)、[日志的持久化协议](/blog/event-driven-mmap-journal/)、[交易回路的一致性](/blog/low-latency-market-strategy-order-loop/)。

## 1. 必须先确定 API 的含义

设队列容量为 N。成功的 push 转移一个值，成功的 pop 将最早的未消费值移动到调用者提供的对象；返回 false 表示这次尝试没有取得进展，调用者可以重试。观察到过期游标可能导致保守的暂时失败，API 不提供“失败时获得了一份全局最新空满快照”的承诺。

使用约束如下：

| 约束 | 原因 |
|---|---|
| 同时只有一个生产者、一个消费者 | 两个线程竞争写同一游标会破坏所有权协议 |
| 构造队列发生在线程使用之前 | 初始化的普通写同样需要安全发布 |
| 析构时生产者和消费者均已停止 | 不能一边读取槽位，一边销毁 optional 数组 |
| pop 的输出对象由消费者独占，且不别名到槽位内部 | 队列只保护自己的槽位 |
| T 的构造、移动赋值和析构不抛异常 | 简化交接协议，失败只来自容量条件 |
| 本目标的 size_t 原子始终 lock-free | 不把底层库的隐式锁误称为算法的进展保证 |

代码用编译期约束检查后两项。仍有一个不能由这些约束推出的性质：T 的操作可能分配内存或等待外部状态。队列不分配，不代表任何 T 都不分配；队列控制路径步数有界，不代表任何 T 都 wait-free。对本文实际使用的整数消息，元素操作是固定成本的。

这一区分决定了“这是一条无锁队列”到底在什么条件下成立。

## 2. 从无限逻辑计数推导有限数组

先暂时忽略整数回绕。令：

- H：消费者已经释放的元素数；
- T：生产者已经发布的元素数；
- N：容量。

核心不变量是：

```text
0 <= T - H <= N
[H, T) 中的逻辑位置已经发布、尚未释放
位置 p 的物理槽位为 p mod N
```

生产者只能在 T − H < N 时写位置 T；消费者只能在 H < T 时读位置 H。

这里的 head 和 tail 表示完成边界，不是“线程准备开始访问的位置”。如果生产者先增加 tail 再构造对象，消费者就可能读到尚未开始生命周期的对象；如果消费者先增加 head 再完成移动和析构，生产者就可能覆盖还在使用的对象。

因此每个槽位的合法生命周期只有：

```text
可写 -> 构造中 -> 已发布 -> 消费中 -> 已释放 -> 下一轮构造
           生产者独占           消费者独占
```

N 取 2 的幂，仅用于把取模优化为位与；它不承担同步职责。用非 2 的幂配合正常取模，同样可以设计正确队列。

## 3. 安全性需要两条独立的 happens-before 链

用 Wp 表示位置 p 的构造，Rp 表示消费者读取，Dp 表示析构，Pp 表示生产者发布 p + 1，Cp 表示消费者释放 p + 1。

第一条链保护“构造完成后才能读”：

```text
Wp
 | sequenced-before
Pp: tail.store(p + 1, release)
 | synchronizes-with（acquire 必须读取相应发布）
L:  tail.load(acquire)
 | sequenced-before
Rp
```

第二条链保护“读取、析构完成后才能复用”：

```text
Rp -> Dp
       | sequenced-before
Cp: head.store(p + 1, release)
       | synchronizes-with
K:  head.load(acquire)
       | sequenced-before
W(p + N)
```

这两条链分别给出 Wp happens-before Rp、Dp happens-before W(p + N)。槽位的普通写、普通读以及对象生命周期转换，因此不会在本协议内无序冲突。

这里使用的语言规则是：release 发布与读取其值的 acquire 建立同步，随后通过线程内顺序传递。规范依据是固定版本 [N4861 的 atomics.order](https://timsong-cpp.github.io/cppwp/n4861/atomics.order#2)；不要拿正在变化的最新草案替代实际编译目标的规则。

### acquire 读到更晚的游标怎么办

消费者可能第一次就读到 tail = 8，而不是依次看到 1、2、3。它能否读取前八个元素？

可以，但原因不是“数值 8 比 1 大”。设这次 acquire 读自生产者发布 8 的 release。生产者对位置 0…7 的构造，都在该 release 之前 sequenced-before，因此都通过这一个 release 被发布。消费者读前八个元素不需要为每个元素重新 acquire。

生产者批量观察 head 的论证对称：读到消费者发布的 head = 8，就获得前八次析构完成的顺序保证。

这不是依赖“任何更晚 store 都属于 release sequence”。C++20 的 release sequence 对后续 RMW 有特定定义；本实现每次游标发布本来就是 release，而且来自唯一写者，直接使用线程内顺序即可。

### 删除任意一条边会发生什么

把消费者读取 tail 的 acquire 改成 relaxed，tail 数值本身仍原子，但 Wp 到 Rp 的跨线程同步消失。即使 x86 反汇编仍是相同的 mov，也不能把硬件现象当作 C++ 语言证明。

保留 tail 同步，只把生产者读取 head 的 acquire 改成 relaxed，也不正确。第一次传递可能看不出问题；到槽位复用时，Dp 与 W(p + N) 之间没有同步，普通读写和生命周期访问不再受协议保护。

因此一个只向前画“生产者发布”的图，恰好漏掉了环形结构最关键的后一半。

## 4. 缓存过期游标为什么只能造成保守失败

实际代码不会每次访问对端原子，而是在本线程保存：

- Hc：生产者缓存的 head；
- Tc：消费者缓存的 tail。

在未回绕的逻辑模型中，生产者的 Hc 不会领先于真实 H：

```text
Hc <= H
因此 T - Hc >= T - H
```

用旧 head 算出来的占用量只会偏大。它可能把已经有空位的队列看成满，但不能把真实满队列看成未满。只有遇到缓存边界，才刷新 head：

```cpp
const auto tail = tail_.value.load(std::memory_order_relaxed);
if (tail - producer_cached_head_ == Capacity) {
    producer_cached_head_ = head_.value.load(std::memory_order_acquire);
    if (tail - producer_cached_head_ == Capacity) return false;
}
slots_[tail & mask].emplace(...);
tail_.value.store(tail + 1, std::memory_order_release);
```

消费者侧有对称不等式：

```text
Tc <= T
因此 Tc - H <= T - H
```

旧 tail 低估可读元素数，只会更早尝试刷新，不会凭空造出已发布元素。

原子读读一致性保证同一线程依次读取同一原子时，不会在该原子的 modification order 中倒退。结合“每次只向缓存边界推进，达到边界才刷新”，缓存不会让本地线程越过已经获得所有权的范围。相关语言约束见 [N4861 intro.races 的 coherence 规则](https://timsong-cpp.github.io/cppwp/n4861/intro.races#16)。

这也说明 acquire 不是“必须读到此刻最新值”。正确性依赖的是看到的值足够保守，而且它承载相应的发布边。

## 5. 哪些操作可以 relaxed，哪些不行

生产者自己的 tail 只有它自己修改。读取 tail 的用途是计算下一位置，不是接收消费者发布的数据，因此使用 relaxed。消费者读取自己的 head 同理。

下表比背诵全部 memory_order 更接近审查代码时需要的信息：

| 原子访问 | 发布或接收什么 | 内存序 |
|---|---|---|
| 生产者读取 tail | 本线程位置 | relaxed |
| 生产者读取 head | 消费者已完成的读与析构 | acquire |
| 生产者写 tail | 本轮元素构造 | release |
| 消费者读取 head | 本线程位置 | relaxed |
| 消费者读取 tail | 生产者已完成的构造 | acquire |
| 消费者写 head | 本轮读取与析构结束 | release |

把所有操作设成 seq_cst 可以保留这些必要同步，但引入更强的总序约束；这不证明它一定更慢，成本取决于架构和编译器。反过来，relaxed 的安全性也不能靠“它只有一个写者”概括：对端读取虽然不竞争写，却承担接收 payload 的职责。

## 6. 成功交接、失败返回与 empty() 的边界

对成功 push，可以把 tail 的 release store 视为元素对消费者可见的提交点。成功 pop 在 head 的 release store 归还容量；在那之前，消费者可以已经完成移动，但生产者仍不能复用槽位。

这个解释不能无条件推广到 empty()：

```cpp
return head.load(acquire) == tail.load(acquire);
```

这是两个独立读取，不是一个事务快照。另一个线程可以在它们之间运行。把 empty() 当成“下一次 pop 一定成功/失败”的授权，是典型的检查与使用分离错误。业务热路径应该直接根据 try_pop 的结果行动。

停止协议也要单独证明。若生产者发布完所有元素后，以 release 写 done；消费者 acquire 看见 done，再 drain 队列，那么 done 为最终发布提供额外顺序。单纯观察某一次 empty() 就析构队列，没有这样的证明。

## 7. 无符号回绕：区分数组回绕与计数器回绕

每传递 N 条，数组下标回到零。这只是在复用槽位，不是计数器发生溢出。

计数器是 w 位无符号整数，真正溢出发生在 2^w。C++ 定义了无符号运算的模 2^w 语义，因此只要逻辑距离保持在可表示范围内：

```text
(T mod 2^w - H mod 2^w) mod 2^w = T - H
```

本队列的逻辑距离不超过 N，缓存距离也由容量边界限制。更关键的是 SPSC 的停顿约束：生产者停止时消费者最多再释放 N 个位置；消费者停止时生产者最多再前进 N 个位置。某个线程不可能在自己完全停顿期间，让对端独自前进整整一个计数器周期。

这个性质使 SPSC 的回绕分析明显简单于 MPMC。在 MPMC 中，一个生产者停顿，其他生产者仍可继续数十亿圈；“队列容量很小”并不能限制某个参与者持有旧观察的年龄。

测试分别从 0、2^63 − 8 和 2^64 − 8 启动容量 4 的队列，反复填满、检查满、全部取空并核对 FIFO。它真实经过有符号边界和无符号回绕；“压力测试传了百万条”若从零开始，则根本碰不到这两个边界。

## 8. 异常与生命周期不是外围细节

早期版本允许任意 constructible 的 T。SPSC 在 emplace 抛异常时尚未推进 tail，通常可以保留队列结构，但构造函数产生的外部副作用不一定可回滚；pop 的移动赋值如果抛异常，还可能留下已被部分移动的槽位值。

本实现选择限制 T，不承诺一般异常安全的容器语义。理由是消息通道本来就使用固定大小数据，支持任意可抛异常业务对象会扩大证明范围，却没有实际收益。

到了 MPMC，这个问题更严重：构造发生在 reservation CAS 之后，异常会留下已占位但永不发布的槽位。这个区别说明容器模板“能编译更多类型”，不一定意味着设计更完整。

## 9. 对齐减少争用，但不参与安全性证明

head、tail 和两侧缓存分别隔离到 64 字节边界，避免两个线程反复写同一个 cache line。

不过 64 只是当前目标布局的选择。std::optional<T> 还可能增加标记和 padding；环中相邻 payload 仍可能共享 cache line；当容量很小，两侧虽然修改不同元素，依然会竞争同一行。

如果把每个槽位都填充到 64 字节，可以减少相邻元素干扰，却会扩大工作集和 TLB 压力。哪一种更快，需要在相同负载和拓扑下对照。不能由“padding 消除了 false sharing”直接推出“整体更快”。

## 10. 验证能支持什么结论

[research.cpp](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/tests/research.cpp) 检查边界与特定反例；[stress.cpp](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/tests/stress.cpp) 检查百万消息并发传输。

本次实际执行了优化构建，以及带 UndefinedBehaviorSanitizer 的研究测试。它们通过了容量边界、计数器回绕和 FIFO 检查。UBSan 不是线程竞争检测器，这里没有运行 ThreadSanitizer，也没有进行 C++ 弱内存模型的穷举。

因而证据分为三层：

1. 上文的 happens-before 推导解释普通对象访问为何安全；
2. 确定性测试检验实现中的算术、边界和状态转换；
3. 并发压力测试检查有限执行中的顺序与数据完整性。

三者互补，不能互相替代。尤其不能因为 x86 上反复跑通，就把缺失 acquire 的实现判为正确。

早期文章给出的 154 ticks 单向延迟也不再作为性能结论。原测试既没有确认 CPU 拓扑，也没有验证跨核 TSC 偏差；后续查明 CPU 2/3 是 SMT 同胞。修订实验改用发起线程本地计时的请求—应答 RTT，细节和原始结果放在[第二篇](/blog/bounded-mpmc-queue-and-measurement/)。

对于这条 SPSC，真正可以保留下来的结论是：在约定的线程所有权、元素操作和原子实现条件下，两条发布链覆盖了槽位完整生命周期；缓存优化只缩小本线程敢于使用的范围。性能数字必须另行回答“测了哪段工作、在哪两个执行上下文之间测、计时器增加了多少工作”。

## 资料与可复现入口

- Anthony Williams，[第二版目录与章节范围](https://livebook.manning.com/book/c-plus-plus-concurrency-in-action-second-edition/about-this-book)。本实验使用其问题框架，没有复制书中实现。
- C++20 工作草案 [N4861 / atomics.order](https://timsong-cpp.github.io/cppwp/n4861/atomics.order)、[intro.races](https://timsong-cpp.github.io/cppwp/n4861/intro.races)。
- [实现、编译命令与测试入口](https://github.com/GyroJibering/GyroJibering.github.io/tree/main/labs/low-latency-lab)。
