---
layout: post
title: "从行情到下单：一个可解释顺序与一致性的低延迟骨架"
date: 2026-09-22 00:40 +0800
categories: [系统设计, 低延迟]
tags: [订单簿, 行情广播, 交易系统, C++, 一致性]
permalink: /blog/low-latency-market-strategy-order-loop/
toc: true
---

最后把前面的队列、内存序、日志和测量放进一个具体系统：行情到达，更新订单簿，策略读取最新盘口，风控后产生订单。实验代码处理 100 万条行情，没有序号缺口，产生 50 万条顺序连续的订单意图。

这不是一个可以连交易所的系统。它刻意保留核心约束，删掉协议细节，以便回答三个问题：订单簿如何组织？行情如何低延迟广播？顺序和一致性到底保证到什么范围？

## 先定数据流和所有权

```text
Market feed
    |
    | SPSC<MarketUpdate>
    v
Book actor -- SPSC<TopOfBook> --> Strategy actor
                                      |
                                      | SPSC<OrderIntent>
                                      v
                               Risk / Order gateway
                                      |
                                      v
                                  Exchange

Book actor --------> single-writer mmap journal
Order gateway -----> single-writer mmap journal
```

每个可变状态都有一个明确 owner：

- feed 线程只负责解码并赋予 feed sequence；
- book 线程独占订单簿；
- strategy 线程独占策略状态和 decision sequence；
- order gateway 独占 session 状态与 order sequence；
- journal writer 独占日志文件顺序。

线程之间传递值，不共享可变订单簿。这样一致性主要由消息顺序表达，而不是由遍布代码的 mutex 表达。

## 订单簿先问清行情语义

“写一个订单簿”没有唯一答案。输入可能是：

- 每档绝对数量更新；
- 增量加减；
- 按订单的 add/modify/cancel；
- 周期 snapshot 加增量；
- 多播 A/B line，允许乱序、重复和丢包。

本实验选择最小模型：单品种、每档绝对数量、`quantity == 0` 删除、全流递增 sequence。它不是 L3 order-by-order book。

价格用整数 ticks，绝不在匹配或风控逻辑中使用浮点。买卖两侧各用固定容量有序数组：bid 从高到低，ask 从低到高。更新一次最多移动 `Depth` 个元素，复杂度 O(Depth)，但无堆分配、内存连续，Depth 很小时常比树结构更适合热路径。

如果要维护几千档或按订单撤单，需要换成更合适的索引：价格范围稳定时可以直接寻址；范围大时可以使用预分配节点池、稠密 top levels 加稀疏深层索引。选择依据是输入语义和工作集，不是看到“订单簿”就默认 `std::map`。

## 缺口不是一条普通错误日志

book actor 维护 `expected_sequence`：

```cpp
if (seq < expected) return stale; // 重复或迟到
if (seq > expected) return gap;   // 丢包，当前状态不可再信
apply(update);
++expected;
```

检测 gap 后继续发布“最新盘口”是危险的，因为策略会在一个自洽但错误的世界里下单。生产系统应进入明确状态机：

```text
LIVE -> GAP_DETECTED -> SNAPSHOT_LOADING -> REPLAY_BUFFERED -> LIVE
```

gap 期间缓存后续增量；取得带 sequence 的 snapshot；丢弃 snapshot 已覆盖的更新；严格连续地 replay；完成前不向策略发布可交易状态。缓存溢出或再次缺口则重新恢复。

当前骨架在 gap 时停止应用该更新并计数，测试验证它能识别 stale 与 gap，但没有实现 snapshot recovery。这是有意暴露的边界。

## 广播不能用一个共享 MPMC 队列代替

队列和广播语义不同。多个消费者从一个 MPMC queue `pop`，每条消息只交给其中一个消费者；行情广播要求每个订阅策略都看到属于自己的那一份流。

简单而稳定的做法是每个订阅者一条 SPSC：

```text
                     -> SPSC -> strategy A
book publisher ------> SPSC -> strategy B
                     -> SPSC -> recorder
```

book 线程把不可变的 `TopOfBook` 值复制到各通道。优点是消费者互不争抢游标、单个消费者的读位置独立、顺序证明沿用 SPSC。代价是 fan-out 做 N 次复制，慢消费者会填满自己的队列。

队列满时必须预先定义策略：

- **阻塞发布者**：无丢失，但一个慢策略拖慢所有订阅者；
- **断开慢消费者**：主链路继续，慢策略进入 stale 状态并恢复；
- **覆盖旧快照**：适合“只要最新状态”的数据，不适合必须逐条处理的增量；
- **写入可重放日志**：消费者从可靠序号恢复，但恢复路径更复杂。

实验选择阻塞自旋以保持所有消息，便于验证；生产交易系统通常不能让观察型消费者阻塞关键行情链路。

## 一致性不是“所有线程同时看到一样”

我给系统定义的是按分区的一致性：同一品种由一个 book owner 处理，book 输出严格继承 market sequence；一个 strategy owner 按接收顺序生成 decision sequence；order gateway 再生成 session 内 order sequence。

每笔订单携带三层因果标识：

```text
market_sequence -> decision_sequence -> order_sequence
```

于是可以回答：这笔订单基于哪一版盘口、是哪次策略决策、在订单会话中排第几。SPSC 的 release/acquire 保证每一跳的数据可见性，单写者保证每层序号的总序。

这没有创造跨所有品种和所有机器的全球总序。若多品种按 symbol 分区，不同分区只能依赖接收时间或外部序号做部分序合并。用 wall clock 强行宣称全局精确顺序通常不成立；需要跨分区原子视图的策略，应明确 barrier、watermark 或撮合端 sequence 的代价。

## 骨架如何运行

四个线程分别执行 feed、book、strategy、order gateway：

```cpp
MarketUpdate update{seq, tsc, price, qty, side};
feed_to_book.try_push(update);

book.apply(update);
book_to_strategy.try_push(book.top());

OrderIntent intent{decision_seq, top.market_sequence, ...};
strategy_to_orders.try_push(intent);

NewOrder order{order_seq, intent.decision_sequence,
               intent.market_sequence, ...};
```

`TopOfBook` 按值传递，策略永远拿不到订单簿内部引用。热路径数据结构在启动时完成分配；价格和数量是固定宽度整数；消息类型没有虚函数和字符串。

一次实测结果：

```text
updates=1000000 gaps=0 orders=500000
```

测试行情交替更新 bid/ask，每次 ask 更新形成完整两边盘口，策略产生一个买单意图，因此订单数应精确等于 50 万。order gateway 同时检查 decision sequence 必须逐一递增。

## 过程中遇到的典型问题

### 1. 把吞吐当延迟

最初在队列中堆积几千条消息再计算 `now - send_tsc`，测到的主要是排队。修复是一次只允许一条在途消息测交接延迟，另开实验测持续吞吐。

### 2. Release build 关闭了测试

第一版用 `assert` 验证百万条结果，`-O3` 环境定义 `NDEBUG` 后断言被编译掉，甚至出现“变量未使用”警告。测试改为始终执行的 `require/abort`。基准编译成功不代表验证真的运行。

### 3. 把 MPMC 当广播

MPMC 的多个消费者分摊消息，不会自动复制。广播改为每订阅者一条 SPSC，并单独设计慢消费者策略。

### 4. 用一个原子只证明半条生命周期

只通过 tail 发布元素，不足以证明生产者安全复用槽位。head 的 release/acquire 负责把“消费者已读取并析构”传回生产者。

### 5. 把无 mutex 写成严格 lock-free

有界 MPMC 中线程认领位置后暂停会形成 hole，因此文章和代码都明确不宣称正式 lock-free 进展保证。

### 6. 把内存可见当成日志持久

release/acquire 解决线程间可见性，`mmap/msync` 和设备协议解决另外一层问题。两者必须分别测试和描述。

## 离生产系统还有多远

下一阶段至少包括：

- 真实行情协议解码、A/B line 仲裁和 snapshot recovery；
- 每品种分区与跨品种 watermark；
- 预交易风控：限价、限量、仓位、频率、自成交保护；
- order session 登录、重连、重发与成交回报状态机；
- CPU isolation、NUMA 固定、huge pages、预触页和实时调度评估；
- Linux `perf`、火焰图、page fault、context switch 与 NIC 时间戳；
- ThreadSanitizer、随机调度、断电/kill 恢复和长时间 soak test；
- 明确 overload 时丢弃、降级、断开或停盘的策略。

低延迟不是把每个数据结构都换成 CAS。更可靠的路线是先缩小共享状态、固定所有权和顺序，再对真正进入预算的环节测量。架构减少争用，内存序负责证明，基准负责反驳直觉。

## 代码与记录

- [完整实验目录](https://github.com/GyroJibering/GyroJibering.github.io/tree/main/labs/low-latency-lab)
- [固定深度订单簿与消息结构](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/include/ll/market.hpp)
- [行情到下单核心骨架](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/src/trading_loop.cpp)
- [本机原始结果记录](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/results/2026-09-22-windows.md)
