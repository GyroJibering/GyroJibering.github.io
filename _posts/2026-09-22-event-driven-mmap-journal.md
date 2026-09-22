---
layout: post
title: "把日志移出热路径：eventfd 驱动的 mmap Journal 实验"
date: 2026-09-22 00:30 +0800
categories: [C++, Linux]
tags: [mmap, eventfd, 日志, 崩溃恢复, 低延迟]
permalink: /blog/event-driven-mmap-journal/
toc: true
---

低延迟系统仍然需要日志：恢复订单状态、重放行情、解释一次异常决策，都要求知道系统实际看见过什么。问题在于，如果每条消息都 `write + fsync`，存储尾延迟会直接进入交易热路径；如果只写内存，进程退出或机器掉电后又没有证据。

我写了一个简化版 Linux journal：文件预分配后 `MAP_SHARED` 映射，单写者顺序追加固定长记录，release 发布 commit marker，后台线程由 `eventfd` 唤醒并批量 `msync`。它的价值不在于“比成熟日志库快”，而在于把**线程可见、内核可见、存储持久**三个常被混淆的层次拆开。

## 为什么坚持单写者

多线程直接向一个持久日志抢全局 offset，会同时引入：

- reservation CAS 争用；
- 先预留的线程停顿形成 hole；
- 哪个序号代表日志顺序的语义争议；
- 崩溃恢复时对未完成 reservation 的处理。

更清晰的结构是每个生产者通过 SPSC 把事件送给一个 journal writer，由它分配唯一递增序号。这样磁盘日志天然是一条总序，恢复程序不必猜测多个并发写者的相对关系。

这里的“单写者”是日志文件的所有权约束，不代表整套系统只有一个线程。

## 64 字节记录布局

实验记录正好占一个常见缓存行：

```cpp
struct alignas(64) JournalRecord {
    uint64_t committed_sequence;
    uint64_t tsc;
    uint64_t stream_sequence;
    uint32_t type;
    uint32_t length;
    uint64_t checksum;
    array<char, 24> payload;
};
```

写入顺序是：

1. 填 `tsc / stream_sequence / type / length / payload`；
2. 计算 checksum；
3. `atomic_ref(committed_sequence).store(seq, release)`；
4. 更新进程内 committed watermark；
5. 每累计一批记录，用 `eventfd` 通知 flusher。

commit marker 是读者判断“这条记录是否完整发布”的最后字段。恢复时从第一条开始扫描，要求：

```text
committed_sequence == expected && checksum(record) == record.checksum
```

遇到第一条不匹配就停止，后面即使碰巧有字节也不视为有效日志。sequence 防止旧内容被错认成新一圈记录，checksum 用于发现 torn/partial record。

## release 只解决线程可见性

这是整个实验最容易说错的地方。

`store(release)` 与恢复线程的 `load(acquire)` 可以建立 happens-before，让另一个 CPU 核心在读到 commit 后看见此前 payload 写入。它并不意味着数据已经离开 CPU cache，也不意味着页面已写回设备，更不意味着断电后还存在。

持久性大致可以分成：

```text
C++ 对象已写
  -> 对其他线程可见（release/acquire）
  -> mmap 脏页被内核跟踪
  -> 发起/等待页面回写（msync）
  -> 设备确认持久化
  -> 断电模型下仍满足协议
```

普通文件的 `MAP_SHARED` 让修改反映到底层文件映射。Linux 手册说明，`MS_ASYNC` 安排异步更新；但从 Linux 2.6.19 起它实际上是 no-op，因为内核已经跟踪脏页。`MS_SYNC` 才会等待更新完成。因此示例后台批处理的 `MS_ASYNC` 只是把热路径和回写策略解耦，析构时的 `MS_SYNC` 才提供等待点。

即使 `MS_SYNC` 返回，也不能把一切简化为“绝对不会丢”。文件系统、设备写缓存、突然掉电、元数据与数据顺序都会影响保证。真正的交易审计日志需要明确目标：只防进程崩溃、要防内核崩溃，还是要防整机断电；然后设计相应的 sync、校验、双写或复制协议。

## 为什么用 eventfd，不用 POSIX signal

这里的“信号驱动”指事件通知，不是异步 signal handler。signal handler 可调用的函数集合很小，在其中做 `msync`、锁、分配或日志都很危险。

`eventfd` 是一个由内核维护的 64 位计数器，可以被 `write` 通知、被 `poll/epoll` 等待。示例做了通知合并：已有 flush 请求未处理时，不重复写 eventfd。每 4096 条才触发一次系统调用，热路径大部分时间只进行顺序内存写。

后台流程：

```text
writer append x 4096
        |
        +-- eventfd write (coalesced)
                         |
flusher poll -> drain eventfd -> snapshot watermark -> msync
```

100 ms poll timeout是兜底，不是硬实时期限。若业务要求“提交后 1 ms 必须持久”，应把 deadline 纳入协议并测量 `MS_SYNC`/设备完成的尾延迟，而不是只调小 timeout。

## 页错误也是延迟

预分配文件不等于所有页都已驻留。第一次触碰新页可能触发 minor/major fault，把毫秒级尖峰带进 append。正式版本至少要考虑：

- 启动阶段 `ftruncate` 后逐页预触碰；
- 根据权限和内存预算使用 `mlock/mbind`；
- 固定 NUMA 节点，避免 writer 跨 socket；
- 预先创建线程、缓冲区和文件，热路径不分配；
- 用 `perf stat` 记录 `page-faults`、`context-switches`、`cpu-migrations`；
- 文件轮转在控制线程完成，通过明确协议切换映射。

映射不要随意使用 `MAP_FIXED`。Linux 手册明确警告，它可能覆盖多线程进程刚创建的其他映射；若确实需要固定地址，应先保留地址区间或使用合适的 `MAP_FIXED_NOREPLACE` 策略。

## 这份代码已经验证到哪里

`journal_demo.cpp` 在本次会话中用 Zig 0.15.2 成功交叉编译为 x86_64 Linux 可执行文件，编译器开启 `-Wall -Wextra -Wpedantic -O3`。当前主机没有 Linux 运行环境，所以我没有编造 append rate 或 `perf` 数据。

在 Linux 上可运行：

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel
./build-release/journal_demo market.journal

perf stat -r 10 \
  -e cycles,instructions,page-faults,context-switches,cpu-migrations \
  ./build-release/journal_demo market.journal
```

崩溃测试应在独立进程中随机 `SIGKILL`，重新打开文件扫描 commit/checksum，并比较调用 `MS_SYNC` 前后的可恢复边界。当前 demo 每次使用 `O_TRUNC` 创建新文件，只展示记录协议和热/冷路径拆分；生产版本还需要 reopen、版本升级、轮转、磁盘满处理和持久 watermark。

## 典型错误清单

- 把 release store 当作持久化屏障；
- 每条记录都触发 syscall，却仍称为纯内存热路径；
- 先写 commit，再写 payload；
- 只有长度没有 sequence，文件复用后读到旧记录；
- 没有 checksum，却声称能识别 torn write；
- 让多个线程抢日志顺序，再在恢复时猜顺序；
- 基准只测温热页面，不测扩展文件和 page fault；
- 把 `MS_ASYNC` 描述成等待落盘。

## 参考资料

- Linux man-pages, [`mmap(2)`](https://man7.org/linux/man-pages/man2/mmap.2.html)
- Linux man-pages, [`msync(2)`](https://man7.org/linux/man-pages/man2/msync.2.html)
- Linux man-pages, [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html)
- Linux kernel, [perf ring buffer documentation](https://docs.kernel.org/userspace-api/perf_ring_buffer.html)
- [本实验 mmap journal](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/src/journal_demo.cpp)
