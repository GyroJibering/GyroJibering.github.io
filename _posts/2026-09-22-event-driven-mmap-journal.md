---
layout: post
title: "mmap 日志的提交语义：发布水位、持久水位与崩溃前缀"
date: 2026-09-22 00:30 +0800
categories: [C++, Linux]
tags: [mmap, 持久化, eventfd, CRC32C, 崩溃恢复]
permalink: /blog/event-driven-mmap-journal/
toc: true
---

一次 append 返回，究竟承诺了什么？

如果只是把字节复制进内存映射，返回只能说明当前进程完成了写入。另一个线程看见这些字节，不代表进程崩溃后能恢复；进程崩溃后能恢复，也不代表掉电后能恢复。“日志库很快”的比较若没有先固定这层语义，可能只是在比较不同的承诺。

本文构造一个单写者、固定容量、只追加的 mmap journal。重点是定义发布和持久确认的边界，给恢复扫描器设计可证伪的故障输入，并解释低延迟如何与 durability budget 发生冲突。

[Linux 写入器](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/src/journal_demo.cpp)已交叉编译；[字节格式与扫描器](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/include/ll/journal_format.hpp)在 Windows 上完成了故障注入测试。没有 Linux 运行结果，也没有掉电测试。本篇不报告虚构的磁盘吞吐。

## 1. 先纠正旧实现中的两个错误

旧版本后台线程调用 MS_ASYNC，却把它描述为批量回写策略。在 Linux 2.6.19 之后，MS_ASYNC 实际上不执行这样的显式回写工作，内核本来就跟踪脏页；用一个线程反复调用它，不等于获得了可控的刷盘期限。[msync(2)](https://man7.org/linux/man-pages/man2/msync.2.html)

更严重的是，旧版本的 recoverable_records() 只扫描当前进程仍映射着的内存，程序再次启动时又用 O_TRUNC。它验证了当前字节的一致性，没有验证重启恢复；把这段函数称为崩溃恢复会误导读者。

修订版改为：

- 后台实际执行 MS_SYNC，并且检查错误；
- create 使用 O_EXCL，拒绝覆盖已有文件；
- recover 独立打开既有文件，只读扫描；
- append 返回 published sequence，close 成功返回 durable sequence；
- 磁盘格式是显式小端字节序，不再把 C++ struct/atomic_ref 直接当成持久格式。

这些变化同时缩小了实现承诺和扩大了可检验范围。

## 2. 三个水位对应三种不同事实

设第 k 条记录有三个状态：

```text
A(k)：写入线程已完成记录编码和复制
P(k)：published 水位至少为 k
D(k)：durable 水位至少为 k
```

A 是线程内部事实；P 通过 release/acquire 向刷盘线程发布；D 只在对应 MS_SYNC 成功后推进。

对一个运行中的实例，目标不变量是：

```text
0 <= D <= P <= capacity
```

append 的返回值是 P，不是 D。若业务必须保证“订单意图已持久后才允许发送”，它需要等待 D 覆盖该意图，而不是等 append 返回。

本 demo 没有实现每个序号的等待接口，只在显式 close() 等待尾部刷盘并返回 D。它也没有持久化 D 本身：重新启动后通过校验扫描得到有效前缀 R。由于操作系统可能提前写回尚未显式确认的页，R 可以大于最后一次对应用报告的 D。

这并不矛盾：确认过的必须在假设成立时保留，未确认的不保证不存在。恢复系统不能把“没有收到 ACK”解释成“该记录必然没写成”。

## 3. 故障模型必须比“断电也安全”具体

本协议在以下假设下讨论持久确认：

1. 同一文件只有一个写入者，不允许并发轮转、截断或外部修改；
2. 已发布记录不再被覆盖；
3. MS_SYNC 成功满足所在操作系统、文件系统与存储栈提供的同步写回语义；
4. 已成功持久的数据不会随后遭遇静默介质损坏或失信设备；
5. 不讨论恶意修改者，CRC 不是认证码。

不同故障对应不同实验：

| 故障 | 可观测现象 | 不能由此推出的结论 |
|---|---|---|
| 正常 close 后重新打开 | 文件格式与扫描一致 | 掉电恢复成立 |
| SIGKILL 写入进程 | 没有析构、页缓存可能仍在 | 已离开机器易失缓存 |
| 内核崩溃/突然断电 | 可能出现未完成持久化的尾部 | 所有设备都遵守相同持久语义 |
| 中间记录位翻转 | 校验失败、扫描终止 | CRC 能抵抗蓄意伪造 |

尤其是 SIGKILL：它杀掉进程，不会清空操作系统页缓存。只测试 kill/restart，最多证明相应故障模型，不应把报告标题改成“电源故障安全”。

## 4. 为什么不用原始 struct 做文件格式

原始 struct 带来三个隐含协议：编译器布局、对象生命周期和本机字节序。sizeof 等于 64 并不能固定未来版本的字段解释，也不能让磁盘上的字节自动变成一个存活的 std::atomic 对象。

修订后的每条记录是明确的 64 字节：

| 偏移 | 长度 | 内容 |
|---:|---:|---|
| 0 | 8 | journal sequence，小端 |
| 8 | 4 | record type，小端 |
| 12 | 4 | payload length，最大 32 |
| 16 | 32 | payload，不足部分补零 |
| 48 | 4 | 前 48 字节的 CRC32C |
| 52 | 4 | 保留字段，必须为零 |
| 56 | 8 | commit_magic XOR sequence |

文件开头另外有 64 字节 header，包含 magic、版本 2、记录大小、容量和校验。记录序号从 1 开始，不环绕复用。固定容量耗尽时明确失败，不把旧记录覆盖成新一圈。

序号、长度、payload 都受 CRC 覆盖。尾部标记提供一个额外的完整性条件，避免全零页被误识别为合法记录。两者不组成硬件原子写，也不承诺某个字段一定比另一个字段更早持久。

编码函数先在本地字节数组中生成完整记录，再 memcpy 到映射。这里不存在“commit marker 的 release store 让磁盘提交”的步骤。线程间发布依赖另一个进程内原子水位：

```text
写映射字节
   -> published.store(k, release)
   -> flusher 读取 published(acquire) 得到 target
   -> msync(映射前缀, MS_SYNC)
   -> durable.store(target, release)
```

所有持久记录是字节协议；所有线程协调是进程内对象。这两个领域的生命周期被明确分开。

## 5. MS_SYNC 的成功如何传递到 durable 水位

刷盘线程先读取 target = P，然后同步包含 header 和记录 1…target 的映射前缀。只有成功返回，才写 D = target。

这是一个保守水位。与此同时，生产者可能已经追加 target + 1，而 MS_SYNC 因页粒度把后续部分也写回了；刷盘线程仍只确认 target，因为它没有为更晚记录建立本轮协议所需的顺序和边界。

逐页刷新增量范围可以减少开销，但起始地址必须页对齐；尾页还可能同时承载本轮已确认数据与下一轮数据。为了把实现缩到可审查范围，本 demo 每次同步已发布前缀，因此长文件下可能重复扫描较大区间，不把它称为完成优化的日志库。

启动时使用 posix_fallocate 分配文件空间并报告 ENOSPC，再映射和预触页。它把一部分分配与缺页成本移到初始化；但之后仍可能遭遇 writeback throttling、调度和页面回收压力。mmap 热路径省掉逐记录 write syscall，不代表最坏延迟有界。

文件第一次创建时，除同步内容外还 fsync 文件与父目录。父目录项的持久性不是“fsync 了文件”自动覆盖的。[fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html)

## 6. eventfd 只是一种通知，不是提交计数

写入者每追加 4096 条，通过非阻塞 eventfd 通知后台。后台同时保留 50 ms poll 超时，以处理不足一批的尾部。

eventfd 的计数用于合并“有工作”的通知；后台醒来仍然读取 P，不能把 eventfd 读到的数字当成记录数或持久序号。[eventfd(2)](https://man7.org/linux/man-pages/man2/eventfd.2.html)

代码处理 write 的 EINTR；遇到 EAGAIN 时，eventfd 已有大量待处理通知，未来仍有唤醒机会。其他错误记录到错误状态，后续 append/close 报错。后台 MS_SYNC 失败时不推进 D。

这也解释了为什么不用异步 POSIX signal handler：这里只需要可等待的事件通知，没有必要把日志处理塞进受 async-signal-safe 限制的执行环境。

### 关闭顺序中的一个真实竞态

后台退出前必须先 acquire 读取 stop，再读取 published：

```cpp
bool stopping = stop.load(acquire);
auto target = published.load(acquire);
flush_through(target);
if (stopping) return;
```

如果反过来，后台可能先读到旧 target，随后读到生产者最后发布的 stop = true，然后直接退出，遗漏最终尾部。

生产者在所有 append 之后 release 写 stop。后台 acquire 看见这个 stop，再读 published，才能利用这条顺序获取最终发布水位。停止协议与数据协议同样需要 happens-before，不能用“析构时 flush 一下”一笔带过。

析构负责停止线程和释放资源，但不能可靠地向调用者报告持久化失败。需要持久确认的调用者必须显式 close() 并处理异常；依赖析构就宣称数据已经持久，是接口层面的错误。

## 7. 恢复扫描到底证明什么

恢复程序是离线扫描器：写入者已经退出，或文件处于静止状态。它不允许一边读取半写入记录，一边把临时校验失败当成永久尾部。

对预期序号 k，只有同时满足以下条件才接受：

```text
完整读取 64 字节
sequence == k
length <= 32
reserved == 0
commit_marker == commit_magic XOR k
CRC32C(bytes[0:48]) == stored_crc
```

第一个失败位置之后立即停止。即使后面第 k + 1 条看起来合法，也不会跳过坏记录继续恢复。原因是业务重放需要连续前缀：缺少一个 cancel 或 fill，后续事件的解释可能完全不同。

CRC32C 对本测试中的单比特错误都能检测，但它不是“任意损坏必定检测”的证明。多比特错误存在碰撞；约 2^-32 的随机碰撞直觉也只能在相应随机模型下使用，不能拿来描述对抗者或任意相关硬件故障。

若校验在文件中部失败，扫描器只知道“这里不能再信”。它不能判断这是正常崩溃尾部、旧格式误读还是持久后介质损坏。生产恢复工具应把偏移、序号、期望值和实际值保存出来，交给明确的运维策略。

## 8. 本次实际运行的故障注入

格式层不依赖 mmap，因此可以在当前 Windows 环境上严格检查字节输入。测试建立 header 加四条记录的 320 字节映像，并执行：

1. 从完整 header 之后的每个位置截断，共 257 种长度；恢复数必须等于完整记录数；
2. 对第三条记录的每一位单独翻转，共 512 种输入；扫描必须在第二条后停止，不能跳到仍完好的第四条；
3. 校验 CRC32C 的标准测试串 123456789，结果为 0xe3069283；
4. 正常映像完整恢复四条。

实际输出：

```text
journal codec: 257 truncations + 512 bit flips + CRC32C vector OK
```

优化构建与 UBSan 构建均通过。这里注入的是序列化字节故障，不是完整文件系统的 crash-consistency 状态空间，更不是对设备刷新顺序的穷举。它证明了本扫描器对这些明确输入的响应。

Linux 程序提供两个独立入口：

```bash
./build/journal_demo create /tmp/ll-journal-unique.bin
./build/journal_demo recover /tmp/ll-journal-unique.bin
```

create 拒绝既有路径；重复实验应使用新路径。正式 kill 测试还需要外部父进程在不同阶段杀死 writer，再以新进程调用 recover；只有把 PID、kill 时机、最后确认的 D 和恢复到的 R 一起记录，才能讨论故障边界。目前仓库没有将这项未运行实验冒充既有结果。

## 9. 异步持久化把什么风险留给业务

如果应用每秒追加 λ 条，后台每 B 条或每 Δt 唤醒一次，那么在均匀负载的粗略模型中，凑批引入的等待大约受 B/λ 与 Δt 中较早触发的一项影响；之后还要加 MS_SYNC、调度和已有刷盘积压时间。这是量级估算，不是最坏延迟上界。

重要的运行指标是 P − D：已经接受但尚未确认持久的记录数。P − D 持续增长说明存储追不上生产者。无界扩大映射只是在推迟资源耗尽，并没有解决吞吐失配。

交易系统需要在这里做业务选择：

- diagnostic 日志可以采样或丢弃，但要独立于审计流；
- 必须恢复的订单意图需要限额、背压或停单；
- 允许先发送再落盘时，恢复协议必须接受“交易所可能已接收、本地没有持久记录”的不确定窗口。

一个高吞吐 append 微基准无法替应用选择这些语义。

## 10. 应当分别测量的三种成本

对日志只报一项 Mrec/s，会把承诺不同的工作混在一起。至少应区分：

| 测量 | 起止点 | 包含的工作 |
|---|---|---|
| append CPU 成本 | 编码开始至 published 推进 | CRC、复制、原子发布、偶发通知 |
| durable ACK 延迟 | append 开始至 D 覆盖序号 | 凑批、调度、回写与同步完成 |
| 恢复时间 | 新进程打开文件至有效前缀确定 | 文件读取、校验、重放或索引重建 |

当前 demo 的 create 输出 append_seconds 与 including_close_seconds，避免把最终同步排除后仍称为持久吞吐。映射初始化、全文件预触页则单独发生在计时前，不能据此宣称冷启动也一样快。

更完整的 Linux 实验还应记录文件系统、挂载选项、存储设备、同步失败、脏页阈值和并发 I/O。没有这些条件，精确到两位小数的日志吞吐很容易失去可比性。

格式层反例、交叉编译命令及尚未完成的系统实验汇总在[实验记录](https://github.com/GyroJibering/GyroJibering.github.io/blob/main/labs/low-latency-lab/results/RESEARCH.md)。
