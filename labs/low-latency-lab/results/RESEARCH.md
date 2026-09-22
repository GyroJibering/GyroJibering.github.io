# 修订实验记录 — 2026-09-22

本文记录这次修订实际执行的工作。原始基准输出在
[revised-benchmark.txt](revised-benchmark.txt)，编译命令在 [README](../README.md)。
旧版 [windows 记录](2026-09-22-windows.md) 保留作历史，不作为修订结论的证据。

## 环境与执行顺序

- Windows 11 Pro，10.0.22631；Ryzen 5 9600X，6 核 12 线程。
- Zig 0.15.2，内置 Clang 20.1.2；C++20，优化实验使用 `-O3`。
- 物理核心对应逻辑处理器：0/1、2/3、4/5、6/7、8/9、10/11。
- CPUID：invariant TSC = 1，hypervisor-present = 0。
- 最终基准在编译、功能测试完成后单独运行；任务没有同时派发其他构建或测试。
  桌面操作系统仍在运行，没有隔离核心、锁定频率或收集调度跟踪。

运行命令（lab 目录）：

```powershell
./build-zig/research.exe
./build-zig/research-ubsan.exe
./build-zig/stress.exe
./build-zig/trading_loop.exe
./build-zig/benchmark.exe all
```

生成最终数据的 `benchmark.exe` SHA-256：

```text
ED2BD25FA2C27EFA358E3C5C871AC066CD42468C40BE29A445870E66BE1D3E1A
```

此后仅修正了 CPU 名称的显示：按 C 字符串输出，去掉品牌字段尾部的 NUL。
原始文本第一行也只去除了这些 NUL；性能结果行未编辑。该散列标识实际测量的
本地二进制，不承诺不同路径或工具链构建出的二进制逐字节一致。

## 正确性与反例

优化构建与 UBSan 构建的 `research` 均正常退出，输出如下：

```text
spsc: sign-boundary and unsigned-wrap OK
mpmc: sign-boundary and unsigned-wrap OK
hole: enqueue(1) completed, later pop returned false
book: overflow, gap latch, snapshot transaction OK
book: 100000 seeded updates match std::map reference
journal codec: 257 truncations + 512 bit flips + CRC32C vector OK
```

测试覆盖的具体命题：

| 实验 | 检查对象 | 不包含的结论 |
|---|---|---|
| 容量 4，初始计数 0、2^63−8、2^64−8，每组 1000 轮 | 满/空、FIFO、符号边界与无符号回绕 | 无限执行的有限标签 ABA 不可能性 |
| 在 reservation 后暂停构造函数 | 后续 enqueue 已返回，pop 仍可失败；恢复后按 0、1 消费 | 任意元素类型的 lock-free 进展 |
| 容量不足、缺口、重复快照条目 | 拒绝截断盘口，隔离状态锁存，快照失败不部分提交 | 实际行情网络的补包与快照切换 |
| 固定种子 20260922 的 10 万条 L2 更新 | 每次最优买卖价量与 std::map 参考实现一致 | L3 撮合或交易所全部消息语义 |
| 64 字节头、4 条 64 字节记录 | 257 个截断边界；第三条每个 bit 单独翻转时均停在第二条 | 页缓存、文件系统、磁盘掉电行为 |
| CRC32C 标准向量 `123456789` | 结果为 `e3069283` | 恶意篡改检测或零碰撞保证 |

独立 `stress` 完成百万条 SPSC 顺序核对和 4P/4C 精确集合核对。
`trading_loop` 输出 `updates=1000000 gaps=0 orders=500000`。
后者是内存内合成消息回路；订单数不是网络发送成功或交易所确认数。

UBSan 用 `-O1 -g -fsanitize=undefined -fno-sanitize-recover=all` 构建。
没有运行 ThreadSanitizer 或弱内存模型检查器。测试通过不替代文章中的
happens-before 证明，也不能证明所有调度都安全。

## 计时器和基准

`measurement::stamp()` 使用带编译器屏障的 `CPUID; RDTSC; CPUID`。
检查 `-O3 -S` 生成的汇编，确认两个 CPUID 均未被优化掉，且位于 RDTSC 两侧。
RTT 开始与结束都在同一个绑定线程计时；响应通过第二条 SPSC 返回。
这避免用两个核心的 TSC 直接相减，不构成对整个平台时钟的校准。

每种 RTT 放置做 5 轮，每轮 2 万次预热、100 万次采样。
空框架 p50/p99 = 195/195 TSC ticks；粗估 TSC 3892.81 MHz。

| RTT 放置 | 五轮 p50 | 五轮 p99 |
|---|---|---|
| 不同物理核心 0:2 | 624 / 624 / 624 / 663 / 624 | 780 / 741 / 780 / 780 / 780 |
| SMT 同胞 0:1 | 351 / 351 / 351 / 351 / 351 | 468 / 468 / 468 / 468 / 468 |

单位为包含计时框架的 TSC ticks，不是 PMU core cycles。
不将 RTT 除二，也不相减分位数以宣称单次操作延迟。
max 保留在原始输出中，没有用缺少调度证据的因果解释将它剔除。

吞吐使用 16 字节消息、1024 槽，每生产者 100 万条，每消费者固定配额；
逐条验证 inverse，本地累加 id 和，退出后验证总数与校验和。
MPMC 与 mutex 交替顺序，五轮结果的中位数：

| 配置 | Mmsg/s |
|---|---:|
| SPSC 1P/1C | 122.429 |
| MPMC 1P/1C | 81.620 |
| Mutex 1P/1C | 17.247 |
| MPMC 2P/2C | 19.1759 |
| Mutex 2P/2C | 16.1744 |
| MPMC 4P/4C | 18.7188 |
| Mutex 4P/4C | 13.6658 |

校验和分别为 499999500000、1999999000000、7999998000000。
校验和不等价于精确集合检查，因此还保留独立 stress。

SPSC 吞吐区间仅约 7–9 ms，属于固定工作量微基准；不据此声称稳态容量。
4P/4C 超过本机物理核心数，使用部分 SMT，因此不能将并发度变化全部归因于 CAS。
没有给出统计显著性、生产 p99、公平性或最大稳定到达率的结论。

## 尚未验证

Linux journal 已用 `-target x86_64-linux-gnu` 交叉编译，未在 Linux 执行。
CMake 配置提供给复现者，但本机没有 CMake；实际构建使用上述直接编译命令。

以下工作没有结果，文章中只提供协议推导或后续实验设计：

- Linux `perf stat/record`、PMU 瓶颈归因、跨 NUMA 对照。
- mmap 日志的 MS_SYNC 延迟、独立进程崩溃恢复、整机掉电与设备 flush 行为。
- 真实 feed 补包、广播慢订阅者、snapshot/epoch 切换、订单风控及交易所重连核对。
- 实际网络接收至下单确认的端到端测量及开放到达模型的过载测试。
