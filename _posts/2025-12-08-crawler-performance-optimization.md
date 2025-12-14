---
layout: post
title: 爬虫性能优化：从基础到极致
date: 2025-12-08
categories: [技术, Python]
tags: [爬虫, Scrapy, 性能优化, Python, 异步IO, Redis, Playwright]
toc: true
author: GyroJ
---

# 爬虫性能优化：从基础到极致

## 概述

本文档展示了如何将爬虫性能从基础实现逐步优化到极致，通过三个阶段的技术演进，实现 **100倍以上！** 的性能提升。

---

## 阶段一：基础实现 - Scrapy + Playwright

### 1.1 为什么选择 Scrapy + Playwright？

**Scrapy**：
- ✅ 成熟的 Python 爬虫框架
- ✅ 强大的数据提取能力
- ✅ 丰富的中间件和扩展

**Playwright**：
- ✅ 支持 JavaScript 渲染
- ✅ 可处理动态加载内容
- ✅ 模拟真实浏览器行为

### 1.2 基础实现

**核心代码结构**：
```python
class GubaSpider(scrapy.Spider):
    name = "guba"
    
    def start_requests(self):
        for url in self.start_urls:
            yield scrapy.Request(
                url=url,
                callback=self.parse,
                meta={"playwright": True}
            )
    
    def parse(self, response):
        # 解析页面，提取数据
        items = extract_data(response)
        yield items
```

**配置**：
```python
# settings.py
DOWNLOAD_DELAY = 2  # 每个请求延迟2秒
CONCURRENT_REQUESTS = 1  # 单线程，一次只处理1个请求
PLAYWRIGHT_BROWSER_TYPE = "chromium"
```

### 1.3 性能表现

- **并发数**：1
- **请求延迟**：2秒/请求
- **爬取速度**：~10-20 条/分钟
- **瓶颈**：顺序执行，大量等待时间

**问题**：
- ❌ 速度太慢
- ❌ 资源利用率低
- ❌ 无法充分利用网络带宽

---

## 阶段二：单线程异步IO优化 - 事件循环模型

### 2.1 优化思路

**核心问题**：爬虫是 **IO密集型** 任务，大部分时间在等待网络响应，而不是CPU计算。

**解决方案**：使用 **异步IO + 事件循环**，在等待网络响应时处理其他请求。

### 2.2 Scrapy 的并发模型

**重要说明**：Scrapy **不是**使用多线程或多进程，而是基于 **单线程 + 事件循环** 的异步IO模型。

#### 2.2.1 核心架构

```
┌─────────────────────────────────────────┐
│         Scrapy 引擎（单线程）            │
│  ┌───────────────────────────────────┐  │
│  │   Twisted Reactor (事件循环)      │  │
│  │  ┌─────────────────────────────┐ │  │
│  │  │  请求队列 (Request Queue)    │ │  │
│  │  │  响应队列 (Response Queue)   │ │  │
│  │  │  回调链 (Callback Chain)     │ │  │
│  │  └─────────────────────────────┘ │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌──────────┐  ┌──────────┐  ┌───────┐ │
│  │下载器    │  │调度器    │  │管道   │ │
│  │(异步IO)  │  │(优先级)  │  │(批量) │ │
│  └──────────┘  └──────────┘  └───────┘ │
└─────────────────────────────────────────┘
```

#### 2.2.2 为什么不用多线程？

| 特性 | 多线程 | Scrapy异步IO |
|------|--------|--------------|
| 并发模型 | 多线程（受GIL限制） | 单线程异步IO |
| 最大并发 | ~100-200 | 1000+ |
| 内存占用 | 高（每线程8MB） | 低（每请求几KB） |
| CPU利用率 | 低（线程切换开销） | 高（事件驱动） |
| 适用场景 | CPU密集型 | IO密集型（爬虫） |

### 2.3 关键优化配置

#### 2.3.1 移除延迟，启用高并发

```python
# settings.py
DOWNLOAD_DELAY = 0  # 移除延迟
CONCURRENT_REQUESTS = 64  # 全局并发数提升到64
CONCURRENT_REQUESTS_PER_DOMAIN = 32  # 每个域名32并发
```

#### 2.3.2 启用异步 Reactor

```python
TWISTED_REACTOR = "twisted.internet.asyncio.AsyncioSelectorReactor"
```

**原理**：
- 使用 Python 3.7+ 的 `asyncio` 作为底层事件循环
- 底层使用 `epoll` (Linux) / `kqueue` (macOS) / `select` (Windows)
- 系统级IO多路复用，可同时监控数千个文件描述符

#### 2.3.3 智能请求策略

**优化前**：所有请求都用 Playwright（慢，~5秒/请求）

**优化后**：
```python
# 先尝试普通 HTTP 请求（快，~0.5秒）
yield scrapy.Request(url, callback=self.parse, meta={"playwright": False})

# 失败时自动回退到 Playwright
def errback_fallback_playwright(self, failure):
    yield scrapy.Request(url, callback=self.parse, meta={"playwright": True})
```

#### 2.3.4 网络连接优化

```python
DNSCACHE_ENABLED = True  # DNS缓存
DNSCACHE_SIZE = 10000
CONCURRENT_ITEMS = 100  # 并发处理items
```

#### 2.3.5 AutoThrottle 智能限流

```python
AUTOTHROTTLE_ENABLED = True
AUTOTHROTTLE_TARGET_CONCURRENCY = 30.0  # 高并发目标
AUTOTHROTTLE_MAX_DELAY = 2.0  # 最大延迟限制
```

### 2.4 异步请求处理流程

```
时间轴：
T0: 发送请求1-64（几乎同时，非阻塞）
T1: 请求1响应到达 → 触发回调 → 解析 → 生成新请求65
T2: 请求2响应到达 → 触发回调 → 解析 → 生成新请求66
T3: 请求3响应到达 → 触发回调 → 解析 → 生成新请求67
...
```

**关键点**：
- 64个请求**同时**在网络中传输
- 不需要等待前一个请求完成
- CPU在等待IO时处理其他请求的回调

### 2.5 性能提升

| 优化项 | 优化前 | 优化后 | 提升 |
|--------|--------|--------|------|
| 并发数 | 1 | 64 | **64倍** |
| 请求延迟 | 2秒 | 0秒 | **∞** |
| 请求策略 | Playwright(5秒) | HTTP(0.5秒) | **10倍** |
| **总体速度** | ~10-20条/分钟 | **~200-1000条/分钟** | **10-50倍** |

---

## 阶段三：多进程分布式 - Redis 消息队列

### 3.1 为什么需要多进程？

**单进程限制**：
- 单进程并发数有上限（~1000-2000）
- CPU密集型任务（HTML解析）会阻塞事件循环
- 单机资源利用不充分

**解决方案**：多进程 + Redis 消息队列，实现分布式爬取。

### 3.2 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    任务调度层                                │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  任务生产者 (Task Producer)                          │  │
│  │  - 读取股票代码列表                                  │  │
│  │  - 生成爬取任务                                      │  │
│  │  - 推送到 Redis 队列                                 │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│                    Redis 消息队列层                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ 请求队列     │  │ 去重集合     │  │ 统计信息     │    │
│  │ (Queue)      │  │ (Set)        │  │ (Hash)       │    │
│  │ guba:requests│  │ guba:dupefilter│ │ guba:stats   │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│                    Scrapy 爬虫进程层                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Process1 │  │ Process2 │  │ Process3 │  │ ProcessN │   │
│  │ 64并发   │  │ 64并发   │  │ 64并发   │  │ 64并发   │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 核心技术：Scrapy-Redis

#### 3.3.1 Scheduler（调度器）

**作用**：从 Redis 队列中获取请求，替代默认的内存队列

**配置**：
```python
SCHEDULER = "scrapy_redis.scheduler.Scheduler"
SCHEDULER_PERSIST = True  # 爬虫关闭时，不清理Redis中的请求队列
SCHEDULER_QUEUE_CLASS = "scrapy_redis.queue.PriorityQueue"
```

#### 3.3.2 DupeFilter（去重过滤器）

**作用**：使用 Redis Set 实现分布式去重

**配置**：
```python
DUPEFILTER_CLASS = "scrapy_redis.dupefilter.RFPDupeFilter"
```

**工作原理**：
- 使用 Redis Set 存储已爬取的 URL 指纹
- 所有进程共享同一个去重集合
- 使用 Redis 的 `SADD` 原子操作保证一致性

#### 3.3.3 Redis 配置

```python
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
```

### 3.4 数据一致性保证

#### 3.4.1 URL 去重

**原理**：
- 所有进程共享同一个 Redis Set
- 使用 Redis `SADD` 原子操作
- 保证每个 URL 只爬取一次

#### 3.4.2 任务分配

**原理**：
- Redis 的 `BRPOP` 是原子操作
- 多个进程同时获取任务时，只有一个能成功
- 保证每个任务只被一个进程处理

#### 3.4.3 数据写入

**方案1：Redis Pipeline（推荐）**
```python
class GubaSpiderPipeline:
    def __init__(self):
        self.redis_client = redis.Redis(host='localhost', port=6379)
        self.batch = []
    
    def process_item(self, item, spider):
        self.batch.append(dict(item))
        if len(self.batch) >= 100:
            # 使用 Redis Pipeline 批量写入（原子操作）
            pipe = self.redis_client.pipeline()
            for item in self.batch:
                pipe.lpush('guba:items', json.dumps(item))
            pipe.execute()
            self.batch = []
        return item
```

**方案2：数据库（最佳）**
- 使用数据库（PostgreSQL、MySQL）保证 ACID
- 数据库事务保证数据一致性

### 3.5 部署方案

#### 3.5.1 单机多进程

```bash
# 启动 4 个进程（假设 4 核 CPU）
for i in {1..4}; do
    scrapy crawl guba &
done
wait
```

**性能**：
- 4 进程 × 64 并发 = 256 并发请求
- 预计提升：**4倍**

#### 3.5.2 多机分布式

```bash
# 机器1
scrapy crawl guba

# 机器2
scrapy crawl guba

# 机器3
scrapy crawl guba
```

**性能**：
- N 机器 × 4 进程 × 64 并发 = N×256 并发请求
- 预计提升：**N×4倍**

### 3.6 性能提升

| 部署方案 | 进程数 | 总并发 | 速度 | 提升 |
|---------|--------|--------|------|------|
| 单进程 | 1 | 64 | ~200-1000条/分钟 | 基准 |
| 4进程 | 4 | 256 | ~800-4000条/分钟 | **4倍** |
| 8进程 | 8 | 512 | ~1600-8000条/分钟 | **8倍** |
| 16进程 | 16 | 1024 | ~3200-16000条/分钟 | **16倍** |

---

## 性能优化总结

### 三个阶段对比

| 阶段 | 技术方案 | 并发数 | 速度 | 提升倍数 |
|------|---------|--------|------|----------|
| **阶段一** | Scrapy + Playwright（基础） | 1 | ~10-20条/分钟 | 基准 |
| **阶段二** | 单线程异步IO优化 | 64 | ~200-1000条/分钟 | **10-50倍** |
| **阶段三** | 多进程 + Redis | 256-1024+ | ~800-16000+条/分钟 | **40-800倍** |

### 优化路径

```
阶段一：基础实现
   ↓ (优化配置、异步IO)
阶段二：单线程高并发
   ↓ (多进程、Redis)
阶段三：分布式爬取
```

### 关键技术点

1. **阶段二核心**：
   - ✅ 异步IO + 事件循环
   - ✅ 高并发配置（64并发）
   - ✅ 智能请求策略（HTTP优先）
   - ✅ 网络连接优化

2. **阶段三核心**：
   - ✅ Scrapy-Redis 分布式调度
   - ✅ Redis 消息队列
   - ✅ 多进程并发
   - ✅ 数据一致性保证

### 适用场景

- **阶段一**：小规模爬取，学习测试
- **阶段二**：中等规模爬取，单机优化
- **阶段三**：大规模爬取，生产环境

---

## 总结

通过三个阶段的技术演进，我们实现了：

1. ✅ **阶段一**：完成基础爬虫功能
2. ✅ **阶段二**：通过异步IO实现 **10-50倍** 性能提升
3. ✅ **阶段三**：通过多进程分布式实现 **40-800倍** 性能提升

**核心思想**：
- 爬虫是IO密集型任务，异步IO比多线程更高效
- 单进程有上限，多进程可突破限制
- Redis 消息队列实现分布式协调和数据一致性

**最终效果**：从 ~10条/分钟 提升到 ~16000+条/分钟，实现 **1600倍** 的性能提升！

