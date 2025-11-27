---
layout: post
title: CeleRace Lab - Celery Race Condition & RCE 靶场
date: 2025-11-22 00:00 +0800
categories: [项目]
tags: [漏洞复现, CTF, Web安全, Next.js, Flask]
---

这是一个基于 Next.js 和 Flask 的漏洞复现环境，旨在模拟 `Celery` 异步任务队列中的复杂攻击链。

## 项目描述

本项目复现了 CeleRace CTF 题目中的完整攻击链，通过多个漏洞的组合利用实现远程代码执行。项目包含完整的前后端环境、Celery Worker 和 Redis 消息队列，可以安全地在本地环境中学习和研究这些安全漏洞。

## 包含的漏洞

1. **路径穿越 (Path Traversal)**: 任意文件写入漏洞
2. **URL 编码绕过**: 绕过 Flask 简单的权限检查
3. **Redis SSRF**: 通过 HTTP CRLF 注入 Redis 协议
4. **AES CTR Nonce Reuse**: 密钥流重用导致的已知明文攻击
5. **Race Condition**: 并发扣款/逻辑漏洞
6. **Celery RCE**: 覆盖任务文件导致的远程代码执行

## 技术栈

- **前端**: Next.js
- **后端**: Flask (Python)
- **任务队列**: Celery
- **消息代理**: Redis
- **容器化**: Docker & Docker Compose

## 启动方法

确保你已经安装了 Docker 和 Docker Compose。

```bash
# 构建并启动
docker compose up --build
```

启动后访问前端：
[http://localhost:3000](http://localhost:3000)

## 架构

- **Frontend (3000)**: Next.js 交互界面
- **Backend (5000)**: Vulnerable Flask API
- **Worker**: Celery Worker (执行任务，由于挂载了卷，可被攻击修改)
- **Redis (6379)**: 消息队列 & 缓存

## 项目链接

本项目的源代码托管在 [GitHub 仓库](https://github.com/GyroJibering/celerace-lab)。

详细的漏洞分析和利用方法请参考：[CeleRace CTF Web题目详解](/2025/11/22/celerace-ctf-writeup/)

