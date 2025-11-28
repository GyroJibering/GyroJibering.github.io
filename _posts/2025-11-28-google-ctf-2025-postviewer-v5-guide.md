---
layout: post
title: "Google CTF 2025: Postviewer v5² 完全指南（bushi"
date: 2025-11-28 00:00 +0800
categories: [Web安全, CTF]
tags: [Race Condition, V8, SOP Bypass, Docker, 漏洞复现]
toc: true
author: GyroJ
---

本文档基于官方 Writeup (by @terjanq) 编写，整合了深度原理解析与基于 Docker 的漏洞复现教程。

---

## 题目解析

> **原文作者**: @terjanq  
> **题目**: Google CTF 2025 - Postviewer v5²
> **核心考点**: Client-side Race Condition (客户端竞争条件), V8 PRNG Prediction (随机数预测), SOP Bypass (同源策略绕过)

### 1. Introduction
Postviewer 系列挑战一直是 Google CTF Web 类别中的亮点。今年的版本使用了一个生产环境级别的库 **SafeContentFrame (SCF)**，这是作者在 Google 开发的用于渲染动态内容的库。本题展示了一种利用巧妙的 **竞争条件 (Race Condition)** 来攻破它的方法。

### 2. 核心机制: SafeContentFrame (SCF)

**SafeContentFrame** 的设计目标是在完全隔离的 Origin（源）中渲染不可信内容，防止 XSS。

#### 隔离原理
每个文件都在一个独特的域名下运行：
*   **域名格式**: `https://<hash>-h748636364.scf.usercontent.goog/google-ctf/shim.html?origin=https://postviewer5.com`
*   **Hash 计算**: `sha256("google-ctf" + "$@#|" + salt + "$@#|" + "https://postviewer5.com")`
*   **关键点**: 
    *   不同的 `salt` 生成不同的 Hash，进而对应不同的 Origin (域名)。
    *   浏览器同源策略 (SOP) 保证了不同 Origin 的 iframe 无法互相访问内容。

#### One Iframe 机制
1.  **App**: 计算 Hash，创建 Shim Iframe。
2.  **App**: 注册 `onload` 监听器。
3.  **Iframe**: 加载完成，触发 `onload` 事件。
4.  **App**: 捕获 `onload`，通过 `postMessage` 发送 `{body, salt}` 给 Iframe。
5.  **Iframe**: 收到数据，发送 `Reloading iframe` 回执。
6.  **App**: 收到回执，**移除 `onload` 监听器**。

### 3. 两种加载模式

题目允许通过 `postMessage` 分享文件，并支持两种模式，这决定了 `salt` 的生成方式：

1.  **Cached Mode (缓存模式)**:
    *   默认: `salt = Hash(FileContent)`。
    *   **漏洞点 (Gadget)**: 如果 `Filename.length > Hash(FileContent).length`，则 `salt = Filename`。
    *   *利用价值*: 只要我们控制文件名，我们就能控制 iframe 的 Origin。

2.  **Non-cached Mode (非缓存模式)**:
    *   规则: `salt = Math.random()`。
    *   *利用价值*: Admin Bot 生成的 Flag 文件也是 Non-cached 模式，意味着它的 Origin 是随机的。

### 4. 攻击思路

我们的目标是窃取 Admin Bot 打开的 Flag 文件内容。

**逻辑链条**:
1.  Flag 文件在 Non-cached 模式下运行，其 Origin 由一个随机数 (`salt_flag`) 决定。
2.  如果我们能**预测**这个随机数 (`salt_flag`)，我们就知道了 Flag 文件的 Origin。
3.  我们构造一个恶意文件，利用 Cached Mode 的漏洞，将其文件名设置为预测出的 `salt_flag`。
4.  这样，我们的恶意文件也会在同一个 Origin 下运行。
5.  当 Admin 同时打开这两个文件时，它们同源，我们可以跨 iframe 读取 Flag。

**核心难点**: 如何获取之前的随机数样本来进行预测？
这需要利用 **竞争条件 (Race Condition)** 来泄露 Non-cached 模式下的 `salt`。

### 5. 竞争条件

我们需要在 App **移除 `onload` 监听器之前**，再次触发 `onload` 事件，让 App 错误地把 `salt` 发送给我们。

**攻击步骤**:
1.  **Share**: 分享一个 Non-cached 文件（这是我们要偷 Salt 的目标）。
2.  **Block**: 发送大量数据触发 `slow` gadget，**阻塞主线程**。
    *   *原理*: 浏览器 UI 线程和 JS 线程是互斥的。当 JS 忙于循环时，消息队列中的 `postMessage` 回执（`Reloading iframe`）会被积压。
3.  **Redirect**: 在 iframe 内部（利用另一个已加载的文件）触发 `location.reload()` 或重定向。
4.  **The Win**:
    *   App 发送第一次 `salt`。
    *   App 主线程卡死，无法处理 Iframe 发回的 "Reloading" 消息（无法移除监听器）。
    *   Iframe 完成刷新，触发第二次 `onload`。
    *   App 主线程解冻，处理第二次 `onload`，**再次发送 `salt`**。
    *   此时 Iframe 已经被我们重定向到了攻击者控制的页面，成功捕获 `salt`。

---

## 复现

使用 Docker 能确保环境与 CTF 比赛时完全一致（特别是 Chrome/Puppeteer 的行为）。

### 1. 启动题目环境 (Docker)

确保已安装 Docker Desktop。

1.  **构建镜像**:
    在 `web-postviewer5` 目录（包含 Dockerfile 的目录）下运行：
    ```powershell
    cd web-postviewer5
    docker build -t postviewer5 .
    ```

2.  **运行容器**:
    我们将容器的 1338 端口映射到本机的 1338 端口。
    ```powershell
    docker run --rm -it --privileged -p 1338:1338 postviewer5
    ```
    *   访问 `http://localhost:1338` 确认题目已运行。

### 2. 准备攻击者服务器 (Host)

运行 `server.py` 来托管攻击脚本和执行 PRNG 预测。[源码链接](https://gist.github.com/terjanq/69fd6290ec2d77852c02635392300660#file-exploit-chrome-html)

(你需要删除所有有关SageMath依赖的内容才能运行代码，至于为什么，可以继续看)

  **启动攻击服务**:
    在根目录（包含 `server.py` 和 `exploit-chrome.html` 的目录）运行：
    ```bash
    python server.py
    ```
    此时攻击服务运行在 `http://localhost:8000`。
### 最后

访问我们的攻击服务器，你将会看到弹出两个浏览器窗口，之后一直在执行某些重复的行为
大概几秒钟后，你会看到这个东西：

<img src="/img/postview/1.png" style="max-width: 80%; height: auto; display: block; margin: 1rem auto; border-radius: 8px;">

---
### 我们做到了什么？ (Current Achievement)

通过上述复现，我们成功捕获了 **Salt**（即 `Non-cached` 模式下生成的随机数）。

**这意味着我们攻克了本题最核心、最困难的技术壁垒：**

1.  **突破了 SafeContentFrame 的设计假设**：
    SCF 假设“只有通过校验的 Origin 才能加载内容”，且“App 会在每次加载完成后立即移除监听器”。我们证明了这个假设在高负载（Blocked Main Thread）下是不成立的。

2.  **赢得了微秒级的竞争 (Winning the Race)**：
    通过 `Slow Gadget` 精确控制了浏览器主线程的阻塞时间，强行改变了事件处理的顺序：
    *   正常顺序：`PostMessage` -> `Reloading` -> `Remove Listener`。
    *   攻击顺序：`PostMessage` -> **`Blocked`** -> `Iframe Reload` -> `PostMessage (Leaked)` -> `Remove Listener`。

### 缺失的最后一步 (The Missing Piece)

完整的 Exploit 链条还包括：
*   **Prediction**: 将泄露的 Salt 输入 V8 PRNG 预测器 (基于 SageMath/Z3)，计算出未来的随机数。
*   **Collision**: 利用预测结果构造同源文件，读取 Flag。

由于 SageMath 环境配置的复杂性，我们在复现中跳过了这一步。但这仅仅是**数学计算**层面的工作，与 Web 安全机制的攻防（本题的核心价值）已无太大关联。只要拿到了 Salt，从安全角度来看，**漏洞已经被彻底证实并利用成功**。

如果能看到这里，你会发现：我们刚才开启的docker根本没有用到，是的！为什么没用到？因为这个SageMath实在是太难装了，需要很多系统级的依赖，博主暂时没那么好的设备，大部分实验都是用的WSL和docker，装了半天装不上去放弃了。
