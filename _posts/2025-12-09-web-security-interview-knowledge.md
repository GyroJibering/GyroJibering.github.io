---
layout: post
title: 用八十岁老奶也能听懂的话总结了面试常用的Web安全漏洞
date: 2025-12-09
categories: [安全, 面试]
tags: [Web安全, 面试, SQL注入, XSS, CSRF, SSRF, XXE, 安全漏洞]
toc: true
author: GyroJ
---

> 面向 **后端 / 安全 / 开发岗面试**
> ORM、SQL 注入、PDO、CORS、XSS、CSRF、SSRF、XXE、本地/横向提权
> 计划长期更新

---

## 一、ORM / PDO / SQL 注入

### 1. ORM 是什么（专业 + 通俗）

**专业**：
ORM（Object Relational Mapping）通过对象模型映射关系数据库，自动生成 SQL 并负责参数绑定。

**通俗**：
你不再手写 SQL，而是用代码操作"对象"，ORM 帮你安全地拼 SQL。

---

### 2. ORM ≠ PDO

| 对比       | PDO     | ORM    |
| -------- | ------- | ------ |
| 定位       | 数据库访问接口 | 高层抽象框架 |
| 是否防 SQLi | ✅（预处理）  | ✅（默认）  |
| 是否可能注入   | ✅（误用）   | ✅（误用）  |

PDO 是**工具**，ORM 是**体系**。

---

### 3. ORM 一定能防 SQL 注入吗？

**不能。**

#### 常见绕过场景

1. `order by` 无法参数化
2. 手写原生 SQL
3. 动态拼接列名 / 表名
4. 特殊语法（如 SQLite FTS MATCH）

#### 危险示例

```php
$sql = "SELECT * FROM users ORDER BY $order"; // 注入点
```

#### 正确写法（白名单）

```php
$allow = ['id','username','created_at'];
if (!in_array($order, $allow)) die('invalid');
```

---

## 二、SQL 注入补充知识

### 1. 预处理 vs 字符串拼接

```php
// ❌ 错误
$sql = "SELECT * FROM users WHERE name='$name'";

// ✅ 正确
$sql = "SELECT * FROM users WHERE name=?";
$stmt->execute([$name]);
```

### 2. 宽字节注入原理

* GBK 中 `%df%27` → 一个汉字 + `'`
* 绕过 addslashes

**本质**：字符集不一致导致转义失效

**防护**：

* 统一 UTF-8
* 使用预处理

---

## 三、XSS（重点高频）

### 1. XSS 是什么

**专业**：攻击者将恶意脚本注入页面，在受害者浏览器中执行。

**通俗**：让你的网站替攻击者执行 JS。

---

### 2. XSS 的危害

* 窃取 Cookie（非 HttpOnly）
* 劫持登录态
* 钓鱼、键盘记录
* 配合 CSRF / SSRF

---

### 3. 简单 XSS 防护示例（面试推荐）

```php
function xss_filter($input) {
    return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
}
```

**核心原则**：

> 不过滤输入，而是**在输出时做编码**

---

### 4. HttpOnly 为什么 JS 读不到 Cookie

```http
Set-Cookie: PHPSESSID=xxx; HttpOnly
```

* 浏览器禁止 `document.cookie` 访问
* 但 Cookie 仍会随请求发送

👉 防 XSS 窃 Cookie，不防 CSRF

---

## 四、CSRF / SSRF

### 1. CSRF

* 利用浏览器自动带 Cookie
* 诱导用户发请求

#### 防护

```html
<input type="hidden" name="csrf_token" value="随机值">
```

* CSRF Token
* SameSite Cookie

---

### 2. SSRF

* 服务端替攻击者访问内部资源
* 常见于 URL 参数

```php
file_get_contents($_GET['url']); // SSRF
```

**防护**：

* 禁止内网 IP
* URL 白名单

---

## 五、CORS & JSONP

### 1. CORS 是什么

浏览器的跨域访问控制机制。

```http
Access-Control-Allow-Origin: https://example.com
```

---

### 2. 致命错误配置

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

👉 浏览器会直接拒绝，但若逻辑错误可能被绕过

---

### 3. JSONP 的问题

* 只能 GET
* 可执行任意 JS
* 本质是 XSS

---

## 六、XXE（XML 外部实体）

### 1. XXE 是什么

XML 解析器加载外部实体，导致：

* 读文件
* SSRF

---

### 2. 经典 payload

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
```

---

### 3. 危害

* 读取敏感文件
* 内网探测
* SSRF

---

### 4. 防护

```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

* 禁用 DOCTYPE
* 使用安全解析器

---

## 七、本地提权 / 横向移动

### 常见方式

* SUID 程序
* sudo 误配置
* cron 权限
* PATH 劫持
* 内核漏洞

---

## 八、SDL（Security Development Lifecycle）

**定义**：
在软件开发全流程中引入安全机制。

**阶段**：

* 设计：威胁建模
* 开发：安全编码
* 测试：代码审计
* 上线：监控

---


## 常见 Web 漏洞百科补充（面试高频）

> 本节目标：**看到漏洞名就能说清原理 + 危害 + 防护**

---

### 1. 文件上传漏洞

**原理**：

* 仅校验后缀 / MIME
* Web 目录可执行

**危害**：

* WebShell
* 远程命令执行（RCE）

**危险示例**：

```php
move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);
```

**防护**：

```php
$ext = pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION);
$allow = ['jpg','png','gif'];
if (!in_array($ext, $allow)) die('invalid');
```

* 重命名文件
* 上传目录不可执行

---

### 2. 文件包含漏洞（LFI / RFI）

**原理**：

* include / require 使用用户输入

```php
include $_GET['page']; // LFI
```

**危害**：

* 读取源码
* 配合日志 getshell

**防护**：

```php
$allow = ['home','about'];
if (!in_array($page,$allow)) die();
include "pages/$page.php";
```

---

### 3. 命令注入

**原理**：

* 系统命令拼接用户输入

```php
system('ping ' . $_GET['ip']);
```

**危害**：

* 直接 RCE

**防护**：

* 禁止拼接
* escapeshellarg

```php
system('ping ' . escapeshellarg($ip));
```

---

### 4. 反序列化漏洞

**原理**：

* 反序列化不可信数据
* 触发危险魔术方法（如 PHP `__destruct`）

```php
unserialize($_GET['data']); // 危险
```

**危害**：

* RCE
* 代码执行

**防护**：

* 不反序列化用户输入
* 使用 JSON
* 白名单类名

---

### 5. 逻辑漏洞 / 越权（IDOR）

**原理**：

* 只校验"是否登录"
* 不校验"是否有权限"

```http
GET /order?id=1001
```

**危害**：

* 数据泄露
* 资产被操作

**防护**：

* 服务端权限校验
* 使用间接引用

---

### 6. Open Redirect

```php
header('Location: ' . $_GET['url']);
```

**危害**：

* 钓鱼
* OAuth 劫持

**防护**：

```php
if (!str_starts_with($url, '/')) die();
```

---

### 7. Clickjacking（点击劫持）

**原理**：

* iframe 覆盖诱导点击

**防护**：

```http
X-Frame-Options: DENY
```

---

### 8. 目录遍历

```php
file_get_contents('files/' . $_GET['f']);
```

**危害**：

* 任意文件读取

**防护**：

* realpath 校验

---

### 9. HTTP 参数污染（HPP）

```http
?id=1&id=2
```

**危害**：

* 绕过校验逻辑

**防护**：

* 参数唯一性校验

---

### 10. 不安全的随机数

**原理**：

* 使用 rand()

**危害**：

* Token 可预测

**防护**：

```php
random_bytes(32);
```

---

### 11. 不安全的加密 / 哈希

❌：

```php
md5($password);
```

✅：

```php
password_hash($password, PASSWORD_DEFAULT);
```

---

### 12. 业务风控类漏洞

* 短信轰炸
* 验证码重放
* 并发条件竞争

**防护**：

* 限流
* 幂等设计

---

### 13. HTTP 请求头走私（HTTP Request Smuggling）

**原理**：

* 前后端对请求边界解析不一致
* 利用 `Content-Length` 和 `Transfer-Encoding` 冲突

**类型**：

* CL.TE：前端用 CL，后端用 TE
* TE.CL：前端用 TE，后端用 CL

**危险示例**：

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**危害**：

* 绕过安全控制
* 请求走私到其他用户
* 缓存投毒

**防护**：

* 统一使用 HTTP/2
* 禁用 `Transfer-Encoding: chunked`
* 严格解析请求边界

---

### 14. JWT 漏洞

**原理**：

* JWT 由 Header.Payload.Signature 组成
* 签名验证依赖算法和密钥

#### 空算法绕过（None）

```json
{
  "alg": "none"
}
```

* 删除签名部分
* 后端未校验算法

**危险示例**：

```http
Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

**防护**：

* 强制验证算法
* 拒绝 `none` 算法

#### 弱密钥 / 密钥泄露

**原理**：

* 使用弱密钥（如 "secret"）
* 密钥硬编码在代码中

**危害**：

* 伪造任意 Token

**防护**：

* 强随机密钥
* 密钥轮换
* 使用 RS256（非对称）

#### 算法混淆

**原理**：

* 将 HS256 改为 RS256
* 用公钥伪造签名

**防护**：

* 验证算法与密钥匹配
* 使用算法白名单

---

### 15. 敏感数据泄露

**表现**：

* 错误信息暴露路径
* Debug 模式开启
* 日志文件可访问
* Git 仓库泄露

**防护**：

* 关闭错误回显
* 生产环境禁用 Debug
* 日志文件权限控制
* `.git` 目录禁止访问

---

### 16. 服务端模板注入（SSTI）

**原理**：

* 模板引擎执行用户输入

```python
template = "Hello " + user_input
render(template) # 危险
```

**危害**：

* RCE
* 文件读取

**防护**：

* 模板变量转义
* 沙箱环境

---

### 17. 不安全的文件操作

**原理**：

* 文件操作使用用户输入
* 路径未校验

```php
unlink($_GET['file']); // 危险
```

**危害**：

* 任意文件删除
* 目录遍历

**防护**：

* 白名单路径
* `realpath` 校验

---

