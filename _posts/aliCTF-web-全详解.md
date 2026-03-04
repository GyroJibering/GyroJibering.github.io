## Easy_Login
>xss、nosql注入
首先，来看源码，看到了熟悉的东西，在我之前的博客中详解过httponly和samesite，这里刚好有：
```ts
 res.cookie('sid', sid, {
      httpOnly: false,
      sameSite: 'lax'
    });
```
httponly设置为flase，意味着cookie并不只是在http发包的时候带上，而是可以被js访问，也就是说在使用 xss攻击的时候可以拿到这个cookie，samesite设置为lax，这是默认安全级别，允许get和顶级导航携带cookie，这部分在我的常见web安全漏洞中有详解。

获取flag的方法，要么是admin，要么不是用户：
```ts
app.get('/admin', (req: AuthedRequest, res: Response) => {
  if (!req.user || req.user.username !== 'admin') {
    return res.status(403).json({ error: 'admin only' });
  }

  res.json({ flag: FLAG });
});

```
是的，这里我们是否能尝试垂直越权，想办法拿到admin权限呢？事实上，稍微聪明一点，这题给了这么明显的xss，解题思路应该在xss上面。

传统的考察xss的题目，通常都会有一个bot，也就是自动访问网站的机器人，这一点在Google CTF 2025中也有考察到，我们来查看这个bot的行为逻辑：
```ts
async function runXssVisit(targetUrl: string): Promise<void> {
  if (typeof targetUrl !== 'string' || !/^https?:\/\//i.test(targetUrl)) {
    throw new Error('invalid target url');
  }

  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  try {
    const page = await browser.newPage();

    await page.goto(APP_INTERNAL_URL + '/', {
      waitUntil: 'networkidle2',
      timeout: 15000
    });

    await page.type('#username', 'admin', { delay: 30 });
    await page.type('#password', ADMIN_PASSWORD, { delay: 30 });

    await Promise.all([
      page.click('#loginForm button[type="submit"]'),
      page.waitForResponse(
        (res) => res.url().endsWith('/login') && res.request().method() === 'POST',
        { timeout: 10000 }
      ).catch(() => undefined)
    ]);

    await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 15000 });

    await new Promise((resolve) => setTimeout(resolve, 5000));
  } finally {
    await browser.close();
  }
}
```
这里使用的是puppeteer的无头浏览器来模拟浏览器行为，有一个需要注意的点：这里禁用了沙箱，也就是说利用xss让bot在本地运行js如果能在chrome进程内执行代码，就直接导致了对方主机上的RCE，如果我们走这条路的话，就只缺少一个chrome 0day漏洞了。

这或许是一种解题方式，但是这题明显没有那么复杂。

事实上，这个题目的解法是nosql注入

漏洞触发点：
```typescript
const sid = req.cookies?.sid as string | undefined;
// ...
const session = await sessionsCollection.findOne({ sid });
```