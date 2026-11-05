# 安全说明 — GhAccel

本项目的本质是**「按用户给的 URL 去请求上游」**，因此它首先是一台**开放代理**。安全边界不是「校验一下
输入」这种泛泛之谈，而是下面逐条落到代码里的判定链。每条都能指到 `src/` 里的实现；指不到的，本节直接
标为**缺口**而不是假装存在。

自检入口：`php bin/selftest.php` 会现场跑一整组 SSRF 用例并逐条打印拒绝码 —— 部署者应一眼看出
「我的实例挡不挡得住」。

---

## 暴露面清单

| 面 | 风险 | 已实现防护 |
|---|---|---|
| 代理入口（`/https://`、`/gh/`、`?u=`、短别名） | 被当开放代理打任意内网 / 云元数据 | SSRF 判定链（下） |
| `/health` | 泄露路径 / 源列表 / 配置 | 免登录但只回聚合三态与缺失项名，零敏感信息（`public/index.php`） |
| 面板 `/panel` | 被扫库、被爆破 | 默认不公网、未登录一律 404、前缀可随机化、写接口全量审计 |
| `var/cache` | webshell 落地点 | 文件名一律 `<sha256>.bin` + 部署侧 `SCRIPT_FILENAME` 锁定入口 |
| 用户可控 `ref` / 文件名 | 存储型 XSS / 响应头注入 | 转义纪律 + `Headers::sanitize` 剥 CR/LF/NUL + `disposition` RFC5987 |

---

## SSRF 判定链（`src/Security/UrlGuard::assertAllowed`，顺序即防线）

任一失败立即抛 `GhpError`，**绝不「降级放行」把原串交给 curl**。逐条：

1. **删控制字符**（`\x00-\x20` 与 `\x7F`）—— 它们在解析器之间制造分歧，且从不出现在合法 URL 里。
2. **长度上限**（`max_url_len`）。
3. **拒绝含反斜杠 `\`**（`backslash_in_url`）：`parse_url("https://evil.com\@github.com")` 得到
   `host=github.com`，而 WHATWG 与部分 curl 把 `\` 当 `/`，于是它们看到 `evil.com`。解析器分歧本身
   就是绕过，与谁更「正确」无关 —— 必须前置拒绝。
4. **`parse_url` 失败或无 host 即拒**：curl 的解析器与 PHP 不同，回退交给 curl 就是分歧。
5. **仅 `https`**（`scheme_not_allowed`），消灭 `http://` 降级与 `file://` 等。
6. **userinfo 一刀切**（`userinfo_not_allowed`）：authority 段（第一个 `/?#` 之前）含 `@` 即拒，一次
   消灭 `\@`、`%40`、`user:pass@`、`#@` 整个 `@` 分歧家族。本项目从不需要在 URL 里带凭据。
   （路径里的 `@` 不受影响，资产名常见。）
7. **端口仅 443/80**（`port_not_allowed`）。
8. **拒绝含 `% : / @ # ? " < > 空格 \ [] '` 的 host**（`illegal_host_chars`）。
9. **再拒任何数字面量** `/^[0-9.]+$/`（`numeric_host_literal`）：`2130706433` / `127.1` / `127` 这类
   在不同解析器里落到不同地址。放在 LDH 之前判，让这类写法落到语义正确的码而不是含糊的「含非法字符」。
10. **纯 LDH + 至少一个点** `/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+$/`：一条规则同时消灭
    **非 ASCII 同形字**（需要 idn_to_ascii 才认得出，缺 intl 也会晚一步告警）、**单标签**、
    **IPv6 字面量**、以及 `0x7f000001` / `0177.0.0.1` 这类带字母的数字写法。
11. **精确 host 集合 `isset` O(1)**：v1 **删掉后缀匹配** —— `ends_with` / `str_contains` 都会被
    `github.com.evil.com`、`notgithub.com` 双双绕过，而 GitHub 侧域名有限可枚举，后缀匹配没有收益只有风险。
    `denied_hosts`（`private-user-images.githubusercontent.com` 等）**先于** `allowed_hosts` 生效，
    即使有人误把通配加进 allowed 也挡得住。
12. **只解析 A 记录**（`gethostbynamel` + `dns_get_record(DNS_A)`）：不做 AAAA 是设计 —— 出站锁 IPv4
    之后，`6to4 / Teredo / NAT64 / v4-mapped` 整条隧道绕过链就没有落地路径。多 IP 全部必须合格，
    「挑一个好的用」等于把 DNS 轮询变成绕过通道。
13. **`IpRange` 逐 IP 校验** → **`CURLOPT_RESOLVE` 钉死 IP + `IPRESOLVE_V4`**：一条 setopt 消灭
    6to4/Teredo/NAT64/v4-mapped 全部绕过。`GuardResult` 构造时自检 RESOLVE 条目 host 与 URL 逐字节一致
    （差一个大小写或尾点就静默失配、curl 重新自行解析、TOCTOU 复活且日志零告警）。
14. **逐跳复校**（`assertRedirectResult`）：把 Location 绝对化后回到判定链顶再跑同一整套（scheme /
    userinfo / host / IP / 回环 / 指回自身），跳数上限 3；拒绝指回本网关入口前缀（`redirect_loop`）。
15. **事后 `CURLINFO_PRIMARY_IP` 比对**（`verifyPrimaryIp`）：实际连上的地址必须落在本次解析出的集合里，
    不符抛 `ssrf_audit_mismatch`（502）并**作废该次观测不写 EWMA** —— 一次没锁住 IP 的交互，它的耗时样本
    不属于这个源。

### DNS 重绑定 TOCTOU：三招与各自的坑

1. **「自解析校验」本身不解决 TOCTOU。** 校验用的是 PHP 的解析路径（`gethostbynamel` / `dns_get_record`），
   而 curl 默认走自己的 `AsynchDNS` —— 两条解析路径可能得到不同结果，校验通过后 curl 仍可能连到另一个
   （内网）地址。所以校验只是必要不充分。
2. **`CURLOPT_RESOLVE` 钉 IP** 才真正消掉「校验所用解析」与「连接所用解析」之间的窗口：curl 不再自行
   解析，直接连我们校验过并写进 RESOLVE 的那个 IP。前提是条目 host 拼写与 URL 逐字节一致（见上 `GuardResult`
   自检）。
3. **`CURLINFO_PRIMARY_IP` 事后比对**是最后一道兜底：即使前两道被绕过，实际连接地址与解析集合不符时，
   这次请求作废且观测丢弃。

三者叠加才把 TOCTOU 压到「TLS 校验 + 内容校验」这一层；单独任何一招都会漏。

### IP 段表（`src/Security/IpRange.php`，全部 fail-closed）

- **v4** 用 uint32 位运算比段表：`0/8, 10/8, 100.64/10（CGNAT）, 127/8, 169.254/16, 172.16/12,
  192.0.0/24, 192.0.2/24, 192.88.99/32, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4, 240/4`，
  并单列云元数据 `169.254.169.254`（被 169.254/16 覆盖）、`100.100.100.200`（阿里云，落在 100.64/10 之外，
  **漏一条就致命**）、`169.254.170.2`（AWS ECS）。可配 `security.extra_deny_cidrs`。段表写错时按「拒绝」处理。
- **v6**：`normalizeIp` 要求 `inet_pton → inet_ntop` 往返逐字符相同（前导零、`0:0:` 未压缩、大小写混合的
  映射段一律判非规范写法拒绝）；再对 `2002::/16`、`2001::/32`、`64:ff9b::/96`、`::ffff:0/96`
  **递归解封装回 v4 判定**（一个都漏不得：只要有一路没解封装，攻击者就用它把 `127.0.0.1` 送进来）。
  `filter_var(..., NO_PRIV_RANGE)` 本机实测放过了这三类隧道，等于没有防护 —— 所以自建段表。
- **v1 默认写死 v4，v6 判定「写了但默认不调用」**（出站已锁 IPv4）。

---

## 滥用中继（把恶意负载放进自己的 GitHub release，借本节点做国内 CDN 分发）

风险成立的前提是「本节点会把这份字节缓存下来并持续分发」。已落地的缓解（`src/Cache/Policy::mayCache`）：

- **低信任源 + 无权威摘要 + 二进制场景 ⇒ 拒绝进 EDGE 缓存**，只流式转发或 302。
  `Trust::mayEdgeWithoutDigest()` 只有 `SelfHosted` 返回 true。理由不是性能而是责任：一旦缓存，之后就是
  由本机域名、带本机 TLS 证书、向国内用户持续分发那份可能被篡改的字节，声誉与法律责任都在部署者这边。
- **`?sha256=` 流式增量校验**（`Streamer`，常数内存 `hash_init/hash_update`），不符即丢弃缓存、
  `FailureKind::Integrity`（权重 3.0 且把源 trust 降 `Suspect`）、返回 `integrity_mismatch`。
- 单请求 / 单 IP 小时日字节配额、`blocked_ext`、`denied_hosts`、UA 闸门。

**运营者仍需自己做**（代码不替保证）：
- 公开部署时监控「新出现且速率异常的 owner/repo」。**注意：计划文档设想的「异常 owner/repo 自动延迟 EDGE」
  在 v1 代码里尚未实现 —— 缺口。**
- **owner/repo 级下架黑名单尚未接入执行点 —— 见「被投诉 / 下架」一节。**

---

## 限流 / 配额 / 并发槽

- **三桶令牌桶**（`src/Security/RateLimiter.php`）：`ip`（请求数，宽）、`ipday`（字节配额，很宽）、
  `panel`（数据面与管理面分桶）。桶键 = `sha256(scope|clientKey|salt)` 派生：IPv6 含 `:` 直接当文件名在
  Windows 上炸，同时不把用户 IP 明文落盘。两级目录分片防单目录爆量。
- **`flock(LOCK_EX|LOCK_NB)` 抢不到即「允许但 `contended=true`」**：阻塞等锁会把所有限程变成一把全局锁，
  高并发下限流器自己就是第一个被打死的组件。回填按实际流逝时间算并 clamp 到 cap（否则空闲一夜会攒出天文配额）。
- **并发槽用 lock-slot 文件数组**（`src/Security/Slots.php`，`var/concurrency/slot_NN` +
  `LOCK_EX|LOCK_NB`），**不用计数器文件**：读 n / 写 n+1 的计数器在 PHP-CGI 崩溃、请求超时被强杀、进程 OOM
  时会留下永久漂移的计数 —— 少减一次就永久少一个槽，跑几天后并发数归零且看不出原因。锁的生命周期绑在 fd
  上，进程一死内核自动回收，槽位自愈。本机 `sysvsem` 缺失也印证信号量不能当依赖。
- 校园网 / 企业 NAT 后几百人共用出口 IP 会互相连坐 → `ip` 只宽限请求数、字节走很宽的 `ipday`、分片按同一
  ref 归并扣桶、提供 `limits.trusted_cidrs` 白名单。
- **Range 请求被限流也必须返 429**（`Dispatcher::renderError`），否则下载工具会把 HTML 错误页当分片写进文件。

---

## 管理面（面板 / `/health`）

> 面板 SSR 由并行交付提供，以下为它必须遵守、且 `public/index.php` / `Auth` 已实现的约束。

- **默认不公网**（`panel.public_exposed = false`）；**未登录一律 404 而非 401 / 登录页** —— 不给扫描器
  「这里有个面板」的信号（`Auth::requireAuth`：HTML 请求给 404，API 请求才给 401）。
- **前缀可随机化**（`panel.path_prefix`，如 `ctl-7f3a9c`）；`/panel` `/admin` `/ui` `/stats` 都在扫描字典里。
- **`/health` 零敏感信息**：只回 `ok / php / critical[] / warnings[] / ts`。
- **写接口全量审计**（`src/Security/Audit.php`）：一行一 JSON 追加 NDJSON，IP 只留哈希、body 只留 sha256，
  绝不记 body 明文。
- **Token**：48 字节 hex = `selector(16)|verifier(80)`，只存 `sha256(verifier)`，比对用 `hash_equals`，
  按 selector 键 O(1) 取值（不遍历比较 → 无枚举侧信道；不存在也哈希一次让两条分支耗时差降到噪声级）。
  **故意不用 bcrypt**：verifier 本身 320bit 全熵，慢哈希不增加破解成本，反而把每次错误验证变成实测 ~167ms
  的 CPU 反射攻击面（发 20 个错 token 就占住 20 个 fpm worker）→ 改用快哈希 + `login` 桶限流 + 失败加倍扣分。
- **自管 session 文件**：PHP 原生 `session_start` 对同 session 并发阻塞，面板多开几个轮询页签会自己卡死。
  Cookie `HttpOnly; SameSite=Strict; Path=<面板前缀>`，**故意不设 Domain（host-only，防子域接管）**。
  会话绑 **IP 前缀**（v4/24、v6/48）而非整 IP，否则移动网络换址就掉线。

### CSRF / Origin：绝不能用 `$_SERVER['HTTP_HOST']` 作基准

`Auth::verifyWriteRequest` 的顺序即强度：`method` → `Sec-Fetch-Site`（攻击者删不掉）→ **`Origin` 严格等值
配置里的 `app.base_origin`** → HMAC CSRF Token（绑 method+path+会话 sid）→ Content-Type 约束。

**为什么不能用 `HTTP_HOST`**：宝塔直通 `$http_host` 且 `server_name` 宽松时，Host 完全由请求方控制；拿它
当同源基准，等于把「同源判定」交给攻击者 —— 校验会直接变成绕过项。`base_origin` 留空时写请求一律被拒
（宁可拒绝也不建立可信基准）。

### CSRF Token 为什么不用全局一枚

绑定到 `method + path + sid` 后，攻击者即使从别处拿到一个 Token，也无法拿去动另一个接口（比如把「改权重」的
Token 拿去删源），泄漏影响面从「整个面板」缩到「一个动作」。

---

## 面板存储型 XSS

决策视图渲染的 `ref` 是**攻击者完全可控字符串**（它来自被代理的 URL）。防护纪律（`public/index.php` 首页已
照此实现，面板 SSR 必须同样遵守）：SSR 一律 `htmlspecialchars(ENT_QUOTES|ENT_SUBSTITUTE)`；JS 走 `textContent`
不拼 `innerHTML`；展示截 120 字符并剥控制符；IDN 显示 punycode + 原文双列。

**CSP**：`default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';
form-action 'self'`。因此 HTML 内不得有 `<script>` 体与任何 `on*=`；初始值放
`<script type="application/json" id="boot">`，CSRF 走 `<meta>`。`style-src 'self' 'unsafe-inline'` 可接受，
`script-src` 一寸不让。`/panel/api/logs` 文件名走枚举白名单，绝不拼路径。

---

## 缓存目录当 webshell 落地点

`var/cache` 是可写目录，也是最想被写入的地方。两道独立防线：

1. **文件名一律 `<sha256>.bin`**（`src/Cache/Key::paths`）：键必须是 64 位小写十六进制否则拒绝拼路径；
   落盘名**永不含 `.php`、也不含原始文件名任何片段**。很多实现会「顺手」把下载文件名（攻击者全控）拼进缓存
   路径 —— 那正是 webshell 落地点。
2. **部署侧 `SCRIPT_FILENAME $document_root/index.php` 锁定只执行入口 + `cgi.fix_pathinfo=0`**：这条比逐目录
   `deny all` 更可靠，因为它不依赖你记住每个新增子目录。是 `var/cache` 被写入后还能不能被当 PHP 执行的真正答案。

---

## 完整性

- `?sha256=` 流式校验（常数内存，边下边算），不符即丢弃、`integrity_mismatch`、源降 `Suspect`。
- 低信任源无权威摘要的二进制不进缓存（见滥用中继一节）。
- **双源交叉校验默认关**（`integrity.dual_source_cross_check = false`）：每次 2 倍上游流量，本身也是流量
  放大器。
- **缺口**：错误码 `content_divergence`（不同源内容不一致）在 v1 **已定义但未接线抛出**，`dual_source_cross_check`
  配置项也无对应的执行路径 —— 二者属于 v1 未落地的交叉校验，不假装已生效。

---

## 被投诉 / 被要求下架时怎么处置

计划文档把「存在 owner/repo 下架黑名单与 `bin/` takedown 手段」列为交付项。当前真实状态：

1. **`php bin/selftest.php takedown --repo=owner/repo`** 把该 owner/repo 原子写入
   `var/state/blocklist.json`（带去重、带时间戳）。
2. **但该清单目前尚未被执行逻辑读取 —— 这是明确的缺口。** 代码里唯一的拒绝点是 host 级
   `security.denied_hosts`，没有任何 owner/repo 级判定。要让下架真正生效，至少需接入：
   - **入口拒绝点**：`public/index.php` 在 `RefParser::parse()` 之后、`Dispatcher::serve()` 之前读
     `blocklist.json`，命中 `ref->owner / ref->repo` 即抛 `GhpError`（建议新增专用码，对外语义可先借用
     404 `not_found`，不给投诉方「存在但被拒」的信号）；
   - **缓存历史清理**：`Cache\Key` 是 `canonical()` 的 sha256，无法按 owner/repo 反查已落地条目 —— 需新增
     `(owner|repo) → keys` 反向索引，否则下架只挡新请求，旧缓存仍会 EDGE 直出。
   在没有这两处之前，运维可对被投诉的仓库**临时把它落到 `sources` 之外**并清 `var/cache`，但那不是精确下架。

`selftest.php takedown` 的输出里会原样打印上述「需接入 2 处」的说明，方便交接。

---

## 报告漏洞

请通过**仓库的安全通告 / issue 加密渠道**提交（不要开公开复现）。
**部署者注意**：本仓库交付时未预置具体的安全联系邮箱 / PGP —— 请在 `config` 的 `app.contact` 与下面的位置
填上你自己的漏洞接收地址后再公开部署：

```
Security contact: <由部署者自行填写，例如 SECURITY.md 顶部或 .well-known/security.txt>
```

报告时尽量附：`request_id`（响应头 `X-GhAccel-Request-Id`）、命中的错误码、以及能触发问题但已脱敏的请求形式。
