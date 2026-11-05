# GhAccel — 宝塔面板部署与踩坑清单

面向「下载 zip 直投宝塔」的部署者。每一条都对应一个**会静默破坏功能**的具体故障，不是通用建议。
装完务必跑一次 `php bin/selftest.php`（见末尾）。示例域名用 `https://gh.example.com`（保留域）。

> 交付定位是**私有 / 自用**。公开开放前请先读仓库根 `SECURITY.md`（滥用中继、合规、GitHub ToS）。

---

## 0. 前置：源码落地与目录

1. 「网站 → 添加站点」，域名填你的加速域名，PHP 版本先占位。
2. 把仓库解压到站点根，例如 `/www/wwwroot/ghaccel/`。
3. 结构里只有 `public/index.php`（与并行交付的 `public/panel.php`）应当被 Web 直接执行，
   `src/`、`config/`、`var/`、`bin/` 都必须在文档根之外（靠下一步的运行目录达成）。

### 首次部署要手动补的两个目录（出厂缺占位）

`var/cache/` 与 `var/ratelimit/` 出厂**没有 `.gitkeep`**，用 git 克隆或某些打包方式会丢掉这两个空目录。
入口的 `Bootstrap::selfCheck()` 把它们列为 **critical**，缺失时首页会直接返回纯文本 500 并点名
`var_cache` / `var_ratelimit`（不会白屏）。先建好再上线：

```bash
mkdir -p var/cache/_partial var/cache/_quarantine var/ratelimit
# 目录权限见第 5 节
```

宝塔里用「文件」管理新建同名空目录即可。`var/` 其余子目录（state/log/journal/sessions/accounting/
concurrency/lock）出厂有 `.gitkeep`，一般不缺。

---

## 1. 运行目录必须设为 `/public`

「网站 → 设置 → 网站目录 → **运行目录**」下拉选 `/public`，保存。

- 这一步等价于把 Nginx 的 `root` 指向 `public/`。不设的话文档根是仓库根，`src/`、`config/`
  里那些 `return [...]` 的 PHP 配置暴露在执行面之下，`config.php` 里若有自建源 token 就成了风险面。
- 设了运行目录后，再对照 `deploy/nginx.example.conf` 把 `merge_slashes off`、
  `fastcgi_buffering off` 等关键项贴进「配置文件」。宝塔自带模板**不会**有这几条。

---

## 2. PHP 版本：8.1 及以上

「网站 → 设置 → PHP 版本」选 8.1 / 8.2 / 8.3。低于 8.1 入口会返回：
`GhAccel 需要 PHP >= 8.1 (enum 与 readonly 是状态机与值对象的刚需)`。

扩展要求（「软件商店 → PHP → 安装扩展」核对）：

| 扩展 | 缺失后果 | selfCheck 分级 |
|---|---|---|
| `curl` / `openssl` / `hash` / `json` | 无法访问 https 上游 / 无法做摘要与编码 | **critical** |
| `mbstring` | 长路径截断退化成字节级 | warning |
| `intl` | 缺 `idn_to_ascii`，同形字域名告警较晚（但仍会被 LDH 拒） | warning |
| `pdo_sqlite` / `sqlite3` | 只影响日志检索，不影响正确性 | info（本机实测就没有） |
| `opcache` | 快照改用「版本化文件名 + 纯文本指针」，非致命 | warning |

---

## 3. 「禁用函数」核对：这几个必须**没**被禁

宝塔「设置 → PHP 禁用函数」出厂常塞一批 `flock`、`curl_multi_exec`、`exec` 之类。GhAccel 依赖的是：

| 函数 | 用途 | 被禁后果 | selfCheck 分级 |
|---|---|---|---|
| `flock` | 限流桶互斥、lock-slot 并发槽、快照/审计写锁 | **限流与并发控制全线失效**，`.part` 落地不安全 | **critical** |
| `curl_multi_exec` | 探活/并行（HEDGE 在 v1 不做，但自检与面板一键探活要用） | 探活能力失效 | **critical** |
| `hash_hmac` | CSRF Token（HMAC 派生） | 管理面写请求无法校验，等于没 CSRF | **critical** |
| `inet_pton` | IPv6 规范化与隧道解封装、CIDR 匹配 | v6 / CIDR 判定退化（v1 出站锁 IPv4，影响较小） | warning |
| `disk_free_space` | 磁盘余量水位保护 | 水位保护退化到保守模式 | warning |
| `popen` | 个别运维脚本便利调用 | 一般不致命 | warning |

在宝塔「PHP 禁用函数」里**删除**上表 critical 的三项（flock、curl_multi_exec、hash_hmac）。
`php bin/selftest.php` 会把被禁的函数逐条点名（`disabled_flock` 等）。

> 若某项禁用函数是别的站点共享 PHP 版本必须保留的，给 GhAccel 单独装一个 PHP 版本，别将就。

---

## 4. `open_basedir`：知道它的边界，别高估它

给站点设 `open_basedir`（限制 PHP 文件操作能碰的目录）是常规加固，GhAccel 允许你设。
但有一条**必须写清楚**，否则会造成危险的安全错觉：

> **`open_basedir` 不限制 curl 出网。**

`open_basedir` 只约束 `fopen/include/unlink` 这类**文件系统**操作，对 cURL 的 socket 连接
（也就是 SSRF 的真正攻击面）**完全无效**。勾上 `open_basedir` 不等于多了一层 SSRF 防护 ——
SSRF 的防线全部在 `src/Security/UrlGuard.php` + `IpRange.php`（精确 host 白名单、只解析 A 记录、
`CURLOPT_RESOLVE` 钉 IP、逐跳复校、`CURLINFO_PRIMARY_IP` 事后比对）。设 `open_basedir` 时只要别把
`var/` 排除在可写之外即可（否则缓存/状态写不进去）。

---

## 5. 目录权限

- `src/` 与 `public/` 的 owner 设为部署者用户、`www` 只读（避免 web 进程改代码）。
- `var/**` 全部 `www:www`、`0770`（限流桶、并发槽、快照、日志、缓存、会话都往这里写）：

```bash
chown -R www:www var
find var -type d -exec chmod 0770 {} \;
```

- `config/config.php`（含 base_origin、可能含自建源 token）建议 `0640`、owner 为部署者、组 `www` 只读。

---

## 6. php.ini 必改三项

「软件商店 → PHP → 设置 → 配置修改」（等价改该版本的 php.ini）。宝塔默认模板里这几项经常是错的：

```ini
zlib.output_compression = Off   ; 【最重要，也最难查】开启会重新分块 -> Content-Length 与实际字节不符
                                ;   -> Range 切片 / ?sha256= 流式校验 / aria2 断点续传 三件事同时坏，
                                ;   症状分散(下载损坏、校验失败、续传错位)，几乎不会有人归因到这一个 ini 开关。
                                ;   Bootstrap::selfCheck 已把它列为 critical: 开着它首页直接 500 点名。
cgi.fix_pathinfo = 0            ; 关路径信息推断: 配合 nginx 的 SCRIPT_FILENAME 锁定，堵住"缓存里被塞的 .php 被执行"
expose_php = Off                ; 不泄露 PHP 版本指纹
```

补充（非 php.ini，但同属"必须知道会坏在哪"）：

- `merge_slashes` 是 **nginx 指令不是 php.ini**，见第 1 节贴配置。
- `output_buffering` 建议 Off（selfCheck 给 warning，只增加首字节延迟，不致命）。

---

## 7. 计划任务：必须用站点 unix 用户，不要用 root 跑 compact

压实器 `bin/compact.php --once`（重放观测、离线算分位数、原子写快照、价值密度淘汰）由宝塔
「计划任务 → Shell 脚本」周期跑（如每 5 分钟）。

**关键坑**：宝塔计划任务默认用 **root** 执行。root 写出来的 `var/state/snap.*.json`、
`var/log/*.ndjson` 等文件属主是 root，Web 进程（`www` 用户）**读不到 / 写不进**，
于是面板看到的是旧快照、选路喂给熔断的实时数据断更 —— **这是宝塔部署最常见的故障**，
现象是"熔断态明明该更新却不动"。

解决：让计划任务以站点运行用户 `www` 身份执行。用 `su`/`sudo -u` 包一层，或直接在计划任务里切用户：

```bash
# 宝塔计划任务 "Shell 脚本", 执行用户选 www; 若界面强制 root, 则显式降权:
sudo -u www /www/server/php/81/bin/php /www/wwwroot/ghaccel/bin/compact.php --once
```

（`php` 路径按你选的版本改。）热路径其实已概率触发压实，计划任务只是保证低峰期也一定跑；两者都以 `www` 身份
才不会互相把文件属主写成 root。

---

## 8. WAF / 免费防火墙 / Nginx 防火墙 的误伤

宝塔的「Nginx 防火墙 / 免费 WAF」会拦一批 GhAccel 的正常特征：

- **面板轮询**：面板四个视图按 `panel.poll_ms`（5s/10s/10s/15s）同源轮询，高频同源请求容易被 WAF
  判成 CC 攻击封 IP。给面板前缀（默认 `/panel`，建议改随机）与 `/health` 加白名单，或对管理面关闭 CC 拦截。
- **`//` 与含 `%` 的 host**：WAF/mod_security 常见规则会把 URL 里的 `//`（绝对形式入口 `/https://`）
  和带百分号编码的参数当作路径穿越/扫描特征拦截。见第 10 节。
- **`Range` 头**：多线程下载（aria2 `-x16`）会高频带 `Range`，个别规则会拦。放行 `/` 上的带 Range 请求。

WAF 是「可选前置」，不是本项目安全模型的一部分：SSRF 与缓存落地的防线在代码里（见 `SECURITY.md`），
不要以为装了 WAF 就够，也不要让 WAF 的误伤把功能判死。

---

## 9. 网站访问日志会截断长 URL

宝塔默认的 Nginx/Apache `log_format` 会截断超长 URI（绝对形式入口 + 签名参数很容易超过），
排查时"日志里 URL 是半截"是常态，不是请求真的被截。需要完整 URI 时把日志格式里的 `$request` 换成
不截断的版本。注意：**这是 Web 服务器的访问日志**，与 GhAccel 自身的观测日志是两回事 —— 后者按隐私设计
本就不存明文 ref（只存 16 位摘要），别把两者混为一谈去"关掉脱敏"。

---

## 10. CDN / 加速插件会折叠 `//`：三种入口形式是应对

宝塔的「加速/CDN 插件」、云 CDN、以及 nginx `merge_slashes on`，都会把 URL 里的 `//` 折叠成 `/`。
如果只依赖绝对形式 `/https://github.com/...`，折叠后就变成 `/https:/github.com/...`，路由对不上、
**一上 CDN 全部失败**。这就是本项目提供三种等价入口的原因（`README.md` 30 秒上手）：

1. 绝对形式 `/https://github.com/...`（人友好，CDN 会坏）
2. 结构化 `/gh/{owner}/{repo}@{ref}/{path}`（无歧义，不含 `//`，**推荐给脚本/Agent/挂了 CDN 的场景**）
3. 查询形式 `?u=<percent-encoded>`（穿透任何改写 `//` 的代理）

挂了宝塔加速/CDN 后，把对外示例统一换成第 2、第 3 种；第 1 种只在没挂 CDN 时用作人肉入口。

---

## 11. mod_security / Apache 侧

若站点用 Apache 或启用了 mod_security：

- **它会拦 `//` 与含 `%` 的 host**：绝对形式入口 `/https://` 里的 `//` 与签名 URL 里的 `%2B/%2F`
  会命中 OWASP 的路径穿越/编码攻击规则。给本站点降相关规则集或对 `/` 前缀关闭 `SecRuleEngine`。
- Apache 本身**不折叠 `//`**（比 nginx 默认好），但 `AllowEncodedSlashes` 默认 Off 会把 `%2f` 在
  PHP 之前判 404 —— 而我们本来就要拒 host 里的 `%2f`（`UrlGuard` 对 host 含百分号编码一律拒绝），
  所以**保持默认 Off 即可，不要开 `AllowEncodedSlashes On`**。
- `.htaccess` 里**绝不能写 `php_value` / `php_flag`**：宝塔 php-fpm 下这会让整站 500。
  要设的 `zlib.output_compression` 等一律改 php.ini（第 6 节）。见仓库根 `.htaccess` 同款注释。

---

## 12. 装完自检

```bash
# 在站点根、用站点 PHP 跑:
/www/server/php/81/bin/php bin/selftest.php
```

它会依次：

1. **聚合测试** —— 跑 `tests/agent_a_check.php`、`agent_b_check.php`、`agent_c1_check.php`、
   `agent_c2_check.php`（存在才跑，缺失跳过并注明），汇总 pass/fail 与退出码；
2. **部署体检** —— `Bootstrap::selfCheck()`，逐条列 critical / warning（禁用函数、目录可写、
   zlib、CA、磁盘余量都在内）；
3. **端到端判定** —— 用真实的 `RefParser` + `UrlGuard` 现场跑：三种入口形式解析、`blob→raw`、
   归档 `allowRange=false`，以及一整组 **SSRF 用例必须全部被拒**
   （`evil.com\@github.com`、`github.com@evil.com`、`github.com.evil.com`、`notgithub.com`、
   `2130706433`、`127.1`、`[::ffff:169.254.169.254]`、`2002:7f00:1::1`、`64:ff9b::7f00:1`、
   `http://` 降级、`file://`、`private-user-images.githubusercontent.com`）—— 每条打印实际拒绝码，
   **让你一眼看出这台实例到底挡不挡得住**。

联网探活出厂源（可选，默认不联网）：

```bash
/www/server/php/81/bin/php -d curl.cainfo='/path/to/ca-bundle.crt' bin/selftest.php --probe
```

下架处置（当前只落地清单，执行点尚未接入，见 `SECURITY.md`）：

```bash
/www/server/php/81/bin/php bin/selftest.php takedown --repo=owner/repo
```

`selftest` 退出码非 0 时先别上线：多半是某个 `var/` 目录不可写、某个禁用函数被禁、或 `zlib.output_compression`
还开着。
