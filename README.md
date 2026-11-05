GhAccel — GitHub 访问 / 下载加速网关。作者 谶Hank · MIT 许可 · 零 Composer 运行时依赖 · 可直投宝塔。

> 一台按资源身份智能选路、能熔断、能缓存、能被 AI Agent 机器可解析调错的 GitHub 反代。
> 定位为**私有 / 自用部署**：默认 EDGE 保守、面板不公网、出站锁 IPv4。面向公众开放前请先读
> [`SECURITY.md`](SECURITY.md) 的合规与 GitHub ToS 章节。

示例域名一律用保留域 `https://gh.example.com`，请替换成你自己的站点。

---

## 30 秒上手

三种**等价入口形式**，各给一个可直接复制的真实例子。为什么要有三种：nginx 的 `merge_slashes`、
云 CDN 与宝塔加速插件都会把 URL 里的 `//` 折叠掉。只依赖绝对形式（第 1 种）的网关，一上 CDN
路由就全灭 —— 所以第 2、第 3 种是刻意冗余的兜底通路。

```bash
# 1) 绝对形式（人友好，经典写法）：把完整 GitHub URL 直接接在域名后面
curl -L https://gh.example.com/https://github.com/cli/cli/releases/download/v2.12.0/gh_2.12.0_linux_amd64.tar.gz -o gh.tar.gz

# 2) 结构化形式（无歧义，推荐给脚本与 Agent）：/gh/{owner}/{repo}@{ref}/{path}
curl -L https://gh.example.com/gh/cli/cli@refs/tags/v2.12.0/README.md

# 3) 查询形式（穿透任何会改写 // 的代理）：?u= 里的值是 percent 编码的
curl -L "https://gh.example.com/?u=https%3A%2F%2Fgithub.com%2Fcli%2Fcli%2Freleases%2Fdownload%2Fv2.12.0%2Fgh_2.12.0_linux_amd64.tar.gz"

# 多线程下载：Range / 206 语义完整透传，可直接并发分片
aria2c -x16 -s16 https://gh.example.com/https://github.com/cli/cli/releases/download/v2.12.0/gh_2.12.0_linux_amd64.tar.gz
```

短别名（`src/Ref/RefParser.php` 的 `parseAlias`，是否开启由 `routing.alias` 决定）：

| 别名 | 语法 | 场景 |
|---|---|---|
| `/raw/{o}/{r}/{ref}/{path}` | 兼容 `blob`/`tree` 标记 | raw 文本与二进制单文件 |
| `/release/{o}/{r}/{tag}/{asset}` | — | Release 资产 |
| `/latest/{o}/{r}[/{asset}]` | 免 API 反解 tag | 最新版本资产 |
| `/zip/{o}/{r}/{ref}` `/tar/…` `/archive/…` | ref 可含斜杠 | 仓库归档快照 |
| `/api/{endpoint}` | — | api.github.com JSON |
| `/gist/{owner}/{id}[/{rev}][/{path}]` | — | gist raw |

`blob → raw` 的改写只在第 3 段位置识别 `/{o}/{r}/blob/`，不做全局替换（`/tree/main/blob/x`
这种真实存在的坑见 `RefParser::parseAbsolute`）。

---

## 支持的场景

| 场景（`src/Enum/Scene.php`） | 真实上游 | 已知限制 |
|---|---|---|
| `raw` | `raw.githubusercontent.com` | 尊重 Range；文件本身是 HTML 时 raw 也回 HTML |
| `release_asset` | 302 → `objects.githubusercontent.com` / `release-assets.githubusercontent.com`（一次性签名 SAS） | 落点域必须在 `security.allowed_hosts` 白名单里，否则第二跳被 `host_not_allowed` 挡；签名 URL 绝不缓存、绝不回吐、绝不再次拼进上游；**默认走 `github.com/…/archive` 之外的 download 链，必须源内部跟完 302（能力位 `follows_redirect_internally`，实测非配置）** |
| `archive` | `github.com/{o}/{r}/archive/…`（302 → `codeload.github.com`） | **实测 `codeload` 对 `Range: bytes=0-64` 返回 200 全量**，故 `allowRange=false`，不注入 `Accept-Ranges` |
| `api_json` | `api.github.com` | 上游 403 rate-limit 时必须停止，不得换源继续刷（`config.dist` `routing.stop_on_upstream_rate_limit` 为文档化，代码不可关）；v1 不 EDGE 缓存 JSON |
| `gist_raw` | `gist.githubusercontent.com` | 无 revision 的 gist 视为可变，TTL 短 |

`config/config.dist.php` 的 `security.allowed_hosts` 出厂缺 `release-assets.githubusercontent.com`
一条 —— 用 `bin/selftest.php` 的 `UpstreamMap::missingAllowedHosts()` 或 `config/config.example.php`
的覆盖补齐，否则 Release 下载会在落点这一跳静默失败。

---

## 多重加速算法（v1 收敛为可解释的 4 因子）

选路实现在 `src/Routing/Selector.php`，入参是「全部候选源 + 每源运行时统计 + 已解析的 `GitHubRef` +
上下文」，输出是 `Plan{ ranked, excluded(带拒绝码), relaxedFlags, coldStart, … }`。

### L0 硬约束布尔筛（带 `RejectCode` 表）

能用布尔解决的绝不进打分（打分是软的会骗人，硬约束不会）。`Selector::screen` 逐源返回命中的拒绝码，
一路带到决策视图与诊断 JSON —— 「为什么没选它」与「为什么选它」同等重要。

| `RejectCode`（`src/Enum/RejectCode.php`） | 含义 |
|---|---|
| `disabled` | 面板或配置已手动停用 |
| `suspect_trust` | 曾因完整性校验失败被降为 `Trust::Suspect`，默认不参与选路 |
| `scene_unsupported` | 该源不支持此资源场景（`Scene::bit` 位掩码比对） |
| `host_not_covered` | 该源不覆盖目标上游域名 |
| `scheme_mismatch` | `host_replace` 形态不覆盖 Release 落点域 |
| `too_big` | 超过该源或全局声明的单文件体积上限 |
| `ext_blocked` | 该源屏蔽此类扩展名（公益镜像常见挡 `exe/zip/apk`） |
| `no_range` | 客户端请求 Range 但该源未实测支持 Range |
| `redirect_loss` | Release 资产会把 302 原样回吐给客户端，等于不加速 |
| `no_api_support` | 该源不代理 `api.github.com` |
| `not_yet_probed` | 尚无实测能力位，不冒险承接（出厂 `caps` 全 false 就命中这档，可逐级放宽） |
| `polite_cooldown` | 未达该源的最小请求间隔 |
| `breaker_open` | 熔断 OPEN 且冷却未到 / HALF_OPEN 探测名额已满 |

保留源不足时按 `RejectCode::relaxationOrder()` 逐级放行：`not_yet_probed → polite_cooldown → breaker_open`，
每放宽一级都记进 `relaxed_flags`，让面板与 Agent 知道「这次是勉强凑出来的路由」而不是悄悄降级。

### L1 打分（4 因子 + UCB）

对数域线性 = 原域乘性，逐项归一化，输出 `breakdown`（面板可逐因子相加核对）。
默认权重见 `config.dist` `algo.weights`（不同场景不同，下为 `default`）：

| 因子 | 算法 | 实际公式 | 默认权重 |
|---|---|---|---|
| `f_p` 成功率 | Wilson score 下界 | `Success::rateForScoring`，`wilson_z` 默认 1.0（`raw`=0.84、`api_json`=1.28、`release_asset`=1.0） | 0.34 |
| `f_c` 预测耗时 | 调和归一 | `c_min / (c_min + c)`，`c = Latency::predictMs`（`ttfb_保守 + bytes/吞吐下限`） | 0.34 |
| `f_w` 人工先验 | 小范围防人压过实测 | `priorFactor`，priority 1–100 映射到 `algo.prior_weight_range` `[0.85, 1.15]`，再乘信任档位 `0.75 + 0.25·trust` | 0.20 |
| `f_b` 礼貌 / 负载 | 命中 `min_interval` 记 0.4，否则 1；小时字节超软帽按 `0.9^超量` 递减 | `Selector::politeFactor` | 0.12 |
| `u` 探索（UCB） | `min(1, √(ln N / n_i))`，权重 `algo.explore.ucb_c` | 确定性、无 RNG、无上界循环 | 0.15 |

不变式：`score = Σ(weight × value)`，`breakdown['sum_check']` 就是逐项相加，面板肉眼相加也成立。
冷启动配额：每合格源每小时至少 `cold_start_quota`（默认 3）次真实机会，全局探索预算 ≤
`budget_ratio`（默认 8%）。

### v1 刻意不做的事

- **不做 Thompson 采样**：PHP 无 Beta 采样器，手写 Marsaglia-Tsang 拒绝采样会给每请求加一条
  测不出来的长尾。改用确定性 UCB。
- **不做 ε-greedy-by-url-hash**：按 URL 哈希分流会让同一链接永久粘在坏源上 —— 用户现象是
  「这个 release 我下十次都失败，同事一次就成」。
- **在线路径不算分位数**：P85/P95 由 `src/Store/Compactor.php` **离线**重放时算好落成标量；
  40 源 × 场景 × 64 桶 ≈ 每请求反序列化上万个数字只为取两个分位数，纯浪费。
- **吞吐不进在线打分**，只作为耗时预测的分母。

### 熔断与失败分型

`CLOSED / OPEN / HALF_OPEN` 状态机在 `src/Routing/Breaker.php`。触发只统计硬故障
（`connect / timeout_ttfb / stall / http_5xx / tls_verify`，见 `FailureKind::countsForBreaker`）。
`FailureKind::weight()` 只影响打分与面板展示，**不进熔断计数**（否则一个用户请求超大文件就能把
新源判死）：`wrong_content` 权重 1.5、`integrity` 3.0 且 `trust` 降 `Suspect`、`oversize`/`client_abort`
权重 0。自适应冷却 `clamp(20s·1.9^(trips-1)·jitter(0.8,1.2), 8s, 900s)`，`trips` 每 2h 半衰
（`config.dist` `algo.breaker`）。

---

## 执行模式（`src/Enum/ExecMode.php` + `src/Execution/Dispatcher.php`）

| 模式 | 行为 | 何时触发 |
|---|---|---|
| `EDGE` | 命中本地完整缓存直出，零上游往返 | 条目存在且新鲜，且资源有缓存资格 |
| `REDIRECT` | **302 到最优镜像源 URL（不是 GitHub 上游）** | 体积 ≥ `algo.mode.redirect_min_bytes`（默认 50MB）且非必须流式 |
| `FAILOVER` | 本机流式转发 + 按 ranked 顺序回退 | **v1 默认** |
| `SPLIT` | `?part=i/of=n` 分片子接口 | 只对已完整缓存的条目开放 |

**REDIRECT 的关键洞察**：302 的目标是**镜像域名**而非 `github.com`。反过来若 302 到 GitHub，
国内客户端会自己跳回跨洋直连，加速当场失败、还泄露上游域名。目标是镜像源时，一处操作同时拿到
三个收益：本机过 0 带宽、不泄露上游域名、并且真的在加速。

`HEDGE`（多源竞速）在 v1 **明确未实现**：`?mode=hedge` 或 `chooseMode` 走到这里会抛
`mode_not_supported_in_v1`（400）。原因不是并发语义（`curl_multi` 是用户态单线程轮询，三种运行时都成立），
而是「响应头一旦发出即固化」与部署侧缓冲链；其收益可用 `connect_timeout=1.2~1.5s + REDIRECT + 顺序 FAILOVER`
以约 1/10 复杂度换到，而成本是多个源同时全量拉同一文件 —— 对反代是滥用放大器。枚举保留是为了接口稳定。

`serve()` 的优先级（`Dispatcher::serve`）：分片 → EDGE 命中 → stale 条件复验 → 模式判定（REDIRECT / FAILOVER）。
`ranked` 为空绝不静默直连 `github.com`，而是抛 `no_eligible_source`（503）并带上每个源的剔除原因码。

---

## 缓存与完整性（`src/Cache/*`、`src/Enum/IdentityKind.php`）

- **资格只由资源身份类型 `IdentityKind` 决定，不靠键前缀猜「看起来不可变」。**
  每条 meta 强制带 `identity_kind ∈ {commit_sha, asset_id, gist_rev, ref_name, mutable_api, ambiguous}`。
  只有前三类可 `immutable`、享长 TTL 与 EDGE 直出；`ref_name` / `ambiguous` 被 `maxTtl()` 死死压在
  120s / 60s；`mutable_api` 一律不 EDGE 缓存（`Scene::edgeCapable` / `Policy::mayCache`）。
- **`(tag, filename)` 当身份为什么是脏缓存**：同名 Release 资产被作者重传时 `asset_id` 会变而
  文件名不变。只有 `asset_id` 定位才稳定 —— 所以 `GitHubRef::canonical()` 让 asset_id 优先于文件名。
- **键里绝不含镜像域名**：`Key::of = sha256(GitHubRef::canonical())`。含域名会「每源一份、切源即换缓存」。
  也绝不直接哈希 URL 字符串（字符串归一化永远补不完）。
- **文件名一律 `<sha256>.bin`**，两级目录打散，永不含 `.php`、不含原始文件名任何片段（见 SECURITY）。
- **ETag 必须自造**：`Policy::etagFor` 产出 `"gha-<key16>-<variant>"`。透传源的 ETag 会在换源后让
  客户端永远拿不到 304。三层协商：客户端 `If-None-Match` vs 我们的缓存（命中即 304）→ stale 用存下来的
  `upstream_etag` 条件请求上游（304 只刷时间戳不重写文件）→ 客户端的 tag 绝不当作对上游的条件头。
- **淘汰不用纯 LRU**：`Policy::valueDensity = hits × freshness / bytes^0.6`（`cache.evict_alpha`）。
  一个 800MB 只下一次的资产重取要 20 分钟，一堆 2KB 的 API JSON 重取只要 0.3 秒，纯 LRU 会先踢前者，方向反了。
  水位：软 70% 后台淘汰 / 硬 85% 写前同步淘汰 / 95% 停写新缓存只命中。

---

## Range / 断点续传 / 分片

- **实测结论**：`codeload.github.com` 对 `Range: bytes=0-64` 返回 **200 全量 10.6MB，无视 Range**。
  所以我们**不假装它支持**：归档 `allowRange=false`，不注入 `Accept-Ranges`，客户端要 Range 而上游回
  200 时如实透传全量并标注 `X-GhAccel-Range: unsupported`。能力位一律**实测**，配置声称不等于实测。
- **绝不在服务端伪造 206 或做字节切片**；单 Range 原样透传并镜像上游状态码（206→206、200→200）；
  多 Range 的 `multipart/byteranges` 连 boundary 一起透传、不改 Content-Type；越界自判 416 +
  `Content-Range: bytes */{total}`。
- **Range 请求被限流也必须返 429**（`problem+json`）而不是 HTML 错误页 —— 否则 aria2 会把错误页当分片
  写进文件，产出静默损坏的产物。这是此类代理最恶名的失败模式，`Dispatcher::renderError` 对带 Range 的
  请求强制 `want_json`。
- **`?part=i/of=n` 只对已完整缓存的条目开放**（`Dispatcher::serveSplit`）：未缓存时回 **409
  `split_requires_cached`**。未缓存时分片等于把同一文件向源拉 N 次，打穿自家带宽、也让镜像把我们当滥用封掉
  （codeload 无视 Range 更放大此问题）。先不带 part 取一次整份，再分片并发。
- 断点续传：`_partial/{key}.part` 用连续前缀模型，`.part` 永不参与命中；`resume_count ≥ 3` 进
  `_quarantine`；写入一律 `.part` → 校验 `filesize == meta.bytes` → `rename` 原子落地。

**README 写死这条**：`?part=` 分片必须命中完整缓存，否则 409 —— 不写清楚第一周就会被 issue 淹没。

---

## 配置参考（键名与 `config/config.dist.php` 逐字一致）

改这里而不是改代码。`Config` 四级深度合并覆盖，后者胜：
`config/config.dist.php → config/config.php → config/config.local.php → var/state/overlay.json`。
最后一层（面板在线改动）只允许覆盖 `algo/cache/limits/budgets/panel/logging/routing` 白名单，
`security` 根基金线只能改配置文件。

### app
| 键 | 默认 | 作用 |
|---|---|---|
| `app.base_origin` | `''` | 同源基准，CSRF/Origin 严格等值比对，**绝不用 `$_SERVER['HTTP_HOST']`**；留空管理面写请求被拒 |
| `app.repo_url` / `app.contact` | `''` | 错误页与页脚展示 |
| `app.user_agent` | `GhAccel/1.0 (+https://github.com; contact=)` | 面向 GitHub 的匿名 UA |
| `app.exposure` | `private` | `public` 才注入 CORS 并放宽 EDGE |

### security
| 键 | 默认 | 作用 |
|---|---|---|
| `security.allowed_hosts` | github.com / api / codeload / raw / objects / gist / gist-raw / uploads / media | **精确 host 集合**，isset O(1)，无后缀匹配 |
| `security.denied_hosts` | private-user-images / cloud.githubusercontent.com | 明确拒绝，判定先于 allowed |
| `security.ip_resolve` | `v4` | 只解析 A 记录并锁 IPv4 出站 |
| `security.extra_deny_cidrs` | `[]` | 容器/K8s 加 Pod/Service CIDR |
| `security.max_redirect_hops` | `3` | 逐跳复校上限 |
| `security.require_user_agent` | `true` | 空 UA 拒绝 |
| `security.ua_block_patterns` | sqlmap/nikto/zgrab…python-requests/GPTBot… | 扫描器与爬虫 UA |
| `security.ua_allow_patterns` | `aria2/ curl/ wget/ IDMan Thunder Xunlei TP FlashGet` | 核心合法下载工具，allow 先于 block 判（防误杀） |
| `security.trusted_proxies` / `trust_proxy_headers` | `[]` / `false` | 开前必须同时填前者，否则 X-Forwarded-* 可伪造 |

### budgets（时间预算）
| 键 | 默认 | 作用 |
|---|---|---|
| `budgets.connect_timeout_ms` | 1500 | 冷启动体验里这一项比任何算法有效 |
| `budgets.ttfb_budget_ms` | 3000 | 首字节预算 |
| `budgets.stall_limit_bytes` / `stall_time_ms` | 1024 / 25000 | `LOW_SPEED_*`，掐死「连上但假活」 |
| `budgets.max_total_ms` | 12000 | 全链 failover 预算 |
| `budgets.failover_min_reserve_ms` | 250 | 剩余预算不足以再试一候选就把重试交回客户端 |

### algo
| 键 | 默认 | 作用 |
|---|---|---|
| `algo.ewma.tau_ttfb_s` / `tau_thr_s` | 90 / 180 | 时间衰减 EWMA 常数 |
| `algo.ewma.alpha_floor` / `thr_floor_kbps` / `min_obs_for_thr` | 0.15 / 20 / 3 | 样本太旧重初始化、防 ln(0) |
| `algo.region_prior` | cn_broadband/global_cdn/cn_mobile/overseas/unknown | 冷启动区域先验（仍是「猜」，面板须标注） |
| `algo.wilson_z` / `wilson_z_by_scene` | 1.0 / {api_json:1.28, release_asset:1.0, raw:0.84} | Wilson 下界置信 |
| `algo.breaker.*` | err_ratio_threshold 0.60, min_window_n 5, consec_fail_trip 3, probe_success_to_close 2, probe_max_inflight 1, cooldown_base_s 20, cooldown_gain 1.9, cooldown_min_s 8, cooldown_max_s 900, jitter [0.8,1.2], trip_halflife_s 7200 | 熔断三态与自适应冷却 |
| `algo.weights` | default{p.34,c.34,w.20,b.12}, api_json, raw, archive, release_asset | 打分权重（和不为 1 时归一化而非报错） |
| `algo.prior_weight_range` | `[0.85, 1.15]` | 人工先验只给小范围 |
| `algo.explore.ucb_c` / `cold_start_quota` / `cold_start_min_gap_s` / `budget_ratio` / `min_sample_for_rank` | 0.15 / 3 / 300 / 0.08 / 30 | 探索与冷启动 |
| `algo.mode.edge_min_bytes` / `redirect_min_bytes` / `split_default_of` / `split_max_of` / `top_k` | 0 / 52428800 / 8 / 16 / 4 | 分片阈值与模式选择 |

### cache
| 键 | 默认 | 作用 |
|---|---|---|
| `cache.enabled` | `true` | 总开关 |
| `cache.dir` | `var/cache` | 落盘目录 |
| `cache.max_bytes` | 10737418240 | 软上限（10 GiB） |
| `cache.soft_watermark` / `hard_watermark` / `stop_watermark` | 0.70 / 0.85 / 0.95 | 三级水位 |
| `cache.min_free_bytes` | 1073741824 | 磁盘剩余不足拒写 |
| `cache.max_entry_bytes` | 1073741824 | 单条最大，超了即使空间够也不落地 |
| `cache.ttl` | raw 120 / release_asset 1209600 / archive 600 / api_json 30 / gist_raw 3600 | 场景 fresh TTL（与 `IdentityKind::maxTtl()` 取小） |
| `cache.stale_while_revalidate_s` | 300 | |
| `cache.small_entry_inline_bytes` | 65536 | 小于此值 meta 与字节合并单文件，inode 减半 |
| `cache.partial_ttl_s` / `partial_max_resume` / `quarantine_ttl_s` / `evict_batch` / `evict_alpha` | 1800 / 3 / 86400 / 20 / 0.6 | 续传、隔离区、淘汰 |

### limits / routing / panel / logging / integrity
| 键 | 默认 | 作用 |
|---|---|---|
| `limits.per_request_bytes` | 536870912 | 单请求体积上限（超限在 WRITEFUNCTION 中止） |
| `limits.per_ip_hour_bytes` / `per_ip_day_bytes` | 2147483648 / 17179869184 | 字节配额 |
| `limits.max_concurrent` | 24 | lock-slot 数量（建议 pm.max_children × 0.8） |
| `limits.trusted_cidrs` | `[]` | 内网直连跳过限流 |
| `limits.buckets` | ip{cap120,rate20} panel{cap10,rate1} ipday{cap16384,rate0.2} login{cap5,rate0.0333} suspect_ua{cap3,rate0.0167} | 三桶令牌桶（MiB/请求数分单位） |
| `routing.enable_absolute_form` / `enable_gh_form` / `enable_query_form` | true/true/true | 三种入口开关 |
| `routing.alias` | raw/gh/release/latest/zip/tar/api | 短别名启停（`archive`/`gist` 代码里恒开） |
| `routing.max_url_len` / `max_query_len` | 4096 / 2048 | 长度上限 |
| `routing.autoref_resolve` | false | 分支名含斜杠时用 API matching-refs 消歧（耗配额、默认关） |
| `routing.stop_on_upstream_rate_limit` | true | 不可关闭，列出仅为文档化 |
| `panel.enabled` / `public_exposed` / `path_prefix` | true / false / `panel` | 面板默认不公网，前缀可随机化 |
| `panel.session_idle_s` / `session_abs_s` / `bind_ip_prefix_v4` / `bind_ip_prefix_v6` | 1800 / 43200 / 24 / 48 | 会话与 IP 前缀绑定 |
| `logging.dir` / `journal_dir` / `access_days` / `ref_display` / `level` | var/log / var/journal / 14 / `hash` / info | 隐私与保留期 |
| `integrity.enabled` / `require_for_release_from_low_trust` / `dual_source_cross_check` / `cross_check_max_bytes` / `head_hash_bytes` | true / true / false / 5242880 / 1048576 | 流式校验、双源默认关 |

`bin/selftest.php` 会打印 `Bootstrap::selfCheck()` 的 critical/warning，并逐条对照上表默认值体检。

---

## 部署路径

### 通用 nginx / Apache
见仓库根 [`.htaccess`](.htaccess) 与 [`deploy/nginx.example.conf`](deploy/nginx.example.conf)。
**必须改的 4 条**及其破坏后果：

- `merge_slashes off`（nginx）与 Apache 侧不折叠 `//`：否则绝对形式入口被折叠成 `/https:/`，路由对不上。
- `zlib.output_compression = Off`（php.ini）：**开启会让 Content-Length 与实际字节不符**，于是
  Range 切片、`?sha256=` 流式校验、aria2 断点续传三件事同时坏，症状分散极难归因到一个 ini 开关。
  `Bootstrap::selfCheck` 把它列为 critical。
- `fastcgi_buffering off` / `fastcgi_max_temp_file_size 0`（nginx）：缓冲会破坏边收边 flush 的零拷贝流式，
  也会让大文件在磁盘上被整块缓存。
- `fastcgi_param SCRIPT_FILENAME $document_root/index.php`（锁定只执行入口）+ `cgi.fix_pathinfo=0`：
  这是 **`var/cache` 被写入 webshell 的唯一硬防线** —— 它不依赖你记住每个新增子目录，比逐目录 `deny all` 更可靠。
  少了这条，一条路径解析差异就能让缓存目录里的上传物被当 PHP 执行。

### 宝塔面板
逐条清单见 [`deploy/bt-panel.md`](deploy/bt-panel.md)（含禁用函数、`open_basedir` 误区、计划任务运行用户等）。

### Docker（需自行构建，仓库不附镜像文件）
最小组合是 `php-fpm + nginx` 两个容器：nginx 侧套 `deploy/nginx.example.conf` 的四项改写；
php-fpm 镜像需装 `curl`/`openssl`/`hash`/`mbstring`/`intl`，并把 `var/**` 挂成本地卷、以站点用户身份跑
`bin/compact.php --once`。本仓库不生成 Dockerfile —— 网络、CA、卷与运行用户都高度依赖部署环境，
给一个通用 Dockerfile 反而会误导。运行前先 `php bin/selftest.php` 确认环境。

---

## 错误码表

由 `src/Errors/GhpError.php` 的 `CATALOG` 生成（`code / HTTP 状态 / 可重试 / 处置`）。

| code | HTTP | 可重试 | 处置建议 |
|---|---|---|---|
| `url_too_long` | 400 | 否 | 精简超长 query，或改用 `?u=` |
| `unparseable_url` | 400 | 否 | 确认加速前缀后是完整可解析的 GitHub URL |
| `backslash_in_url` | 400 | 否 | 反斜杠造成域名归属分歧，一律拒绝 |
| `userinfo_not_allowed` | 400 | 否 | 去掉 `user@host` 形式的凭据段 |
| `numeric_host_literal` | 400 | 否 | 十进制/八进制/十六进制整型 IP 写法会被拒 |
| `illegal_host_chars` | 400 | 否 | host 只允许 LDH |
| `path_traversal` | 400 | 否 | 路径不含 `.` / `..` 段 |
| `ambiguous_ref` | 400 | 否 | 分支名含斜杠时用 `refs/heads/xxx` 或绝对形式 |
| `unsupported_method` | 405 | 否 | 只读网关，仅 GET / HEAD（OPTIONS 由预检直接 204） |
| `mode_not_supported_in_v1` | 400 | 否 | hedge 在 v2；去掉 `mode=hedge` 用默认 failover |
| `host_not_allowed` | 403 | 否 | 只代理 GitHub 官方域名，安全边界不可放开 |
| `ip_denied` | 403 | 否 | 解析到内网/环回/链路本地/云元数据 |
| `scheme_not_allowed` | 403 | 否 | 只允许 https |
| `port_not_allowed` | 403 | 否 | 只允许 443 / 80 |
| `redirect_loop` | 403 | 否 | Location 指回本网关前缀 |
| `ua_required` | 403 | 否 | 必须携带 User-Agent |
| `ua_blocked` | 403 | 否 | 下载工具被误杀时把 UA 移出黑名单配置 |
| `split_requires_cached` | 409 | 是 | 先不带 part 取一次整份，再分片并发 |
| `rate_limited` | 429 | 是 | 按 Retry-After 等待，勿紧密循环 |
| `upstream_rate_limited` | 429 | 是 | 已停止换源继续刷 |
| `quota_exceeded` | 429 | 是 | 配额按小时/日补充，或改用自带 302 |
| `oversize` | 413 | 否 | 提高 `limits.per_request_bytes` 或配可信大文件源 |
| `integrity_mismatch` | 422 | 否 | 内容不符，已丢弃未入缓存，核对校验值来源 |
| `content_divergence` | 422 | 是 | 不同源内容不一致，宁可失败也不猜 |
| `upstream_not_found` | 404 | 否 | GitHub 返回 404，核对 owner/repo/ref/path 大小写 |
| `not_found` | 404 | 否 | 面板未登录时统一 404，不暴露「这里有面板」 |
| `unauthenticated` | 401 | 否 | 用 `bin/token.php` 签发的管理 Token 登录 |
| `csrf_failed` | 403 | 否 | 需带 X-CSRF-Token 且 Origin 与 `app.base_origin` 一致 |
| `scope_required` | 403 | 否 | 当前 Token 只读，签发带 write 的 |
| `confirm_required` | 428 | 否 | 破坏性操作需 `confirm:true` |
| `upstream_failed` | 502 | 是 | 所有源均未取回，看诊断 JSON 每源分型 |
| `redirect_too_many` | 502 | 是 | 正常最多 2 跳，超限说明上游改版需更新白名单 |
| `tls_verify_failed` | 502 | 是 | 该源证书/链异常，绝不关校验绕过 |
| `wrong_content` | 502 | 是 | 假 200 回了 HTML，按源侧故障处理未写缓存 |
| `ssrf_audit_mismatch` | 502 | 否 | 实际连接地址与校验不符（DNS 重绑定征兆），已中止 |
| `no_eligible_source` | 503 | 是 | 决策视图列出每源剔除码，按原因放开源或补配置 |
| `all_sources_tripped` | 503 | 是 | 全部源熔断，面板可手动复位或立即探活 |
| `overloaded` | 503 | 是 | 并发槽耗尽，不计入源健康度，稍后再试 |
| `upstream_timeout` | 504 | 是 | 整链预算耗尽，可提高 `budgets.max_total_ms` |

### Agent 集成
错误统一 `application/problem+json`，字段契约（`GhpError::toProblem`）：
`type` / `title` / `status` / `code` / `retryable` / `request_id`（必有），
`detail` / `hint` / `context`（有则给），`retry_after` + `next_action`（重试型才有）。
context 一律过 `scrub()`：不得泄露服务器路径、Token、真实上游最终地址与解析到的 IP。
可用性探测打 `GET /health`（免登录）：只回 `ok / php / critical[] / warnings[] / ts`，零敏感信息，
critical 非空时 503。带 `Accept: application/json`、`X-Requested-With`、`?json` 或带 Range 时强制 JSON。

---

## 隐私

一台公开 GitHub 反代事实上就是「哪些项目正在被国内下载」的时间序列，这是真实义务而非形式。

- 日志不存明文 IP：限流桶键 = `sha256(scope|clientKey|salt)` 派生（IPv6 含 `:` 在 Windows 文件系统直接炸，
  同时不把用户 IP 明文落盘）；审计里 IP 只留 `ipHash`，换 salt 即历史作废。
- ref 只存 16 位摘要（`Key::of(ref)` 截断），不落明文；`logging.ref_display = hash`。
- `logging.access_days` 默认 14 天（计划文档记 7–14）。
- 请求 body 只进 sha256，绝不明文（`Audit`）。

---

## 诚实的局限（不软化、不删）

1. **第三方公益镜像的可用性、内容正确性、是否会中间人篡改，本项目不承诺。** 无权威摘要时低信任源的
   二进制**不进缓存只转发**（`Policy::mayCache` + `Trust::mayEdgeWithoutDigest` 只有 `SelfHosted` 为 true），
   这是取舍不是漏实现。若你是会自动执行下载产物的 AI Agent，请传 `?sha256=`。
2. **冷启动期（样本 < `algo.explore.min_sample_for_rank`，默认 30）多因子打分实质退化为人工先验表**，
   这是此类系统的固有代价不是 bug；面板显式标注「冷启动中」，否则运维会误判算法坏了而乱改权重。
3. **公开开放需自行评估 GitHub ToS 与国内备案/内容合规**；交付定位为**私有 / 自用部署**。
4. **本机实测环境局限**：`api.github.com` 曾被管理规则拦成 403，API 场景只能验证「上游拒绝时的降级与
   不 failover 行为」，真实 JSON 透传需在可直连环境复测；本机无 php-fpm + nginx，`fastcgi_buffering`、
   `zlib.output_compression`、`merge_slashes` 三项必须在目标机复测。
5. **v1 未实现清单**（计划 §12）：HEDGE 竞速、在线分位数与直方图、IPv6 出站与隧道判定启用、
   未缓存条目的真分片、`?part=` 上游 Range 协商、HTTP/2 多路复用与 zstd/brotli 透传、
   Thompson/纪元化 rank 缓存、API JSON 的 EDGE 缓存、Prometheus `/metrics` 与告警、
   面板日志检索与配置全表单、多节点状态同步、Docker 与 CI/PHPUnit 套件、限时签名公开配额。
6. **owner/repo 级下架黑名单尚未接入执行点**：`bin/selftest.php takedown` 只落地
   `var/state/blocklist.json`，真正挡住请求还需接入口拒绝点与缓存反向索引（详见
   [`SECURITY.md`](SECURITY.md)「被投诉 / 被要求下架时怎么处置」）。这是当前明确的缺口，不假装功能已存在。

---

## CLI

```bash
php bin/selftest.php                 # 聚合 tests/*.php + Bootstrap::selfCheck + 端到端判定（默认不联网）
php bin/selftest.php --probe         # 额外对 config/sources.dist.php 的源各发一次 1.5s 超时探活
php bin/selftest.php takedown --repo=owner/repo   # 写 var/state/blocklist.json（见上「缺口」）
```

退出码：`0` 全通过；`1` 任一硬失败（测试失败 / selfCheck 有 critical / 端到端判定不符）。
缺失的测试文件（如 `tests/agent_c2_check.php`）会被 `is_readable` 优雅跳过并注明，不当作失败。

令牌签发 `bin/token.php`、压实 `bin/compact.php`、面板 `public/panel.php` 由并行交付提供，
本 README 不重复描述其未落地细节；`public/index.php` 首页与 `/health` 的行为以源码为准。

---

许可见 `LICENSE`（MIT，`Copyright (c) 2026 谶Hank`）。变更见 `CHANGELOG.md`，安全暴露面见 `SECURITY.md`。
