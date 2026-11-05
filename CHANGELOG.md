# 更新日志

本项目版本号取 `src/Bootstrap.php` 的 `Bootstrap::VERSION`。遵循 Keep a Changelog 的格式思路与语义化版本，
但只记录真实落进代码的变化。

## 1.0.0 — 2026-11-05

首个可交付版本。定位为**私有 / 自用部署**的 GitHub 访问 / 下载加速网关，零 Composer 运行时依赖，
PHP 8.1 下限，可直投宝塔。

### 新增

- **入口与表面分发**（`public/index.php`）：单一 HTTP 入口，只做「捕获 → 定表面 → 闸门 → 解析 → 投递 →
  收尾」六步；`home / health / panel / assets / proxy` 五个互斥表面，绝不由 URI 推文件路径。
- **三种等价 URL 入口形式 + 短别名**（`src/Ref/RefParser.php`）：绝对形式、`/gh/{o}/{r}@{ref}/{path}`、
  `?u=`，外加 `raw / release / latest / zip / tar / archive / api / gist` 别名。为「`//` 会被
  merge_slashes / CDN / 宝塔加速插件折叠」而刻意冗余。`blob→raw`、`tree→contents` 位置限定改写。
- **四场景上游重写**（`src/Ref/UpstreamMap.php`）：raw / Release 资产（302 落点到带一次性签名的
  objects / release-assets）/ 归档（走 archive，实测 codeload 无视 Range）/ api JSON / gist；
  `releases/latest` 免 API 反解 tag；`requiredHosts()` 与 `missingAllowedHosts()` 暴露白名单缺口给自检。
- **SSRF 判定链**（`src/Security/UrlGuard.php`、`IpRange.php`）：15 步顺序即防线，精确 host 集合、
  纯 LDH、只解析 A 记录、`CURLOPT_RESOLVE` 钉 IP + `IPRESOLVE_V4`、逐跳复校、`CURLINFO_PRIMARY_IP` 事后比对；
  v4 位运算段表 + v6 隧道递归解封装，全 fail-closed。
- **多重加速算法**（`src/Routing/*`）：L0 硬布尔筛（带 `RejectCode` 一路传到决策视图）→ 4 因子打分
  （Wilson 下界 / 预测耗时调和归一 / 人工先验小权重 / 礼貌惩罚）→ 确定性 UCB 探索 + 冷启动配额。
  v1 刻意不做 Thompson、不做 ε-greedy-by-url-hash、在线不算分位数。
- **执行模式**（`src/Enum/ExecMode.php`、`src/Execution/Dispatcher.php`、`Failover.php`）：
  EDGE / REDIRECT（302 到镜像源而非 GitHub 上游）/ FAILOVER / SPLIT；HEDGE 返回 `mode_not_supported_in_v1`。
  上游 403 / 429 绝不换源继续刷。
- **两阶段零拷贝流式**（`src/Transport/Streamer.php`、`Headers.php`）：Phase R 用 `Range: bytes=0-0` 的 GET
  实测能力位与最终地址（一字节不给客户端），Phase S 先发表头再 `WRITEFUNCTION → php://output` 边收边 flush；
  512 字节嗅探门判假 200、字节上限、客户端断连只用 fwrite 短写判定。头走白名单透传、ETag 自造。
- **缓存与完整性**（`src/Cache/*`）：键 = `sha256(canonical())` 不含镜像域名，文件名 `<sha256>.bin`；
  资格只由 `IdentityKind` 决定；三层 ETag 协商；价值密度淘汰（非纯 LRU）+ 三级水位；`.part` 连续前缀续传 +
  隔离区；`?sha256=` 常数内存流式校验。
- **状态存储**（`src/Store/*`）：版本化文件名 JSON 快照 + 纯文本指针（不用 `var_export` PHP 文件，规避
  CLI / FPM 不共享 OPcache 的坑）；观测单行 NDJSON 追加（每请求 1 次、不 fsync）；`LOCK_EX|LOCK_NB`
  抢不到即放弃的单写者压实器，分位数离线算好落标量。
- **限流 / 并发 / 管理面身份**（`src/Security/RateLimiter.php`、`Slots.php`、`Auth.php`、`Audit.php`）：
  三桶令牌桶（键 sha256 派生、不落明文 IP）、lock-slot 并发槽（不用计数器文件）、
  selector/verifier 双段 Token（快哈希 + 桶限流，故意不用 bcrypt）、自管 session、CSRF/Origin/Sec-Fetch-Site
  链（基准取 `app.base_origin` 而非 `HTTP_HOST`）、写接口全量审计。
- **结构化错误**（`src/Errors/GhpError.php`）：全部 `GHP_*` 码与 `application/problem+json` 载荷，
  三态渲染（Agent / 浏览器 / 纯文本），Range 请求被限流强制 JSON。
- **配置出厂**（`config/config.dist.php`、`config/sources.dist.php`）：逐项注释的算法 / 限流 / 缓存 / 安全默认值，
  与含形态建模（prefix_full / prefix_path / host_replace / template）和 priority 梯度的出厂源表。
- **部署交付物与 CLI**：`README.md`、`SECURITY.md`、`CHANGELOG.md`、`.htaccess`、
  `deploy/nginx.example.conf`、`deploy/bt-panel.md`、`config/config.example.php`、
  `bin/selftest.php`（聚合测试 + 部署体检 + 端到端判定 + `takedown` + `--probe`）。

### 已知缺口（v1 如实标注，未假装已实现）

- HEDGE 竞速、在线分位数、IPv6 出站与隧道判定启用、未缓存条目真分片、API JSON 的 EDGE 缓存等，推迟到 v2
  （见 README「诚实的局限」与计划 §12）。
- **owner/repo 级下架黑名单尚未接入执行点**：`bin/selftest.php takedown` 只落地 `var/state/blocklist.json`，
  真正挡住请求还需「入口拒绝点」与「缓存反向索引」两处接入（见 SECURITY「被投诉 / 下架」）。
- `integrity.dual_source_cross_check` 与错误码 `content_divergence` 已定义但未接线，双源交叉校验属未落地项。
- `config/config.dist.php` 的 `security.allowed_hosts` 出厂缺 `release-assets.githubusercontent.com`，
  需按 `config.example.php` 覆盖或补进 dist，否则 Release 落点这一跳会被挡。
- `security.forward_client_token`、`algo.l0_require_probed`、`algo.mode.top_k_agent`、
  `limits.bucket_salt`、`panel.csrf_secret`、`security.max_url_len` 等键由代码按默认值读取，
  未写进 `config.dist.php`（配置表里如需调整需自行补全）。

> 并行交付中的 `bin/token.php`、`bin/compact.php`、`public/panel.php`、`src/Panel/*`、
> `public/panel/assets/*`、`tests/agent_c2_check.php` 不在本版本文件集内，未就绪时 `bin/selftest.php`
> 会以 `is_readable` 优雅跳过。
