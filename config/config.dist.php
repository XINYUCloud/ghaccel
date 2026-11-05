<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 全部默认配置与逐项注释。这是算法参数的唯一来源, 改这里而不是改代码。
 *             复制为 config.php 后按需覆盖; config.local.php 与面板 overlay 依次再覆盖。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

return [

    'app' => [
        // 同源基准。CSRF/Origin 校验严格等值比这个值, 绝不用 $_SERVER['HTTP_HOST'],
        // 因为 Host 头可伪造, 宝塔直通 $http_host 且 server_name 宽松时会导致校验被绕过。
        'base_origin'        => '',
        'repo_url'           => '',
        'contact'            => '',
        // 面向 GitHub 的 UA 标识。匿名 API 有速率限制且要求可识别来源, 不伪装浏览器 UA。
        'user_agent'         => 'GhAccel/1.0 (+https://github.com; contact=)',
        // 部署定位: private 表示自用, 默认不公网开面板、EDGE 保守。
        'exposure'           => 'private',
    ],

    'security' => [
        // 精确 host 集合, isset O(1) 判定。v1 不做后缀匹配: GitHub 侧域名有限可枚举,
        // 而 endswith/str_contains 会被 github.com.evil.com 与 notgithub.com 双双绕过。
        // 漏掉 objects.githubusercontent.com 会让全部 Release 下载失败(302 落点)。
        'allowed_hosts' => [
            'github.com',
            'api.github.com',
            'codeload.github.com',
            'raw.githubusercontent.com',
            'objects.githubusercontent.com',
            'gist.github.com',
            'gist.githubusercontent.com',
            'uploads.github.com',
            'media.githubusercontent.com',
            // Release 资产的第二跳落点。漏掉它 = 每一次 Release 下载都在跟到这一跳时被
            // 自己的白名单判成 host_not_allowed, 症状是"源全绿但下载全 403"。
            'release-assets.githubusercontent.com',
        ],
        // 明确拒绝的 host: 带签名私有资源, 不该由公开代理取。判定顺序上 denied 先于
        // allowed 生效, 这样即使有人误把通配加进 allowed 也挡得住。
        'denied_hosts' => [
            'private-user-images.githubusercontent.com',
            'cloud.githubusercontent.com',
        ],
        // 只解析 A 记录并锁 IPv4 出站。一条 IPRESOLVE_V4 消灭 6to4/Teredo/NAT64/
        // v4-mapped 整条隧道绕过链, 代价是不支持 v6-only 镜像(GitHub 都有 A 记录)。
        'ip_resolve'         => 'v4',
        'extra_deny_cidrs'   => [],   // 容器/K8s 部署时把 Pod CIDR 与 Service CIDR 加进来
        'max_redirect_hops'  => 3,    // 真实链路最长 2 跳, 3 已含冗余
        'require_user_agent' => true,
        // 空 UA 与扫描器一律拒。但 aria2/curl/wget/IDMan/迅雷是本项目核心合法用户,
        // 误杀它们等于把最有价值的流量挡在门外, 所以黑名单可配且不硬编码。
        'ua_block_patterns'  => [
            'sqlmap', 'nikto', 'zgrab', 'masscan', 'nmap', 'nuclei', 'httpx',
            'dirbuster', 'wpscan', 'havij', 'acunetix', 'nessus',
            'python-requests', 'aiohttp', 'go-http-client', 'okhttp', 'scrapy',
            'GPTBot', 'ClaudeBot', 'Bytespider', 'PetalBot', 'AhrefsBot',
            'SemrushBot', 'MJ12bot', 'DataForSeoBot', 'anthropic-ai',
        ],
        'ua_allow_patterns'  => ['aria2/', 'curl/', 'wget/', 'IDMan', 'Thunder', 'Xunlei', 'TP', 'FlashGet'],
        // 允许 302 直出的前提是目标为镜像源而非 GitHub 上游。若配成允许直出到 GitHub,
        // 国内客户端会自己跳回跨洋直连, 加速彻底失败。此项在代码里不作为开关提供。
        'trusted_proxies'    => [],
        'trust_proxy_headers'=> false, // 开启前必须同时填 trusted_proxies, 否则 X-Forwarded-* 可伪造
    ],

    'budgets' => [
        'connect_timeout_ms'   => 1500, // 冷启动体验里, 这一项比任何算法都有效
        'ttfb_budget_ms'       => 3000,
        'stall_limit_bytes'    => 1024, // LOW_SPEED_LIMIT
        'stall_time_ms'        => 25000,// LOW_SPEED_TIME: 掐死"连上了但假活"的连接
        'max_total_ms'         => 12000,// failover 全链时间预算, 防 3 个源各超时 10s 把客户端吊死
        'failover_min_reserve_ms'=> 250,// 剩余预算不足以跑下一个候选就不再试, 把重试留给客户端
    ],

    'algo' => [
        'ewma' => [
            'tau_ttfb_s'    => 90,    // 3 分钟前的样本权重降到 e^-2, 源下线几天后不该背历史
            'tau_thr_s'     => 180,
            'alpha_floor'   => 0.15,  // 样本太旧直接丢弃旧值用新样本重新初始化
            'thr_floor_kbps'=> 20,     // 防 ln(0)
            'min_obs_for_thr' => 3,
        ],
        // 冷启动区域先验。新源不从零瞎猜, 但注意这仍是"猜", 面板必须标注冷启动中。
        'region_prior' => [
            'cn_broadband' => ['ttfb_ms' => 400.0, 'thr_bps' => 2097152.0],
            'global_cdn'   => ['ttfb_ms' => 250.0, 'thr_bps' => 4194304.0],
            'cn_mobile'    => ['ttfb_ms' => 600.0, 'thr_bps' => 1258291.0],
            'overseas'     => ['ttfb_ms' => 900.0, 'thr_bps' => 838860.0],
            'unknown'      => ['ttfb_ms' => 800.0, 'thr_bps' => 1048576.0],
        ],
        // Wilson 下界。比"Beta 后验 + 正态近似"少写一个函数, 且专为小样本设计:
        // 后者在 n<20 时可能算出负数被 clamp 成 0, 于是所有低样本源同分, 排序彻底失效。
        'wilson_z' => 1.0,
        'wilson_z_by_scene' => ['api_json' => 1.28, 'release_asset' => 1.0, 'raw' => 0.84],

        'breaker' => [
            'err_ratio_threshold' => 0.60,
            'min_window_n'        => 5,
            'consec_fail_trip'    => 3,
            'probe_success_to_close' => 2,   // HALF_OPEN 需连续 2 次合格
            'probe_max_inflight'  => 1,      // HALF_OPEN 同时只放 1 个探测
            'cooldown_base_s'     => 20,
            'cooldown_gain'       => 1.9,    // 每次 trip 指数增长
            'cooldown_min_s'      => 8,
            'cooldown_max_s'      => 900,
            'jitter'              => [0.8, 1.2],  // 防同批熔断源同步恢复造成惊群
            'trip_halflife_s'     => 7200,   // trip_count 半衰, 坏了一周的源不该一回来就 15 分钟冷却
            'slo_ttfb_ms'         => ['api_json' => 1200, 'raw' => 1500, 'archive' => 2500, 'release_asset' => 3000],
            // HALF_OPEN 恢复还要求 TTFB 达标, 不是"1 次成功就放开门"
            'release_ttfb_factor' => 1.5,
        ],

        // 打分只有 4 个因子。评审结论: 原本设想的长尾风险/区域亲和/信任/吞吐第二路,
        // 在样本稀少时全部退化成常数, 在样本充足时与 TTFB 高度共线 —— 加了不改变排序,
        // 只增加调试面积。
        'weights' => [
            'default'       => ['p' => 0.34, 'c' => 0.34, 'w' => 0.20, 'b' => 0.12],
            'api_json'      => ['p' => 0.32, 'c' => 0.20, 'w' => 0.26, 'b' => 0.22],
            'raw'           => ['p' => 0.32, 'c' => 0.36, 'w' => 0.20, 'b' => 0.12],
            'archive'       => ['p' => 0.36, 'c' => 0.40, 'w' => 0.16, 'b' => 0.08],
            'release_asset' => ['p' => 0.36, 'c' => 0.40, 'w' => 0.16, 'b' => 0.08],
        ],
        'prior_weight_range' => [0.85, 1.15],  // 人工先验只给小范围加分, 防止人压过实测

        'explore' => [
            'ucb_c'          => 0.15,  // 确定性 UCB, 不用 Thompson: PHP 无 Beta 采样器,
                                       // 手写拒绝采样会给每请求加一条测不出来的长尾
            'cold_start_quota' => 3,   // 每合格源每小时至少 3 次真实机会
            'cold_start_min_gap_s' => 300,
            'budget_ratio'   => 0.08,  // 全局最多 8% 流量用于探索
            'min_sample_for_rank' => 30, // 低于此值面板显示"冷启动中, 实质按人工先验"
        ],

        // 分片(客户端并发)阈值与模式选择
        'mode' => [
            'edge_min_bytes'      => 0,
            'redirect_min_bytes'  => 52428800, // >=50MB 不当数据管道, 302 到最优镜像源
            'split_default_of'    => 8,
            'split_max_of'        => 16,
            'top_k'               => 4,
        ],
    ],

    'cache' => [
        'enabled'        => true,
        'dir'            => 'var/cache',
        'max_bytes'      => 10737418240,  // 10 GiB 软上限
        'soft_watermark' => 0.70,         // 后台淘汰
        'hard_watermark' => 0.85,         // 写前同步淘汰一批
        'stop_watermark' => 0.95,         // 停写新缓存, 只服务命中
        'min_free_bytes' => 1073741824,   // 磁盘剩余不足直接拒绝写入(宁可慢不可炸盘)
        // 单条可缓存的最大体积。超过它即使空间够也不落地, 因为一次中断就白占满水位。
        'max_entry_bytes'=> 1073741824,
        // 分场景 fresh TTL(秒), 再与 IdentityKind::maxTtl() 取小。
        // sha 级 raw 与 asset_id 级 Release 是不可变的, 命中即绝对正确, 给最长。
        'ttl' => [
            'raw'           => 120,
            'release_asset' => 1209600,
            'archive'       => 600,
            'api_json'      => 30,
            'gist_raw'      => 3600,
        ],
        'stale_while_revalidate_s' => 300,
        'small_entry_inline_bytes' => 65536,  // 小于此值 meta 与字节合并成单文件, inode 减半
        'partial_ttl_s'   => 1800,
        'partial_max_resume' => 3,
        'quarantine_ttl_s'   => 86400,
        'evict_batch'     => 20,
        // 淘汰不用纯 LRU: 一个 800MB 只下载一次的资产重取要 20 分钟, 一堆 2KB 的 API
        // JSON 重取只要 0.3 秒, LRU 会先踢前者, 方向完全反了。
        'evict_alpha'     => 0.6,   // score = hits * freshness / bytes^alpha
    ],

    'limits' => [
        'per_request_bytes'  => 536870912,   // 512 MiB。超限在 WRITEFUNCTION 里中止
        'per_ip_hour_bytes'  => 2147483648,
        'per_ip_day_bytes'   => 17179869184,
        'max_concurrent'     => 24,          // lock-slot 数量, 建议 pm.max_children * 0.8
        'trusted_cidrs'      => [],          // 自用/内网直连场景跳过限流
        'salt_rotate_at'     => 0,
        'buckets' => [
            // 请求数桶要宽: 校园网/企业 NAT 后几百人共用一个出口 IP, 桶窄会让正常用户
            // 被邻居的 aria2 连坐。字节配额走很宽的 ipday 桶。
            'ip'         => ['cap' => 120.0, 'rate' => 20.0],
            'panel'      => ['cap' => 10.0,  'rate' => 1.0],   // 数据面与管理面必须分桶
            'ipday'      => ['cap' => 16384.0, 'rate' => 0.2], // 单位 MiB
            'login'      => ['cap' => 5.0,   'rate' => 0.0333],
            'suspect_ua' => ['cap' => 3.0,   'rate' => 0.0167],
        ],
    ],

    'routing' => [
        // 三种等价 URL 形式。把 /https:// 当唯一入口是设计错误: nginx merge_slashes、
        // 云 CDN 与宝塔加速插件都会折叠 //, 一折叠路由就全灭。
        'enable_absolute_form' => true,
        'enable_gh_form'       => true,
        'enable_query_form'    => true,
        'alias' => [
            'raw' => 'raw/{owner}/{repo}/{ref}/{path}',
            'gh'  => 'gh/{owner}/{repo}@{ref}/{path}',
            'release'  => 'release/{owner}/{repo}/{tag}/{asset}',
            'latest'   => 'latest/{owner}/{repo}/{asset}',
            'zip'      => 'zip/{owner}/{repo}/{ref}',
            'tar'      => 'tar/{owner}/{repo}/{ref}',
            'api'      => 'api/{endpoint}',
        ],
        'max_url_len'   => 4096,
        'max_query_len' => 2048,
        // 分支名含 / 时用 API matching-refs 消歧。默认关: 消耗配额, 且本机实测 API 常被拦。
        'autoref_resolve'=> false,
        // API 回 403 rate-limit 时必须停止, 不得换源继续刷 —— 否则等于把 GitHub 的限速
        // 信号变成"换个镜像接着刷", 很快全源被封。此项不可关闭, 列出仅为文档化。
        'stop_on_upstream_rate_limit' => true,
    ],

    'panel' => [
        'enabled'          => true,
        // 默认不公网。前缀可随机化, /panel /admin /ui /stats 都在扫描字典里。
        'public_exposed'   => false,
        'path_prefix'      => 'panel',
        'session_idle_s'   => 1800,
        'session_abs_s'    => 43200,
        'bind_ip_prefix_v4'=> 24,   // 绑 IP 前缀而非全 IP, 否则移动网络换 IP 就掉线
        'bind_ip_prefix_v6'=> 48,
        'poll_ms'          => ['summary' => 5000, 'timeseries' => 10000, 'mirrors' => 10000, 'cache' => 15000],
        'audit_enabled'    => true,
    ],

    'logging' => [
        'dir'             => 'var/log',
        'journal_dir'     => 'var/journal',
        'access_days'     => 14,    // 一台公开 GitHub 反代事实上是"哪些项目正在被国内下载"
        'ref_display'     => 'hash',// 日志默认不存明文 ref, 面板原始视图需要 write 作用域
        'compact'         => ['trigger_lines' => 200, 'trigger_age_s' => 15, 'prob_divisor' => 200],
        'level'           => 'info',
    ],

    'integrity' => [
        'enabled'          => true,
        // 客户端传 ?sha256= 时流式增量校验, 不符则丢弃且不进缓存。
        'require_for_release_from_low_trust' => true,
        'dual_source_cross_check' => false,  // 默认关: 每次 2 倍上游流量, 本身也是流量放大器
        'cross_check_max_bytes'   => 5242880,
        'head_hash_bytes'         => 1048576, // .part 续传时校验前缀未被改动
    ],
];
