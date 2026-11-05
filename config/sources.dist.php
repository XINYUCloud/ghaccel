<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 出厂源表与人工先验梯度。冷启动期(n < min_sample_for_rank)多因子打分实质
 *             就靠这张表, 它比任何算法都有效 —— 所以 priority 的阶梯是认真排的。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

/**
 * ============================ 必读免责 ============================
 * 1. 这里列出的是"国内社区长期已知的公共反代形态", 不是可用性承诺。第三方公益镜像随时
 *    可能改规则、限流、关站, 甚至换拼接方式。部署者上线后必须用面板「一键探活」逐源
 *    复测, 本项目不承诺任何第三方镜像的可用性与内容正确性。
 *
 * 2. 三种拼接形态(prefix_full / prefix_path / host_replace)都给了例子, 因为它们拼错就
 *    是 404, 而 404 在选路里只表现为"这个源成功率低", 极难排查。给三类例子的目的正是
 *    让部署者知道自己配的到底是哪一类。url_template 形态另给一个自建例子。
 *
 * 3. caps 里的 range / follows_redirect_internally / json_api_ok 一律先写 false, 并且
 *    代码里只承认"探测实测"的值 —— 配置声称不等于实测。本机实测就是证据: codeload 声称
 *    支持 Range, 却对 `bytes=0-64` 返回 200 全量。把 true 写进配置不会产生任何加速效果,
 *    只会让选路在没被实测纠正之前一直相信一个谎言。
 *
 *    未实测的源在 L0 命中 RejectCode::NotYetProbed(可逐级放宽的那一档), 所以出厂全 false
 *    不会让第一个请求就 503; 但一旦被实测证伪, 该源会被硬性挡在对应场景之外。
 *
 * 4. priority 是 1-100 的人工先验, 只映射到 algo.prior_weight_range 的 [0.85, 1.15] 这个
 *    小区间(故意只给小权重, 防人压过实测)。梯度含义:
 *      90+ 自建(可控、可信、可长期依赖)
 *      70-89 社区长期已知、近半年活跃、支持完整原始 URL 形态
 *      50-69 社区已知但规则多变, 或只覆盖部分域名
 *      30-49 区域性/临时性镜像, 只适合当兜底
 *      <30   不指望它活, 只用于增加冗余
 *    ======================= 必读免责结束 =======================
 */

return [
    'schema' => 1,
    'updated_at' => '2026-11-05',

    // defaults 会被 SourceRepo 浅合并进每一条源, 目的是避免 20 遍同样的 timeout。
    // 注意是"浅合并": 同名字段整条替换, 所以某源要改 hosts 时必须写完整的 hosts 列表。
    'defaults' => [
        'enabled' => true,
        'trust' => 'community',
        'region' => 'cn_broadband',
        'connect_timeout_ms' => 1500,
        'ttfb_budget_ms' => 3000,
        'stall_timeout_ms' => 25000,
        'max_size_bytes' => 0,          // 0 = 沿用 limits.per_request_bytes
        'blocked_ext' => [],
        // 公益镜像普遍按 IP 限流。间隔太小会被对端封, 最后用户只会怪本网关。
        'min_interval_ms' => 150,
        'max_concurrent' => 4,
        'hourly_bytes_soft_cap' => 2147483648,  // 2 GiB/小时, 超了打分打折而不熔断
        // 能力位: 全部 false = "未实测"。见文件头第 3 条。
        'caps' => [
            'range' => false,
            'follows_redirect_internally' => false,
            'json_api_ok' => false,
        ],
    ],

    'sources' => [
        // ------------------------------------------------------------------
        // 自建: 唯一可以完全信任的档位(自己的 Worker / Nginx / 内网代理)。
        // 这条默认停用, 因为绝大多数部署者还没有自己的源; 打开前请把 base_url 改掉。
        // ------------------------------------------------------------------
        [
            'id' => 'self-template',
            'base_url' => 'https://worker.example.com',
            'mode' => 'template',
            'url_template' => 'https://worker.example.com/proxy/{url}',
            'enabled' => false,
            'trust' => 'self',
            'priority' => 95,
            'scenes' => ['raw', 'release_asset', 'archive', 'api_json', 'gist_raw'],
            'hosts' => [
                'github.com',
                'raw.githubusercontent.com',
                'codeload.github.com',
                'objects.githubusercontent.com',
                'api.github.com',
                'gist.github.com',
                'gist.githubusercontent.com',
                'uploads.github.com',
            ],
            'min_interval_ms' => 0,
            'max_concurrent' => 16,
            'hourly_bytes_soft_cap' => 0,   // 自建源不受公益镜像那种 courtesy 限制
            'region' => 'cn_broadband',
            'owner_note' => '自建源示例: 部署者自己的 Worker/Nginx。必须改成真实域名并把 enabled 置 true, 否则保持停用。',
        ],

        // ------------------------------------------------------------------
        // prefix_full: {base}/https://github.com/... 经典 ghproxy 形态, 覆盖面最广。
        // 国内社区已知且长期在跑的域名; 三者都只是"形态示例", 可用性需自行复测。
        // ------------------------------------------------------------------
        [
            'id' => 'ghfast',
            'base_url' => 'https://ghfast.top',
            'mode' => 'prefix_full',
            'priority' => 78,
            'scenes' => ['raw', 'release_asset', 'archive', 'gist_raw'],
            'hosts' => [
                'github.com',
                'raw.githubusercontent.com',
                'codeload.github.com',
                'objects.githubusercontent.com',
                'gist.github.com',
                'gist.githubusercontent.com',
            ],
            'region' => 'cn_broadband',
            'owner_note' => '社区长期已知的公共反代(prefix_full 形态示例)。计划 §1 的本机实测里它对 api.github.com 与上游同判 403, 因此这里不含 api_json 场景; 可用性与内容正确性需部署者上线后用面板一键探活自行复测, 本项目不承诺。',
        ],
        [
            'id' => 'gh-proxy',
            'base_url' => 'https://gh-proxy.com',
            'mode' => 'prefix_full',
            'priority' => 70,
            'scenes' => ['raw', 'release_asset', 'archive', 'gist_raw'],
            'hosts' => [
                'github.com',
                'raw.githubusercontent.com',
                'codeload.github.com',
                'objects.githubusercontent.com',
                'gist.github.com',
                'gist.githubusercontent.com',
            ],
            'region' => 'cn_broadband',
            'owner_note' => '同类公共反代(prefix_full 形态示例)。此类项目的体积上限与扩展名策略改动频繁, 上线后必须复测; 本项目不承诺其可用性与内容正确性。',
        ],
        [
            'id' => 'ghproxy-net',
            'base_url' => 'https://ghproxy.net',
            'mode' => 'prefix_full',
            'priority' => 62,
            'scenes' => ['raw', 'release_asset', 'archive', 'gist_raw'],
            'hosts' => [
                'github.com',
                'raw.githubusercontent.com',
                'codeload.github.com',
                'objects.githubusercontent.com',
            ],
            // 常见策略: 挡可执行与安装包。真实屏蔽列表必须由探活确认, 这里只是保守示例。
            'blocked_ext' => ['exe', 'apk', 'iso'],
            'region' => 'cn_broadband',
            'owner_note' => '社区已知反代(prefix_full 形态示例), 历史上对可执行类文件有屏蔽策略。blocked_ext 是保守示例值, 必须探活实测后调整; 不承诺可用性。',
        ],

        // ------------------------------------------------------------------
        // prefix_path: {base}/github.com/owner/repo/... (去掉协议头)。
        // 与 prefix_full 互不兼容: 用错形态就是 404, 而且 404 会被算成源的低成功率,
        // 排查成本极高 —— 所以这个形态必须单独有一个例子。
        // ------------------------------------------------------------------
        [
            'id' => 'path-form-demo',
            'base_url' => 'https://gh-proxy.example.org',
            'mode' => 'prefix_path',
            'priority' => 52,
            'enabled' => false,
            'scenes' => ['raw', 'archive', 'gist_raw'],
            'hosts' => [
                'github.com',
                'raw.githubusercontent.com',
                'codeload.github.com',
            ],
            'region' => 'cn_broadband',
            'owner_note' => 'prefix_path 形态的占位示例(域名是示例, 默认停用)。用途是让部署者看清"去协议头"这种拼法与 prefix_full 不可互换; 填自己确认可用的域名后再启用。',
        ],

        // ------------------------------------------------------------------
        // host_replace: 把 github.com 换成镜像域名, 路径原样。
        // 关键短板: 对 Release 的 302(落到 objects.githubusercontent.com)通常不覆盖,
        // 而且兄弟域(raw/codeload)各有各的镜像域名, 不能靠一条替换搞定。
        // ------------------------------------------------------------------
        [
            'id' => 'host-replace-demo',
            'base_url' => 'https://github.example-mirror.net',
            'mode' => 'host_replace',
            'priority' => 46,
            'enabled' => false,
            'scenes' => ['raw', 'release_asset', 'archive'],
            'hosts' => ['github.com'],
            'region' => 'cn_broadband',
            'owner_note' => 'host_replace 形态的占位示例(域名是示例, 默认停用)。这类镜像一般只代理 github.com 本体: 选路会因 coversHost 与 SchemeMismatch 自动把它挡在 raw/codeload 之外, 这正是形态建模的意义。必须换成真实可用域名后启用, 本项目不承诺任何第三方镜像。',
        ],
        [
            'id' => 'raw-mirror',
            'base_url' => 'https://raw.example-mirror.net',
            'mode' => 'host_replace',
            'priority' => 40,
            'enabled' => false,
            'scenes' => ['raw'],
            'hosts' => ['raw.githubusercontent.com'],
            'owner_note' => '兄弟域专用镜像的示例(默认停用): 有些社区镜像只替换 raw.githubusercontent.com。填真实域名后启用, 需自行复测。',
        ],

        // ------------------------------------------------------------------
        // 冗余兜底: 不指望它活, 只是多一条线路降低"全站同时挂"的概率。
        // ------------------------------------------------------------------
        [
            'id' => 'ghgo',
            'base_url' => 'https://ghgo.xyz',
            'mode' => 'prefix_full',
            'priority' => 34,
            'scenes' => ['raw', 'release_asset', 'archive'],
            'hosts' => [
                'github.com',
                'raw.githubusercontent.com',
                'codeload.github.com',
            ],
            'min_interval_ms' => 400,
            'hourly_bytes_soft_cap' => 536870912,  // 512 MiB
            'region' => 'cn_broadband',
            'owner_note' => '社区偶发可用的兜底镜像(prefix_full 形态)。间隔与小时帽都设得很保守: 它的容量小, 打穿它对谁都没好处。不承诺可用性。',
        ],

        // ------------------------------------------------------------------
        // API 场景单独一条: 公共镜像多数不代理 api.github.com, 而本机实测(计划 §1)也证实
        // ghfast 对 API 与上游同判 403。所以 API 只在自建源上才是可信路径。
        // json_api_ok 仍然必须是实测出来的 true, 这里不写 true 是因为没人替它保证。
        // ------------------------------------------------------------------
        [
            'id' => 'api-fallback',
            'base_url' => 'https://api.example-mirror.net',
            'mode' => 'prefix_full',
            'priority' => 28,
            'enabled' => false,
            'scenes' => ['api_json'],
            'hosts' => ['api.github.com'],
            'min_interval_ms' => 1000,
            'region' => 'cn_broadband',
            'owner_note' => 'API 代理占位示例(默认停用)。注意: 上游回 403 rate-limit 时选路与回退链必须停止, 不得换源硬刷, 否则很快全源同时被封。填真实域名后启用并实测 json_api_ok。',
        ],

        // ------------------------------------------------------------------
        // github.com 直连: 默认停用, 且代码在任何情况下都不会"静默直连"它 ——
        // 只有部署者显式把它当一条源启用时才会参与选路(给海外机器与开发环境用)。
        // ------------------------------------------------------------------
        [
            'id' => 'github-direct',
            'base_url' => 'https://github.com',
            'mode' => 'template',
            'url_template' => '{url}',
            'priority' => 12,
            'enabled' => false,
            'trust' => 'unknown',
            'scenes' => ['raw', 'release_asset', 'archive', 'api_json', 'gist_raw'],
            'hosts' => [
                'github.com',
                'raw.githubusercontent.com',
                'codeload.github.com',
                'objects.githubusercontent.com',
                'api.github.com',
                'gist.github.com',
                'gist.githubusercontent.com',
            ],
            'min_interval_ms' => 0,
            'owner_note' => '直连兜底(默认停用)。启用它意味着本机不再加速, 只是把本网关当纯透传用; 校园网/有直连条件的开发机才会需要。所有源被 L0 过滤光时, 代码抛 NO_ELIGIBLE_SOURCE 而绝不自动退回到这一条。',
        ],
    ],
];
