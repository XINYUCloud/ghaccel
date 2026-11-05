<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 起步模板。把它复制成 config/config.php 后按需覆盖 —— 这里只放"必须改的项"
 *             与"出厂白名单的唯一已知缺口", 其余全部留在 config/config.dist.php 里逐条注释。
 *             Config 的四级覆盖是 config.dist.php -> config.php -> config.local.php -> overlay.json,
 *             本文件是第二层, 深度合并, 只写你要改的键即可, 不必整段照抄。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

return [

    'app' => [
        // 【必须改】同源基准。CSRF / Origin / Sec-Fetch-Site 校验严格等值比对这一个值,
        // 代码绝不拿 $_SERVER['HTTP_HOST'] 当基准(Host 可伪造)。留空时管理面的写请求会
        // 一律被拒(csr f_failed), 因为无法建立可信的同源基准。
        // 填你对外服务的那个绝对 origin, 结尾不带斜杠, 例如: https://gh.example.com
        'base_origin' => '',

        // 【建议改】上游项目地址与联系方式。repo_url 的实际用途是拼进发往 GitHub 的 UA
        // 作为出处标识(见 Transport\Headers::userAgent), 派生/fork 应改成自己的仓库地址。
        'repo_url'    => 'https://github.com/XINYUCloud/ghaccel',
        'contact'     => '',

        // 【可选】面向 GitHub 的匿名 UA。API 有速率限制且要求可识别来源, 不要伪装成浏览器。
        // 留空时自动组合成 GhAccel/<版本> (+repo_url; contact=…), 版本号跟随 Bootstrap::VERSION。
        'user_agent'  => '',

        // 【定位】private = 自用/私有部署(默认, EDGE 保守、面板不公网)。public 会额外注入
        // CORS, 并把下载当作对外服务对待 —— 公开开放前请先读 SECURITY.md 的合规与 ToS 章节。
        'exposure'    => 'private',
    ],

    // 【唯一已知缺口】2026-11 实测: Release 资产的 302 落点已从 objects.githubusercontent.com
    // 迁移到 release-assets.githubusercontent.com(jq、cli 两个仓库都验证过), 而出厂
    // config/config.dist.php 的 security.allowed_hosts 还没有这一条。不补的话, 每一次 Release
    // 下载都会在"跳到落点"这一跳被 host_not_allowed 挡掉。
    //
    // 做法二选一:
    //   A. 直接在 config/config.dist.php 的 security.allowed_hosts 里加一行
    //      'release-assets.githubusercontent.com', 然后删掉下面这段覆盖;
    //   B. 保留出厂文件不动, 在本 config.php 里把 security.allowed_hosts 覆盖成下面的完整列表
    //      (注意: 数组是整条替换而不是追加, 所以必须写全, 漏一项就少一类场景)。
    'security' => [
        'allowed_hosts' => [
            'github.com',
            'api.github.com',
            'codeload.github.com',
            'raw.githubusercontent.com',
            'objects.githubusercontent.com',
            'release-assets.githubusercontent.com', // <-- 缺它 Release 全挂
            'gist.github.com',
            'gist.githubusercontent.com',
            'uploads.github.com',
            'media.githubusercontent.com',
        ],
    ],

    // 【部署必改】面板入口前缀。默认 panel 在扫描字典里; 自用建议改成随机串(如 ctl-7f3a9c),
    // 未登录一律 404。改这里的同时, 面板登录 Cookie 的 Path 会跟着这个前缀走。
    // 'panel' => [
    //     'path_prefix'    => 'panel',
    //     'public_exposed' => false,
    // ],

    // 【限流】校园网/企业 NAT 后多人共用出口 IP 时, 把内网段填进 trusted_cidrs 跳过请求数桶,
    // 否则正常用户会被邻居的 aria2 连坐。字节配额仍走很宽的 ipday 桶。
    // 'limits' => [
    //     'trusted_cidrs' => ['192.168.0.0/16', '10.0.0.0/8'],
    // ],

    // 【容器 / K8s】把 Pod CIDR 与 Service CIDR 加进 extra_deny_cidrs, 防 SSRF 横移到集群内网。
    // 'security' => [
    //     'extra_deny_cidrs' => ['10.244.0.0/16', '10.96.0.0/16'],
    // ],
];
