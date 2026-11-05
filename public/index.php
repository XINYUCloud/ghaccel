<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 唯一 HTTP 入口。只做"捕获 -> 定表面 -> 闸门 -> 解析 -> 投递 -> 收尾"六步,
 *             不含任何业务规则。业务规则都在 src/ 里, 这样 CLI 自检才能绕过 HTTP 直接复用它们。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

// ---- PHP 版本前置守卫 ----
// 纯文本 500 而不是白屏: 部署者需要一眼看到"装哪个版本", 而不是一堆 500 空白页去猜。
if (PHP_VERSION_ID < 80100) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'GhAccel 需要 PHP >= 8.1 (enum 与 readonly 是状态机和值对象的刚需)。当前版本: '
        . PHP_VERSION . "\n";

    return;
}

$ROOT = dirname(__DIR__);

require $ROOT . '/src/Bootstrap.php';
require $ROOT . '/src/Config.php';
require $ROOT . '/src/Http.php';
GhAccel\Bootstrap::register();

use GhAccel\Bootstrap;
use GhAccel\Config;
use GhAccel\Errors\GhpError;
use GhAccel\Http;
use GhAccel\Ref\RefParser;
use GhAccel\Security\Auth;
use GhAccel\Security\RateLimiter;
use GhAccel\Security\Slots;

$cfg = Config::load($ROOT);

// ---- 表面分发 ----
// 三个互斥表面 + 静态资源。绝不由 URI 推文件路径, 否则解析差异与目录穿越一起进来。
$p = new RefParser($cfg);
$cap = Http::capture($cfg);
$rawPath = (string) $cap['raw_path'];
$surface = $p->surface($rawPath);

// 致命环境问题的优先级高于一切功能: 半死实例会让每个大文件都静默失败, 比直接拒绝服务坏得多。
$check = Bootstrap::selfCheck($ROOT);
if ($surface === 'health') {
    // 免登录探针, 只回聚合三态与缺失项名, 不含路径、源列表或任何配置值。
    Http::json([
        'ok'        => $check['critical'] === [],
        'php'       => PHP_VERSION,
        'critical'  => array_keys($check['critical']),
        'warnings'  => array_keys($check['warnings']),
        'ts'        => time(),
    ], $check['critical'] === [] ? 200 : 503, ['Cache-Control' => 'no-store']);

    return;
}
if ($check['critical'] !== []) {
    Http::text('GhAccel 环境自检未通过: ' . implode('; ', $check['critical']), 500);

    return;
}

// ---- 首页 ----
if ($surface === 'home') {
    renderHome($cfg, $ROOT, $check);

    return;
}

// ---- 面板与静态资源 ----
if ($surface === 'panel' || $surface === 'assets') {
    $auth = new Auth($cfg, $ROOT);
    $panelEntry = $ROOT . '/public/panel.php';
    if (!is_readable($panelEntry)) {
        // 未登录一律 404 而不是 401/登录页: 不给扫描器"这里有个面板"的信号。
        Http::text('Not Found', 404);

        return;
    }
    require $panelEntry;

    return;
}

// ---- 代理面 ----
$obs = null;
$slots = null;
try {
    // OPTIONS 预检必须在任何闸门之前: 预检请求没有 Range、没有目标 URL, 走代理链路会被
    // UrlGuard 判成非法 method, 结局是"浏览器全挂、命令行全正常", 极难从报错定位。
    if ($cap['method'] === 'OPTIONS') {
        Http::noBuffering();
        $disp = new GhAccel\Execution\Dispatcher($cfg, $ROOT);
        $disp->preflight();

        return;
    }

    if (!in_array($cap['method'], ['GET', 'HEAD'], true)) {
        throw GhpError::make(GhpError::UNSUPPORTED_METHOD, (string) $cap['method']);
    }

    $disp = new GhAccel\Execution\Dispatcher($cfg, $ROOT);
    $obs = $disp->observatory();

    // User-Agent 闸门: 空 UA 一律拒。但 aria2/curl/wget/IDM/迅雷是本项目核心合法用户,
    // 误杀它们等于把最有价值的流量挡在门外, 所以黑名单来自配置而不是硬编码。
    $ua = (string) $cap['ua'];
    if ($cfg->bool('security.require_user_agent', true) && trim($ua) === '') {
        throw GhpError::make(GhpError::UA_REQUIRED);
    }
    if (uaBlocked($cfg, $ua)) {
        throw GhpError::make(GhpError::UA_BLOCKED, substr($ua, 0, 80));
    }

    // 限流与并发槽在解析之前: 被打满时最贵的往往是解析与选路, 先挡在门外才有意义。
    $rl = new RateLimiter($cfg, $ROOT);
    $ip = (string) $cap['client_ip'];
    $trusted = $cfg->arr('limits.trusted_cidrs', []);
    $bypass = $trusted !== [] && ipInCidrList($ip, $trusted);

    if (!$bypass) {
        $r = $rl->consume('ip', $ip, 1.0);
        if (!$r['allowed']) {
            throw GhpError::make(GhpError::RATE_LIMITED, '请求数超限', [
                'retry_after' => $r['retry_after'],
                'scope'       => 'ip',
                'limit'       => $r['limit'],
            ]);
        }
    }

    // Slots 的入参是**项目根**, 它自己负责拼 var/concurrency 子目录; 传子目录会得到
    // var/concurrency/var/concurrency/slot_* 这种套两层的脏路径(锁仍然成立, 但位置错且无法清理)。
    $slots = new Slots($ROOT, max(1, $cfg->int('limits.max_concurrent', 24)));
    if ($slots->acquire() === null) {
        // 并发满不是源的错, 因此绝不能进任何失败统计 —— 观察者会看到整池源同时"变差"。
        throw GhpError::make(GhpError::OVERLOADED, '并发槽耗尽', ['retry_after' => 2]);
    }

    $ref = $p->parse($rawPath, (string) $cap['raw_query']);

    // 下架清单必须卡在 serve() 之前, 而不是只卡在网络取回之前: 已经落地的缓存条目同样
    // 不能再被供出去, 否则"下架"只挡住了新下载、挡不住旧内容继续由本机域名分发。
    if (takenDown($cfg, $ref->owner, $ref->repo)) {
        throw GhpError::make(GhpError::REPO_TAKEN_DOWN, $ref->owner . '/' . $ref->repo);
    }

    $split = GhAccel\Execution\Dispatcher::parseSplit((string) $cap['raw_query'], $cfg);

    $diag = isset($_GET['debug']) && (new Auth($cfg, $ROOT))->session() !== null;

    $result = $disp->serve($ref, [
        'method'            => $cap['method'],
        'range'             => (string) $cap['range'],
        'if_none_match'     => (string) $cap['if_none_match'],
        'if_modified_since' => (string) $cap['if_modified_since'],
        'client_headers'    => $cap['headers'],
        'client_ip'         => $ip,
        'is_agent'          => (bool) $cap['is_agent'],
        'want_json'         => (bool) $cap['want_json'],
        'split'             => $split,
        'diag_visible'      => $diag,
        'bypass_quota'      => $bypass,
    ]);

    // 记账: 字节配额只在真的过了本机带宽时才扣, 302 与缓存直出不该占用户的额度。
    if (!$bypass && is_array($result) && (int) ($result['bytes'] ?? 0) > 0) {
        $rl->consume('ipday', $ip, (int) $result['bytes'] / 1048576.0);
    }

    $disp->flushObservations();
} catch (GhpError $e) {
    if (isset($disp) && $disp instanceof GhAccel\Execution\Dispatcher) {
        $disp->renderError($e, [
            'want_json' => (bool) ($cap['want_json'] ?? false),
            'is_agent'  => (bool) ($cap['is_agent'] ?? false),
            'range'     => (string) ($cap['range'] ?? ''),
        ]);
    } else {
        Http::problem($e->toProblem(Http::requestId()), ['Cache-Control' => 'no-store']);
    }
    if (isset($disp) && $disp instanceof GhAccel\Execution\Dispatcher) {
        $disp->flushObservations();
    }
} catch (\Throwable $t) {
    // 兜底不得泄露堆栈、路径或任何上游信息; request_id 是给运维去日志里捞的唯一线索。
    error_log('[GhAccel] uncaught ' . get_class($t) . ': ' . $t->getMessage() . ' req=' . Http::requestId());
    $wrap = GhpError::make(GhpError::UPSTREAM_FAILED, '内部错误', ['request_id' => Http::requestId()], $t);
    if (isset($disp) && $disp instanceof GhAccel\Execution\Dispatcher) {
        $disp->renderError($wrap, ['want_json' => true]);
    } else {
        Http::problem($wrap->toProblem(Http::requestId()), ['Cache-Control' => 'no-store']);
    }
} finally {
    if ($slots !== null) {
        $slots->release();
    }
    if ($obs !== null) {
        $obs->flush();
        // 概率触发压实, 抢不到锁立即返回, 绝不在请求路径上阻塞。
        $obs->maybeCompact();
    }
}

// ----------------------------------------------------------------------
// 首页与工具函数
// ----------------------------------------------------------------------

/**
 * UA 黑名单匹配。
 *
 * 命中判定必须在 allow 之前跳过: aria2 的 UA 里可能同时出现被拦子串, 黑名单一条就误杀
 * 整个下载工具是这类代理最常见的自伤。
 */
function uaBlocked(Config $cfg, string $ua): bool
{
    if ($ua === '') {
        return false;
    }
    $low = strtolower($ua);
    foreach ((array) $cfg->arr('security.ua_allow_patterns', []) as $allow) {
        if ($allow !== '' && str_contains($low, strtolower((string) $allow))) {
            return false;
        }
    }
    foreach ((array) $cfg->arr('security.ua_block_patterns', []) as $pat) {
        if ($pat !== '' && str_contains($low, strtolower((string) $pat))) {
            return true;
        }
    }

    return false;
}

/**
 * owner/repo 级下架判定。清单来自 bin/selftest.php takedown --repo=owner/repo 落下的
 * var/state/blocklist.json, 结构 {repos: ["owner/repo"], owners: ["owner"]}。
 *
 * 每次请求重读而不做进程内缓存: PHP 无常驻状态, 而"改完清单要等压实周期才生效"对一次
 * 下架处置来说是不可接受的。文件极小, 一次 json_decode 换即时生效。
 */
function takenDown(Config $cfg, string $owner, string $repo): bool
{
    if ($owner === '') {
        return false;
    }
    $file = $cfg->root() . '/var/state/blocklist.json';
    if (!is_readable($file)) {
        return false;
    }
    $raw = (string) @file_get_contents($file);
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        return false;
    }
    $repos = array_map(static fn ($v): string => strtolower(trim((string) $v)), (array) ($data['repos'] ?? []));
    if (in_array($owner . '/' . $repo, $repos, true)) {
        return true;
    }
    $owners = array_map(static fn ($v): string => strtolower(trim((string) $v)), (array) ($data['owners'] ?? []));

    return in_array($owner, $owners, true);
}

function ipInCidrList(string $ip, array $cidrs): bool
{
    foreach ($cidrs as $cidr) {
        $c = (string) $cidr;
        if (!str_contains($c, '/')) {
            if ($c === $ip) {
                return true;
            }
            continue;
        }
        [$sub, $bits] = explode('/', $c, 2);
        $a = @inet_pton($ip);
        $b = @inet_pton($sub);
        if ($a === false || $b === false || strlen($a) !== strlen($b)) {
            continue;
        }
        $bits = (int) $bits;
        $full = intdiv($bits, 8);
        if ($full > 0 && substr($a, 0, $full) !== substr($b, 0, $full)) {
            continue;
        }
        $rem = $bits % 8;
        if ($rem > 0) {
            $mask = chr((0xFF << (8 - $rem)) & 0xFF);
            if ((ord($a[$full]) & ord($mask)) !== (ord($b[$full]) & ord($mask))) {
                continue;
            }
        }

        return true;
    }

    return false;
}

/**
 * 使用说明页。
 *
 * 全部动态文案一律 htmlspecialchars: 这里的 base 域名来自配置, 但面板与首页共用同一套
 * 转义纪律, 不给"这行数据是我自己配的所以安全"留口子。
 */
function renderHome(Config $cfg, string $root, array $check): void
{
    $base = rtrim($cfg->str('app.base_origin', ''), '/');
    if ($base === '') {
        // Host 头只用于展示示例链接, 绝不参与任何安全判定 —— CSRF 的同源基准一律取
        // 配置里的 app.base_origin, 因为 Host 可伪造。
        $host = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
        $base = 'https://' . preg_replace('/[^A-Za-z0-9.\-_:]/', '', $host);
    }
    $esc = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $sample = $base . '/gh/cli/cli@refs/tags/v2.12.0/README.md';
    $abs = $base . '/https://github.com/cli/cli/releases/download/v2.12.0/gh_2.12.0_linux_amd64.tar.gz';

    Http::noBuffering();
    Http::header('Cache-Control', 'no-store');
    Http::header('X-Content-Type-Options', 'nosniff');
    Http::header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");

    $warn = '';
    if ($check['warnings'] !== []) {
        $items = '';
        foreach ($check['warnings'] as $k => $v) {
            $items .= '<li>' . $esc((string) $k) . ' — ' . $esc((string) $v) . '</li>';
        }
        $warn = '<div class="card warn"><h2>环境告警</h2><ul>' . $items . '</ul></div>';
    }

    echo '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<title>GhAccel · GitHub 加速网关</title>'
        . '<style>'
        . 'body{font:15px/1.7 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;'
        . 'max-width:60rem;margin:0 auto;padding:2rem 1.25rem;color:#1b1f24;background:#fbfcfd}'
        . 'h1{font-size:1.5rem;margin:0 0 .25rem}h2{font-size:1rem;margin:0 0 .5rem}'
        . '.sub{color:#57606a;margin:0 0 1.5rem}'
        . '.card{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:1rem 1.1rem;margin:0 0 1rem}'
        . '.warn{border-color:#d4a72c;background:#fff8e5}'
        . 'code,pre{font:13px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace}'
        . 'pre{background:#f2f4f6;border-radius:6px;padding:.7rem .8rem;overflow-x:auto;margin:.4rem 0}'
        . 'table{border-collapse:collapse;width:100%}td{padding:.35rem .5rem;vertical-align:top;border-top:1px solid #eaeef2}'
        . 'td:first-child{width:12rem;color:#57606a}'
        . 'a{color:#0969da}ul{margin:.3rem 0;padding-left:1.2rem}'
        . '.tag{display:inline-block;font-size:12px;padding:.05rem .45rem;border:1px solid #d0d7de;border-radius:99px;margin-left:.4rem;color:#57606a}'
        . '</style></head><body>'
        . '<h1>GhAccel <span class="tag">GitHub 加速网关</span></h1>'
        . '<p class="sub">谶Hank · MIT 许可 · 为国内访问与 AI Agent 工作台加速 GitHub 资源。'
        . '多重算法选路：源健康度实测、熔断自适应冷却、按资源身份的缓存资格判定。</p>';

    echo $warn;

    echo '<div class="card"><h2>三种等价入口</h2><p>把前缀替换成你的域名即可。'
        . '之所以提供三种，是因为 nginx 的 <code>merge_slashes</code>、云 CDN 与宝塔加速插件都会折叠 <code>//</code> —— '
        . '只依赖绝对形式的话，一上 CDN 路由就全灭。</p>'
        . '<pre>' . $esc($abs) . '</pre>'
        . '<pre>' . $esc($sample) . '</pre>'
        . '<pre>' . $esc($base . '/?u=https%3A%2F%2Fgithub.com%2Fcli%2Fcli%2Freleases%2Fdownload%2Fv2.12.0%2Fgh_2.12.0_linux_amd64.tar.gz') . '</pre>'
        . '</div>';

    echo '<div class="card"><h2>短别名</h2><table>'
        . '<tr><td><code>/raw/{o}/{r}/{ref}/{path}</code></td><td>raw 源码与文本文件</td></tr>'
        . '<tr><td><code>/release/{o}/{r}/{tag}/{asset}</code></td><td>Release 资产（自动跟到签名落点）</td></tr>'
        . '<tr><td><code>/latest/{o}/{r}/{asset}</code></td><td>最新版本的资产（免 API 反解 tag）</td></tr>'
        . '<tr><td><code>/zip/{o}/{r}/{ref}</code> <code>/tar/…</code></td><td>仓库归档快照</td></tr>'
        . '<tr><td><code>/api/{endpoint}</code></td><td>api.github.com JSON</td></tr>'
        . '</table></div>';

    echo '<div class="card"><h2>下载工具</h2><pre>aria2c -x16 -s16 "' . $esc($abs) . '"</pre>'
        . '<p>Range 与 206 语义完整透传，多线程下载可直接用。归档（codeload）实测不尊重 Range，'
        . '那时网关会回 <code>X-Ghaccel-Range: unsupported</code> 并单线程全量返回。</p>'
        . '<p>想对同一个文件并发分片取，需该文件已完整落在缓存中：<code>?part=3&amp;of=16</code>。'
        . '未缓存时分片会把同一文件向源拉 N 次，网关会以 <code>409 split_requires_cached</code> 拒绝。</p></div>';

    echo '<div class="card"><h2>Agent 集成</h2><p>错误统一 <code>application/problem+json</code>，'
        . '带 <code>code</code> / <code>retryable</code> / <code>retry_after</code> / <code>next_action</code> / <code>request_id</code>。'
        . '可用性探测打 <code>/health</code>。Range 请求被限流时一定回 429 而不是 HTML 错误页 —— '
        . '否则下载工具会把错误页当分片写进文件。</p>'
        . '<p>自带校验值的安装脚本请传 <code>?sha256=...</code>，网关流式增量校验，不符则丢弃且不入缓存。</p></div>';

    echo '<div class="card"><h2>面板</h2><p><a href="' . $esc($base) . '/'
        . $esc($cfg->str('panel.path_prefix', 'panel')) . '">监控与源管理</a>。'
        . '默认不对公网开放，未登录一律 404。用 <code>bin/token.php issue</code> 签发管理令牌。</p></div>';

    echo '<div class="card"><h2>部署要点</h2><ul>'
        . '<li>nginx 需 <code>merge_slashes off</code> 与 <code>fastcgi_buffering off</code></li>'
        . '<li>php.ini 需 <code>zlib.output_compression = Off</code>（否则 Content-Length 与实际字节不符，断点续传与 sha256 校验一起失效）</li>'
        . '<li><code>var/</code> 必须可写且在本地磁盘</li>'
        . '<li>计划任务跑 <code>bin/compact.php --once</code>，用站点运行用户而不是 root</li>'
        . '</ul></div>';

    echo '<p class="sub" style="font-size:12px">第三方公益镜像的可用性与内容正确性需部署者自行复测，本项目不作承诺。'
        . '详见 <code>SECURITY.md</code>。</p></body></html>';
}
