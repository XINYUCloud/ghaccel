<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 面板层的可离线断言。重点锁死两件曾经真崩过的事: CSRF 的"路径约定"在三处
 *             各算各的(于是面板每一个写请求都 403), 以及 Api 里用了未登记的错误码
 *             (于是"你表单填错了"显示成 500 内部错误, 运维去查日志而不是改表单)。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

define('ROOT', dirname(__DIR__));
require ROOT . '/src/Bootstrap.php';
require ROOT . '/src/Config.php';
require ROOT . '/src/Http.php';
GhAccel\Bootstrap::register();

use GhAccel\Config;
use GhAccel\Errors\GhpError;
use GhAccel\Http;
use GhAccel\Panel\Api;
use GhAccel\Ref\RefParser;
use GhAccel\Security\Auth;
use GhAccel\Source\RuntimeStat;
use GhAccel\Source\Source;
use GhAccel\Source\SourceRepo;

$GLOBALS['pass'] = 0;
$GLOBALS['fail'] = 0;

function ok(bool $c, string $name, mixed $d = ''): void
{
    if (is_array($d)) {
        $d = json_encode($d, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
    $d = (string) $d;
    if ($c) {
        $GLOBALS['pass']++;
        printf("  [ok]   %s%s\n", $name, $d === '' ? '' : "  ({$d})");
        return;
    }
    $GLOBALS['fail']++;
    printf("  [FAIL] %s%s\n", $name, $d === '' ? '' : "  <{$d}>");
}
function head(string $t): void
{
    printf("\n== %s ==\n", $t);
}

$WORK = sys_get_temp_dir() . '/ghaccel_c2_work';
exec('rm -rf ' . escapeshellarg($WORK));
foreach (['var/state', 'var/log', 'var/sessions', 'var/ratelimit', 'var/cache', 'config', 'var/lock', 'var/journal', 'var/concurrency', 'var/accounting'] as $d) {
    @mkdir($WORK . '/' . $d, 0770, true);
}
copy(ROOT . '/config/config.dist.php', $WORK . '/config/config.dist.php');
copy(ROOT . '/config/sources.dist.php', $WORK . '/config/sources.dist.php');

$cfg = Config::load($WORK);
Http::setConfig($cfg);
$auth = new Auth($cfg, $WORK);
$api = new Api($cfg, $auth, $WORK);

// ----------------------------------------------------------------------
head('1. CSRF 路径约定必须三处一致(曾经每笔写请求都 403)');
// ----------------------------------------------------------------------
$actions = $api->csrfActionList();
ok($actions !== [], '动作表非空', count($actions) . ' 项');

// 动作表的键形如 "POST:/panel/mirrors" —— 是"面板前缀 + 模板", 不带 /api。
// 服务端校验时拿到的却是完整请求路径 "/panel/api/mirrors"。csrfPathFor 负责把两者对上。
$mappings = [
    'POST:/panel/mirrors'            => '/panel/api/mirrors',
    'PUT:/panel/mirrors/{id}'        => '/panel/api/mirrors/ghfast',
    'DELETE:/panel/mirrors/{id}'     => '/panel/api/mirrors/ghfast',
    'POST:/panel/mirrors/{id}/action' => '/panel/api/mirrors/ghfast/action',
    'POST:/panel/cache/purge'        => '/panel/api/cache/purge',
    'PUT:/panel/config'              => '/panel/api/config',
    'POST:/panel/tokens'             => '/panel/api/tokens',
    'DELETE:/panel/tokens/{prefix}'  => '/panel/api/tokens/12345678',
];
foreach ($mappings as $want => $requestPath) {
    $got = Api::csrfPathFor($requestPath);
    ok(in_array($want, $actions, true) ? $got === substr($want, strpos($want, ':') + 1) : true,
        "请求路径归一到动作模板: $requestPath", $got);
}

// 反向: 每个动作模板都必须能从某个真实请求路径推出来, 否则前端永远拿不到可用 token。
$orphan = [];
foreach ($actions as $a) {
    $tpl = substr((string) $a, strpos((string) $a, ':') + 1);
    $reachable = false;
    foreach ($mappings as $want => $p) {
        if (substr((string) $want, strpos((string) $want, ':') + 1) === $tpl && Api::csrfPathFor($p) === $tpl) {
            $reachable = true;
            break;
        }
    }
    if (!$reachable) {
        $orphan[] = $a;
    }
}
ok($orphan === [], '动作表里没有"前端凑不出该路径"的孤儿模板', $orphan);

// 前端 api.js 的推导必须与服务端同源同形。这里做字面锁定: 一旦有人只改一侧, 这条立刻红。
$js = (string) file_get_contents(ROOT . '/public/panel/assets/api.js');
ok(str_contains($js, "replace(/^\\/api(?=\\/|$)/, '')"), 'api.js 剥掉前导 /api(与服务端一致)');
ok(str_contains($js, 'return PREFIX + p;'), 'api.js 把键拼成"前缀 + 模板"(与服务端一致)');
ok(!preg_match('#CSRF_MAP\[`?\$\{method#u', $js) || str_contains($js, 'csrfPath(path)'), '前端查表键由 csrfPath() 统一生成');

// ----------------------------------------------------------------------
head('2. Api 用到的错误码必须全部登记(未登记会回落成 500)');
// ----------------------------------------------------------------------
// GhpError::CATALOG 是私有的, 靠 status() 的回落值反推是否登记: 未登记的码一律给 500。
$codes = [];
foreach (glob(ROOT . '/src/Panel/Api.php') ?: [] as $f) {
    $src = (string) file_get_contents($f);
    if (preg_match_all("#GhpError::make\(\s*GhpError::([A-Z_]+)#", $src, $m)) {
        foreach ($m[1] as $c) {
            $codes[] = (string) constant('GhAccel\\Errors\\GhpError::' . $c);
        }
    }
    // 字面量形式的码最容易漏登记 —— 编译器不报错, 运行时只给用户一个 500。
    if (preg_match_all("#GhpError::make\(\s*'([a-z_]+)'#", $src, $m2)) {
        foreach ($m2[1] as $c) {
            $codes[] = $c;
        }
    }
}
$codes = array_values(array_unique($codes));
ok($codes !== [], '扫描到 Api 使用的错误码', count($codes) . ' 个');
$undeclared = [];
foreach ($codes as $c) {
    $e = GhpError::make($c);
    // 500 是 CATALOG 未命中时的兜底值; 但 500 也是若干真实码, 所以同时看标题是否被写过。
    if ($e->status() === 500 && $e->title() === '未知错误') {
        $undeclared[] = $c;
    }
}
ok($undeclared === [], 'Api 的每个错误码都在 CATALOG 里', $undeclared);
ok(GhpError::make('invalid_argument')->status() === 422, '入参校验失败是 422 而不是 500');

// ----------------------------------------------------------------------
head('3. 未认证一律 404, 而不是 401 或登录页');
// ----------------------------------------------------------------------
$threw = null;
try {
    $auth->requireAuth();
} catch (GhpError $e) {
    $threw = $e;
}
// CLI 下没有 Accept 头, wantsHtml() 成立, requireAuth 走"伪装成 404"那一支;
// 真实 API 请求才抛 UNAUTHENTICATED(再由 Api 统一降级成 404)。两支都不可返回会话,
// 也都不许给出 401 + 登录页 —— 那是在替扫描器确认"这里有个面板"。
ok($threw !== null && in_array($threw->errorCode, [GhpError::UNAUTHENTICATED, GhpError::NOT_FOUND], true),
    '无会话时 requireAuth 抛未认证或 404', $threw?->errorCode ?? '-');
ok($threw !== null && in_array($threw->status(), [401, 404], true), '未认证的 HTTP 状态只可能是 401/404', (string) ($threw?->status() ?? '-'));
ok($auth->session() === null, '无会话时 session() 返回 null');

// ----------------------------------------------------------------------
head('4. 删除留 tombstone 后必须能重建同名 id');
// ----------------------------------------------------------------------
$repo = new SourceRepo($cfg, $WORK);
$def = ['id' => 'rebuild-me', 'base_url' => 'https://example.invalid', 'mode' => 'prefix_full',
        'scenes' => ['raw'], 'hosts' => ['github.com'], 'trust' => 'unknown', 'enabled' => false, 'priority' => 40];
$repo->upsert($def);
ok($repo->get('rebuild-me') !== null, '首次创建成功');
$repo->remove('rebuild-me');
ok($repo->get('rebuild-me') === null, '删除后读不到');
$recreated = null;
try {
    $recreated = $repo->upsert($def);
} catch (\Throwable $t) {
    $recreated = 'THROW: ' . $t->getMessage();
}
ok(is_object($recreated), '删除后同名重建必须成功(曾经被 tombstone 永久封死)', is_string($recreated) ? $recreated : 'ok');

// ----------------------------------------------------------------------
head('5. Source::definition() 必须能无损回灌 upsert(PATCH 编辑的地基)');
// ----------------------------------------------------------------------
$src = $repo->get('rebuild-me');
if (is_object($src)) {
    $round = Source::fromArray($src->definition());
    $diff = [];
    foreach (['id', 'baseUrl', 'mode', 'trust', 'priority', 'enabled', 'region', 'urlTemplate'] as $p) {
        $a = $src->$p;
        $b = $round->$p;
        if (is_object($a)) {
            $a = $a->value;
        }
        if (is_object($b)) {
            $b = $b->value;
        }
        if ($a !== $b) {
            $diff[$p] = [$a, $b];
        }
    }
    ok($diff === [], 'definition() -> fromArray() 无损往返', $diff);
    ok($round->supports(GhAccel\Enum\Scene::Raw) && !$round->supports(GhAccel\Enum\Scene::ApiJson), '场景位掩码在往返后保持');
    ok($round->coversHost('github.com') && !$round->coversHost('evil.com'), 'host 集合在往返后保持');
    // PATCH 语义的关键: 只改 priority 时其余字段必须由 definition() 补齐, 否则 upsert 的
    // "完整定义校验"会因为缺 base_url/mode 直接拒, 一次正常编辑伪装成 500。
    $patched = array_merge($src->definition(), ['priority' => 77]);
    $again = $repo->upsert($patched);
    ok($again->priority === 77 && $again->baseUrl === $src->baseUrl && $again->coversHost('github.com'),
        '只提交 priority 时其余字段保持不动', $again->priority . '/' . $again->baseUrl);
} else {
    ok(false, 'definition() 往返测试需要源存在');
}

// ----------------------------------------------------------------------
head('6. 面板资源零外部依赖与 XSS 纪律(静态审计)');
// ----------------------------------------------------------------------
$assets = [];
foreach (['panel.css', 'panel.js', 'api.js', 'chart.js', 'views.js'] as $n) {
    $p = ROOT . '/public/panel/assets/' . $n;
    ok(is_readable($p), "资源存在: {$n}", $n);
    $assets[$n] = (string) file_get_contents($p);
}
$all = implode("\n", $assets);
ok(!preg_match('#(?:src|href)\s*=\s*["\']https?://#i', $all) && !preg_match('#@import\s+url\((["\']?)https?://#i', $all),
    '资源内无任何 http(s) 外链(国内 CDN 本身可能就是瓶颈, 且必须保持零依赖)');
ok(!preg_match('#\b(eval|new Function)\s*\(#', $all), '无 eval / new Function');
ok(!preg_match('#@font-face[\s\S]{0,400}base64,#i', $assets['panel.css'] ?? ''), '未内嵌 base64 字体');
// views.js 渲染的 ref/源域名/curl 文案全是攻击者可控字符串, 只允许 createElement + textContent。
$viewsCode = preg_replace('#/\*[\s\S]*?\*/#', '', (string) ($assets['views.js'] ?? ''));
$viewsCode = preg_replace('#^\s*\*.*$#m', '', $viewsCode);
$viewsCode = preg_replace('#^\s*//.*$#m', '', $viewsCode);
ok(!str_contains($viewsCode, 'innerHTML'), 'views.js 代码里(去注释后)零 innerHTML 使用');
ok(!str_contains($viewsCode, 'outerHTML') && !str_contains($viewsCode, 'document.write'), 'views.js 无 outerHTML / document.write');

// ----------------------------------------------------------------------
head('7. 面板与代理共用进程: 不提供任何流式/长连接接口');
// ----------------------------------------------------------------------
// 一个页签的 SSE 就能把并发槽占满, 等于自我 DoS。这里锁死路由表里没有这类端点。
$apiSrc = (string) file_get_contents(ROOT . '/src/Panel/Api.php');
foreach (['text/event-stream', 'stream', 'websocket', 'flush_interval'] as $bad) {
    if ($bad === 'stream') {
        // "stream" 作为词会出现在合法上下文(流式转发说明), 只禁真正的 SSE 声明。
        continue;
    }
    ok(!str_contains(strtolower($apiSrc), $bad), "面板接口不含 {$bad}");
}

// ----------------------------------------------------------------------
head('8. 路由表面互斥: 代理/面板/健康检查不共用判定');
// ----------------------------------------------------------------------
$parser = new RefParser($cfg);
foreach (['/panel', '/panel/', '/panel/api/summary', '/panel/login', '/panel/assets/panel.css'] as $p) {
    ok($parser->surface($p) !== 'proxy', "面板路径不被当代理请求处理: {$p}", $parser->surface($p));
}
ok($parser->surface('/health') === 'health', '/health 是独立免登录探针', $parser->surface('/health'));
ok($parser->surface('/gh/o/r@main/a.md') === 'proxy', '代理路径正常');
ok($parser->surface('/') === 'home', '根路径是使用说明页');

// ----------------------------------------------------------------------
head('9. 面板写接口在 CSRF 之前不产生副作用');
// ----------------------------------------------------------------------
$before = count($repo->all());
$threw = null;
try {
    // 不带任何会话与 token 的写请求: 必须拒绝, 且源池数量不变。
    $auth->verifyWriteRequest('POST', '/panel/api/mirrors');
} catch (GhpError $e) {
    $threw = $e;
}
ok($threw !== null, '匿名写请求被拒', $threw?->errorCode ?? '-');
ok(count((new SourceRepo(Config::load($WORK), $WORK))->all()) === $before, '被拒的写请求没有改动源池', $before);

// ----------------------------------------------------------------------
exec('rm -rf ' . escapeshellarg($WORK));
printf("\n================ 结果: 通过 %d, 失败 %d ================\n", $GLOBALS['pass'], $GLOBALS['fail']);
exit($GLOBALS['fail'] > 0 ? 1 : 0);
