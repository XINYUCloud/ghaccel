<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 面板的服务端外壳 —— 静态资源固定映射、登录页、四视图骨架、boot JSON、
 *             CSRF meta、以及决策视图的服务端转义渲染。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 * @see       https://github.com/  完整版权与许可信息见仓库根目录 LICENSE
 */

declare(strict_types=1);

use GhAccel\Bootstrap;
use GhAccel\Config;
use GhAccel\Errors\GhpError;
use GhAccel\Http;
use GhAccel\Panel\Api;
use GhAccel\Security\Audit;
use GhAccel\Security\Auth;
use GhAccel\Security\IpRange;

/**
 * 本文件由 public/index.php 在 surface === 'panel' || 'assets' 时 require。
 * 入口已经把 $ROOT / $cfg / $auth / $cap / $surface 备好了, 但直接 php -S 指到本文件
 * 或别的调用方式也必须能用, 所以每个变量都先做存在性兜底 —— 面板白屏的排查成本比代理
 * 链路高得多(没有任何错误可看), 宁可在这里多花五行。
 */
$ROOT = (isset($ROOT) && is_string($ROOT)) ? rtrim($ROOT, '/\\') : dirname(__DIR__);
if (!class_exists(Config::class, false)) {
    require $ROOT . '/src/Bootstrap.php';
    require $ROOT . '/src/Config.php';
    require $ROOT . '/src/Http.php';
    Bootstrap::register();
}
$cfg = (isset($cfg) && $cfg instanceof Config) ? $cfg : Config::load($ROOT);
$auth = (isset($auth) && $auth instanceof Auth) ? $auth : new Auth($cfg, $ROOT);
$cap = (isset($cap) && is_array($cap)) ? $cap : Http::capture($cfg);
$surface = (isset($surface) && is_string($surface)) ? $surface : 'panel';
// 自检必须在任何 noBuffering() 之前拿到: Http::noBuffering() 用 ini_set 把
// zlib.output_compression 写成字符串 "Off", 而 (bool)"Off" 为真, 重跑自检就会凭空多出一条
// "zlib 未关闭"的严重项。入口已经算过的那份才是对的。
$check = (isset($check) && is_array($check)) ? $check : Bootstrap::selfCheck($ROOT);

$PANEL_ON = $cfg->bool('panel.enabled', true);
$PREFIX = trim($cfg->str('panel.path_prefix', 'panel'), '/');
$BASE = '/' . $PREFIX;

/** 出 HTML 的唯一出口: 转义纪律集中在这里, 别处不再手搓 htmlspecialchars。 */
function panelEsc(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * 显示前处理攻击者可控字符串。
 *
 * 与 Api::scrub() 同一套规则(剥控制字符 -> 抹绝对路径 -> 截 120), 但在 SSR 侧必须自己
 * 做一遍: SSR 走的是 HTML 通道, 漏一个字段就是一个可以被人点开看的 XSS 面。两处口径
 * 一致才能让"前端看到的"和"源码里看到的"是同一份内容。
 */
function panelSanitize(?string $s, int $max = 120): string
{
    $s = (string) $s;
    if ($s === '') {
        return '';
    }
    $s = preg_replace('/[\x00-\x1F\x7F]/u', ' ', $s) ?? '';
    $s = preg_replace('#[A-Za-z]:[\\\\/][^\s\'",;)\]}]*#', '[path]', $s) ?? $s;
    $s = trim($s);
    if (mb_strlen($s) > $max) {
        $s = mb_substr($s, 0, $max) . '…';
    }

    return $s;
}

function panelHeader(string $n, string $v): void
{
    Http::header($n, $v);
}

/**
 * 只有这几个动作能进静态表: 键 -> 绝对路径的固定映射, 由 Api::assets() 提供。
 * 绝不按 URL 拼文件路径(那是目录穿越 + webshell 落地点)。
 */
function panelServeAsset(string $name, string $root): void
{
    $map = Api::assets();
    $name = basename(str_replace('\\', '/', $name));
    if (!isset($map[$name])) {
        Http::text('Not Found', 404);

        return;
    }
    $file = $root . '/' . $map[$name];
    if (!is_readable($file)) {
        // 文件缺失也回 404: 不回"权限问题"之类的细节, 运维看日志足矣。
        Http::text('Not Found', 404);

        return;
    }
    $type = str_ends_with($name, '.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8';
    Http::noBuffering();
    panelHeader('Content-Type', $type);
    panelHeader('Cache-Control', 'public, max-age=3600');
    panelHeader('X-Content-Type-Options', 'nosniff');
    panelHeader('Cross-Origin-Resource-Policy', 'same-origin');
    // 指纹用 filemtime() 而不是内容 hash: 省一次全文件读, 而 ?v= 只要能区分新旧就够了。
    panelHeader('ETag', 'W/"' . dechex((int) @filemtime($file)) . '-' . sprintf('%x', (int) @filesize($file)) . '"');
    readfile($file);
}

// ------------------------------------------------------------------
// 1) 静态资源
// ------------------------------------------------------------------
if ($surface === 'assets') {
    $rawPath = (string) ($cap['raw_path'] ?? '/');
    $seg = array_values(array_filter(explode('/', $rawPath), static fn (string $s): bool => $s !== ''));
    $name = (string) end($seg);
    panelServeAsset($name, $ROOT);

    return;
}

// ------------------------------------------------------------------
// 2) 路径判定
// ------------------------------------------------------------------
$rawPath = (string) ($cap['raw_path'] ?? '/');
$normPath = '/' . ltrim($rawPath, '/');
$rest = $normPath;
if ($BASE !== '/' && str_starts_with($normPath, $BASE)) {
    $rest = substr($normPath, strlen($BASE));
}
$rest = '/' . ltrim((string) $rest, '/');
$method = strtoupper((string) ($cap['method'] ?? Http::method()));

$segments = array_values(array_filter(explode('/', $rest), static fn (string $s): bool => $s !== ''));
$route = (string) ($segments[0] ?? '');

if (!$PANEL_ON) {
    Http::text('Not Found', 404);

    return;
}

// 面板默认不公网: public_exposed=false 时只放行回环与 limits.trusted_cidrs。
// 这一层是给"面板被误挂到公网"兜底的, 认证之外的第二道门。
if (!$cfg->bool('panel.public_exposed', false)) {
    $ip = (string) ($cap['client_ip'] ?? '');
    $loopback = in_array($ip, ['127.0.0.1', '::1', 'localhost'], true) || str_starts_with($ip, '127.');
    $trusted = IpRange::inCidrs($ip, (array) $cfg->arr('limits.trusted_cidrs', []));
    if (!$loopback && !$trusted) {
        Http::text('Not Found', 404);

        return;
    }
}

$api = new Api($cfg, $auth, $ROOT);
$api->useSelfCheck($check);

// ------------------------------------------------------------------
// 3) 接口
// ------------------------------------------------------------------
if ($route === 'api') {
    $api->handle($method, $normPath);

    return;
}

// ------------------------------------------------------------------
// 4) 登录 / 登出
// ------------------------------------------------------------------
$loginUrl = $BASE . '/login';

if ($route === 'login') {
    $error = '';
    if ($method === 'POST') {
        try {
            $auth->handleLogin();
            // handleLogin 自己发 302 + Cookie 但不 exit; 这里必须停止后续输出, 否则登录页
            // 会被当成响应体跟在 302 后面发出去。
            return;
        } catch (GhpError $e) {
            // 失败原因不进详情页: 错误码与文案可能提示"Token 长度不对"这类可利用信息,
            // 统一给一句"凭据无效"。
            $error = '凭据无效或已过期';
        }
    }
    panelLoginPage($cfg, $BASE, $error, $loginUrl);

    return;
}

if ($route === 'logout' && $method === 'POST') {
    $auth->handleLogout();

    return;
}

// ------------------------------------------------------------------
// 5) 外壳(需已登录; 未登录一律 404)
// ------------------------------------------------------------------
$session = null;
try {
    $session = $auth->requireAuth();
} catch (GhpError) {
    // 未登录/未启用一律 404, 且不带任何解释性文案: 401 或登录页都是在替扫描器确认目标。
    Http::text('Not Found', 404);

    return;
}

$view = (string) Http::queryStr('view');
if ($view === '' && $route !== '' && $route !== 'index' && $route !== 'login') {
    $view = $route;
}
$VIEWS = ['summary', 'mirrors', 'decisions', 'cache'];
if (!in_array($view, $VIEWS, true)) {
    $view = 'summary';
}

// 每个资源各自的 filemtime 作指纹: 不用内容 hash, 省一次整文件读, 而 ?v= 只要能区分新旧。
$verAt = static fn (string $n): int => (int) (@filemtime($ROOT . '/public/panel/assets/' . $n) ?: 0);
$res = static fn (string $n): string => $BASE . '/assets/' . $n . '?v=' . $verAt($n);
$ver = (string) $verAt('panel.js');

$initial = [];
try {
    $initial = $api->initialData($view);
} catch (\Throwable $t) {
    error_log('[GhAccel panel] initial data failed: ' . $t->getMessage());
    $initial = ['view' => $view, 'error' => '初始数据生成失败, 前端将重试'];
}

$csrfActions = $api->csrfActionList();
$csrfMap = $auth->csrfMap($csrfActions);
$generatedAt = microtime(true);

$boot = [
    'prefix' => $BASE,
    'view' => $view,
    'generated_at' => round($generatedAt, 3),
    'snapshot_version' => (string) ($initial['summary']['snapshot_version'] ?? ''),
    'poll_ms' => $cfg->arr('panel.poll_ms', []),
    'csrf' => $csrfMap,
    'csrf_actions' => $csrfActions,
    'initial' => $initial,
    'session' => [
        'label' => panelSanitize((string) ($session['label'] ?? ''), 64),
        'selector_prefix' => substr((string) ($session['selector'] ?? ''), 0, 8),
        'scopes' => (array) ($session['scopes'] ?? []),
    ],
    'caps' => ['range', 'follows_redirect_internally', 'json_api_ok'],
    'asset_version' => $ver,
    'stats_window_s' => max(30, $cfg->int('panel.stats_window_s', 300)),
];

Http::noBuffering();
Http::status(200);
panelHeader('Content-Type', 'text/html; charset=utf-8');
panelHeader('Cache-Control', 'no-store');
panelHeader('X-Content-Type-Options', 'nosniff');
panelHeader('X-Frame-Options', 'DENY');
panelHeader('Referrer-Policy', 'no-referrer');
panelHeader('Cross-Origin-Resource-Policy', 'same-origin');
// script-src 'self' 不写 unsafe-inline: 于是 HTML 里既不能有 <script> 体也不能有 on*=,
// 初始数据走下面的 application/json 块, 尺寸类样式走 CSS 自定义属性由 JS 设置。
panelHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    . "font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
);

$bootJson = json_encode(
    $boot,
    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
);
if (!is_string($bootJson)) {
    $bootJson = '{"prefix":"' . panelEsc($BASE) . '","initial":{}}';
}

?><!doctype html>
<html lang="zh-CN" data-theme="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="csrf-token" content="<?= panelEsc($auth->csrfToken()) ?>">
<title>GhAccel 监控面板</title>
<link rel="stylesheet" href="<?= panelEsc($res('panel.css')) ?>">
</head>
<body>
<a id="top" class="skip" href="#main">跳到主内容</a>
<header class="topbar">
  <div class="brand">
    <span class="logo" aria-hidden="true">⌁</span>
    <strong>GhAccel</strong>
    <span class="tag" id="brand-tag">监控面板</span>
  </div>
  <div class="topmeta">
    <span class="kv" id="meta-version" title="快照版本: 数字不动时用它区分"采集坏了"还是"缓存旧"">
      snapshot <code><?= panelEsc((string) ($boot['snapshot_version'] !== '' ? $boot['snapshot_version'] : '—')) ?></code>
    </span>
    <span class="kv" id="meta-generated">生成 <code><?= panelEsc(date('H:i:s', (int) $generatedAt)) ?></code></span>
    <span class="kv" id="meta-clock" title="服务器时间">—</span>
    <button type="button" class="ghost" id="btn-theme" title="切换深/浅主题">主题</button>
    <button type="button" class="ghost" id="btn-refresh" title="立即刷新当前视图">刷新</button>
    <form id="logout-form" method="post" action="<?= panelEsc($BASE . '/logout') ?>" class="inlineform">
      <button type="submit" class="ghost">登出</button>
    </form>
  </div>
</header>

<div id="link-down" class="banner danger" hidden>
  数据链路中断：连续多次请求失败，已退避到 30 秒。请检查网关日志与登录会话是否过期。
</div>
<div id="notice" class="banner info" hidden></div>

<nav class="tabs" aria-label="视图">
  <a class="tab<?= $view === 'summary' ? ' on' : '' ?>" href="#summary" data-view="summary">概览</a>
  <a class="tab<?= $view === 'mirrors' ? ' on' : '' ?>" href="#mirrors" data-view="mirrors">源池</a>
  <a class="tab<?= $view === 'decisions' ? ' on' : '' ?>" href="#decisions" data-view="decisions">决策追踪</a>
  <a class="tab<?= $view === 'cache' ? ' on' : '' ?>" href="#cache" data-view="cache">缓存</a>
  <span class="spacer"></span>
  <label class="pollctl" for="poll-factor">轮询
    <select id="poll-factor">
      <option value="0.5">快</option>
      <option value="1" selected>标准</option>
      <option value="2">慢</option>
      <option value="0">暂停</option>
    </select>
  </label>
</nav>

<main id="main">
  <section id="v-summary" class="view<?= $view === 'summary' ? ' on' : '' ?>" data-view="summary"></section>

  <section id="v-mirrors" class="view<?= $view === 'mirrors' ? ' on' : '' ?>" data-view="mirrors"></section>

  <section id="v-decisions" class="view<?= $view === 'decisions' ? ' on' : '' ?>" data-view="decisions">
<?= panelDecisionSsr($initial['decisions'] ?? null) ?>
  </section>

  <section id="v-cache" class="view<?= $view === 'cache' ? ' on' : '' ?>" data-view="cache"></section>
</main>

<footer class="foot">
  <span>GhAccel · 谶Hank · MIT</span>
  <span id="foot-meta">—</span>
</footer>

<script type="application/json" id="boot"><?= $bootJson ?></script>
<script type="module" src="<?= panelEsc($res('panel.js')) ?>"></script>
</body>
</html>
<?php

// ----------------------------------------------------------------------
// 渲染与登录页
// ----------------------------------------------------------------------

/**
 * 决策视图的服务端首屏。
 *
 * 为什么这一视图单独 SSR 而不是只丢给 boot JSON: 它渲染的 ref、源域名、失败分型与
 * curl 文案全部由外部输入决定, 首屏必须已经带着 HTML 转义出去; 前端 textContent 是
 * 第二道, 不是第一道。同时"未登录扫到 404"与"登录后首屏可读"两件事都要成立。
 */
function panelDecisionSsr(mixed $dec): string
{
    if (!is_array($dec)) {
        return '<p class="muted">决策数据首屏生成失败，前端将自动重试。</p>';
    }
    $h = static fn (string $s): string => panelEsc(panelSanitize($s, 120));
    $num = static fn (mixed $v, int $d = 4): string => is_numeric($v) ? number_format((float) $v, $d) : '—';

    $plan = (array) (($dec['decision'] ?? [])['plan'] ?? []);
    $ranked = (array) ($plan['ranked'] ?? []);
    $out = '<div class="ssr-block">';
    $out .= '<h2 class="h">决策追踪 · 重放</h2>';
    $out .= '<p class="meta-line">输入 <code>' . $h((string) ($dec['ref_input'] ?? '')) . '</code>'
        . ($dec['ref_default'] ?? false ? '（默认样例）' : '')
        . ' · 场景 <code>' . $h((string) ($dec['scene'] ?? '')) . '</code>'
        . ' · 身份 <code>' . $h((string) ($dec['identity_kind'] ?? '')) . '</code>'
        . ' · 摘要 <code>' . $h((string) ($dec['ref_digest'] ?? '')) . '</code></p>';
    if (($dec['parse_error'] ?? '') !== '') {
        $out .= '<p class="warnline">解析失败：' . $h((string) $dec['parse_error']) . '</p>';
    }
    if (($dec['upstream_host']['display'] ?? '') !== '') {
        $up = (array) $dec['upstream_host'];
        $out .= '<p class="meta-line">上游 host <code>' . $h((string) ($up['display'] ?? '')) . '</code>';
        if (($up['idn'] ?? false) === true) {
            $out .= ' · punycode <code>' . $h((string) ($up['punycode'] ?? '')) . '</code>'
                . ' <span class="badge idn">IDN 双列，防同形字</span>';
        }
        $out .= '</p>';
    }

    if ($ranked === []) {
        $out .= '<p class="warnline">重放结果为空 ranked —— 所有源都被硬约束筛掉了。</p>';
    } else {
        $out .= '<table class="tbl"><thead><tr><th>#</th><th>源</th><th>总分</th><th>因子（权重 × 归一值 = 贡献）</th>'
            . '<th>预测 ms</th><th>样本</th><th>放宽</th></tr></thead><tbody>';
        foreach ($ranked as $i => $row) {
            $facs = [];
            foreach ((array) ($row['factors'] ?? []) as $k => $f) {
                $facs[] = $h((string) $k) . ' ' . $num($f['weight'] ?? null) . '×' . $num($f['value'] ?? null)
                    . '=' . $num($f['contrib'] ?? null);
            }
            $ok = ($row['sum_matches_score'] ?? false) ? '一致' : '不一致';
            $out .= '<tr><td>' . (int) $i . '</td>'
                . '<td><code>' . $h((string) ($row['id'] ?? '')) . '</code></td>'
                // 显示两个数: 取整后的 score(排序用的视图)与贡献求和的精确值。面板必须能自证
                // "相加等于总分", 否则整套打分就没有可核对的入口。
                . '<td class="num">' . $num($row['score'] ?? null)
                . '<br><span class="muted">精确 ' . $num($row['score_exact'] ?? null) . '</span></td>'
                . '<td class="brk">' . implode(' · ', $facs) . ' <span class="muted">(Σ=' . $num($row['contrib_sum'] ?? null)
                . ' ' . $ok . ')</span></td>'
                . '<td class="num">' . $num($row['predicted_ms'] ?? null, 0) . '</td>'
                . '<td class="num">' . (int) (($row['breakdown'] ?? [])['samples'] ?? 0) . '</td>'
                . '<td>' . $h(implode(',', (array) ($row['relaxed'] ?? []))) . '</td></tr>';
        }
        $out .= '</tbody></table>';
    }

    $excl = (array) ($dec['excluded'] ?? []);
    if ($excl !== []) {
        $out .= '<h3 class="h3">未入选（为什么没选它）</h3><ul class="excl">';
        foreach ($excl as $e) {
            $out .= '<li><code>' . $h((string) ($e['id'] ?? '')) . '</code> '
                . '<span class="badge">' . $h((string) ($e['code'] ?? '')) . '</span> '
                . $h((string) ($e['detail'] ?? ''))
                . (isset($e['retry_after_s']) && $e['retry_after_s'] !== null
                    ? ' · 冷却剩 ' . $num($e['retry_after_s'], 1) . 's' : '')
                . '</li>';
        }
        $out .= '</ul>';
    } else {
        $out .= '<p class="muted">本次重放没有被硬约束剔除的源。</p>';
    }

    $flags = array_map('strval', (array) ($dec['relaxed_flags'] ?? []));
    $out .= '<p class="meta-line">放宽档 <code>' . ($flags === [] ? '无' : $h(implode(',', $flags))) . '</code>'
        . ' · 冷启动 ' . (($dec['cold_start'] ?? false) ? '是' : '否')
        . ' · top1-top2 分差 <code>' . $num($dec['score_gap'] ?? null) . '</code>'
        . ' · 快照 <code>' . $h((string) ($dec['snapshot_version'] ?? '')) . '</code></p>';

    $att = (array) ($dec['decision']['attempts'] ?? []);
    $out .= '<h3 class="h3">最近真实请求（观测流回读，共 ' . count($att) . ' 条）</h3>';
    if ($att === []) {
        $out .= '<p class="muted">观测流暂无记录：还没跑过真实请求，或日志已被压实轮转。</p>';
    } else {
        $out .= '<ul class="attempts">';
        foreach ($att as $a) {
            $out .= '<li><code>' . $h((string) ($a['req'] ?? '')) . '</code> <span class="muted">'
                . $h(date('H:i:s', (int) $a['at'])) . '</span> ref <code>' . $h((string) ($a['ref_digest'] ?? '')) . '</code>'
                . ' → ' . $h((string) ($a['outcome'] ?? '')) . '<ul>';
            foreach ((array) ($a['events'] ?? []) as $ev) {
                $out .= '<li class="ev"><code>' . $h((string) ($ev['source'] ?? '')) . '</code> '
                    . $h((string) ($ev['type'] ?? '')) . '/' . $h((string) ($ev['kind'] ?? ''))
                    . ' · ' . (int) ($ev['status'] ?? 0)
                    . ' · ' . $num($ev['ttfb_ms'] ?? null, 1) . 'ms'
                    . ' · ' . (int) ($ev['bytes'] ?? 0) . 'B'
                    . ' · ' . $h((string) ($ev['cache'] ?? ''))
                    . '</li>';
            }
            $out .= '</ul></li>';
        }
        $out .= '</ul>';
    }
    $out .= '<p class="note">' . $h((string) ($dec['note'] ?? '')) . '</p>';
    $out .= '</div>';

    return $out;
}

/**
 * 登录页。
 *
 * 只由显式入口 /{prefix}/login 渲染 —— 其他任何未登录访问都给 404, 不给扫描器"这里有个
 * 面板"的信号。表单没有内联脚本与 on* 属性, 与 CSP 的 script-src 'self' 完全兼容。
 */
function panelLoginPage(Config $cfg, string $base, string $error, string $action): void
{
    Http::noBuffering();
    Http::status($error === '' ? 200 : 401);
    panelHeader('Content-Type', 'text/html; charset=utf-8');
    panelHeader('Cache-Control', 'no-store');
    panelHeader('X-Content-Type-Options', 'nosniff');
    panelHeader('X-Frame-Options', 'DENY');
    panelHeader('Referrer-Policy', 'no-referrer');
    panelHeader('Cross-Origin-Resource-Policy', 'same-origin');
    panelHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        . "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'");

    $h = static fn (string $s): string => panelEsc($s);
    $hint = $cfg->str('app.contact', '');

    echo '<!doctype html><html lang="zh-CN" data-theme="auto"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<meta name="referrer" content="no-referrer">'
        . '<title>GhAccel 面板登录</title>'
        . '<link rel="stylesheet" href="' . $h($base . '/assets/panel.css') . '">'
        . '</head><body class="loginbody">'
        . '<main class="loginwrap"><form class="login" method="post" action="' . $h($action) . '">'
        . '<h1 class="brand">GhAccel <span class="tag">管理面板</span></h1>'
        . '<p class="muted">粘贴 <code>bin/token.php issue</code> 签发的管理令牌。'
        . '令牌只存 sha256 摘要，丢失无法找回，只能重签。</p>'
        . ($error === '' ? '' : '<p class="warnline">' . $h($error) . '</p>')
        . '<label class="fld" for="token">管理令牌<span></span></label>'
        . '<input id="token" name="token" type="password" autocomplete="off" spellcheck="false" required>'
        . '<button type="submit" class="primary">进入面板</button>'
        . '<p class="fineprint">会话 Cookie 为 host-only、HttpOnly、SameSite=Strict，且只发给面板前缀。'
        . ($hint === '' ? '' : ' 联系方式：' . $h($hint))
        . '</p></form></main></body></html>';
}
