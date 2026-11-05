<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 压实入口(cron)与待探活队列的排空。把请求路径上不做的事(全量重放、
 *             离线分位数、能力位探测)集中在这里跑一次。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 * @see       https://github.com/  完整版权与许可信息见仓库根目录 LICENSE
 */

declare(strict_types=1);

if (PHP_VERSION_ID < 80100) {
    fwrite(STDERR, 'GhAccel 需要 PHP >= 8.1, 当前 ' . PHP_VERSION . "\n");
    exit(1);
}

$ROOT = dirname(__DIR__);
require $ROOT . '/src/Bootstrap.php';
require $ROOT . '/src/Config.php';
require $ROOT . '/src/Http.php';
GhAccel\Bootstrap::register();

use GhAccel\Config;
use GhAccel\Enum\Scene;
use GhAccel\Http;
use GhAccel\Security\IpRange;
use GhAccel\Source\Source;
use GhAccel\Store\Compactor;
use GhAccel\Store\Observatory;

/**
 * 为什么探活放在这里而不是面板里: 面板与代理共用同一个 PHP 进程池, 一次 3 秒的同步
 * 上游请求就占住一个 worker, 两个页签点几下就能把并发槽打满。面板只写"待探活"标记,
 * 真正打上游的是这个 CLI 入口(或下一次真实请求的实测能力位)。
 *
 * 上游可达性在这里是**允许**阻塞的, 但每条压到 1.5s 以内并如实打印 —— cron 里堆十个
 * 超时源会跑十几秒, 而面板上那个按钮的回执必须说清"这不是同步测出来的"。
 */
function compactParse(array $argv): array
{
    $flags = [];
    $opts = [];
    foreach (array_slice($argv, 1) as $a) {
        $a = (string) $a;
        if (!str_starts_with($a, '--')) {
            $flags['pos'][] = $a;
            continue;
        }
        $body = substr($a, 2);
        if (str_contains($body, '=')) {
            [$k, $v] = explode('=', $body, 2);
            $opts[strtolower(trim($k))] = trim($v);
        } else {
            $opts[strtolower(trim($body))] = '1';
        }
    }

    return [$opts, $flags];
}

function compactUsage(): void
{
    fwrite(STDOUT, <<<TXT
用法: php bin/compact.php [--once] [--no-probe] [--probe-timeout-ms=1500] [--help]

  --once                  跑一轮压实(Compactor::run(true))。不给参数时行为相同。
  --no-probe              只压实, 不排空面板写下的待探活队列。
  --probe-timeout-ms=     单次探活的时间上限, 默认 1500(与 budgets.connect_timeout_ms 同级)。

退出码: 0 压实成功; 1 锁被占用/快照写失败/探测异常。
计划任务请用站点的运行用户(通常是 www)执行: root 写出的文件 www 读不到是最常见故障。
TXT . "\n");
}

function compactSay(string $s): void
{
    fwrite(STDOUT, $s . "\n");
}

[$opts] = compactParse($argv);
if (isset($opts['help']) || isset($opts['h'])) {
    compactUsage();
    exit(0);
}

$cfg = Config::load($ROOT);
$root = $ROOT;

// ------------------------------------------------------------------
// 1) 排空待探活
// ------------------------------------------------------------------
$probeFile = $root . '/var/state/probes.json';
$drained = [];
$skippedProbes = isset($opts['no-probe']);
if (!$skippedProbes && is_readable($probeFile)) {
    $data = json_decode((string) @file_get_contents($probeFile), true);
    $pending = is_array($data) ? (array) ($data['pending'] ?? []) : [];
    if ($pending !== []) {
        $obs = new Observatory($root, $cfg);
        $repo = (new GhAccel\Source\SourceRepo($cfg, $root));
        $timeoutMs = max(300, min(3000, (int) ($opts['probe-timeout-ms'] ?? 1500)));
        foreach (array_keys($pending) as $id) {
            $id = (string) $id;
            $src = $repo->get($id);
            if ($src === null) {
                // 源已经被删: 留在队列里只会每轮空转一次, 直接摘掉。
                unset($pending[$id]);
                continue;
            }
            $r = probeSource($src, $cfg, $timeoutMs);
            $obs->record([
                'source' => $id,
                'type' => 'outcome',
                'kind' => $r['kind'],
                'scene' => Scene::Raw->value,
                'ttfb_ms' => $r['ttfb_ms'],
                // 探活在拿到首字节后就主动掐断, 吞吐不是实测值 —— 写 0 让 Latency 不去更新它,
                // 而不是编一个数字进去。
                'thr_bps' => 0.0,
                'bytes' => 0,
                'caps' => $r['caps'],
                'observed_at' => microtime(true),
                'status' => $r['status'],
                'committed' => false,
                'mode' => 'probe',
                'req' => 'probe' . substr(hash('sha256', $id . microtime(true)), 0, 10),
            ]);
            $drained[$id] = $r;
            unset($pending[$id]);
        }
        $obs->flush();
        Config::atomicWrite($probeFile, (string) json_encode([
            'pending' => (object) $pending,
            'updated_at' => time(),
            'last_drained' => array_map(static fn (array $x): array => [
                'kind' => $x['kind'], 'status' => $x['status'], 'ttfb_ms' => $x['ttfb_ms'], 'caps' => $x['caps'],
            ], $drained),
        ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
    }
}

// ------------------------------------------------------------------
// 2) 压实
// ------------------------------------------------------------------
$startedAt = microtime(true);
$res = (new Compactor($root, $cfg))->run(true);
$took = round((microtime(true) - $startedAt) * 1000.0, 1);

compactSay('GhAccel 压实 ' . date('Y-m-d H:i:s'));
if ($drained !== []) {
    compactSay('待探活队列(' . count($drained) . ' 个, 同步阻塞上限 '
        . (int) ($opts['probe-timeout-ms'] ?? 1500) . 'ms/个):');
    foreach ($drained as $id => $r) {
        $caps = [];
        foreach ((array) $r['caps'] as $k => $v) {
            $caps[] = $k . '=' . ($v ? 'yes' : 'no');
        }
        compactSay(sprintf(
            '  %-22s kind=%-12s status=%-5s ttfb=%8.1fms %s%s',
            $id,
            $r['kind'],
            (string) $r['status'],
            $r['ttfb_ms'],
            implode(' ', $caps),
            $r['note'] === '' ? '' : '  (' . $r['note'] . ')'
        ));
    }
} elseif (!$skippedProbes) {
    compactSay('待探活队列: 空');
}

if (($res['locked'] ?? false) === true) {
    // 抢不到锁不是失败, 但在 cron 输出里必须显眼: 否则"面板数字不动"会被归因到采集。
    compactSay('结果: 跳过 —— 已有单写者持有压实锁' . (isset($res['error']) ? " ({$res['error']})" : ''));
    exit(1);
}

compactSay(sprintf(
    '结果: 重放观测=%d 源=%d 轮转文件=%d 缓存释放=%d 写入快照=%s 耗时=%.1fms',
    (int) ($res['obs'] ?? 0),
    (int) ($res['sources'] ?? 0),
    (int) ($res['rotated'] ?? 0),
    (int) ($res['freed'] ?? 0),
    empty($res['written']) ? 'false' : 'true',
    $took
));
if (isset($res['skipped'])) {
    compactSay('说明: ' . $res['skipped'] . ' —— 没有新观测也没轮转, 不写新版本快照(空转会在 var/state 堆垃圾文件)。');
}

exit(empty($res['written']) && !isset($res['skipped']) ? 1 : 0);

// ------------------------------------------------------------------
// 探活实现
// ------------------------------------------------------------------

/**
 * 单次探活: 拿首字节与两个能力位就掐断。
 *
 * 只测 range 与 follows_redirect_internally: json_api_ok 需要另一条 api.github.com 的
 * 探针, 而本机实测 api 被管理规则拦截 —— 用它做默认探测会把"上游拒绝"误记成"源不支持"。
 * 该位留给真实 API 请求的实测回写。
 *
 * 不做 host 白名单以外的任何事, 也不解析返回字节; 时间上限 1.5s 是硬约束。
 *
 * @return array{kind:string,status:int,ttfb_ms:float,caps:array<string,bool>,note:string}
 */
function probeSource(Source $src, Config $cfg, int $timeoutMs): array
{
    $inner = 'https://raw.githubusercontent.com/octocat/Hello-World/trunk/README';
    $url = $src->accelerate($inner);
    $out = ['kind' => 'connect', 'status' => 0, 'ttfb_ms' => 0.0, 'caps' => [], 'note' => ''];

    if (!function_exists('curl_init')) {
        $out['note'] = 'curl 不可用';

        return $out;
    }

    $ch = curl_init();
    if ($ch === false) {
        $out['note'] = 'curl_init 失败';

        return $out;
    }

    $firstAt = null;
    $got = 0;
    // 收到第一个数据块就返回 0 中止传输: 探活要的是状态码与首字节时间, 不是内容。
    // 不这么做的话, 不尊重 Range 的镜像会把整个文件打到 cron 的标准输出流量里。
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HTTPGET, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, false);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_NOPROGRESS, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, max(200, min(1200, $timeoutMs)));
    curl_setopt($ch, CURLOPT_TIMEOUT_MS, $timeoutMs);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_NOSIGNAL, 1);
    curl_setopt($ch, CURLOPT_TCP_KEEPALIVE, 1);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, null);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Range: bytes=0-64',
        'User-Agent: ' . $cfg->str('app.user_agent', 'GhAccel/1.0'),
        'Accept: */*',
    ]);
    curl_setopt($ch, CURLOPT_WRITEFUNCTION, static function ($ch, string $chunk) use (&$firstAt, &$got): int {
        if ($firstAt === null) {
            $firstAt = microtime(true);
        }
        $got += strlen($chunk);

        return 0;
    });
    // 这些常量在精简的 curl 构建里可能缺席, 逐项按存在再设。
    foreach ([
        'CURLOPT_IPRESOLVE' => defined('CURLOPT_IPRESOLVE') ? CURL_IPRESOLVE_V4 : null,
        'CURLOPT_PROTOCOLS_STR' => null,
    ] as $name => $value) {
        if (defined($name) && $value !== null) {
            curl_setopt($ch, constant($name), $value);
        }
    }
    if (defined('CURLOPT_PROTOCOLS_STR')) {
        curl_setopt($ch, CURLOPT_PROTOCOLS_STR, 'https');
    }

    $ok = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $start = (float) curl_getinfo($ch, CURLINFO_STARTTRANSFER_TIME);
    $total = (float) curl_getinfo($ch, CURLINFO_TOTAL_TIME);
    $errNo = (int) curl_errno($ch);
    $errStr = (string) curl_error($ch);
    curl_close($ch);

    // 主动中止会让 curl_exec 返回 false, 这是设计如此而不是失败: 判据看有没有状态码。
    if ($status > 0) {
        $out['status'] = $status;
        $out['ttfb_ms'] = round(max(0.0, ($start > 0 ? $start : $total) * 1000.0), 1);
        $out['kind'] = $status >= 500 ? 'http_5xx' : ($status >= 400 ? 'http_4xx' : 'none');
        $out['caps']['range'] = $status === 206;
        // 不跟随重定向: 3xx 就说明该源把跳转原样回吐给客户端, Release 场景等于不加速。
        $out['caps']['follows_redirect_internally'] = $status < 300 || $status >= 400;
        if ($status >= 300 && $status < 400) {
            $out['note'] = '回吐 3xx, 判定为不内部跟跳';
        }
        if ($out['caps']['range'] === false && $status === 200) {
            $out['note'] = '无视 Range 回了 200 全量(与 codeload 同一类行为)';
        }
    } else {
        // 别假设 curl 扩展的所有常量都在: 本机实测有 curl 错误码常量未导出的情况, 28 是
        // CURLE_OPERATION_TIMEDOUT 的标准值, 拿不到常量时按数值比。
        $timedout = defined('CURLE_OPERATION_TIMEDOUT') ? (int) CURLE_OPERATION_TIMEDOUT : 28;
        $out['kind'] = $errNo === $timedout ? 'timeout_ttfb' : 'connect';
        // 只带上 curl 的短文本, 不拼 URL: 探活 URL 里可能带令牌的镜像参数。
        $out['note'] = 'curl#' . $errNo . ' ' . substr(preg_replace('/[\x00-\x1F]/', ' ', $errStr) ?? '', 0, 60);
    }

    return $out;
}
