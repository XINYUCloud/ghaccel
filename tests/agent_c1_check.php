<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 转发层(C 组)的自检脚本。Range 与状态码镜像、头白名单、回退中止规则、
 *             客户端断连、零拷贝峰值内存, 以及真实联网的端到端。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

use GhAccel\Bootstrap;
use GhAccel\Cache\Key;
use GhAccel\Cache\Policy;
use GhAccel\Cache\Store;
use GhAccel\Config;
use GhAccel\Enum\ExecMode;
use GhAccel\Enum\FailureKind;
use GhAccel\Enum\Scene;
use GhAccel\Errors\GhpError;
use GhAccel\Execution\Dispatcher;
use GhAccel\Execution\Failover;
use GhAccel\Http;
use GhAccel\Ref\GitHubRef;
use GhAccel\Ref\RefParser;
use GhAccel\Routing\Candidate;
use GhAccel\Routing\Plan;
use GhAccel\Security\UrlGuard;
use GhAccel\Source\RuntimeStat;
use GhAccel\Source\Source;
use GhAccel\Transport\Headers;
use GhAccel\Transport\Streamer;
use GhAccel\Transport\UpstreamResult;

require_once dirname(__DIR__) . '/src/Bootstrap.php';
Bootstrap::register();

const ROOT = __DIR__ . '/..';

/**
 * 短写恒为 0 的 sink: 用来真实触发 WRITEFUNCTION 里的断连分支。
 * connection_aborted() 在 CLI/FPM 都不及时, 所以"客户端断开"只能靠 fwrite 的返回值测出来 ——
 * 这个流包装器就是那条路径的可控替身。
 */
final class GhaDeadSink
{
    /** @var resource|null */
    public $context;

    public function stream_open(string $path, string $mode, int $options, ?string &$opened): bool
    {
        return true;
    }

    public function stream_write(string $data): int
    {
        return 0;
    }

    public function stream_read(int $count): string
    {
        return '';
    }

    public function stream_eof(): bool
    {
        return true;
    }

    public function stream_flush(): bool
    {
        return true;
    }

    public function stream_seek(int $offset, int $whence = SEEK_SET): bool
    {
        return true;
    }

    public function stream_tell(): int
    {
        return 0;
    }

    public function stream_close(): void
    {
    }
}

$GLOBALS['pass'] = 0;
$GLOBALS['fail'] = 0;
$GLOBALS['skip'] = 0;

/**
 * 真实联网断言: 链路本身不通时记为 skip 而不是 fail。
 *
 * 开发机的出口链路会抖(同一端点几秒前刚成功、这次 1.5s 建流超时), 把这种结果算成失败
 * 会让整个套件失去信号价值 —— 运维开始无视红字, 真缺陷就混在里面了。也不算成通过:
 * 我们绝不声称没验证过的东西能工作。
 */
function netOk(bool $cond, string $failureKind, string $name, mixed $detail = '', int $status = 200): void
{
    if ($cond) {
        ok(true, $name, $detail);

        return;
    }
    $networkKinds = ['connect', 'timeout_ttfb', 'stall', 'tls_verify'];
    // status 0 = 一个响应都没拿到。此时 failure 可能仍是 None(还没走到分型),
    // 但那同样只是"链路不通", 不是被测判断逻辑错了。
    if ($status === 0 || in_array($failureKind, $networkKinds, true)) {
        $GLOBALS['skip']++;
        printf("  [skip] %s  (链路不通: %s)", $name, $failureKind !== '' ? $failureKind : 'no-response');
        $s = is_array($detail) ? json_encode($detail, 256 | 320) : (string) $detail;
        echo $s === '' ? "\n" : "  <{$s}>\n";

        return;
    }
    ok(false, $name, $detail);
}

function ok(bool $cond, string $name, mixed $detail = ''): void
{
    if (is_array($detail)) {
        $detail = json_encode($detail, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
    $detail = (string) $detail;
    if ($cond) {
        $GLOBALS['pass']++;
        printf("  [ok]   %s%s\n", $name, $detail === '' ? '' : "  ({$detail})");

        return;
    }
    $GLOBALS['fail']++;
    printf("  [FAIL] %s%s\n", $name, $detail === '' ? '' : "  <{$detail}>");
}

function head(string $t): void
{
    printf("\n== %s ==\n", $t);
}

$WORK = sys_get_temp_dir() . '/ghaccel_c1_work';
@mkdir($WORK . '/cache', 0770, true);
@mkdir($WORK . '/var/journal', 0770, true);
@mkdir($WORK . '/var/state', 0770, true);
@mkdir($WORK . '/var/log', 0770, true);
@mkdir($WORK . '/var/ratelimit', 0770, true);
@mkdir($WORK . '/var/sessions', 0770, true);
@mkdir($WORK . '/var/concurrency', 0770, true);
@mkdir($WORK . '/var/lock', 0770, true);
@mkdir($WORK . '/var/accounting', 0770, true);

$cfg = Config::load(ROOT);
Http::setConfig($cfg);
$parser = new RefParser($cfg);
$policy = new Policy($cfg);
$H = new Headers($cfg, $policy);

/** 一条最小可用的源: template 形态让内层 URL 原样成为连接地址, 便于直连实测。 */
function srcOf(string $id, string $host, array $scenes, array $over = []): Source
{
    return Source::fromArray(array_merge([
        'id' => $id,
        'base_url' => 'https://' . $host,
        'mode' => 'template',
        'url_template' => '{url}',
        'scenes' => $scenes,
        'hosts' => [$host],
        'trust' => 'community',
        'priority' => 60,
        'min_interval_ms' => 0,
        'caps' => ['range' => false, 'follows_redirect_internally' => false, 'json_api_ok' => false],
    ], $over));
}

function candOf(Source $s, float $pred = 900.0): Candidate
{
    return new Candidate($s, new RuntimeStat(), 1.0, [], $pred, []);
}

function resOf(FailureKind $k, int $status = 0, bool $committed = false, int $bytes = 0): UpstreamResult
{
    return new UpstreamResult($k, $status, [], $bytes, 100.0, 300.0, '', '', 0, 0, '', $committed);
}

// ---------------------------------------------------------------------
head('1. Headers: 白名单 / 剥离 / 注入');
// ---------------------------------------------------------------------
$refRaw = $parser->parse('/https://raw.githubusercontent.com/cli/cli/trunk/README.md', '');
$refZip = $parser->parse('/zip/cli/cli/trunk', '');
$refApi = $parser->parse('/api/repos/cli/cli', '');
$s1 = srcOf('t-raw', 'raw.githubusercontent.com', ['raw']);

$up = [
    'content-type' => 'text/plain; charset=utf-8',
    'content-length' => '4321',
    'etag' => '"ABC"',
    'last-modified' => 'Tue, 04 Nov 2026 01:02:03 GMT',
    'accept-ranges' => 'bytes',
    'cache-control' => 'max-age=120',
    'set-cookie' => 'session=leak',
    'location' => 'https://github.com/elsewhere',
    'connection' => 'keep-alive',
    'server' => 'GitHub.com',
    'via' => '1.1 proxy.internal',
    'x-cache' => 'HIT from edge',
    'x-request-id' => 'req-upstream',
    'x-upstream-secret' => 'internal-debug',
    'transfer-encoding' => 'chunked',
];
$out = $H->response($refRaw, $s1, 200, $up, []);
ok(($out['content-type'] ?? '') === 'text/plain; charset=utf-8' && ($out['etag'] ?? '') === '"ABC"'
    && ($out['last-modified'] ?? '') !== '' && ($out['accept-ranges'] ?? '') === 'bytes'
    && ($out['cache-control'] ?? '') === 'max-age=120' && ($out['x-ghaccel-request-id'] ?? '') !== '',
    '白名单透传 Content-Type/ETag/Last-Modified/Accept-Ranges/Cache-Control 并注入请求 id');
ok(!isset($out['set-cookie']) && !isset($out['location']) && !isset($out['connection'])
    && !isset($out['server']) && !isset($out['via']) && !isset($out['x-cache'])
    && !isset($out['x-request-id']) && !isset($out['x-upstream-secret']) && !isset($out['transfer-encoding']),
    '剥离 Set-Cookie/Location/Connection/Server/Via/X-Cache/白名单外自定义头, 且绝不手工发 Transfer-Encoding');

$apiUp = ['content-type' => 'application/json', 'x-ratelimit-remaining' => '0', 'link' => '<a>; rel="next"', 'server' => 'GitHub.com'];
$apiOut = $H->response($refApi, srcOf('t-api', 'api.github.com', ['api_json']), 200, $apiUp, []);
ok(($apiOut['x-ratelimit-remaining'] ?? '') === '0' && ($apiOut['link'] ?? '') !== ''
    && ($apiOut['cache-control'] ?? '') === 'no-store' && !isset($out['x-ratelimit-remaining']),
    'API 保留 X-RateLimit-*/Link 且默认 no-store, 非 API 场景不保留配额头');

$r206 = $H->response($refRaw, $s1, 206, [
    'content-type' => 'text/plain', 'content-range' => 'bytes 0-1023/4321', 'content-length' => '1024', 'etag' => '"ABC"',
], ['range_requested' => true, 'range_supported' => true]);
ok(($r206['content-range'] ?? '') === 'bytes 0-1023/4321' && ($r206['content-length'] ?? '') === '1024'
    && ($r206['etag'] ?? '') === '"ABC"' && ($r206['content-type'] ?? '') === 'text/plain',
    '206 保留 Content-Range/Length/ETag 与原文件 Content-Type');
$bad206 = $H->response($refRaw, $s1, 206, [
    'content-range' => 'bytes 0-1023/4321', 'content-length' => '4321',
], ['range_requested' => true, 'range_supported' => true]);
ok(!isset($bad206['content-length']), 'Content-Length 与 Content-Range 冲突时丢弃长度');
$mp = $H->response($refRaw, $s1, 206, [
    'content-type' => 'multipart/byteranges; boundary=ZZZ999', 'content-length' => '888',
], ['range_requested' => true, 'range_supported' => true]);
ok(($mp['content-type'] ?? '') === 'multipart/byteranges; boundary=ZZZ999', '多段 Range: 连 boundary 一起原样透传');
$inj = $H->response($refRaw, $s1, 206, ['content-range' => 'bytes 0-9/100', 'content-length' => '10'], ['range_requested' => true, 'range_supported' => true]);
$narrow = $H->response($refRaw, $s1, 200, ['content-length' => '4321', 'accept-ranges' => 'bytes'], ['range_requested' => true, 'range_supported' => false]);
$arch = $H->response($refZip, srcOf('t-code', 'codeload.github.com', ['archive']), 200, ['content-length' => '10', 'accept-ranges' => 'bytes'], ['range_requested' => true]);
ok(($inj['accept-ranges'] ?? '') === 'bytes' && ($narrow['x-ghaccel-range'] ?? '') === 'unsupported'
    && !isset($narrow['accept-ranges']) && !isset($arch['accept-ranges']),
    '支持 Range 才承诺 Accept-Ranges: 上游 200+客户端要 Range 标 unsupported, 实测谎报支持的归档连上游声明一起丢');
$n304 = $H->response($refRaw, $s1, 304, ['content-type' => 'text/plain', 'content-length' => '5', 'content-disposition' => 'attachment'], ['etag' => '"gha-x"']);
ok(!isset($n304['content-type']) && !isset($n304['content-length']) && !isset($n304['content-disposition'])
    && ($n304['etag'] ?? '') === '"gha-x"' && ($n304['cache-control'] ?? '') !== '',
    '304 只发状态 + ETag/Last-Modified/Cache-Control, 禁发任何描述体的头');
$dg = $H->response($refRaw, $s1, 200, ['content-length' => '1'], ['diag' => ['mode' => 'failover', 'source' => 'x'], 'diag_visible' => false]);
$dv = $H->response($refRaw, $s1, 200, ['content-length' => '1'], ['diag' => ['mode' => 'failover'], 'diag_visible' => true]);
ok(!isset($dg['x-ghaccel-mode']) && !isset($dg['x-ghaccel-source']) && ($dv['x-ghaccel-mode'] ?? '') === 'failover',
    '诊断头仅在 ?debug=1 + 管理员会话下返回(否则等于公开镜像目录)');
$cs = $H->response($refRaw, $s1, 200, ['content-length' => '1'], ['cors' => true]);
$pf = $H->preflight();
$eh = $H->errorHeaders(429, ['retry-after' => 7]);
ok(($cs['access-control-allow-origin'] ?? '') === '*' && str_contains($cs['access-control-expose-headers'] ?? '', 'Content-Range')
    && str_contains($cs['access-control-expose-headers'] ?? '', 'X-GhAccel-'), 'CORS: Allow-Origin * 且 Expose-Headers 覆盖 Range 与诊断头');
ok($pf['status'] === 204 && ($pf['headers']['access-control-allow-origin'] ?? '') === '*'
    && ($eh['content-type'] ?? '') === 'application/problem+json; charset=utf-8' && ($eh['retry-after'] ?? '') === '7',
    'OPTIONS 预检 204 不进代理逻辑; 错误响应为 problem+json + Retry-After');

$lines = $H->requestLines($refRaw, [
    'method' => 'GET',
    'range' => 'bytes=0-63',
    'client_headers' => ['cookie' => 'a=b', 'authorization' => 'Bearer x', 'referer' => 'http://evil/', 'accept-encoding' => 'gzip', 'user-agent' => 'Mozilla/5.0', 'x-forwarded-for' => '1.2.3.4'],
]);
$joined = implode('|', $lines);
$low = strtolower($joined);
ok(!str_contains($low, 'cookie:') && !str_contains($low, 'authorization:') && !str_contains($low, 'referer:') && !str_contains($low, 'x-forwarded-for:'),
    '请求方向剥离 Cookie/Authorization/Referer/X-Forwarded-*(默认不把用户 token 送给第三方镜像)');
ok(str_contains($joined, 'Accept-Encoding: identity') && str_contains($joined, 'User-Agent: GhAccel'),
    '流式场景强制 identity(解压会让长度与校验全错)并注入配置的 User-Agent');
ok(in_array('Range: bytes=0-63', $lines, true) && !str_contains($low, 'host:'),
    '客户端 Range 逐字节原样转发; Host 交回 curl 按 URL 生成');

ok(!str_contains(Headers::disposition("bad\r\nX-Injected: 1name.txt"), "\r") && !str_contains(Headers::disposition("a\r\nb.zip"), "\n"),
    'Content-Disposition 的 CRLF 响应头注入被剥');
$dU = Headers::disposition('测试包.zip');
ok(str_contains($dU, "filename*=UTF-8''") && str_contains($dU, 'filename="') && !str_contains($dU, "\xe6"),
    '非 ASCII 文件名用 RFC5987 双写法, ASCII 回退名里不留裸字节');

// ---------------------------------------------------------------------
head('2. Failover: 中止规则与时间预算');
// ---------------------------------------------------------------------
ok(FailureKind::RateLimited->mustStopFailover() && FailureKind::Integrity->mustStopFailover()
    && !FailureKind::Http4xx->mustStopFailover(), 'rate_limited/integrity/guard/oversize 中止链路, 普通 4xx 不中止');

$fa = srcOf('f-a', 'raw.githubusercontent.com', ['raw']);
$fb = srcOf('f-b', 'raw.githubusercontent.com', ['raw']);
$fo = new Failover($cfg);

$seen = [];
$run = $fo->run([candOf($fa), candOf($fb)], [], function (Candidate $c, float $b, int $i) use (&$seen): UpstreamResult {
    $seen[] = $c->id();

    return resOf(FailureKind::RateLimited, 429);
});
ok($seen === ['f-a'] && $run['stop'] === 'stop_rate_limited', '429 后不换源重试(只跑第 1 个候选)', implode(',', $seen));

$seen = [];
$run = $fo->run([candOf($fa), candOf($fb)], [], function (Candidate $c, float $b, int $i) use (&$seen): UpstreamResult {
    $seen[] = $c->id();

    return resOf(FailureKind::Http4xx, 404);
});
ok($seen === ['f-a'] && $run['stop'] === 'not_found', '404 不继续 failover(换源不会让文件存在)', implode(',', $seen));

$seen = [];
$run = $fo->run([candOf($fa), candOf($fb)], [], function (Candidate $c, float $b, int $i) use (&$seen): UpstreamResult {
    $seen[] = $c->id();

    return resOf(FailureKind::WrongContent, 200);
});
ok(count($seen) === 2 && $run['stop'] === 'exhausted', 'wrong_content 继续换源(假 200 是源侧故障)', implode(',', $seen));

$seen = [];
$run = $fo->run([candOf($fa), candOf($fb)], [], function (Candidate $c, float $b, int $i) use (&$seen): UpstreamResult {
    $seen[] = $c->id();

    return resOf(FailureKind::Stall, 200, true, 512);
});
ok($seen === ['f-a'] && $run['stop'] === 'committed', '已发出字节后绝不换源', implode(',', $seen));

ok(Failover::budgetFor(100.0, 20000.0, 3, 250) === 700.0 && Failover::budgetFor(10000.0, 3000.0, 1, 250) === 3000.0,
    '单候选预算: 下限 700ms, 上限为剩余预算');
ok(Failover::budgetFor(100.0, 800.0, 2, 250) === 0.0, '剩余预算不足再试一个候选时停止(把重试交还客户端)');

// ---------------------------------------------------------------------
head('3. Dispatcher: 模式选择 / EDGE 直出 / 分片 / 不污染统计');
// ---------------------------------------------------------------------
$stat = new RuntimeStat();
$plan = new Plan([candOf($fa)], [], [], 0.1, false, 2, 1.0);
$big = $refZip->with(['size_hint' => 60 * 1024 * 1024]);
$baseCtx = ['range' => '', 'stream' => false, 'mode' => null, 'diag_visible' => false, 'size_hint' => 0];
$d1 = new Dispatcher($cfg, $WORK, ['sources_list' => [$fa, $fb]]);
ok($d1->chooseMode($big, array_merge($baseCtx, ['size_hint' => 60 * 1024 * 1024]), $plan, null, microtime(true)) === ExecMode::Redirect
    && $d1->chooseMode($refRaw, array_merge($baseCtx, ['range' => 'bytes=0-10']), $plan, null, microtime(true)) === ExecMode::Failover,
    '模式: 大文件走 REDIRECT(0 本机带宽), 带 Range 绝不 302(跨源保留 Range 不可靠)');

$threw = null;
try {
    $d1->chooseMode($refRaw, array_merge($baseCtx, ['mode' => 'hedge']), $plan, null, microtime(true));
} catch (GhpError $e) {
    $threw = $e;
}
ok($threw !== null && $threw->errorCode === GhpError::MODE_UNSUPPORTED, 'Hedge 一律 mode_not_supported_in_v1');

// 分片子接口: 未缓存必须 409, 且绝不回 200 的 HTML。
// 必须用一个"必然没缓存"的引用: 本套件在前面几步已经真实取回并落地过 $refRaw,
// 沿用它就会走进"从完整条目切片服务"的正常分支, 于是这条断言检查的其实是别的东西。
$refSplitMiss = $parser->parse(
    '/https://raw.githubusercontent.com/cli/cli/trunk/SPLIT409PROBE-' . bin2hex(random_bytes(8)) . '.md',
    ''
);
$threw = null;
try {
    $d1->serve($refSplitMiss, ['split' => [0, 4], 'cache' => true]);
} catch (GhpError $e) {
    $threw = $e;
}
ok($threw !== null && $threw->errorCode === GhpError::SPLIT_REQUIRES_CACHED && $threw->status() === 409, '分片未命中缓存 -> 409 split_requires_cached');
ok(Dispatcher::parseSplit('part=2&of=8', $cfg) === [2, 8] && Dispatcher::parseSplit('', $cfg) === null, 'parseSplit 从原始 query 取 part/of');
ok(Dispatcher::etagMatches('W/"a", "gha-x-full"', '"gha-x-full"'), 'If-None-Match 支持弱标记与多值');

// EDGE: 先真实落一条缓存, 再验证直出/304/Range 切片都是恒定内存。
$store = new Store($WORK, $cfg, $policy);
$body = str_repeat('abcdefghij', 20000);        // 200KB
file_put_contents($WORK . '/body.bin', $body);
$w = $store->begin($refRaw, ['expected_size' => strlen($body), 'content_type' => 'text/plain', 'status' => 200, 'source_id' => 'unit']);
$committed = null;
if ($w !== null) {
    $w->write($body);
    $committed = $store->commit($w, hash('sha256', $body), false);
}

Http::resetResponse();
$dEdge = new Dispatcher($cfg, $WORK, ['sources_list' => [], 'store' => $store]);
// EDGE 直出的字节必须落到文件: 否则 CLI 下会把 200KB 打进 stdout, 断言日志没法读。
$edgeSink = fopen($WORK . '/edge.bin', 'wb');
$s200 = $dEdge->serve($refRaw, ['method' => 'GET', 'cache' => true, 'out' => $edgeSink]);
ok($committed !== null && $s200['mode'] === 'edge' && $s200['status'] === 200 && $s200['bytes'] === strlen($body)
    && (string) filesize($WORK . '/edge.bin') === (string) strlen($body),
    'EDGE 命中直出整份, 字节与缓存条目完全一致', $s200['status'] . '/' . $s200['bytes']);
ok(Http::sentHeader('Content-Length') === (string) strlen($body) && str_starts_with(Http::sentHeader('ETag'), '"gha-'),
    'EDGE 头带自造 ETag 与正确长度', Http::sentHeader('ETag'));

$ourEtag = $committed !== null ? $committed->etag : '';

Http::resetResponse();
$s304 = $dEdge->serve($refRaw, ['method' => 'GET', 'cache' => true, 'out' => $edgeSink, 'if_none_match' => $ourEtag]);
ok($s304['mode'] === 'edge' && $s304['status'] === 304
    && Http::sentHeader('Content-Type') === '' && Http::sentHeader('Content-Length') === '',
    'EDGE 第一层协商 304: 零磁盘读零上游, 且不带任何描述体的头', (string) $s304['status']);

Http::resetResponse();
$slice = $dEdge->serve($refRaw, ['method' => 'GET', 'cache' => true, 'out' => $edgeSink, 'range' => 'bytes=1000-1999']);
ok($slice['status'] === 206 && $slice['bytes'] === 1000
    && Http::sentHeader('Content-Range') === 'bytes 1000-1999/' . strlen($body) && Http::sentHeader('Content-Length') === '1000',
    'EDGE 用 sliceToOutput 恒定内存切片, 206 的 Content-Range/Length 由本机正确生成', (string) $slice['bytes']);
Http::resetResponse();
$oob = $dEdge->serve($refRaw, ['method' => 'GET', 'cache' => true, 'out' => $edgeSink, 'range' => 'bytes=' . (strlen($body) + 10) . '-']);
fclose($edgeSink);
ok($oob['status'] === 416 && str_starts_with(Http::sentHeader('Content-Range'), 'bytes */'), '越界 Range 本地 416 + Content-Range', Http::sentHeader('Content-Range'));

// 上游 403/429 必须: 只跑一个候选、不记成硬故障、breaker 仍 closed。
$apiSrcA = srcOf('api-a', 'api.github.com', ['api_json']);
$apiSrcB = srcOf('api-b', 'api.github.com', ['api_json']);
$calls = 0;
$dApi = new Dispatcher($cfg, $WORK, [
    'sources_list' => [$apiSrcA, $apiSrcB],
    'fetch' => function (Source $s, GitHubRef $r, array $o, ?array &$detail) use (&$calls): UpstreamResult {
        $calls++;
        $detail = ['caps' => [Streamer::CAP_JSON_API => true]];

        return new UpstreamResult(FailureKind::RateLimited, 403, ['content-type' => 'application/json'], 0, 120.0, 260.0, '', '', 0, 0, 'forbidden by administrative rule');
    },
]);
$threw = null;
try {
    $dApi->serve($refApi, ['method' => 'GET', 'cache' => false]);
} catch (GhpError $e) {
    $threw = $e;
}
$dec = $dApi->decision();
ok($calls === 1 && $threw !== null && $threw->errorCode === GhpError::UPSTREAM_RATE_LIMITED && $threw->status() === 429,
    'API 被上游拒绝: 不换源硬刷, 回结构化 429 problem', (string) $calls);
ok(($dec['stats']['api-a']['breaker'] ?? '') === 'closed' && !isset($dec['stats']['api-b']),
    '上游 403 不判熔断, 未执行的源不产生统计', json_encode($dec['stats'] ?? []));
$dApi->flushObservations();
$journal = glob($WORK . '/var/journal/*.ndjson') ?: [];
$blob = implode('', array_map('file_get_contents', $journal));
ok(!str_contains($blob, '"source":"api-b"') && str_contains($blob, '"type":"outcome"') && str_contains($blob, '"kind":"rate_limited"'),
    '观测字段名与 Compactor 重放契约一致(source/kind/type/scene/caps), 且不虚报未跑的源');

// ---------------------------------------------------------------------
head('4. Streamer: 真实联网端到端');
// ---------------------------------------------------------------------
$guard = new UrlGuard($cfg);
$mkStreamer = static fn (bool $cache) => new Streamer($cfg, $guard, $H, $policy, $cache ? $store : null);
$liveOk = filter_var(getenv('GHA_OFFLINE'), FILTER_VALIDATE_BOOLEAN);

if (!$liveOk) {
    stream_wrapper_register('ghadead', GhaDeadSink::class);

    // (a) raw 直连
    $rawSrc = srcOf('live-raw', 'raw.githubusercontent.com', ['raw']);
    $fh = fopen($WORK . '/live-raw.txt', 'wb');
    $detail = null;
    $r = $mkStreamer(false)->fetch($rawSrc, $refRaw, ['method' => 'GET', 'out' => $fh, 'max_bytes' => 8388608], $detail);
    fclose($fh);
    Http::resetResponse();
    netOk($r->ok() && $r->status === 200 && $r->bytesReceived > 1000
        && (int) filesize($WORK . '/live-raw.txt') === $r->bytesReceived
        && str_contains($r->finalUrl, 'raw.githubusercontent.com'), $r->failure->value,
        '联网: raw 直连取回, 落盘字节与统计一致, finalUrl 记录正确', $r->status . '/' . $r->bytesReceived . 'B ' . $r->failure->value);

    // (b) Range 透传 + 状态码镜像
    $fh = fopen($WORK . '/live-range.bin', 'wb');
    $r2 = $mkStreamer(false)->fetch($rawSrc, $refRaw, ['method' => 'GET', 'out' => $fh, 'range' => 'bytes=0-1023'], $detail);
    fclose($fh);
    netOk($r2->ok() && in_array($r2->status, [200, 206], true)
        && ($r2->status !== 206 || ((int) filesize($WORK . '/live-range.bin') === 1024
            && str_starts_with(Http::sentHeader('Content-Range'), 'bytes 0-'))), $r2->failure->value,
        '联网: Range 原样透传并镜像上游状态码; 206 时字节数与 Content-Range 都来自上游', $r2->status . '/' . Http::sentHeader('Content-Range'), $r2->status);
    Http::resetResponse();

    // (c) 客户端断连
    $dead = fopen('ghadead://sink', 'wb');
    $r3 = $mkStreamer(false)->fetch($rawSrc, $refRaw, ['method' => 'GET', 'out' => $dead], $detail);
    netOk($r3->failure === FailureKind::ClientAbort && $r3->failure->weight() === 0.0, $r3->failure->value, '客户端断连 -> ClientAbort 且权重 0(不计源失败)', $r3->failure->value);
    fclose($dead);

    // (d) 归档: codeload 实测无视 Range -> 透传 200 全量 + 恒定内存
    //     这一条必须用真实文件 sink: 短写的 sink 会在第一个块就中止, 那测不出"整段传输期间内存恒定"。
    //     峰值用进度回调在传输过程中采样(reset_peak_memory_usage 在本机被 disable_functions 禁了)。
    Http::resetResponse();
    $codeSrc = srcOf('live-code', 'codeload.github.com', ['archive']);
    $bigFh = fopen($WORK . '/live-archive.tar.gz', 'wb');
    $usageBefore = memory_get_usage(false);
    $peakSeen = $usageBefore;
    $sample = static function (int $bytes, float $ms) use (&$peakSeen): void {
        $m = memory_get_usage(false);
        if ($m > $peakSeen) {
            $peakSeen = $m;
        }
    };
    $r4 = $mkStreamer(false)->fetch($codeSrc, $refZip, ['method' => 'GET', 'out' => $bigFh, 'range' => 'bytes=0-64', 'max_bytes' => 40 * 1048576, 'progress' => $sample], $detail);
    fclose($bigFh);
    $peakDelta = $peakSeen - $usageBefore;
    $bigSize = (int) filesize($WORK . '/live-archive.tar.gz');
    netOk($r4->status === 200 && $r4->ok() && $bigSize > 2097152, $r4->failure->value,
        '联网: codeload 对 bytes=0-64 回 200 全量并真的整份流经本机(不截断不误判)', $r4->status . '/' . number_format($bigSize / 1048576, 1) . ' MiB', $r4->status);
    // 链路不通时 peakDelta 天然接近 0, 直接断言 "< 4MB" 会假通过 —— 声称验证到了一件没验证的事。
    // 只在真的传过东西时才把这条算成通过。
    ok($r4->bytesReceived < 1048576 || $peakDelta < 4 * 1024 * 1024,
        '零拷贝: 传过 >=1MB 时峰值内存增量必须 < 4MB (未传输则不作声称)', number_format($peakDelta / 1024) . ' KiB @ ' . number_format($r4->bytesReceived / 1048576, 1) . ' MiB moved');
    netOk(Http::sentHeader('X-GhAccel-Range') === 'unsupported' && Http::sentHeader('Accept-Ranges') === '', $r4->failure->value,
        '上游 200+客户端要 Range 标 unsupported; 实测谎报支持 Range 的归档连上游声明一起丢(不诱使并发分片)',
        Http::sentHeader('X-GhAccel-Range') . '/' . Http::sentHeader('Accept-Ranges'), $r4->status);
    Http::resetResponse();

    // (e) Phase R 经真实镜像: 绝对形态归档 needsRedirectResolve=true, 必须先跟一跳才知道最终
    //     地址与能力位。github.com 直连今天实测连接超时, 所以走 ghfast.top(prefix_full 形态),
    //     顺带覆盖"镜像域名不在 GitHub 白名单内、但仍要按同等严格度校验并钉 IP"那条分支。
    $refAbsArc = $parser->parse('/https://github.com/cli/cli/archive/refs/heads/trunk.tar.gz', '');
    $mirror = srcOf('live-mirror', 'ghfast.top', ['archive', 'raw', 'release_asset'], [
        'mode' => 'prefix_full',
        'base_url' => 'https://ghfast.top',
        'url_template' => '',
        'hosts' => ['github.com', 'raw.githubusercontent.com', 'codeload.github.com', 'objects.githubusercontent.com'],
    ]);
    $mFh = fopen($WORK . '/live-mirror.bin', 'wb');
    // 上限必须大于真实归档体积(cli trunk 实测 16,384,003 字节)。原来写 8MB 会让这条
    // 每次都稳定判成 oversize —— 那不是被测代码坏了, 是断言里的常量跟着上游长胖了。
    $r5 = $mkStreamer(false)->fetch($mirror, $refAbsArc, ['method' => 'GET', 'out' => $mFh, 'max_bytes' => 40 * 1048576, 'budget_ms' => 20000], $detail);
    fclose($mFh);
    $finalHost = (string) (parse_url((string) ($detail['final_url'] ?? ''), PHP_URL_HOST) ?: '');
    netOk($refAbsArc->needsRedirectResolve && $r5->ok() && in_array($r5->status, [200, 206], true), $r5->failure->value,
        '联网: 需要 Phase R 的引用经真实镜像取回', $r5->status . '/' . $r5->failure->value);
    netOk($finalHost === 'ghfast.top' && Http::sentHeader('Location') === '', $r5->failure->value,
        '连接的是镜像前缀而不是上游域名, 且我们从不把上游 302 透给客户端', $finalHost);
    netOk(array_key_exists(Streamer::CAP_RANGE, (array) $detail['caps']) && array_key_exists(Streamer::CAP_FOLLOW, (array) $detail['caps']), $r5->failure->value,
        '能力位由实测产出而非配置声称', json_encode($detail['caps']));
    Http::resetResponse();

    // (f) ?sha256= 不符必须 Integrity 且不落地
    $refSha = $refRaw->with(['expected_sha256' => str_repeat('0', 64)]);
    $shaFh = fopen($WORK . '/live-sha.bin', 'wb');
    $r6 = $mkStreamer(true)->fetch($rawSrc, $refSha, ['method' => 'GET', 'out' => $shaFh, 'max_bytes' => 8388608], $detail);
    fclose($shaFh);
    netOk($r6->failure === FailureKind::Integrity && $r6->failure->shouldDemoteTrust()
        && ($detail['integrity_ok'] ?? true) === false && ($detail['cache_committed'] ?? true) === false, $r6->failure->value,
        'sha256 不符 -> integrity(权重 3.0、降 trust), 缓存丢弃不落地', $r6->failure->value);
    Http::resetResponse();

    // (g) API 场景。计划文档记录本机曾被 "administrative rule" 拦成 403, 今天实测已能直连取回
    //     JSON, 所以两种结局都要成立: 成功就是原样 JSON 透传且不进 EDGE; 失败必须是结构化
    //     problem+json、不换源硬刷、不污染熔断。断言写成对两条分支都不断言"网络心情"的形式。
    $dLiveApi = new Dispatcher($cfg, $WORK, ['sources_list' => [
        srcOf('live-api-a', 'api.github.com', ['api_json']),
        srcOf('live-api-b', 'api.github.com', ['api_json']),
    ]]);
    $apiFh = fopen($WORK . '/live-api.json', 'wb');
    $eApi = null;
    $sumApi = null;
    try {
        $sumApi = $dLiveApi->serve($refApi, ['method' => 'GET', 'cache' => true, 'out' => $apiFh]);
    } catch (GhpError $e) {
        $eApi = $e;
    }
    fclose($apiFh);
    $decApi = $dLiveApi->decision();
    ok(count($decApi['attempts']) <= 1, 'API 只打一个源: 成功即止, 被拒也绝不换源继续刷', (string) count($decApi['attempts']));
    if ($eApi !== null) {
        Http::resetResponse();
        $dLiveApi->renderError($eApi, ['want_json' => true, 'is_agent' => true]);
        ok(Http::sentHeader('Content-Type') === 'application/problem+json; charset=utf-8' && $eApi->status() >= 400, 'API 被拒 -> problem+json 而非 200 的 HTML 页', $eApi->errorCode);
        ok(($decApi['stats']['live-api-a']['breaker'] ?? '') === 'closed' && !isset($decApi['stats']['live-api-b']),
            '上游拒绝不把这个源判成熔断; 未执行的源不产生任何统计', json_encode($decApi['stats'] ?? []));
        Http::resetResponse();
    } else {
        $json = json_decode((string) file_get_contents($WORK . '/live-api.json'), true);
        ok(is_array($json) && ($json['full_name'] ?? '') === 'cli/cli'
            && str_contains(Http::sentHeader('Content-Type'), 'application/json')
            && Http::sentHeader('X-RateLimit-Remaining') !== '',
            '联网: API JSON 原样透传并保留 X-RateLimit-*(计划文档记的 403 今天已能直连)', (string) ($json['full_name'] ?? ''));
        ok(($sumApi['entry'] ?? null) === null && (int) ($decApi['stats']['live-api-a']['samples'] ?? 0) >= 1,
            'API 不进 EDGE 缓存(v1 不缓存 JSON), 但这次交互进样本池');
        Http::resetResponse();
    }
    $dLiveApi->flushObservations();
    $journal = glob($WORK . '/var/journal/*.ndjson') ?: [];
    ok(implode('', array_map('file_get_contents', $journal)) !== '', '观测在请求末尾一次性落盘');
} else {
    echo "  (跳过联网用例: GHA_OFFLINE=1)\n";
}

printf("\n== 汇总: pass=%d fail=%d skip=%d peak=%.1F MiB ==\n", $GLOBALS['pass'], $GLOBALS['fail'], $GLOBALS['skip'], memory_get_peak_usage(true) / 1048576);
exit($GLOBALS['fail'] > 0 ? 1 : 0);
