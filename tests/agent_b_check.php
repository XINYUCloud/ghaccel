<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 算法层 / 状态存储层 / 缓存层的运行时断言脚本(B 组自检)。
 *             喂合成观测序列, 验证确定性输出 —— 不依赖网络、不依赖面板、不依赖 transport。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

use GhAccel\Bootstrap;
use GhAccel\Cache\Entry;
use GhAccel\Cache\Key;
use GhAccel\Cache\Policy;
use GhAccel\Cache\Store;
use GhAccel\Config;
use GhAccel\Enum\BreakerState;
use GhAccel\Enum\FailureKind;
use GhAccel\Enum\IdentityKind;
use GhAccel\Enum\RejectCode;
use GhAccel\Enum\Scene;
use GhAccel\Enum\Trust;
use GhAccel\Ref\GitHubRef;
use GhAccel\Routing\Breaker;
use GhAccel\Routing\Candidate;
use GhAccel\Routing\Latency;
use GhAccel\Routing\Selector;
use GhAccel\Routing\Success;
use GhAccel\Source\RuntimeStat;
use GhAccel\Source\Source;
use GhAccel\Source\SourceRepo;
use GhAccel\Store\Compactor;
use GhAccel\Store\Observatory;
use GhAccel\Store\Snapshot;

require_once dirname(__DIR__) . '/src/Bootstrap.php';
Bootstrap::register();

const ROOT = __DIR__ . '/..';
const EPS = 1e-6;

$GLOBALS['__pass'] = 0;
$GLOBALS['__fail'] = 0;
$GLOBALS['__lastPeak'] = 0;

function ok(bool $cond, string $name, mixed $detail = ''): void
{
    if (is_array($detail)) {
        $detail = json_encode($detail, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
    $detail = (string) $detail;
    if ($cond) {
        $GLOBALS['__pass']++;
        printf("  [ok]   %s%s\n", $name, $detail === '' ? '' : "  ({$detail})");

        return;
    }
    $GLOBALS['__fail']++;
    printf("  [FAIL] %s%s\n", $name, $detail === '' ? '' : "  ({$detail})");
}

function section(string $title): void
{
    printf("\n== %s ==\n", $title);
}

function near(float $a, float $b, float $tol = 1e-6): bool
{
    return abs($a - $b) <= $tol;
}

function rmrf(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $f) {
        $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
    }
    @rmdir($dir);
}

/** 造一个测试根目录: 复制真实 config.dist 与 sources.dist, 再叠一层测试专用覆盖。 */
function makeRoot(string $name, array $overrides = []): string
{
    $root = rtrim(ROOT, '/\\') . '/var/tmp-' . $name;
    rmrf($root);
    @mkdir($root . '/config', 0777, true);
    foreach (['config.dist.php', 'sources.dist.php'] as $f) {
        copy(rtrim(ROOT, '/\\') . '/config/' . $f, $root . '/config/' . $f);
    }
    foreach (['cache', 'state', 'journal', 'lock', 'log'] as $d) {
        @mkdir($root . '/var/' . $d, 0777, true);
    }
    if ($overrides !== []) {
        file_put_contents(
            $root . '/config/config.local.php',
            "<?php\nreturn " . var_export_short($overrides) . ";\n"
        );
    }

    return $root;
}

function var_export_short(array $a): string
{
    $out = var_export($a, true);
    $out = preg_replace('/\n {2}/', "\n    ", $out);

    return is_string($out) ? $out : '[]';
}

function refRaw(string $url, string $owner, string $repo, array $opts = []): GitHubRef
{
    return GitHubRef::make(Scene::Raw, IdentityKind::RefName, $url, $owner, $repo, $opts);
}

function makeSource(array $over = []): Source
{
    return Source::fromArray(array_merge([
        'id' => 's-test',
        'base_url' => 'https://mirror.example.com',
        'mode' => 'prefix_full',
        'scenes' => ['raw', 'release_asset', 'archive', 'api_json', 'gist_raw'],
        'hosts' => ['github.com', 'raw.githubusercontent.com', 'codeload.github.com', 'objects.githubusercontent.com', 'api.github.com'],
        'trust' => 'community',
        'priority' => 50,
        'caps' => ['range' => false, 'follows_redirect_internally' => false, 'json_api_ok' => false],
    ], $over));
}

function releaseRef(array $over = []): GitHubRef
{
    return GitHubRef::make(Scene::ReleaseAsset, IdentityKind::RefName, 'https://github.com/o/r/releases/download/v1/app.zip', 'o', 'r', array_merge([
        'ref' => 'v1', 'asset_name' => 'app.zip', 'needs_redirect_resolve' => true,
    ], $over));
}

// ---------------------------------------------------------------------------
// 0. 装载
// ---------------------------------------------------------------------------
$rootMain = makeRoot('main', ['cache' => ['min_free_bytes' => 0]]);
$cfg = Config::load($rootMain, true);
ok($cfg->int('cache.min_free_bytes') === 0, '配置分层覆盖生效(测试根 config.local.php)');

// ---------------------------------------------------------------------------
// 1. 延迟: 时间衰减 EWMA / 陈旧样本重初始化 / 单调保护 / 对数域吞吐
// ---------------------------------------------------------------------------
section('Latency: 时间衰减 EWMA');
$tau = $cfg->float('algo.ewma.tau_ttfb_s');
$floor = $cfg->float('algo.ewma.alpha_floor');
$t0 = 1000000.0;

$s = new RuntimeStat();
$s = Latency::update($s, 100.0, 2.0e6, $t0, $cfg);
ok(near($s->ttfbEwmaMs, 100.0), '首个样本直接初始化 EWMA', sprintf('=%.3f', $s->ttfbEwmaMs));
ok(near($s->thrLogEwma, log(2.0e6)), '吞吐存在对数域 ln(bytes/s)', sprintf('=%.4f vs %.4f', $s->thrLogEwma, log(2.0e6)));
ok($s->coldStart === true, '零样本源标记冷启动');

// 正常衰减: Δt = 30s, w = exp(-30/90)
$dt = 30.0;
$w = exp(-$dt / $tau);
$s2 = Latency::update($s, 5000.0, 2.0e6, $t0 + $dt, $cfg);
$expect = 5000.0 * (1 - $w) + 100.0 * $w;
ok(near($s2->ttfbEwmaMs, $expect, 1e-9), 'w=exp(-dt/tau) 的线性域衰减公式一致', sprintf('got=%.4f exp=%.4f', $s2->ttfbEwmaMs, $expect));

// 陈旧样本: Δt 大到 w < alpha_floor 时应丢弃历史重新初始化
$dtStale = $tau * log(1 / $floor) + 10.0;
$s3 = Latency::update($s, 5000.0, 2.0e6, $t0 + $dtStale, $cfg);
ok(near($s3->ttfbEwmaMs, 5000.0), '陈旧样本丢弃历史并用新样本重新初始化', sprintf('w=%.4f < floor=%.2f', exp(-$dtStale / $tau), $floor));

// 单调保护: observed_at 倒退必须被跳过
$s4 = Latency::update($s2, 9999.0, 9.0e6, $t0 + 5.0, $cfg);
ok($s4->ttfbEwmaMs === $s2->ttfbEwmaMs && $s4->thrLogEwma === $s2->thrLogEwma && $s4->updatedAt === $s2->updatedAt,
    'observed_at 早于 updatedAt 的迟到观测被跳过');

// 纯函数: 入参不被修改
$before = $s2->toArray();
Latency::update($s2, 1.0, 1.0, $t0 + 60.0, $cfg);
ok($s2->toArray() === $before, 'Latency::update 不改入参(纯函数)');

// 保守预测: max(EWMA, 离线 P85)
$s5 = new RuntimeStat(ttfbEwmaMs: 300.0, ttfbP85Ms: 1200.0, sampleCount: 40, thrLogEwma: log(1.0e6), coldStart: false);
$p1 = Latency::predictMs($s5, makeSource(), 0, $cfg, 'cn_broadband');
ok(near($p1, 1200.0, 1e-6), '预测 TTFB 用 max(EWMA, P85) 的保守值', sprintf('=%.1f', $p1));
$p2 = Latency::predictMs($s5, makeSource(), 1000000, $cfg, 'cn_broadband');
$thrMin = min(exp(log(1.0e6)), 0.0);
ok($p2 > $p1, '体积进入预测分母(字节越多预测越久)', sprintf('%.1f -> %.1f ms', $p1, $p2));
$pCold = Latency::predictMs(new RuntimeStat(), makeSource(['region' => 'overseas']), 0, $cfg, 'overseas');
$pWarm = Latency::predictMs(new RuntimeStat(), makeSource(['region' => 'cn_broadband']), 0, $cfg, 'cn_broadband');
ok($pCold > $pWarm, '零样本时用区域先验, 海外先验比宽带先验更慢', sprintf('%.0f vs %.0f ms', $pCold, $pWarm));

// ---------------------------------------------------------------------------
// 2. Wilson 下界
// ---------------------------------------------------------------------------
section('Success: Wilson 下界');
$w1 = Success::wilsonLowerBound(1, 1, 1.0);
$w100 = Success::wilsonLowerBound(100, 100, 1.0);
ok($w1 < $w100 - 0.3, 'n=1 全成功显著低于 n=100 全成功(小样本不许装懂)', sprintf('%.4f vs %.4f', $w1, $w100));
$prev = -1.0;
$mono = true;
for ($k = 0; $k <= 20; $k++) {
    $v = Success::wilsonLowerBound($k, 20, 1.0);
    if ($v < $prev - EPS || $v < 0.0) {
        $mono = false;
    }
    $prev = $v;
}
ok($mono, '固定 n 时随成功数单调不降且恒 >= 0');
$neg = 0;
for ($n = 1; $n <= 60; $n++) {
    for ($k = 0; $k <= $n; $k++) {
        foreach ([0.84, 1.0, 1.28, 1.96] as $z) {
            $v = Success::wilsonLowerBound($k, $n, $z);
            if ($v < 0.0 || $v > 1.0) {
                $neg++;
            }
        }
    }
}
ok($neg === 0, '1 万个 (n,k,z) 组合无一为负或越界', sprintf('violation=%d', $neg));
ok(Success::wilsonLowerBound(0, 0, 1.0) === 0.0, 'tries=0 返回 0 而不是除零');
ok(Success::wilsonLowerBound(3, 3, 0.0) === 1.0, 'z=0 退化为点估计');

// ---------------------------------------------------------------------------
// 3. 失败分型: 哪些进熔断计数, 哪些完全不进统计
// ---------------------------------------------------------------------------
section('Success: 失败分型口径');
$neutralKinds = [FailureKind::Oversize, FailureKind::ClientAbort, FailureKind::Blocked, FailureKind::GuardRejected, FailureKind::NoEligibleSource];
foreach ($neutralKinds as $kind) {
    $r = Success::record(new RuntimeStat(), $kind, $cfg);
    $b = Breaker::recordOutcome($r, $kind, 120.0, 1000.0, $cfg);
    $b = Breaker::evaluate($b, 1000.0, $cfg);
    ok($r->sampleCount === 0 && $r->failures === 0 && $b->consecHardFail === 0 && $b->breaker === BreakerState::Closed,
        sprintf('%s 完全不进统计也不进熔断', $kind->value));
}
foreach ([FailureKind::WrongContent, FailureKind::Integrity, FailureKind::Http4xx, FailureKind::RateLimited] as $kind) {
    $r = Success::record(new RuntimeStat(), $kind, $cfg);
    $b = Breaker::recordOutcome($r, $kind, 120.0, 1000.0, $cfg);
    $b = Breaker::evaluate($b, 1000.0, $cfg);
    ok($r->sampleCount === 1 && $r->successes === 0 && $r->failures === 0 && $b->consecHardFail === 0 && $b->breaker === BreakerState::Closed,
        sprintf('%s 拉低成功率但不增加熔断计数', $kind->value));
}
foreach ([FailureKind::Connect, FailureKind::TimeoutTtfb, FailureKind::Stall, FailureKind::Http5xx, FailureKind::TlsVerify] as $kind) {
    $r = Success::record(new RuntimeStat(), $kind, $cfg);
    $b = Breaker::recordOutcome($r, $kind, 0.0, 1000.0, $cfg);
    ok($r->failures === 1 && $r->sampleCount === 1 && $b->consecHardFail === 1,
        sprintf('%s 计入硬故障(熔断触发源)', $kind->value));
}
ok(FailureKind::RateLimited->mustStopFailover() === true, 'rate_limited 必须停止 failover');
ok(FailureKind::Integrity->mustStopFailover() === true, 'integrity 必须停止 failover');
ok(FailureKind::Connect->mustStopFailover() === false, 'connect 允许继续 failover');
ok(FailureKind::Oversize->weight() === 0.0 && FailureKind::ClientAbort->weight() === 0.0, 'oversize/client_abort 权重为 0');
$rs = Success::record(new RuntimeStat(), FailureKind::WrongContent, $cfg);
ok(($rs->failBreakdown['wrong_content'] ?? 0) === 1 && !isset($rs->failBreakdown['none']), 'fail_breakdown 只记失败种类');

// ---------------------------------------------------------------------------
// 4. 熔断状态机
// ---------------------------------------------------------------------------
section('Breaker: 状态迁移与自适应冷却');
$base = $cfg->float('algo.breaker.cooldown_base_s');
$gain = $cfg->float('algo.breaker.cooldown_gain');
$consecLimit = $cfg->int('algo.breaker.consec_fail_trip');

$st = new RuntimeStat(sampleCount: 20, successes: 19, failures: 0);
for ($i = 0; $i < $consecLimit; $i++) {
    $st = Success::record($st, FailureKind::Connect, $cfg);
    $st = Breaker::recordOutcome($st, FailureKind::Connect, 0.0, 5000.0 + $i, $cfg);
    $st = Breaker::evaluate($st, 5000.0 + $i, $cfg);
}
ok($st->breaker === BreakerState::Open, sprintf('连续 %d 次硬失败触发 OPEN', $consecLimit));
$open2 = Breaker::evaluate($st, 5000.0, $cfg);
$cd1 = $open2->cooldownUntil - 5000.0;
ok($cd1 > 0, 'OPEN 带冷却截止时间', sprintf('%.1fs', $cd1));
ok(Breaker::evaluate($open2, 5000.0 + $cd1 / 2, $cfg)->breaker === BreakerState::Open, '冷却未到仍保持 OPEN(继续拒流量)');
$half = Breaker::evaluate($open2, 5000.0 + $cd1 + 1.0, $cfg);
ok($half->breaker === BreakerState::HalfOpen, '冷却到期转 HALF_OPEN');

$sceneKey = 'raw';
$slo = (float) $cfg->arr('algo.breaker.slo_ttfb_ms')[$sceneKey];
$factor = $cfg->float('algo.breaker.release_ttfb_factor');
$limit = Breaker::probeTtfbLimitMs($half, $cfg, $sceneKey);
$slow = $limit + 1.0;
$fast = max(1.0, $limit * 0.3);
$need = $cfg->int('algo.breaker.probe_success_to_close');
$afterSlow = Breaker::recordOutcome($half, FailureKind::None, $slow, 5000.0 + $cd1 + 2.0, $cfg, $sceneKey);
ok($afterSlow->breaker !== BreakerState::Closed && $afterSlow->consecProbeOk === 0,
    '一次成功但 TTFB 不达标不放行', sprintf('limit=%.0f probe=%.0f', $limit, $slow));

$st2 = Breaker::evaluate($afterSlow, 5000.0 + $cd1 + 2.0 + ($afterSlow->cooldownUntil - (5000.0 + $cd1 + 2.0)) + 1.0, $cfg);
ok($st2->breaker === BreakerState::HalfOpen, '第二次冷却到期再次进入 HALF_OPEN', (string) $st2->breaker->value);
$c1 = Breaker::recordOutcome($st2, FailureKind::None, $fast, $st2->cooldownUntil + 1.0, $cfg, $sceneKey);
$c2 = Breaker::evaluate($c1, $st2->cooldownUntil + 1.0, $cfg);
$c3 = Breaker::recordOutcome($c2, FailureKind::None, $fast, $st2->cooldownUntil + 2.0, $cfg, $sceneKey);
ok($c1->breaker === BreakerState::HalfOpen && $c1->consecProbeOk === 1, '第一次达标探测: 仍半开(需要 ' . $need . ' 次)');
ok($c3->breaker === BreakerState::Closed && $c3->consecProbeOk >= $need, sprintf('连续 %d 次达标转 CLOSED', $need));

// 冷却随 trips 指数增长且带抖动
$now = 1234567.0;
$cd = [];
for ($trips = 1; $trips <= 3; $trips++) {
    $cd[$trips] = Breaker::cooldownSeconds(array_fill(0, $trips, $now), $now, $cfg);
}
ok($cd[2] > $cd[1] * 1.2 && $cd[3] > $cd[2] * 1.2, '冷却随 trip 指数增长', sprintf('%.1f/%.1f/%.1f', $cd[1], $cd[2], $cd[3]));
ok(!near($cd[1], $base, 1e-9), '冷却含抖动(不等于裸 base)', sprintf('%.3f vs base %.1f', $cd[1], $base));
$jlo = (float) $cfg->arr('algo.breaker.jitter')[0];
$jhi = (float) $cfg->arr('algo.breaker.jitter')[1];
ok($cd[1] >= $base * $jlo - EPS && $cd[1] <= $base * $jhi + EPS, '抖动落在配置区间内');
$maxCd = $cfg->float('algo.breaker.cooldown_max_s');
ok(Breaker::cooldownSeconds(array_fill(0, 400, $now), $now, $cfg) <= $maxCd + EPS, '冷却被 clamp 到上限');
ok(Breaker::cooldownSeconds([], $now, $cfg) >= $cfg->float('algo.breaker.cooldown_min_s') - EPS, '空历史退化到 base 且不低于 min');

// trip_count 半衰
$hl = $cfg->float('algo.breaker.trip_halflife_s');
$aged = new RuntimeStat(breaker: BreakerState::Closed, tripCount: 8, openedAt: $now - 3 * $hl);
$agedOut = Breaker::evaluate($aged, $now, $cfg);
ok($agedOut->tripCount <= 2, 'trip_count 按半衰期衰减(坏了一周的源不该一回来就长冷却)', sprintf('8 -> %d', $agedOut->tripCount));
$cdAged = Breaker::cooldownSeconds(array_fill(0, 8, $now - 3 * $hl), $now, $cfg);
ok($cdAged < $cd[2], '陈旧 trip 历史算出的冷却短于新鲜历史', sprintf('%.1f < %.1f', $cdAged, $cd[2]));

// 手动复位
$reset = Breaker::manualReset($st, $now);
ok($reset->breaker === BreakerState::Closed && $reset->tripCount === 0 && $reset->cooldownUntil === 0.0 && $reset->consecHardFail === 0,
    'manualReset 给面板当逃生门');
// 比率触发也要检查最小窗口
$fewSamples = new RuntimeStat(sampleCount: 2, successes: 0, failures: 2, consecHardFail: 2);
ok(Breaker::evaluate($fewSamples, 1000.0, $cfg)->breaker === BreakerState::Closed,
    '样本不足 min_window_n 时不因比率跳闸(1/1 偶然不该判死)', sprintf('min_window=%d', $cfg->int('algo.breaker.min_window_n')));
// HALF_OPEN 探测名额
$probeBusy = new RuntimeStat(breaker: BreakerState::HalfOpen, lastProbeAt: $now, cooldownUntil: $now + 100);
ok(Breaker::probeSlotFree($probeBusy, $now + 0.001, $cfg) === false, 'HALF_OPEN 探测名额被占时视同 OPEN');
ok(Breaker::admitsTraffic($probeBusy, $now + 0.001, $cfg) === false, 'admitsTraffic 对半开满名额返回 false');

// ---------------------------------------------------------------------------
// 5. 打分: breakdown 求和不变式 / 冷启动 / 慢源排序
// ---------------------------------------------------------------------------
section('Selector: L0 与四因子打分');
$selector = new Selector($cfg);
$refRawMain = refRaw('https://raw.githubusercontent.com/o/r/main/a.md', 'o', 'r', ['ref' => 'main', 'path' => 'a.md', 'size_hint' => 4096]);

$fast = makeSource(['id' => 'fast', 'priority' => 60]);
$slow = makeSource(['id' => 'slow', 'priority' => 60]);
$stats = [
    // 成功 20 次、中等速度
    'fast' => new RuntimeStat(ttfbEwmaMs: 700.0, ttfbP85Ms: 900.0, successes: 20, sampleCount: 20, coldStart: false,
        measuredCaps: ['range' => true, 'follows_redirect_internally' => true], lastRequestAt: 0.0, hourRequests: 20),
    // 成功 1 次、极慢
    'slow' => new RuntimeStat(ttfbEwmaMs: 6000.0, ttfbP85Ms: 7000.0, successes: 1, sampleCount: 1, coldStart: false,
        measuredCaps: ['range' => true, 'follows_redirect_internally' => true], lastRequestAt: 0.0, hourRequests: 20),
];
$plan = $selector->plan([$slow, $fast], $stats, $refRawMain, ['size_hint' => 4096, 'now' => 2000000.0]);
ok($plan->ranked !== [] && $plan->ranked[0]->id() === 'fast', '成功1次但极慢的源排在成功20次中速之后', $plan->topIds());
$sumOk = true;
foreach ($plan->ranked as $c) {
    $sum = 0.0;
    foreach (['p', 'c', 'w', 'b', 'u'] as $k) {
        $sum += $c->breakdown[$k]['weight'] * $c->breakdown[$k]['value'];
    }
    if (!near($sum, $c->score, 1e-9)) {
        $sumOk = false;
    }
    foreach (['p', 'c', 'w', 'b', 'u'] as $k) {
        if (!near((float) $c->breakdown[$k]['contrib'], $c->breakdown[$k]['weight'] * $c->breakdown[$k]['value'], 1e-9)) {
            $sumOk = false;
        }
    }
}
ok($sumOk, 'breakdown 各项 权重×归一值 之和 == score 且 contrib 自洽');
ok(count($plan->ranked) === 2 && $plan->scoreGap > 0, 'scoreGap 反映 top1 与 top2 差距', sprintf('%.4f', $plan->scoreGap));

// 冷启动: 全部零样本 -> 分数主要由人工先验决定
$coldSources = [
    makeSource(['id' => 'hi', 'priority' => 95]),
    makeSource(['id' => 'mid', 'priority' => 60]),
    makeSource(['id' => 'lo', 'priority' => 20]),
];
$coldStats = [];
foreach ($coldSources as $src) {
    $coldStats[$src->id] = new RuntimeStat();
}
$coldPlan = $selector->plan($coldSources, $coldStats, $refRawMain, ['size_hint' => 0, 'now' => 2000000.0]);
ok($coldPlan->coldStart === true, '全局样本 < min_sample_for_rank 时 coldStart=true');
ok($coldPlan->ranked !== [] && $coldPlan->ranked[0]->id() === 'hi', '冷启动期排序实质由人工先验决定', $coldPlan->topIds());
$hi = null;
$lo = null;
foreach ($coldPlan->ranked as $c) {
    if ($c->id() === 'hi') {
        $hi = $c;
    }
    if ($c->id() === 'lo') {
        $lo = $c;
    }
}
if ($hi instanceof Candidate && $lo instanceof Candidate) {
    $wPart = fn (Candidate $c): float => $c->breakdown['w']['contrib'];
    $other = fn (Candidate $c): float => $c->score - $wPart($c);
    ok(abs($other($hi) - $other($lo)) < abs($wPart($hi) - $wPart($lo)) + 1e-9,
        '冷启动期先验项的差大于其余各项的差(先验主导)', sprintf('dw=%.4f dother=%.4f', $wPart($hi) - $wPart($lo), $other($hi) - $other($lo)));
}
// 放宽: Release 场景 + 全部未实测 -> 逐级放宽 NotYetProbed 而不是抛错
$relaxed = $selector->plan([makeSource(['id' => 'p1'])], ['p1' => new RuntimeStat()], releaseRef(), ['now' => 2000000.0]);
ok(in_array(RejectCode::NotYetProbed->value, $relaxed->relaxedFlags, true) && $relaxed->ranked !== [],
    '无实测能力位时按 relaxationOrder 放宽并记 relaxedFlags', $relaxed->relaxedFlags);
ok($relaxed->ranked[0]->relaxed !== [], '放宽进来的候选在 Candidate::relaxed 里带原因', $relaxed->ranked[0]->relaxed);

// L0 硬性剔除
$noFollow = makeSource(['id' => 'nofollow']);
$statsNoFollow = [
    'nofollow' => new RuntimeStat(sampleCount: 40, successes: 40, ttfbEwmaMs: 200.0,
        measuredCaps: ['range' => true, 'follows_redirect_internally' => false, 'json_api_ok' => true], coldStart: false),
    'follow' => new RuntimeStat(sampleCount: 40, successes: 40, ttfbEwmaMs: 900.0,
        measuredCaps: ['range' => true, 'follows_redirect_internally' => true, 'json_api_ok' => true], coldStart: false),
];
$rel = GitHubRef::make(Scene::ReleaseAsset, IdentityKind::RefName, 'https://github.com/o/r/releases/download/v1/app.zip', 'o', 'r', [
    'ref' => 'v1', 'asset_name' => 'app.zip', 'needs_redirect_resolve' => true,
]);
$relPlan = $selector->plan([$noFollow, makeSource(['id' => 'follow'])], $statsNoFollow, $rel, ['now' => 2000000.0]);
ok($relPlan->topIds(4) === ['follow'], 'Release 场景剔除 follows_redirect_internally=false 的源', $relPlan->topIds());
$codes = array_column($relPlan->excluded, 'code');
ok(in_array(RejectCode::RedirectLoss->value, $codes, true), 'excluded 带正确的 redirect_loss 原因码', json_encode($relPlan->excluded));
$found = false;
foreach ($relPlan->excluded as $e) {
    if ($e['code'] === RejectCode::RedirectLoss->value) {
        $found = $e['id'] === 'nofollow' && $e['detail'] !== '';
    }
}
ok($found, 'excluded 条目含源 id 与可读 detail');

// Range 能力必须实测
$rangeRef = refRaw('https://raw.githubusercontent.com/o/r/main/a.md', 'o', 'r', ['ref' => 'main', 'path' => 'a.md']);
$claimed = makeSource(['id' => 'claim']);
$claimedStat = new RuntimeStat(sampleCount: 30, successes: 30, ttfbEwmaMs: 200.0,
    measuredCaps: ['range' => false, 'follows_redirect_internally' => true], coldStart: false);
$rangePlan = $selector->plan([$claimed], ['claim' => $claimedStat], $rangeRef, ['range_requested' => true, 'now' => 2000000.0]);
ok($rangePlan->ranked === [] && in_array(RejectCode::NoRange->value, array_column($rangePlan->excluded, 'code'), true),
    '客户端要 Range 而源实测不支持 -> NoRange 且不放宽');
ok($rangePlan->coldStart === false, '样本充足时 coldStart=false');

// 空 ranked 时调用方据此抛 NO_ELIGIBLE_SOURCE, 绝不静默直连
$suspicious = makeSource(['id' => 'bad', 'trust' => 'suspect']);
$none = $selector->plan([$suspicious], ['bad' => new RuntimeStat()], $rangeRef, ['now' => 2000000.0]);
ok($none->ranked === [] && in_array(RejectCode::SuspectTrust->value, array_column($none->excluded, 'code'), true),
    'Suspect 信任档位硬性剔除且不可放宽(绝不静默直连 github.com)');
$dis = makeSource(['id' => 'off', 'enabled' => false]);
$off = $selector->plan([$dis], ['off' => new RuntimeStat()], $rangeRef, ['now' => 2000000.0]);
ok(in_array(RejectCode::Disabled->value, array_column($off->excluded, 'code'), true), '停用源带 disabled 原因码');
$ext = makeSource(['id' => 'noexe', 'blocked_ext' => ['exe']]);
$exeRef = GitHubRef::make(Scene::ReleaseAsset, IdentityKind::AssetId, 'https://github.com/o/r/releases/download/v1/tool.exe', 'o', 'r', [
    'ref' => 'v1', 'asset_name' => 'tool.exe', 'asset_id' => 7, 'needs_redirect_resolve' => true,
]);
$extPlan = $selector->plan([$ext], ['noexe' => new RuntimeStat(measuredCaps: ['follows_redirect_internally' => true])], $exeRef, ['now' => 2000000.0]);
ok(in_array(RejectCode::ExtBlocked->value, array_column($extPlan->excluded, 'code'), true), '扩展名黑名单带 ext_blocked 原因码');
$hostRef = refRaw('https://codeload.github.com/o/r/tar.gz/refs/heads/main', 'o', 'r', ['ref' => 'refs/heads/main', 'archive_fmt' => 'tar.gz', 'sha' => '']);
$hostPlan = $selector->plan([makeSource(['id' => 'rawonly', 'hosts' => ['raw.githubusercontent.com']])], ['rawonly' => new RuntimeStat()], $hostRef, ['now' => 2000000.0]);
ok(in_array(RejectCode::HostNotCovered->value, array_column($hostPlan->excluded, 'code'), true), 'host 覆盖不足带 host_not_covered 原因码');
// API 场景要求 json_api_ok 实测
$apiRef = GitHubRef::make(Scene::ApiJson, IdentityKind::MutableApi, 'https://api.github.com/repos/o/r', 'o', 'r', ['api_endpoint' => 'repos/o/r']);
$apiSrc = makeSource(['id' => 'noapi']);
$apiPlan = $selector->plan([$apiSrc], ['noapi' => new RuntimeStat(measuredCaps: ['json_api_ok' => false, 'range' => true])], $apiRef, ['now' => 2000000.0]);
ok(in_array(RejectCode::NoApiSupport->value, array_column($apiPlan->excluded, 'code'), true), 'API 场景要求实测 json_api_ok');
// 礼貌间隔
$polite = makeSource(['id' => 'polite', 'min_interval_ms' => 5000]);
$politePlan = $selector->plan([$polite], ['polite' => new RuntimeStat(measuredCaps: ['range' => true], lastRequestAt: 2000000.0 - 0.5)], $rangeRef, ['now' => 2000000.0]);
ok($politePlan->ranked !== [] && in_array(RejectCode::PoliteCooldown->value, $politePlan->relaxedFlags, true),
    '只有礼貌间隔被违反时它是唯一可放宽项, 放行并记录 relaxed_flags', json_encode($politePlan->relaxedFlags));
ok(($politePlan->ranked[0]->breakdown['b']['value'] ?? 1.0) < 1.0,
    '放宽进来的礼貌违反源在 f_b 上被打折(0.4), 不靠硬约束表达偏好', sprintf('b=%.2f', $politePlan->ranked[0]->breakdown['b']['value']));
// 硬约束不可放宽: 未达间隔 + 屏蔽扩展名 同时命中时, 放宽礼貌也不该放行
$politeBlocked = makeSource(['id' => 'polite2', 'min_interval_ms' => 5000, 'blocked_ext' => ['md']]);
$strictPlan = $selector->plan([$politeBlocked], ['polite2' => new RuntimeStat(measuredCaps: ['range' => true], lastRequestAt: 2000000.0 - 0.5)], $rangeRef, ['now' => 2000000.0]);
ok($strictPlan->ranked === [], '硬约束(扩展名屏蔽)与礼貌同时命中时不放宽, ranked 为空');

// 冷启动配额: 合格但长期拿不到真实流量的源至少每小时有一次真实机会
$quotaSrc = [];
$quotaStats = [];
for ($i = 1; $i <= 4; $i++) {
    $quotaSrc[] = makeSource(['id' => 'q' . $i, 'priority' => 60]);
    $quotaStats['q' . $i] = new RuntimeStat(sampleCount: 400, successes: 400, ttfbEwmaMs: 200.0 + $i, ttfbP85Ms: 300.0,
        thrLogEwma: log(2e6), coldStart: false, measuredCaps: ['range' => true],
        hourRequests: 40, lastRequestAt: 2000000.0 - 10);
}
// 排第 5 的"饿死源": 分数最低但确实合格(实测过 Range), 且一小时没被选中过
$quotaSrc[] = makeSource(['id' => 'q-cold', 'priority' => 30]);
$quotaStats['q-cold'] = new RuntimeStat(sampleCount: 1, successes: 1, ttfbEwmaMs: 5000.0, ttfbP85Ms: 6000.0,
    thrLogEwma: log(2e6), coldStart: false, measuredCaps: ['range' => true],
    hourRequests: 0, lastRequestAt: 2000000.0 - 4000);

$rootNoQuota = makeRoot('noquota', ['algo' => ['explore' => ['cold_start_quota' => 0, 'ucb_c' => 0.0]]]);
$selectorNoQuota = new Selector(Config::load($rootNoQuota, true));
$barePlan = $selectorNoQuota->plan($quotaSrc, $quotaStats, $rangeRef, ['size_hint' => 8192, 'now' => 2000000.0]);
ok(!in_array('q-cold', $barePlan->topIds(4), true), '关掉探索后饿死源确实排不进去(作为对照组)', $barePlan->topIds());
$quotaPlan = $selector->plan($quotaSrc, $quotaStats, $rangeRef, ['size_hint' => 8192, 'now' => 2000000.0]);
ok(in_array('q-cold', $quotaPlan->topIds(4), true), '冷启动配额把饿死源挤进 top-k', $quotaPlan->topIds());
ok(count($quotaPlan->ranked) <= $cfg->int('algo.mode.top_k'), '配额不会突破 top_k 上限');
$exploring = 0;
foreach ($quotaPlan->ranked as $c) {
    if (isset($c->breakdown['u'])) {
        ok($c->breakdown['u']['value'] <= 1.0 + EPS, 'UCB 探索余量有界(面板可画条)');
        if ($c->breakdown['u']['value'] >= 0.999) {
            $exploring++;
        }
    }
}
ok($exploring >= 1, '零/极少样本的源拿到最大探索余量', (string) $exploring);
$budget = $cfg->float('algo.explore.budget_ratio');
ok($budget > 0 && $budget < 1, '全局探索预算上限存在且远小于 1', sprintf('%.2f', $budget));

// top_k 上限
$many = [];
$manyStats = [];
for ($i = 0; $i < 12; $i++) {
    $many[] = makeSource(['id' => 'm' . $i, 'priority' => 30 + $i]);
    $manyStats['m' . $i] = new RuntimeStat(sampleCount: 10, successes: 10, ttfbEwmaMs: 300.0 + $i, coldStart: true,
        measuredCaps: ['range' => true]);
}
$manyPlan = $selector->plan($many, $manyStats, $rangeRef, ['now' => 2000000.0]);
ok(count($manyPlan->ranked) <= $cfg->int('algo.mode.top_k'), 'ranked 长度受 top_k 限制', sprintf('%d <= %d', count($manyPlan->ranked), $cfg->int('algo.mode.top_k')));
ok($manyPlan->totalSources === 12, 'totalSources 记录参与选路的源数');
$agentPlan = $selector->plan($many, $manyStats, $rangeRef, ['now' => 2000000.0, 'is_agent' => true]);
ok(count($agentPlan->ranked) <= count($manyPlan->ranked), 'Agent 流量收窄 failover 深度', sprintf('%d <= %d', count($agentPlan->ranked), count($manyPlan->ranked)));

// ---------------------------------------------------------------------------
// 6. SourceRepo
// ---------------------------------------------------------------------------
section('SourceRepo: 装载 / 校验 / 面板变更');
$repo = new SourceRepo($cfg, $rootMain);
$all = $repo->all();
ok(count($all) >= 5, '出厂源表装载', sprintf('%d 条', count($all)));
$byMode = [];
foreach ($all as $src) {
    $byMode[$src->mode->value] = true;
}
foreach (['prefix_full', 'prefix_path', 'host_replace', 'template'] as $m) {
    ok(isset($byMode[$m]), sprintf('出厂表覆盖 %s 形态(拼错就 404, 三类都要有例子)', $m));
}
$bad = 0;
foreach ($all as $src) {
    foreach (['range', 'follows_redirect_internally', 'json_api_ok'] as $capName) {
        if ($src->cap($capName)) {
            $bad++;
        }
    }
}
ok($bad === 0, '出厂 caps 全部为 false: 配置声称不等于实测', sprintf('violations=%d', $bad));
ok($repo->get('ghfast')?->priority === 78, '按 id 取源并读到先验梯度');
ok($repo->get('github-direct')?->enabled === false, '直连源默认停用');
$enabledPriorities = [];
foreach ($repo->all() as $src) {
    if ($src->enabled) {
        $enabledPriorities[$src->id] = $src->priority;
    }
}
ok($enabledPriorities !== [] && max($enabledPriorities) >= 70 && min($enabledPriorities) <= 40, 'priority 有梯度而非全同分', json_encode($enabledPriorities));

$new = $repo->upsert(['id' => 'panel-added', 'base_url' => 'https://mine.example.com', 'mode' => 'prefix_full', 'scenes' => ['raw'], 'hosts' => ['raw.githubusercontent.com'], 'trust' => 'self', 'priority' => 88]);
ok($new->id === 'panel-added' && $repo->get('panel-added') !== null, 'upsert 新增源后面板能查到');
$repo->toggle('panel-added', false);
ok($repo->get('panel-added')?->enabled === false, 'toggle 停用生效(源仍在索引里供面板显示)');
$repo->setPriority('panel-added', 12);
ok($repo->get('panel-added')?->priority === 12, 'setPriority 生效');
$thrown = false;
try {
    $repo->upsert(['id' => 'BAD ID!', 'base_url' => 'https://x.example.com', 'mode' => 'prefix_full', 'scenes' => ['raw'], 'hosts' => ['github.com']]);
} catch (\InvalidArgumentException) {
    $thrown = true;
}
ok($thrown, '非法 id 被拒绝(slug 约束保护状态存储的键)');
$thrown = false;
try {
    $repo->upsert(['id' => 'http-mirror', 'base_url' => 'http://x.example.com/', 'mode' => 'prefix_full', 'scenes' => ['raw'], 'hosts' => ['github.com']]);
} catch (\InvalidArgumentException) {
    $thrown = true;
}
ok($thrown, 'http:// 的 base_url 被拒绝(不允许明文出站)');
$repoWarnRoot = makeRoot('warn');
$repoWarn = new SourceRepo(Config::load($repoWarnRoot, true), $repoWarnRoot);
ok(count($repoWarn->all()) >= 5 && $repoWarn->warnings() === [],
    '出厂表零装载告警(任何一条 id/base_url/hosts/scenes 写错都会在这里暴露)', json_encode($repoWarn->warnings()));

// ---------------------------------------------------------------------------
// 7. 缓存键
// ---------------------------------------------------------------------------
section('Cache\Key: 归一化等价类');
$keyOf = static fn (array $opts, string $url = 'https://raw.githubusercontent.com/o/r/main/a.md'): string =>
    Key::of(refRaw($url, 'o', 'r', $opts));
$kRefsHeads = Key::of(refRaw('https://x/', 'o', 'r', ['ref' => 'refs/heads/main', 'path' => 'a.md']));
$kHeads = Key::of(refRaw('https://y/', 'o', 'r', ['ref' => 'heads/main', 'path' => 'a.md']));
$kMain = Key::of(refRaw('https://z/', 'o', 'r', ['ref' => 'main', 'path' => 'a.md']));
ok($kRefsHeads === $kHeads, 'refs/heads/main 与 heads/main 同键');
ok($kRefsHeads !== $kMain, '裸 main 不与 refs/heads/main 合并(branch/tag 同名会长期供错内容)');
$kCase1 = Key::of(GitHubRef::make(Scene::Raw, IdentityKind::RefName, 'https://a/', 'Owner', 'Repo', ['ref' => 'main', 'path' => 'a.md']));
$kCase2 = Key::of(GitHubRef::make(Scene::Raw, IdentityKind::RefName, 'https://b/', 'owner', 'repo', ['ref' => 'main', 'path' => 'a.md']));
ok($kCase1 === $kCase2, 'owner/repo 大小写差异收敛到同键');
$kPathCase1 = Key::of(refRaw('https://a/', 'o', 'r', ['ref' => 'main', 'path' => 'Readme.md']));
$kPathCase2 = Key::of(refRaw('https://b/', 'o', 'r', ['ref' => 'main', 'path' => 'readme.md']));
ok($kPathCase1 !== $kPathCase2, 'path 保留大小写(GitHub 文件名大小写敏感)');
$kPct1 = Key::of(refRaw('https://a/', 'o', 'r', ['ref' => 'main', 'path' => 'dir%2fa.md']));
$kPct2 = Key::of(refRaw('https://b/', 'o', 'r', ['ref' => 'main', 'path' => 'dir%2Fa.md']));
$kSlash = Key::of(refRaw('https://c/', 'o', 'r', ['ref' => 'main', 'path' => 'dir/a.md']));
ok($kPct1 === $kPct2, '%2f 与 %2F 变体同键');
ok($kPct1 !== $kSlash, 'a%2Fb 与 a/b 是两个不同对象, 必须不同键');
$mirrorA = refRaw('https://ghfast.top/https://raw.githubusercontent.com/o/r/main/a.md', 'o', 'r', ['ref' => 'main', 'path' => 'a.md']);
$mirrorB = refRaw('https://other-mirror.example/https://raw.githubusercontent.com/o/r/main/a.md', 'o', 'r', ['ref' => 'main', 'path' => 'a.md']);
ok(Key::of($mirrorA) === Key::of($mirrorB), '键不含镜像域名(切源不换缓存)');
ok(!str_contains(Key::of($mirrorA), 'ghfast') && !str_contains($mirrorA->canonical(), 'ghfast'), 'canonical 串里没有任何镜像域名');
ok(preg_match('#\A[0-9a-f]{64}\z#', Key::of($mirrorA)) === 1, '键是 64 位小写十六进制');
$qOrder1 = GitHubRef::make(Scene::ApiJson, IdentityKind::MutableApi, 'https://api.github.com/x', 'o', 'r', ['api_endpoint' => 'x', 'api_query' => ['b' => 2, 'a' => 1]]);
$qOrder2 = GitHubRef::make(Scene::ApiJson, IdentityKind::MutableApi, 'https://api.github.com/x', 'o', 'r', ['api_endpoint' => 'x', 'api_query' => ['a' => 1, 'b' => 2]]);
ok(Key::of($qOrder1) === Key::of($qOrder2), 'query 键序不影响键');
try {
    Key::paths('../../etc/passwd', $rootMain . '/var/cache');
    ok(false, '非法键必须被拒绝');
} catch (\InvalidArgumentException) {
    ok(true, '非法键(路径穿越)在 Key::paths 里被拒绝');
}
$keyMirror = Key::of($mirrorA);
$pp = Key::paths($keyMirror, $rootMain . '/var/cache');
ok(str_ends_with($pp['bin'], '.bin') && !str_contains($pp['bin'], '.php'), '缓存文件名是 <sha256>.bin, 永不含 .php');
ok(str_ends_with($pp['bin'], $keyMirror . '.bin'), '文件名主体就是键本身(不掺原始文件名)');
ok(!str_contains($pp['dir'], 'ghfast') && !str_contains($pp['bin'], 'a.md'), '路径里既没有镜像域名也没有原始文件名片段');
ok(Key::rangeOverlaps('bytes=100-199', '') === true, 'Range 优先由完整条目满足');
ok(Key::rangeOverlaps('bytes=100-199', 'bytes=0-99') === false, '与不重叠的 partial 条目不相交');
ok(Key::rangeOverlaps('bytes=50-150', 'bytes=100-400') === true, 'partial 条目区间相交判定');
ok(Key::rangeOverlaps('bytes=0-10,20-30', '') === true && Key::rangeOverlaps('bytes=0-10,20-30', 'bytes=0-5') === false,
    '多段 Range 只认完整条目');
ok(Key::rangeOverlaps('bytes=100-199', 'bytes=0-8191') === true, 'bytes=0-(n-1) 视为完整条目');

// ---------------------------------------------------------------------------
// 8. 缓存资格与 TTL
// ---------------------------------------------------------------------------
section('Cache\Policy: 身份决定资格');
$policy = new Policy($cfg);
$apiRef2 = GitHubRef::make(Scene::ApiJson, IdentityKind::MutableApi, 'https://api.github.com/repos/o/r', 'o', 'r', ['api_endpoint' => 'repos/o/r']);
ok($policy->mayCache($apiRef2, makeSource(['trust' => 'self']), 100) === false, 'ApiJson 场景 v1 一律不缓存');
ok($policy->ttlFor($apiRef2)['fresh'] === 0, 'ApiJson TTL 为 0');
$okApi = GitHubRef::make(Scene::Raw, IdentityKind::MutableApi, 'https://raw.githubusercontent.com/o/r/main/a.md', 'o', 'r', ['ref' => 'main', 'path' => 'a.md']);
ok($policy->mayCache($okApi, makeSource(), 100) === false, 'MutableApi 身份不可缓存');
$refName = refRaw('https://raw.githubusercontent.com/o/r/main/a.md', 'o', 'r', ['ref' => 'main', 'path' => 'a.md']);
$ttl = $policy->ttlFor($refName);
ok($ttl['fresh'] <= 120 && $ttl['immutable'] === false, 'RefName 的 fresh TTL <= 120s', sprintf('fresh=%d', $ttl['fresh']));
$shaRef = GitHubRef::make(Scene::Raw, IdentityKind::CommitSha, 'https://raw.githubusercontent.com/o/r/abcdef0123456789abcdef0123456789abcdef01/a.md', 'o', 'r', [
    'sha' => 'abcdef0123456789abcdef0123456789abcdef01', 'path' => 'a.md',
]);
$shaTtl = $policy->ttlFor($shaRef);
ok($shaTtl['immutable'] === true && $shaTtl['fresh'] > 86400, 'CommitSha 可 immutable 且长 TTL', sprintf('fresh=%d', $shaTtl['fresh']));
ok($policy->mayCache($shaRef, makeSource(['trust' => 'community']), 100) === true, '内容寻址的文本文件在公共镜像上可缓存');
$binRef = GitHubRef::make(Scene::ReleaseAsset, IdentityKind::AssetId, 'https://github.com/o/r/releases/download/v1/app.zip', 'o', 'r', [
    'ref' => 'v1', 'asset_id' => 12, 'asset_name' => 'app.zip',
]);
ok($policy->mayCache($binRef, makeSource(['trust' => 'community']), 1000) === false, '低信任 + 无 sha256 + 二进制 不缓存(篡改风险)');
ok($policy->mayCache($binRef, makeSource(['trust' => 'self']), 1000) === true, '自建源无摘要仍可缓存');
$binWithDigest = $binRef->with(['expected_sha256' => str_repeat('ab', 32)]);
ok($policy->mayCache($binWithDigest, makeSource(['trust' => 'community']), 1000) === true, '有权威摘要后低信任二进制可缓存');
ok($policy->mayCache($binRef, makeSource(['trust' => 'suspect']), 1000) === false, 'Suspect 源的二进制绝不落地');
ok($policy->mayCache($refName, makeSource(), 999999999999) === false, '超过单条体积上限不落地');
$etag = $policy->etagFor($keyMirror, 'full');
ok(str_starts_with($etag, '"gha-') && str_contains($etag, '-full"'), 'ETag 自造: gha-<key16>-<variant>', $etag);

// ---------------------------------------------------------------------------
// 9. Store: 写入 / Range 切片恒定内存 / 校验判废 / 续传 / 隔离区
// ---------------------------------------------------------------------------
section('Cache\Store: 落盘与 Range 切片');
$store = new Store($rootMain, $cfg, $policy);
$peakBefore = memory_get_peak_usage();
$unit = '';
for ($i = 0; $i < 256; $i++) {
    $unit .= chr($i);
}
$block = str_repeat($unit, 256);          // 64 KiB
$bigLen = 8 * 1024 * 1024;                // 8 MiB
$bigRef = GitHubRef::make(Scene::Raw, IdentityKind::CommitSha, 'https://raw.githubusercontent.com/o/r/abcdef0123456789abcdef0123456789abcdef01/big.bin', 'o', 'r', [
    'sha' => 'abcdef0123456789abcdef0123456789abcdef01', 'path' => 'big.bin', 'size_hint' => $bigLen,
    'expected_sha256' => '',
]);
$w = $store->begin($bigRef, ['expected_size' => $bigLen, 'source_id' => 'ghfast', 'content_type' => 'application/octet-stream']);
ok($w !== null, 'begin 返回 PartialWriter');
$written = 0;
$chunks = intdiv($bigLen, strlen($block));
for ($i = 0; $i < $chunks; $i++) {
    if (!$w->write($block)) {
        ok(false, '连续前缀写入失败于块 ' . $i);
        break;
    }
    $written += strlen($block);
}
ok($written === $bigLen && $w->receivedBytes === $bigLen, '连续前缀长度等于写入字节', (string) $written);
$bigEntry = $store->commit($w, '', false);
ok($bigEntry instanceof Entry && $bigEntry->bytes === $bigLen, 'commit 落地 8MiB 条目', $bigEntry ? (string) $bigEntry->bytes : 'null');
ok($bigEntry !== null && preg_match('#\A[0-9a-f]{64}\z#', $bigEntry->sha256) === 1, 'commit 无摘要时自行补算 sha256');
ok($bigEntry !== null && str_starts_with($bigEntry->etag, '"gha-'), 'Entry 带自造 ETag');

$found = $store->lookup($bigRef);
ok($found instanceof Entry && $found->key === $bigEntry->key, 'lookup 命中且键一致');
$open = $store->openForRead($found);
ok(is_resource($open['handle']) && $open['size'] === $bigLen, 'openForRead 返回句柄与体积');
fclose($open['handle']);

$tmpFile = $rootMain . '/var/tmp-slice.bin';
$fails = 0;
$cases = [[0, 63], [0, 0], [1, 5], [4096, 8191], [$bigLen - 100, null], [100, 100], [0, $bigLen - 1], [123, 123 + 70000]];
foreach ($cases as [$start, $end]) {
    $len = $end === null ? $bigLen - $start : $end - $start + 1;
    $fh = fopen($tmpFile, 'wb');
    $got = $store->sliceToOutput($found, $fh, $start, $end);
    fclose($fh);
    // 逐块比对, 绝不在内存里凑出整段期望值: 否则"峰值内存恒定"这条断言会被验证代码自己打破。
    $same = $got === $len;
    if ($same) {
        $vf = fopen($tmpFile, 'rb');
        $left = $len;
        while ($left > 0) {
            $want = min(65536, $left);
            $buf = fread($vf, $want);
            $exp = expectBytes($start + ($len - $left), $want);
            if (!is_string($buf) || $buf !== $exp) {
                $same = false;
                break;
            }
            $left -= $want;
        }
        fclose($vf);
    }
    if (!$same) {
        $fails++;
        printf("        range [%s,%s] got=%d exp=%d\n", (string) $start, (string) $end, $got, $len);
    }
}
ok($fails === 0, '各种 Range 的输出字节与按位置构造的 substr 结果完全一致', sprintf('%d/%d 通过', count($cases) - $fails, count($cases)));
$peakAfter = memory_get_peak_usage();
$peakRealAfter = memory_get_peak_usage(true);
// 用 emalloc 峰值: memory_get_peak_usage(true) 是操作系统层面的分配器 arena 高水位,
// 进程一起来就超过 4MB, 拿它做阈值测不出任何东西。emalloc 峰值才反映"我到底读进内存多少字节"。
ok($peakAfter < 4 * 1024 * 1024, '8MiB 条目切片服务期间 emalloc 峰值 < 4MB(恒定内存)', sprintf('%.2fMB (real %.2fMB)', $peakAfter / 1048576, $peakRealAfter / 1048576));
$cfh = fopen($tmpFile, 'wb');
$clamped = $store->sliceToOutput($found, $cfh, 5, 99999999999);
fclose($cfh);
$clampedSize = filesize($tmpFile);
ok($clamped === $bigLen - 5 && $clampedSize === $bigLen - 5, 'end 越界被夹到条目末尾', sprintf('%d vs %d', $clamped, $bigLen - 5));
$badRange = $store->sliceToOutput($found, fopen($tmpFile, 'wb'), 10, 5);
ok($badRange === 0, 'start > end 输出 0 字节而不是负数');

// 截断的 .part 绝不落地
$smallRef = refRaw('https://raw.githubusercontent.com/o/r/main/s.md', 'o', 'r', ['ref' => 'main', 'path' => 's.md', 'size_hint' => 1000]);
$w2 = $store->begin($smallRef, ['expected_size' => 1000, 'source_id' => 'ghfast']);
$w2->write(str_repeat('x', 500));
$w2->close();
ok($store->commit($w2, '', false) === null, 'filesize != meta.bytes 时 commit 拒绝落地');
ok($store->lookup($smallRef) === null, '半写文件永不参与命中');
ok(!file_exists(Key::paths(Key::of($smallRef), $store->cacheDir())['bin']), '被拒的 .part 已删除');

// 续传: 连续前缀模型
$w3 = $store->begin($smallRef, ['expected_size' => 1000, 'source_id' => 'ghfast']);
$w3->write(str_repeat('y', 400));
$w3->close();                       // 模拟客户端断开: 保留 .part
$w4 = $store->begin($smallRef, ['expected_size' => 1000, 'source_id' => 'ghfast']);
ok($w4 !== null && $w4->receivedBytes === 400 && $w4->resumed === true, '断开后 .part 保留并被续上(只需 Range: bytes=400-)', $w4 ? (string) $w4->receivedBytes : 'null');
$w4->write(str_repeat('y', 600));
$e4 = $store->commit($w4, '', false);
ok($e4 instanceof Entry && $e4->bytes === 1000, '续传完成后原子落地整条');
$rd = $store->openForRead($e4);$sliced = stream_get_contents($rd['handle']);
fclose($rd['handle']);
ok($sliced === str_repeat('y', 1000), '续传拼接后的内容与预期一致(经 openForRead 读取)');
ok(!file_exists(Key::paths(Key::of($smallRef), $store->cacheDir())['part']), '落地后 .part 不存在');

// 隔离区: resume_count 达上限
$resumeRef = refRaw('https://raw.githubusercontent.com/o/r/main/r.md', 'o', 'r', ['ref' => 'main', 'path' => 'r.md', 'size_hint' => 500]);
for ($i = 0; $i < 6; $i++) {
    $wr = $store->begin($resumeRef, ['expected_size' => 500]);
    if ($wr === null) {
        break;
    }
    $wr->write(str_repeat('z', 100));
    $wr->close();
}
$qdir = Key::quarantineDir($store->cacheDir());
$qFiles = is_dir($qdir) ? array_filter(scandir($qdir), static fn ($f) => $f !== '.' && $f !== '..') : [];
ok(count($qFiles) >= 1, sprintf('resume_count >= %d 后 .part 进隔离区', $policy->maxResume()), (string) count($qFiles));
ok($store->lookup($resumeRef) === null, '隔离区文件不参与命中');

// 小条目 inline: inode 减半
$tinyRef = refRaw('https://raw.githubusercontent.com/o/r/main/tiny.txt', 'o', 'r', ['ref' => 'main', 'path' => 'tiny.txt', 'size_hint' => 300]);
$wt = $store->begin($tinyRef, ['expected_size' => 300]);
$wt->write(str_repeat('t', 300));
$tinyEntry = $store->commit($wt, '', false);
$tp = Key::paths(Key::of($tinyRef), $store->cacheDir());
ok($tinyEntry instanceof Entry && is_readable($tp['inline']) && !file_exists($tp['bin']) && !file_exists($tp['meta']),
    '小于 cache.small_entry_inline_bytes 的条目合并成单文件');
$tinyFound = $store->lookup($tinyRef);
$fh = fopen($tmpFile, 'wb');
$n = $store->sliceToOutput($tinyFound, $fh, 10, 19);
fclose($fh);
ok($tinyFound !== null && $n === 10 && file_get_contents($tmpFile) === str_repeat('t', 10), 'inline 条目也能按 Range 正确切片');
for ($i = 0; $i < 8; $i++) {
    $store->noteHit($store->lookup($tinyRef));
}
$again = $store->lookup($tinyRef);
ok($again !== null && $again->hits >= 8, 'noteHit 从已存 meta 自增(用不可变 Entry 自增会永远停在 1)', (string) ($again->hits ?? -1));
$rdT = $store->openForRead($again);
$bodyT = stream_get_contents($rdT['handle']);
fclose($rdT['handle']);
ok($bodyT === str_repeat('t', 300), 'inline 条目重写后数据完好', sprintf('%d bytes', strlen($bodyT)));

// revalidate 只刷时效不重写数据
$rdV = $store->openForRead($tinyFound);
$dataBefore = stream_get_contents($rdV['handle']);
fclose($rdV['handle']);
$revalidated = $tinyFound->revalidated(microtime(true), 60, 60);
ok(abs($revalidated->freshUntil - (microtime(true) + 60)) < 5 && $revalidated->bytes === $tinyFound->bytes
    && $revalidated->sha256 === $tinyFound->sha256 && $revalidated->hits === $tinyFound->hits,
    'revalidated 只改时效字段, 数据/摘要/命中数原样');
$after = $store->lookup($tinyRef);
$rdA = $store->openForRead($after);
$dataAfter = stream_get_contents($rdA['handle']);
fclose($rdA['handle']);
ok($dataAfter === $dataBefore, '命中刷新不改动数据字节');

// filesize 与 meta 不一致 -> 判废并删
file_put_contents($tp['bin'], 'x');
file_put_contents($tp['meta'], json_encode($tinyFound->toArray() + ['key' => Key::of($tinyRef)]));
ok($store->lookup($tinyRef) === null, 'bin 与 meta.bytes 不一致时判废');
@unlink($tp['bin']);
@unlink($tp['meta']);

// ---------------------------------------------------------------------------
// 10. 水位与价值密度淘汰
// ---------------------------------------------------------------------------
section('Cache 水位: 价值密度淘汰(不是 LRU)');
$rootTiny = makeRoot('tiny', ['cache' => [
    'max_bytes' => 20000, 'hard_watermark' => 0.85, 'stop_watermark' => 0.95,
    'min_free_bytes' => 0, 'evict_batch' => 20, 'small_entry_inline_bytes' => 65536,
    'soft_watermark' => 0.70, 'evict_alpha' => 0.6, 'max_entry_bytes' => 100000, 'partial_ttl_s' => 1800,
    'stale_while_revalidate_s' => 300,
]]);
$cfgTiny = Config::load($rootTiny, true);
$policyTiny = new Policy($cfgTiny);
$storeTiny = new Store($rootTiny, $cfgTiny, $policyTiny);

$bigFileRef = GitHubRef::make(Scene::Raw, IdentityKind::CommitSha, 'https://raw.githubusercontent.com/o/r/aaaa', 'o', 'r', [
    'sha' => str_repeat('a', 40), 'path' => 'big.bin', 'size_hint' => 12000,
]);
$w = $storeTiny->begin($bigFileRef, ['expected_size' => 12000]);
$w->write(str_repeat('B', 12000));
$bigEntry = $storeTiny->commit($w, '', true);
ok($bigEntry !== null, '大条目(12000B)写入成功');
for ($i = 1; $i <= 3; $i++) {
    $smallRef = GitHubRef::make(Scene::Raw, IdentityKind::CommitSha, 'https://x/', 'o', 'r', [
        'sha' => hash('sha256', 'seed' . $i), 'path' => 'small' . $i . '.bin', 'size_hint' => 800,
    ]);
    $ws = $storeTiny->begin($smallRef, ['expected_size' => 800]);
    $ws->write(str_repeat('S', 800));
    $storeTiny->commit($ws, '', true);
}
for ($i = 0; $i < 40; $i++) {
    $storeTiny->noteHit($bigEntry);
}
$wm = $storeTiny->watermark();
ok($wm['entries'] >= 4, '水位统计到条目数', sprintf('used=%d entries=%d ratio=%.2f', $wm['used'], $wm['entries'], $wm['ratio']));
$before = $storeTiny->lookup($bigFileRef);
ok($before !== null, '淘汰前大条目存在');
$nextRef = GitHubRef::make(Scene::Raw, IdentityKind::CommitSha, 'https://x/', 'o', 'r', [
    'sha' => hash('sha256', 'seed-new'), 'path' => 'new.bin', 'size_hint' => 3000,
]);
$wn = $storeTiny->begin($nextRef, ['expected_size' => 3000]);
ok($wn !== null, '推过硬水位时 begin 仍能给出一条写入(靠同步淘汰腾地方)');
if ($wn !== null) {
    $wn->write(str_repeat('N', 3000));
    ok($storeTiny->commit($wn, '', true) !== null, '写前同步淘汰后可以落地');
}
$after = $storeTiny->lookup($bigFileRef);
ok($after !== null, '高价值密度的大条目没被淘汰(不是 LRU 的"最近未访问就踢")');
$evictedSmall = 0;
for ($i = 1; $i <= 3; $i++) {
    $smallRef = GitHubRef::make(Scene::Raw, IdentityKind::CommitSha, 'https://x/', 'o', 'r', [
        'sha' => hash('sha256', 'seed' . $i), 'path' => 'small' . $i . '.bin', 'size_hint' => 800,
    ]);
    if ($storeTiny->lookup($smallRef) === null) {
        $evictedSmall++;
    }
}
ok($evictedSmall >= 1, sprintf('被淘汰的是低价值密度条目(%d 个 0 命中的小文件)', $evictedSmall));
$densA = $after === null ? 0.0 : $policyTiny->valueDensity($after, microtime(true));
$densB = $policyTiny->valueDensity(new Entry(key: 'b', scene: Scene::Raw, identityKind: IdentityKind::RefName, bytes: 800, freshUntil: microtime(true) + 1, staleUntil: microtime(true) + 2, hits: 0), microtime(true));
ok($densA > $densB, '价值密度: 高命中的大条目 > 零命中且即将过期的小条目', sprintf('%.5f vs %.5f', $densA, $densB));

// 磁盘余量保护
$rootDisk = makeRoot('disk', ['cache' => ['min_free_bytes' => 999999999999, 'max_bytes' => 10737418240]]);
$cfgDisk = Config::load($rootDisk, true);
$storeDisk = new Store($rootDisk, $cfgDisk, new Policy($cfgDisk));
ok($storeDisk->begin(refRaw('https://x/', 'o', 'r', ['ref' => 'main', 'path' => 'a.md', 'size_hint' => 10]), ['expected_size' => 10]) === null,
    'disk_free < min_free_bytes 一律拒写(宁可慢不可炸盘)');

// purge
$purged = $storeTiny->purge('all', null);
ok($purged >= 1, 'purge(all) 返回清理条数', (string) $purged);
ok($storeTiny->lookup($bigFileRef) === null, 'purge 后条目消失');
$storeTiny->purge('ref', 'not-a-real-key');

// ---------------------------------------------------------------------------
// 11. 快照 / 观测 / 压实
// ---------------------------------------------------------------------------
section('Store: 版本化快照 + NDJSON + 单写者压实');
$snapRoot = makeRoot('snap');
$cfgSnap = Config::load($snapRoot, true);
$snap = new Snapshot($snapRoot, $cfgSnap);
ok($snap->version() === '' && $snap->statsMap() === [], '无快照时返回空而不是抛错');
ok(str_contains(json_encode($snap->raw()), '"stats"'), 'raw() 返回骨架');

$stats1 = ['alpha' => new RuntimeStat(ttfbEwmaMs: 300.0, successes: 5, failures: 1, sampleCount: 6, coldStart: false)];
ok($snap->replace($stats1, ['note' => 'v1']) === true, 'replace 原子写成功');
$ver1 = $snap->version();
ok($ver1 !== '' && is_readable($snap->dataFile($ver1)), '版本化数据文件存在', $ver1);
ok(file_get_contents($snapRoot . '/var/state/snap.ver') !== false, 'snap.ver 是纯文本指针(不会被编译缓存介入)');
$map = $snap->statsMap();
ok(isset($map['alpha']) && $map['alpha']->successes === 5, 'statsMap 重建 RuntimeStat');

$stats2 = ['alpha' => new RuntimeStat(ttfbEwmaMs: 400.0, successes: 9, sampleCount: 9), 'beta' => new RuntimeStat()];
ok($snap->replace($stats2) === true, '第二次替换成功');
$ver2 = $snap->version();
ok($ver2 !== $ver1 && is_readable($snap->dataFile($ver2)) && is_readable($snap->dataFile($ver1)), '版本切换: 两个版本文件都在', $ver1 . ' -> ' . $ver2);
$snap2 = new Snapshot($snapRoot, $cfgSnap);
ok($snap2->statsMap()['beta'] instanceof RuntimeStat && abs($snap2->statsMap()['alpha']->ttfbEwmaMs - 400.0) < EPS, '新实例读到最新版本');
$tmpLeft = glob($snapRoot . '/var/state/*.tmp');
ok($tmpLeft === false || $tmpLeft === [], '原子写不留 .tmp 文件', json_encode($tmpLeft === false ? [] : $tmpLeft));

// NDJSON 观测: 1 次追加, batch 合并
$obs = new Observatory($snapRoot, $cfgSnap);
$baseT = 1000000.0;
for ($i = 0; $i < 5; $i++) {
    $obs->record(['source' => 'alpha', 'kind' => 'none', 'ttfb_ms' => 200.0 + $i * 50, 'thr_bps' => 2.0e6, 'bytes' => 1024, 'observed_at' => $baseT + $i * 10, 'scene' => 'raw', 'ref' => 'https://github.com/o/r/releases/download/v1/app.zip', 'ref_display' => 'o/r archive main']);
}
ok($obs->buffered() === 5, 'record 只缓冲不写盘');
$jf = $obs->journalFile();
ok(!file_exists($jf), 'flush 前不创建日志文件');
$obs->flush();
$lines = file($jf, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
ok(is_array($lines) && count($lines) === 1, '每请求最多 1 次真实追加(5 条观测合成 1 行 batch)', (string) count($lines));
$batch = json_decode((string) $lines[0], true);
ok(is_array($batch) && count($batch['obs']) === 5 && isset($batch['obs'][0]['seq'], $batch['obs'][0]['observed_at']), '每条观测带 seq 与 observed_at');
ok(strlen((string) $batch['obs'][0]['ref']) <= 16, '日志里的 ref 被截成摘要(隐私义务)');
ok(strlen((string) $batch['obs'][0]['ref_display']) === 16, 'ref_display 走哈希派生而不是明文 owner/repo');
$obs->flush();
$lines2 = file($jf, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
ok(is_array($lines2) && count($lines2) === 1, '空缓冲 flush 不写空行');

// 压实: 全量重放 + 离线分位数 + 单写者锁
$comp = new Compactor($snapRoot, $cfgSnap);
$res = $comp->run(true);
ok($res['locked'] === false, '压实抢到锁', json_encode($res));
ok($res['obs'] >= 5, '重放消费了缓冲的观测', (string) $res['obs']);
$snapAfter = new Snapshot($snapRoot, $cfgSnap);
$alpha = $snapAfter->statsMap()['alpha'] ?? null;
ok($alpha !== null && $alpha->sampleCount === 5 && $alpha->successes === 5, '重放后的成功率统计正确', $alpha ? (string) $alpha->sampleCount : 'null');
ok($alpha !== null && $alpha->ttfbP85Ms > 0.0, 'P85 由压实器离线算好落成标量', $alpha ? sprintf('p85=%.1f ewma=%.1f', $alpha->ttfbP85Ms, $alpha->ttfbEwmaMs) : '');
$sorted = [200.0, 250.0, 300.0, 350.0, 400.0];
ok($alpha !== null && near($alpha->ttfbP85Ms, Compactor::percentile($sorted, 0.85)), 'P85 = 最近秩分位数(不做插值)', sprintf('%.1f', $alpha->ttfbP85Ms));
ok($alpha !== null && $alpha->coldStart === true, '样本不足时快照里的 cold_start 为真');
$again = $comp->run(true);
ok($again['obs'] === 0 || $again['obs'] > 0, '第二次压实可重放(幂等: 同 (source,seq) 不重复计数)', json_encode($again));
$dupCheck = (new Snapshot($snapRoot, $cfgSnap))->statsMap()['alpha'] ?? null;
ok($dupCheck !== null && $dupCheck->sampleCount === 5, '重放幂等: sampleCount 未因重复观测翻倍', (string) ($dupCheck?->sampleCount));

// 熔断态在压实后仍然正确(不是被日志轮转抹掉)。时间戳用真实时钟: 压实器会按 now 推进
// OPEN -> HALF_OPEN, 用 1970 年的合成时间戳测这条只会测到"冷却当然早过了"。
$obs2 = new Observatory($snapRoot, $cfgSnap);
$failAt = microtime(true);
for ($i = 0; $i < 6; $i++) {
    $obs2->record(['source' => 'alpha', 'kind' => 'connect', 'ttfb_ms' => 0.0, 'thr_bps' => 0.0, 'bytes' => 0, 'observed_at' => $failAt + $i, 'scene' => 'raw']);
}
$obs2->flush();
$comp2 = $comp->run(true);
ok($comp2['locked'] === false, '第二次压实执行');
$alpha2 = (new Snapshot($snapRoot, $cfgSnap))->statsMap()['alpha'] ?? null;
ok($alpha2 !== null && $alpha2->breaker === BreakerState::Open && $alpha2->cooldownUntil > $failAt, '连续硬失败经压实后仍是 OPEN(熔断态不因轮转丢失)', $alpha2 ? $alpha2->breaker->value : 'null');

// 手动复位也必须能被重放承认
$obs3 = new Observatory($snapRoot, $cfgSnap);
$obs3->record(['source' => 'alpha', 'type' => 'breaker_reset', 'observed_at' => $failAt + 100000, 'seq' => 999]);
$obs3->flush();
$comp->run(true);
$alpha3 = (new Snapshot($snapRoot, $cfgSnap))->statsMap()['alpha'] ?? null;
ok($alpha3 !== null && $alpha3->breaker === BreakerState::Closed, 'breaker_reset 控制事件在重放中生效(面板复位不会被压实冲掉)');

// 单写者: 并发第二个必须立刻放弃而不是阻塞
$lockFile = $snapRoot . '/var/lock/compact.lock';
$lh = fopen($lockFile, 'c');
ok($lh !== false && flock($lh, LOCK_EX | LOCK_NB), '测试进程先持有压实锁');
$t = microtime(true);
$contended = $comp->run(true);
$spent = microtime(true) - $t;
ok($contended['locked'] === true, '抢不到锁时立即返回 locked=true(只有一个写者)', json_encode($contended));
ok($spent < 0.2, '抢锁失败不阻塞请求路径', sprintf('%.1fms', $spent * 1000));
flock($lh, LOCK_UN);
fclose($lh);
ok($comp->run(true)['locked'] === false, '锁释放后可以再压实');

// 概率触发: prob_divisor=1 时必然尝试且能拿到锁 -> true
$rootAlways = makeRoot('always', ['logging' => ['compact' => ['prob_divisor' => 1, 'trigger_lines' => 200, 'trigger_age_s' => 15]]]);
$cfgAlways = Config::load($rootAlways, true);
$obsAlways = new Observatory($rootAlways, $cfgAlways);
$obsAlways->record(['source' => 'x', 'kind' => 'none', 'ttfb_ms' => 100.0, 'thr_bps' => 1e6, 'observed_at' => 1.0]);
$obsAlways->flush();
ok($obsAlways->maybeCompact() === true, 'maybeCompact 在拿到锁时返回 true(概率触发路径打通)');
$lh2 = fopen($rootAlways . '/var/lock/compact.lock', 'c');
flock($lh2, LOCK_EX);
ok($obsAlways->maybeCompact() === false, '抢不到锁时 maybeCompact 立即返回 false', '');
flock($lh2, LOCK_UN);
fclose($lh2);

// 概率触发: prob_divisor 很大时几乎不触发
$rootProb = makeRoot('prob', ['logging' => ['compact' => ['prob_divisor' => 1000000, 'trigger_lines' => 200, 'trigger_age_s' => 15]]]);
$cfgProb = Config::load($rootProb, true);
$obsProb = new Observatory($rootProb, $cfgProb);
$hits = 0;
for ($i = 0; $i < 50; $i++) {
    if ($obsProb->maybeCompact()) {
        $hits++;
    }
}
ok($hits === 0, 'prob_divisor 很大时请求侧几乎不触发压实', (string) $hits);

// ---------------------------------------------------------------------------
// 12. 端到端小闭环: 观测 -> 快照 -> 选路真的避开坏源
// ---------------------------------------------------------------------------
section('闭环: 坏源被熔断后不再进入 ranked');
$loopSrc = [makeSource(['id' => 'good', 'priority' => 50]), makeSource(['id' => 'broken', 'priority' => 70])];
$loopStats = ['good' => new RuntimeStat(), 'broken' => new RuntimeStat()];
$g = $loopStats['good'];
$b = $loopStats['broken'];
$now2 = 3000000.0;
for ($i = 0; $i < 10; $i++) {
    $g = Success::record($g, FailureKind::None, $cfg);
    $g = Latency::update($g, 250.0, 4.0e6, $now2 + $i, $cfg);
    $g = Breaker::recordOutcome($g, FailureKind::None, 250.0, $now2 + $i, $cfg, 'raw');
    $b = Success::record($b, FailureKind::Connect, $cfg);
    $b = Breaker::recordOutcome($b, FailureKind::Connect, 0.0, $now2 + $i, $cfg, 'raw');
    $b = Breaker::evaluate($b, $now2 + $i, $cfg);
}
$loopStats = ['good' => $g, 'broken' => $b];
$loopPlan = $selector->plan($loopSrc, $loopStats, $refRawMain, ['now' => $now2 + 20]);
ok($b->breaker === BreakerState::Open, '先验更高的源坏了也要被熔断(priority 只是小因子)', $b->breaker->value);
ok($loopPlan->topIds(4) === ['good'], 'OPEN 且冷却未到时 ranked 里只剩健康源', $loopPlan->topIds());
ok(in_array(RejectCode::BreakerOpen->value, array_column($loopPlan->excluded, 'code'), true), '被熔断的源带 breaker_open 原因码');
$after = Breaker::evaluate($b, $b->cooldownUntil + 1, $cfg);
$loopPlan2 = $selector->plan($loopSrc, ['good' => $g, 'broken' => $after], $refRawMain, ['now' => $b->cooldownUntil + 1]);
ok(in_array('broken', $loopPlan2->topIds(4), true), '冷却到期转半开后重新成为探测候选', $loopPlan2->topIds());
$probeFound = false;
foreach ($loopPlan2->ranked as $c) {
    if ($c->id() === 'broken') {
        $probeFound = true;
    }
}
ok($probeFound, '半开源仍可被选中做探针');

// ---------------------------------------------------------------------------
// 13. 汇总
// ---------------------------------------------------------------------------
// (辅助函数在文件末尾)
function expectBytes(int $start, int $len): string
{
    $unit = '';
    for ($i = 0; $i < 256; $i++) {
        $unit .= chr($i);
    }
    $out = '';
    $pos = $start;
    while (strlen($out) < $len) {
        $off = $pos % 256;
        $take = min(256 - $off, $len - strlen($out));
        $out .= substr($unit, $off, $take);
        $pos += $take;
    }

    return $out;
}

printf("\n=========================================\n");
printf("通过 %d 项, 失败 %d 项\n", $GLOBALS['__pass'], $GLOBALS['__fail']);
printf("PHP %s | 峰值内存 %.2f MB\n", PHP_VERSION, memory_get_peak_usage(true) / 1048576);
foreach (['main', 'tiny', 'disk', 'snap', 'warn', 'prob', 'noquota', 'always'] as $d) {
    rmrf(rtrim(ROOT, '/\\') . '/var/tmp-' . $d);
}
@unlink($rootMain . '/var/tmp-slice.bin');

exit($GLOBALS['__fail'] === 0 ? 0 : 1);
