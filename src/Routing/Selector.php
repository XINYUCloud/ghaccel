<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 选路。L0 硬布尔筛(带拒绝原因码) -> L1 四因子打分 -> 确定性 UCB 探索 ->
 *             冷启动配额 -> ranked + breakdown + excluded。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Routing;

use GhAccel\Config;
use GhAccel\Enum\BreakerState;
use GhAccel\Enum\RejectCode;
use GhAccel\Enum\Scene;
use GhAccel\Enum\SourceMode;
use GhAccel\Enum\Trust;
use GhAccel\Ref\GitHubRef;
use GhAccel\Source\RuntimeStat;
use GhAccel\Source\Source;

final class Selector
{
    /** 能力位的唯一键名。这三个都必须由探测实测, 配置声称不等于实测。 */
    private const CAP_RANGE = 'range';
    private const CAP_FOLLOW_REDIRECT = 'follows_redirect_internally';
    private const CAP_JSON_API = 'json_api_ok';

    public function __construct(private readonly Config $cfg)
    {
    }

    /**
     * @param list<Source>          $sources
     * @param array<string, RuntimeStat> $statsById
     * @param array{size_hint?:int, range_requested?:bool, needs_redirect?:bool, is_agent?:bool, now?:float} $ctx
     */
    public function plan(array $sources, array $statsById, GitHubRef $ref, array $ctx): Plan
    {
        $t0 = microtime(true);
        $now = (float) ($ctx['now'] ?? microtime(true));
        $sizeHint = max(0, (int) ($ctx['size_hint'] ?? $ref->sizeHint));
        $rangeRequested = (bool) ($ctx['range_requested'] ?? false);
        $needsRedirect = (bool) ($ctx['needs_redirect'] ?? $ref->needsRedirectResolve);
        $isAgent = (bool) ($ctx['is_agent'] ?? false);

        $scene = $ref->scene;
        $sceneKey = $scene->configKey();
        $ext = self::extensionOf($ref);
        $perRequestBytes = max(0, $this->cfg->int('limits.per_request_bytes', 0));

        $kept = [];
        $rejected = [];
        foreach ($sources as $source) {
            $stat = $statsById[$source->id] ?? new RuntimeStat();
            $codes = $this->screen($source, $stat, $scene, $ext, $sizeHint, $perRequestBytes, $rangeRequested, $needsRedirect, $ref->upstreamHost, $now);
            if ($codes === []) {
                $kept[$source->id] = [$source, $stat];
            } else {
                $rejected[$source->id] = [$source, $stat, $codes];
            }
        }

        // 逐级放宽。每一步都记进 relaxed_flags, 让面板与 Agent 知道"这次是勉强凑出来的路由"。
        $relaxedFlags = [];
        $allowedRelaxations = [];
        while ($kept === [] && $rejected !== []) {
            $next = null;
            foreach (RejectCode::relaxationOrder() as $code) {
                if (!isset($allowedRelaxations[$code->value])) {
                    $next = $code;
                    break;
                }
            }
            if ($next === null) {
                break;
            }
            $allowedRelaxations[$next->value] = true;
            foreach ($rejected as $id => [$src, $stat, $codes]) {
                $remaining = array_values(array_filter(
                    $codes,
                    static fn (RejectCode $c): bool => !isset($allowedRelaxations[$c->value])
                ));
                if ($remaining === []) {
                    $kept[$id] = [$src, $stat, $codes];
                    unset($rejected[$id]);
                    $relaxedFlags[$next->value] = true;
                }
            }
        }
        foreach (array_keys($allowedRelaxations) as $v) {
            // 只保留真正放进来过源的那一级, 否则面板会显示一串没生效的放宽。
            if (!isset($relaxedFlags[$v])) {
                unset($relaxedFlags[$v]);
            }
        }

        if ($kept === []) {
            // 绝不静默直连 github.com: 这里返回空 ranked, 由调用方抛 NO_ELIGIBLE_SOURCE。
            return new Plan(
                ranked: [],
                excluded: $this->excludedList($rejected, $now, $statsById),
                relaxedFlags: array_keys($relaxedFlags),
                scoreGap: 1.0,
                coldStart: $this->isColdStart($sources, $statsById),
                totalSources: count($sources),
                elapsedMs: (microtime(true) - $t0) * 1000.0,
            );
        }

        // 第一遍: 预测耗时。归一化要跨候选取最小值, 所以必须先全部算出来。
        $bytesForPredict = $sizeHint > 0 ? $sizeHint : $this->cfg->int('algo.mode.edge_min_bytes', 0);
        $pred = [];
        $cMin = INF;
        foreach ($kept as $id => $row) {
            [$src, $stat] = $row;
            $ms = Latency::predictMs($stat, $src, $bytesForPredict, $this->cfg, $src->region);
            $pred[$id] = $ms;
            $cMin = min($cMin, $ms);
        }
        if (!is_finite($cMin) || $cMin <= 0.0) {
            $cMin = 1.0;
        }

        $weights = self::weightsFor($this->cfg, $scene);
        $z = $this->zForScene($sceneKey);
        $totalSamples = 0;
        foreach ($kept as $row) {
            $totalSamples += $row[1]->sampleCount;
        }
        $nTotal = max(1, $totalSamples);
        $logN = log($nTotal + 1.0);
        $ucbC = max(0.0, $this->cfg->float('algo.explore.ucb_c', 0.15));

        $scored = [];
        foreach ($kept as $id => $row) {
            [$src, $stat] = $row;
            $relaxed = array_map(
                static fn (RejectCode $c): string => $c->value,
                $row[2] ?? []
            );

            $nP = Success::rateForScoring($stat, $this->cfg, $z);
            $nC = $cMin / ($cMin + $pred[$id]);
            $nW = $this->priorFactor($src);
            $nB = $this->politeFactor($src, $stat, $now, $relaxed);
            $nU = $stat->sampleCount > 0
                ? min(1.0, sqrt($logN / $stat->sampleCount))
                : 1.0;

            $rows = [
                'p' => ['w' => $weights['p'], 'v' => $nP],
                'c' => ['w' => $weights['c'], 'v' => $nC],
                'w' => ['w' => $weights['w'], 'v' => $nW],
                'b' => ['w' => $weights['b'], 'v' => $nB],
                // UCB 作为独立的一行进入 breakdown: 这样"各项权重×归一值之和 == score"
                // 这条不变式在加了探索项之后依然成立, 面板不需要额外解释一个黑箱偏移。
                'u' => ['w' => $ucbC, 'v' => $nU],
            ];
            // 不变式: score 严格等于 breakdown 里"权重 × 归一值"之和。为此先按展示精度把
            // weight/value 定下来, 再用定下来的值算 contrib 与 score —— 面板上肉眼相加也成立。
            $score = 0.0;
            $breakdown = [];
            foreach ($rows as $k => $r) {
                $wr = round($r['w'], 6);
                $vr = round($r['v'], 6);
                $contrib = $wr * $vr;
                $score += $contrib;
                $breakdown[$k] = [
                    'weight' => $wr,
                    'value'  => $vr,
                    'contrib'=> $contrib,
                ];
            }
            $breakdown['predicted_ms'] = round($pred[$id], 1);
            $breakdown['samples'] = $stat->sampleCount;
            $breakdown['breaker'] = $stat->breaker->value;
            $breakdown['sum_check'] = $score;

            $scored[$id] = [
                'score' => $score,
                'cand'  => new Candidate($src, $stat, $score, $breakdown, $pred[$id], $relaxed),
                'probe' => $stat->breaker === BreakerState::HalfOpen,
                'explore' => $this->needsColdStartQuota($stat, $now),
            ];
        }

        uasort($scored, static fn (array $a, array $b): int => $b['score'] <=> $a['score']);

        $topK = max(1, $this->cfg->int('algo.mode.top_k', 4));
        if ($isAgent) {
            // Agent 自己会重试, 深链回退等于把同一个文件向源打 N 次; 收窄候选长度。
            $topK = min($topK, max(2, $this->cfg->int('algo.mode.top_k_agent', 3)));
        }

        $ranked = [];
        $probesUsed = 0;
        $probeLimit = max(1, $this->cfg->int('algo.breaker.probe_max_inflight', 1));
        $exploreLimit = max(1, (int) floor($topK * max(0.0, $this->cfg->float('algo.explore.budget_ratio', 0.08))));
        $exploreUsed = 0;
        $deferred = [];
        foreach ($scored as $id => $row) {
            if ($row['probe'] && $probesUsed >= $probeLimit) {
                // 同一请求最多带 probe_max_inflight 个半开探测, 其余仍按 OPEN 处理。
                $deferred[$id] = [self::srcOf($row), self::statOf($row), [RejectCode::BreakerOpen]];
                continue;
            }
            $ranked[] = $row['cand'];
            if ($row['probe']) {
                $probesUsed++;
            }
            if (count($ranked) >= $topK) {
                break;
            }
        }

        // 冷启动配额: 合格但长期拿不到真实流量的源(公共镜像最常见的死法), 强制挤进 top-k。
        $promoted = [];
        if ($exploreLimit > 0) {
            foreach ($scored as $id => $row) {
                if (!$row['explore'] || $exploreUsed >= $exploreLimit) {
                    continue;
                }
                $already = false;
                foreach ($ranked as $c) {
                    if ($c->id() === $id) {
                        $already = true;
                        $exploreUsed++;
                        break;
                    }
                }
                if ($already) {
                    continue;
                }
                $insertAt = max(0, count($ranked) - 1);
                $insertAt = min($insertAt, $topK - 1);
                array_splice($ranked, $insertAt, 0, [$row['cand']]);
                $ranked = array_slice($ranked, 0, $topK);
                $promoted[] = $id;
                $exploreUsed++;
            }
        }

        $excluded = $this->excludedList($rejected + $deferred, $now, $statsById);
        foreach ($promoted as $id) {
            // 被配额挤进 top-k 的源不该同时出现在"未入选"列表里, 那会让面板自相矛盾。
            $excluded = array_values(array_filter($excluded, static fn (array $e): bool => $e['id'] !== $id));
        }

        $gap = 1.0;
        if (count($ranked) >= 2) {
            $gap = round(max(0.0, $ranked[0]->score - $ranked[1]->score), 6);
        }

        return new Plan(
            ranked: $ranked,
            excluded: $excluded,
            relaxedFlags: array_keys($relaxedFlags),
            scoreGap: $gap,
            coldStart: $this->isColdStart($sources, $statsById),
            totalSources: count($sources),
            elapsedMs: (microtime(true) - $t0) * 1000.0,
        );
    }

    /**
     * L0 硬布尔筛。能用布尔解决的绝不进打分 —— 打分是软的, 会骗人; 硬约束不会。
     *
     * @return list<RejectCode> 空数组代表通过
     */
    private function screen(
        Source $source,
        RuntimeStat $stat,
        Scene $scene,
        string $ext,
        int $sizeHint,
        int $perRequestBytes,
        bool $rangeRequested,
        bool $needsRedirect,
        string $upstreamHost,
        float $now
    ): array {
        $codes = [];
        $add = static function (RejectCode $c) use (&$codes): void {
            foreach ($codes as $exist) {
                if ($exist === $c) {
                    return;
                }
            }
            $codes[] = $c;
        };

        if (!$source->enabled) {
            $add(RejectCode::Disabled);
        }
        if ($source->trust === Trust::Suspect) {
            $add(RejectCode::SuspectTrust);
        }
        if (!$source->supports($scene)) {
            $add(RejectCode::SceneUnsupported);
        }
        if ($upstreamHost !== '' && !$source->coversHost($upstreamHost)) {
            $add(RejectCode::HostNotCovered);
        }
        if ($source->mode === SourceMode::HostReplace && ($needsRedirect || $scene === Scene::ReleaseAsset)) {
            // host_replace 只替换请求 URL 里那一段域名。Release 的真实落点是 302 之后的
            // objects.githubusercontent.com, 不在它覆盖范围内的话, 客户端跟完跳就回到跨洋直连。
            if (!$source->coversHost('objects.githubusercontent.com')) {
                $add(RejectCode::SchemeMismatch);
            }
        }
        if ($perRequestBytes > 0 && $sizeHint > $perRequestBytes) {
            $add(RejectCode::TooBig);
        }
        if ($source->maxSizeBytes > 0 && $sizeHint > $source->maxSizeBytes) {
            $add(RejectCode::TooBig);
        }
        if ($ext !== '' && $source->blocksExt($ext)) {
            $add(RejectCode::ExtBlocked);
        }

        // 能力位只认实测值。配置里写的 true 只是声称: 本机实测 codeload 声称支持 Range
        // 却对 bytes=0-64 返回 200 全量, 这就是为什么要探测。
        $unprobed = false;
        if ($rangeRequested && !$this->capMeasured($stat, self::CAP_RANGE)) {
            $unprobed = true;
        } elseif ($rangeRequested && !$this->capTrue($stat, self::CAP_RANGE)) {
            $add(RejectCode::NoRange);
        }

        if ($needsRedirect || $scene === Scene::ReleaseAsset) {
            // Release 资产必须源内部跟完 302 再吐字节。否则源把 302 原样回吐, 客户端自己
            // 跳回跨洋直连, 等于完全不加速。
            if (!$this->capMeasured($stat, self::CAP_FOLLOW_REDIRECT)) {
                $unprobed = true;
            } elseif (!$this->capTrue($stat, self::CAP_FOLLOW_REDIRECT)) {
                $add(RejectCode::RedirectLoss);
            }
        }

        if ($scene === Scene::ApiJson) {
            if (!$this->capMeasured($stat, self::CAP_JSON_API)) {
                $unprobed = true;
            } elseif (!$this->capTrue($stat, self::CAP_JSON_API)) {
                $add(RejectCode::NoApiSupport);
            }
        }

        if ($unprobed && $this->cfg->bool('algo.l0_require_probed', true)) {
            $add(RejectCode::NotYetProbed);
        }

        // 礼貌间隔: 公益镜像会被打 IP 限流, 打它的人最后会怪本项目。
        if ($source->minIntervalMs > 0 && $stat->lastRequestAt > 0.0) {
            $gapMs = ($now - $stat->lastRequestAt) * 1000.0;
            if ($gapMs < $source->minIntervalMs) {
                $add(RejectCode::PoliteCooldown);
            }
        }

        // 熔断: OPEN 且冷却未到剔除; HALF_OPEN 只在探测名额空着时留作探针候选。
        if ($stat->breaker === BreakerState::Open && $now < $stat->cooldownUntil) {
            $add(RejectCode::BreakerOpen);
        } elseif ($stat->breaker === BreakerState::HalfOpen && !Breaker::probeSlotFree($stat, $now, $this->cfg)) {
            $add(RejectCode::BreakerOpen);
        }

        return $codes;
    }

    private function capMeasured(RuntimeStat $stat, string $cap): bool
    {
        return array_key_exists($cap, $stat->measuredCaps);
    }

    private function capTrue(RuntimeStat $stat, string $cap): bool
    {
        return (bool) ($stat->measuredCaps[$cap] ?? false);
    }

    /** 人工先验因子: 映射到一个小区间, 故意只给小权重, 防止人压过实测。 */
    private function priorFactor(Source $source): float
    {
        [$lo, $hi] = $this->priorRange();
        $span = max(1e-9, $hi - $lo);
        $raw = $lo + $span * ($source->priority / 100.0);
        // 信任档位通过先验参与打分(而不是单列一个因子): 样本稀少时独立信任因子会退化成常数,
        // 而它挂在先验上至少能表达"这条线我更早就信/更晚才信"。
        $raw *= 0.75 + 0.25 * $source->trust->value();

        return max(0.0, min(1.0, ($raw - $lo) / $span));
    }

    private function politeFactor(Source $source, RuntimeStat $stat, float $now, array $relaxed): float
    {
        // 命中 min_interval(即被放宽放进来的)记 0.4, 正常记 1。
        $base = in_array(RejectCode::PoliteCooldown->value, $relaxed, true) ? 0.4 : 1.0;
        if ($source->minIntervalMs > 0 && $stat->lastRequestAt > 0.0
            && ($now - $stat->lastRequestAt) * 1000.0 < $source->minIntervalMs) {
            $base = 0.4;
        }

        $cap = $source->hourlyBytesSoftCap;
        if ($cap > 0 && $stat->hourBytes > $cap) {
            $excess = ($stat->hourBytes - $cap) / max(1, $cap);
            $base *= 0.9 ** $excess;
        }

        return max(0.0, min(1.0, $base));
    }

    /** 冷启动配额: 每小时至少给 N 次真实机会, 且两次之间至少隔 gap。 */
    private function needsColdStartQuota(RuntimeStat $stat, float $now): bool
    {
        $quota = max(0, $this->cfg->int('algo.explore.cold_start_quota', 3));
        if ($quota === 0) {
            return false;
        }
        if ($stat->hourRequests >= $quota) {
            return false;
        }
        $gap = max(0.0, $this->cfg->float('algo.explore.cold_start_min_gap_s', 300.0));

        return $stat->lastRequestAt <= 0.0 || ($now - $stat->lastRequestAt) >= $gap;
    }

    private function isColdStart(array $sources, array $statsById): bool
    {
        $min = max(1, $this->cfg->int('algo.explore.min_sample_for_rank', 30));
        $total = 0;
        foreach ($sources as $src) {
            $stat = $statsById[$src->id] ?? null;
            if ($stat !== null) {
                $total += $stat->sampleCount;
            }
        }

        return $total < $min;
    }

    private function zForScene(string $sceneKey): float
    {
        $byScene = $this->cfg->arr('algo.wilson_z_by_scene', []);
        if (isset($byScene[$sceneKey]) && is_numeric($byScene[$sceneKey])) {
            return max(0.0, (float) $byScene[$sceneKey]);
        }

        return max(0.0, $this->cfg->float('algo.wilson_z', 1.0));
    }

    /** @return array{p:float,c:float,w:float,b:float} */
    public static function weightsFor(Config $cfg, Scene $scene): array
    {
        $table = $cfg->arr('algo.weights', []);
        $row = (array) ($table[$scene->configKey()] ?? $table['default'] ?? []);
        $w = [
            'p' => (float) ($row['p'] ?? 0.34),
            'c' => (float) ($row['c'] ?? 0.34),
            'w' => (float) ($row['w'] ?? 0.20),
            'b' => (float) ($row['b'] ?? 0.12),
        ];
        // 权重表被改坏(和不为 1)时归一化而不是报错: 配置错误不该让线上请求全挂,
        // 面板会显示实际生效权重。
        $sum = array_sum($w);
        if ($sum <= 0.0) {
            return ['p' => 0.25, 'c' => 0.25, 'w' => 0.25, 'b' => 0.25];
        }
        foreach ($w as $k => $v) {
            $w[$k] = $v / $sum;
        }

        return $w;
    }

    /** @return array{0:float,1:float} */
    private function priorRange(): array
    {
        $r = $this->cfg->arr('algo.prior_weight_range', [0.85, 1.15]);
        $lo = (float) ($r[0] ?? 0.85);
        $hi = (float) ($r[1] ?? 1.15);
        if ($hi <= $lo) {
            return [0.0, 1.0];
        }

        return [$lo, $hi];
    }

    /** @return list<array{id:string, code:string, detail:string}> */
    private function excludedList(array $rejected, float $now, array $statsById): array
    {
        $out = [];
        foreach ($rejected as $id => $row) {
            $codes = $row[2] ?? [];
            $stat = $row[1] ?? ($statsById[$id] ?? new RuntimeStat());
            foreach ($codes as $code) {
                $item = ['id' => (string) $id, 'code' => $code->value, 'detail' => $code->detail()];
                if ($code === RejectCode::BreakerOpen && $stat->breaker !== BreakerState::Closed) {
                    $left = max(0.0, $stat->cooldownUntil - $now);
                    $item['retry_after_s'] = round($left, 1);
                    $item['breaker'] = $stat->breaker->value;
                }
                $out[] = $item;
            }
        }

        return $out;
    }

    private static function srcOf(array $row): Source
    {
        return $row['cand']->source;
    }

    private static function statOf(array $row): RuntimeStat
    {
        return $row['cand']->stat;
    }

    /** 从引用里取扩展名(小写、不含点), 用于 blocksExt 判定。 */
    public static function extensionOf(GitHubRef $ref): string
    {
        $name = $ref->assetName !== '' ? $ref->assetName
            : ($ref->downloadName !== '' ? $ref->downloadName
            : ($ref->path !== '' ? basename($ref->path) : ''));
        if ($name === '' && $ref->archiveFmt !== '') {
            // 归档没有文件名, 用格式当扩展名: 很多镜像屏蔽 zip/tar.gz。
            return strtolower(str_replace('.', '', $ref->archiveFmt));
        }
        $dot = strrpos($name, '.');
        if ($dot === false) {
            return '';
        }
        $ext = strtolower(substr($name, $dot + 1));

        return preg_match('#\A[a-z0-9]{1,12}\z#', $ext) ? $ext : '';
    }
}
