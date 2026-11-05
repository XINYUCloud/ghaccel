<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 熔断三态状态机与自适应冷却。它的存在是为了让"已经打死的源"停止吃流量,
 *             同时保证恢复过程本身不会把源打死第二次。
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
use GhAccel\Enum\FailureKind;
use GhAccel\Source\RuntimeStat;

final class Breaker
{
    /**
     * 状态迁移(CLOSED -> OPEN -> HALF_OPEN -> CLOSED), 只依据硬故障。
     *
     * 触发判据两条, 任一命中即跳闸:
     *  - 窗口内硬故障率 >= err_ratio_threshold 且 sampleCount >= min_window_n
     *    (样本不足时比率毫无意义: 1/1 失败 = 100%, 但那只是一个偶然)
     *  - 连续硬失败 >= consec_fail_trip (抓的是"正在坏", 不等样本量攒够)
     *
     * $failures 只由 countsForBreaker() 的分型累加(见 Success::record), 所以 wrong_content /
     * integrity 这类"内容问题"永远不会走到这里把源判死。
     */
    public static function evaluate(RuntimeStat $s, float $now, Config $cfg): RuntimeStat
    {
        $n = clone $s;

        // trip_count 半衰: 坏了一周的源不该一回来就 15 分钟冷却。
        $halflife = max(1.0, $cfg->float('algo.breaker.trip_halflife_s', 7200.0));
        if ($n->tripCount > 0 && $n->openedAt > 0.0 && $now > $n->openedAt) {
            $decay = exp(-($now - $n->openedAt) * M_LN2 / $halflife);
            $n->tripCount = max(0, (int) floor($n->tripCount * $decay + 0.5));
        }

        switch ($n->breaker) {
            case BreakerState::Open:
                if ($now >= $n->cooldownUntil) {
                    $n->breaker = BreakerState::HalfOpen;
                    $n->consecProbeOk = 0;
                    $n->lastProbeAt = 0.0;
                }
                break;

            case BreakerState::HalfOpen:
                // 半开太久没被探测(流量全走了别的源)说明它其实没被验证过, 冷却到期后
                // 退回 OPEN 再等一轮, 而不是让它长期挂在一个"谁也没试过"的中间态。
                $patience = self::cooldownSeconds(self::history($n), $now, $cfg);
                if ($n->cooldownUntil > 0.0 && $now >= $n->cooldownUntil + $patience) {
                    $n->breaker = BreakerState::Open;
                    $n->cooldownUntil = $now + $patience;
                    $n->openedAt = $now;
                }
                break;

            case BreakerState::Closed:
                $minWindow = max(1, $cfg->int('algo.breaker.min_window_n', 5));
                $ratioLimit = $cfg->float('algo.breaker.err_ratio_threshold', 0.6);
                $consecLimit = max(1, $cfg->int('algo.breaker.consec_fail_trip', 3));
                $ratioTrip = $n->sampleCount >= $minWindow && Success::hardFailRate($n) >= $ratioLimit;
                if ($ratioTrip || $n->consecHardFail >= $consecLimit) {
                    self::trip($n, $now, $cfg);
                }
                break;
        }

        return $n;
    }

    /**
     * 把一次结局计入状态机。
     *
     * HALF_OPEN 转 CLOSED 需要连续 probe_success_to_close 次成功**且每次 TTFB 达标**:
     * "1 次成功就放开门"会让一个慢到不可用的源反复开关(抖熔断), 每次抖动都真真切切地把
     * 用户当探针用。$sceneKey 是可选的(SLO 表按场景取值), 传空则用表内最宽松的一档兜底。
     */
    public static function recordOutcome(RuntimeStat $s, FailureKind $kind, float $ttfbMs, float $now, Config $cfg, string $sceneKey = ''): RuntimeStat
    {
        $n = clone $s;

        if (!$kind->isFailure()) {
            $n->consecHardFail = 0;
            if ($n->breaker === BreakerState::HalfOpen) {
                $ok = $ttfbMs > 0.0 && $ttfbMs <= self::probeTtfbLimitMs($n, $cfg, $sceneKey);
                if ($ok) {
                    $n->consecProbeOk++;
                    if ($n->consecProbeOk >= max(1, $cfg->int('algo.breaker.probe_success_to_close', 2))) {
                        $n->breaker = BreakerState::Closed;
                        $n->cooldownUntil = 0.0;
                        $n->openedAt = 0.0;
                        $n->consecHardFail = 0;
                    }
                } else {
                    // 成功但慢: 探测没过, 重新按累计 trip 冷却。不加新 trip 也不清零,
                    // 保持"它还没证明自己"的原状。
                    $n->consecProbeOk = 0;
                    $n->breaker = BreakerState::Open;
                    $n->openedAt = $now;
                    $n->cooldownUntil = $now + self::cooldownSeconds(self::history($n), $now, $cfg);
                }
            }

            return $n;
        }

        if (!$kind->countsForBreaker()) {
            // 软失败: 不改 consecHardFail。一次 404 不该把"连续 3 次连不上"清零,
            // 那等于给正在坏掉的源发了一张免死金牌。
            return $n;
        }

        $n->consecHardFail++;
        $n->consecProbeOk = 0;

        $consecLimit = max(1, $cfg->int('algo.breaker.consec_fail_trip', 3));
        $minWindow = max(1, $cfg->int('algo.breaker.min_window_n', 5));
        $ratioLimit = $cfg->float('algo.breaker.err_ratio_threshold', 0.6);
        $ratioTrip = $n->sampleCount >= $minWindow && Success::hardFailRate($n) >= $ratioLimit;

        if ($n->breaker === BreakerState::HalfOpen) {
            // 半开期探针直接失败: 立刻重新熔断, 并且这次带 trip 递增(冷却变长)。
            self::trip($n, $now, $cfg);

            return $n;
        }

        if ($n->consecHardFail >= $consecLimit || $ratioTrip) {
            self::trip($n, $now, $cfg);
        }

        return $n;
    }

    /**
     * 冷却时长 = clamp(base * gain^(trips-1) * jitter, min, max)。
     *
     * $tripHistory 是历史跳闸时刻列表。每一项按 0.5^(Δt/半衰期) 衰减后求和, 所以一周没再
     * 跳闸的源等效 trips≈1(最短冷却), 刚连续跳闸的源等效 trips 满额(最长冷却)。
     * jitter 由 (trips, now 的毫秒位) 确定性地导出: 同一批一起熔断的源因为跳闸时刻不同而
     * 拿到不同的抖动值, 不会在同一秒集体恢复造成惊群; 同时保持纯函数可测(不引入 RNG)。
     */
    public static function cooldownSeconds(array $tripHistory, float $now, Config $cfg): float
    {
        $base = max(0.0, $cfg->float('algo.breaker.cooldown_base_s', 20.0));
        $gain = max(1.01, $cfg->float('algo.breaker.cooldown_gain', 1.9));
        $min = max(0.0, $cfg->float('algo.breaker.cooldown_min_s', 8.0));
        $max = max($min, $cfg->float('algo.breaker.cooldown_max_s', 900.0));
        $halflife = max(1.0, $cfg->float('algo.breaker.trip_halflife_s', 7200.0));
        [$jlo, $jhi] = self::jitterRange($cfg);

        $trips = 0.0;
        foreach ($tripHistory as $t) {
            $age = max(0.0, $now - (float) $t);
            $trips += exp(-$age * M_LN2 / $halflife);
        }
        $trips = max(1.0, $trips);

        $jitter = self::jitter($trips, $now, $jlo, $jhi);
        $raw = $base * ($gain ** ($trips - 1.0)) * $jitter;

        return max($min, min($max, $raw));
    }

    /** 面板一键复位: 无条件回 CLOSED 并清空累计, 这是给运维的逃生门而不是算法分支。 */
    public static function manualReset(RuntimeStat $s, float $now): RuntimeStat
    {
        $n = clone $s;
        $n->breaker = BreakerState::Closed;
        $n->consecHardFail = 0;
        $n->consecProbeOk = 0;
        $n->tripCount = 0;
        $n->openedAt = 0.0;
        $n->cooldownUntil = 0.0;
        $n->lastProbeAt = 0.0;
        $n->updatedAt = max($n->updatedAt, $now);

        return $n;
    }

    /**
     * 该源此刻能否承接正常流量。
     *
     * HALF_OPEN 同时只放 probe_max_inflight 个探测: PHP 是 shared-nothing, 本进程看不到
     * 其他 worker 的在途探测, 所以这里用"距上次探测的时间窗"近似并发度, 真需要严格并发由
     * Security/Slots 的 lock-slot 承担。近似的效果是防止同一时刻多个 worker 同时把用户
     * 当探针, 而不是精确计数。
     */
    public static function admitsTraffic(RuntimeStat $s, float $now, Config $cfg): bool
    {
        return match ($s->breaker) {
            BreakerState::Closed => true,
            BreakerState::Open => $now >= $s->cooldownUntil,
            BreakerState::HalfOpen => self::probeSlotFree($s, $now, $cfg),
        };
    }

    /** 此刻能否占用一个探测名额(供选路决定是否把半开源排进候选)。 */
    public static function probeSlotFree(RuntimeStat $s, float $now, Config $cfg): bool
    {
        $inflight = max(1, $cfg->int('algo.breaker.probe_max_inflight', 1));
        if ($inflight > 1) {
            // 允许多路探测时按窗口宽度折算: 一个冷却周期内均匀放行。
            $window = max(1.0, self::cooldownSeconds(self::history($s), $now, $cfg) / $inflight);

            return $s->lastProbeAt <= 0.0 || ($now - $s->lastProbeAt) >= $window;
        }

        $gapMs = max(0.0, $cfg->float('algo.breaker.probe_min_gap_ms', 1000.0)) / 1000.0;

        return $s->lastProbeAt <= 0.0 || ($now - $s->lastProbeAt) >= $gapMs;
    }

    /** 探测期 TTFB 合格线: 场景 SLO × release_ttfb_factor; 没有场景则取表内最宽松一档。 */
    public static function probeTtfbLimitMs(RuntimeStat $s, Config $cfg, string $sceneKey = ''): float
    {
        $table = $cfg->arr('algo.breaker.slo_ttfb_ms', []);
        $factor = max(1.0, $cfg->float('algo.breaker.release_ttfb_factor', 1.5));
        $slo = $sceneKey !== '' && isset($table[$sceneKey]) ? (float) $table[$sceneKey] : 0.0;
        if ($slo <= 0.0) {
            $slo = $table === [] ? 3000.0 : max(array_map('floatval', $table));
        }
        // 已经观测到过该源正常水平时, 要求它恢复到接近自己历史最好水平, 防止
        // "慢源靠一条极快的偶然样本重新开门"。取两者较小值即更严格。
        $own = $s->ttfbEwmaMs > 0.0 ? $s->ttfbEwmaMs * $factor : 0.0;

        return $own > 0.0 ? min($slo * $factor, $own) : $slo * $factor;
    }

    /** 从 stat 里能重建的历史(只有最近一次跳闸时刻), 供没有显式历史表时退化使用。 */
    private static function history(RuntimeStat $s): array
    {
        if ($s->openedAt <= 0.0) {
            return [];
        }

        // tripCount 次跳闸都记在最近这一次的时间戳上: 衰减按最坏(最新)情况算,
        // 宁可让冷却略长也不让坏源提前恢复。
        return array_fill(0, max(1, $s->tripCount), $s->openedAt);
    }

    private static function trip(RuntimeStat $n, float $now, Config $cfg): void
    {
        $halflife = max(1.0, $cfg->float('algo.breaker.trip_halflife_s', 7200.0));
        $decayed = $n->openedAt > 0.0 && $now > $n->openedAt
            ? $n->tripCount * exp(-($now - $n->openedAt) * M_LN2 / $halflife)
            : (float) $n->tripCount;
        $trips = max(1, (int) round(max(0.0, $decayed)) + 1);

        $n->breaker = BreakerState::Open;
        $n->tripCount = $trips;
        $n->openedAt = $now;
        $n->consecProbeOk = 0;
        $n->consecHardFail = 0;
        $n->cooldownUntil = $now + self::cooldownSeconds(array_fill(0, $trips, $now), $now, $cfg);
    }

    /** @return array{0:float,1:float} */
    private static function jitterRange(Config $cfg): array
    {
        $j = $cfg->arr('algo.breaker.jitter', [0.8, 1.2]);
        $lo = (float) ($j[0] ?? 0.8);
        $hi = (float) ($j[1] ?? 1.2);
        if ($hi <= $lo) {
            return [1.0, 1.0];
        }

        return [max(0.1, $lo), $hi];
    }

    /**
     * 确定性抖动: 由 (trips, now 的亚秒位) 散列到 [lo,hi]。
     * 用 hash 而不是 mt_rand 是为了让单测可复现, 同时保留"同批熔断源不同时恢复"的效果
     * —— 各源的 now 落在不同的毫秒上, 散列值自然不同。
     */
    private static function jitter(float $trips, float $now, float $lo, float $hi): float
    {
        $seed = sprintf('%.4f|%.3f', $trips, fmod($now, 3600.0));
        $h = hex2bin(substr(hash('sha256', $seed), 0, 8));
        $u = $h === false ? 0 : (unpack('N', $h)[1] ?? 0);
        $unit = (($u & 0xFFFFFF) / 0xFFFFFF);

        return $lo + $unit * ($hi - $lo);
    }
}
