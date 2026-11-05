<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 成功率的统计口径。Wilson 下界负责"样本少时不许装懂", 失败分型负责
 *             "不是所有失败都该记在源头上, 也不是所有失败都能触发熔断"。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Routing;

use GhAccel\Config;
use GhAccel\Enum\FailureKind;
use GhAccel\Source\RuntimeStat;

final class Success
{
    /**
     * Wilson score 区间下界。
     *
     * 为什么不是"Beta 后验 + 正态近似": 实测在 n<20 时那个组合会算出负数, 被 clamp 成 0 之后
     * 所有低样本源同分, 排序彻底失效 —— 而低样本恰恰是冷启动期唯一的状态。Wilson 专为小样本
     * 设计, 有界、单调、无 clamp, 且只是一个闭式表达式。
     *
     * 单调性: n 固定时随 k 单调上升; k/n 固定时随 n 单调上升(下界收紧), 所以"1 次全成"必然
     * 显著低于"100 次全成", 这正是我们想要的谦逊程度。
     */
    public static function wilsonLowerBound(int $successes, int $tries, float $z): float
    {
        if ($tries <= 0) {
            return 0.0;
        }
        $k = max(0, min($tries, $successes));
        $n = (float) $tries;
        $z2 = $z * $z;
        $phat = $k / $n;

        $center = $phat + $z2 / (2.0 * $n);
        $margin = $z * sqrt(($phat * (1.0 - $phat) + $z2 / (4.0 * $n)) / $n);
        $lower = ($center - $margin) / (1.0 + $z2 / $n);

        return max(0.0, min(1.0, $lower));
    }

    /**
     * 记录一次结局。只动 successes / failures / sample_count / fail_breakdown 四个字段,
     * 熔断相关的 consec_* 与 breaker 状态归 Breaker::recordOutcome 负责, 两边不重叠。
     *
     * 口径(三条, 每条都对应一类真实事故):
     *  - weight()==0 的分型(oversize / client_abort / blocked / guard_rejected /
     *    no_eligible_source)完全不进统计: 用户请求超大文件被本地截断、Agent 主动超时中断,
     *    都不是源的错, 记进去会误伤刚上线的源。
     *  - 假 200(wrong_content)与 integrity 增加分母 sample_count 但不增加 successes, 于是
     *    它们拉低成功率, 却不增加 $failures —— $failures 是硬故障计数, 只喂熔断。
     *    分型权重只影响打分与面板, 绝不进熔断触发计数: 否则一个镜像缓存了旧 tag 内容
     *    触发一次 wrong_content 就能把刚上线的源判死。
     *  - 硬故障(countsForBreaker)才同时增加 $failures。
     */
    public static function record(RuntimeStat $s, FailureKind $kind, Config $cfg): RuntimeStat
    {
        $n = clone $s;

        if ($kind === FailureKind::None) {
            $n->successes++;
            $n->sampleCount++;
            // fail_breakdown 顾名思义只记失败; 把 none 记进去会让面板的失败饼图出现
            // 一个"none: 1200"的大扇区, 反而看不见真正的故障类型。
            $n->lastFailureKind = '';

            return $n;
        }

        // 部署者可以把某个分型临时视为"与源无关"(例如迁移期上游批量 4xx), 不需要改代码。
        $neutral = array_map('strval', $cfg->arr('algo.stats_neutral_kinds', []));
        if (in_array($kind->value, $neutral, true) || $kind->weight() <= 0.0) {
            return $n;
        }

        $n->sampleCount++;
        if ($kind->countsForBreaker()) {
            $n->failures++;
        }
        $n->failBreakdown = self::bump($n->failBreakdown, $kind->value, $cfg);
        $n->lastFailureKind = $kind->value;

        return $n;
    }

    /**
     * 打分用的成功率因子输入。tries 为 0 时返回配置里的冷启动先验值而不是 0 ——
     * 没有实测就别假装实测有用: 让所有零样本源在成功率上打平, 排序交给人工先验因子,
     * 同时由 Plan::$coldStart 明确告诉运维"现在是先验在起作用"。
     */
    public static function rateForScoring(RuntimeStat $s, Config $cfg, float $z): float
    {
        if ($s->sampleCount <= 0) {
            return $cfg->float('algo.cold_start_success_prior', 0.72);
        }

        return self::wilsonLowerBound($s->successes, $s->sampleCount, $z);
    }

    /** 观测到的失败占比(硬故障/全部样本), 熔断与面板共用同一口径。 */
    public static function hardFailRate(RuntimeStat $s): float
    {
        return $s->sampleCount > 0 ? $s->failures / $s->sampleCount : 0.0;
    }

    private static function bump(array $map, string $key, Config $cfg): array
    {
        $map[$key] = (int) ($map[$key] ?? 0) + 1;

        // fail_breakdown 会随快照常驻内存, 极端部署里失败种类可能很多; 给一个上限,
        // 超限只保留计数最大的若干项, 面板丢的是最稀的那类而不是最重要的那类。
        $maxKeys = max(4, $cfg->int('algo.fail_breakdown_max_keys', 16));
        if (count($map) > $maxKeys) {
            arsort($map);
            $map = array_slice($map, 0, $maxKeys, true);
        }

        return $map;
    }
}
