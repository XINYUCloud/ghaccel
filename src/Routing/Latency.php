<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 延迟与吞吐的时间衰减 EWMA, 以及"预测拿到全部字节要多久"。在线路径绝不
 *             在这里算分位数 —— 分位数由压实器离线算好写成标量, 这里只读标量。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Routing;

use GhAccel\Config;
use GhAccel\Source\RuntimeStat;
use GhAccel\Source\Source;

final class Latency
{
    /**
     * 用一条新观测更新 EWMA, 返回新的 stat 实例(不改入参, 选路要能对同一 base 试算多次)。
     *
     * 三个必须遵守的规则:
     *  1. 单调保护: observed_at 早于已记录的 updatedAt 直接跳过。慢请求会在响应结束后很久
     *     才回写观测, 若不做保护, 一条迟到样本会把 EWMA 拖回过去的值, 时间轴倒退且不可复现。
     *  2. 陈旧样本重初始化: 旧值权重 w = exp(-Δt/τ) 低于 alpha_floor 时丢弃历史, 用新样本
     *     重新开始。否则一个下线三天的源回来还背着几天前的脏数据, 面板数字与真实体验脱节。
     *  3. TTFB 用线性域(加性量), 吞吐用 ln 域(乘性量)。线性域做吞吐 EWMA 会被一次突发
     *     严重污染: 一次 50MB/s 的样本能顶掉二十次 2MB/s 的中位数。
     */
    public static function update(RuntimeStat $s, float $ttfbMs, float $thrBps, float $observedAt, Config $cfg): RuntimeStat
    {
        if ($observedAt <= 0.0 || $observedAt < $s->updatedAt) {
            return clone $s;
        }

        $n = clone $s;
        $tauTtfb = max(1.0, $cfg->float('algo.ewma.tau_ttfb_s', 90.0));
        $tauThr  = max(1.0, $cfg->float('algo.ewma.tau_thr_s', 180.0));
        $floor   = $cfg->float('algo.ewma.alpha_floor', 0.15);
        $hasHistory = $s->updatedAt > 0.0 && $s->ttfbEwmaMs > 0.0;

        if ($ttfbMs > 0.0) {
            if (!$hasHistory) {
                $n->ttfbEwmaMs = $ttfbMs;
            } else {
                $w = exp(-(max(0.0, $observedAt - $s->updatedAt)) / $tauTtfb);
                $n->ttfbEwmaMs = $w < $floor
                    ? $ttfbMs
                    : $ttfbMs * (1.0 - $w) + $s->ttfbEwmaMs * $w;
            }
        }

        $thrFloorBps = max(1024.0, $cfg->float('algo.ewma.thr_floor_kbps', 20.0) * 1024.0);
        if ($thrBps > 0.0) {
            // 下限截断同时防 ln(0) 与防"一次 100B/s 的抖动脉冲"把对数域拖穿。
            $x = log(max($thrBps, $thrFloorBps));
            $hasThr = $s->updatedAt > 0.0 && $s->thrLogEwma > 0.0;
            if (!$hasThr) {
                $n->thrLogEwma = $x;
            } else {
                $w = exp(-(max(0.0, $observedAt - $s->updatedAt)) / $tauThr);
                $n->thrLogEwma = $w < $floor ? $x : $x * (1.0 - $w) + $s->thrLogEwma * $w;
            }
        }

        $n->updatedAt = $observedAt;

        // 冷启动标记跟着样本量走: 压实器与热路径都不再单独维护它, 避免两处口径不一致
        // 让面板忽亮忽灭。
        $minRank = max(1, $cfg->int('algo.explore.min_sample_for_rank', 30));
        $n->coldStart = $n->sampleCount < $minRank;

        return $n;
    }

    /**
     * 预测"从发起请求到拿满 $bytes 需要多少毫秒"。
     *
     * 保守取值是刻意的: 用户超时的直接原因是长尾而不是均值, 所以首字节取 max(EWMA, 离线 P85),
     * 吞吐取样本充足时的 min(EWMA, 离线 P10)(即更慢的那个)。RuntimeStat::conservativeTtfbMs()
     * 已经实现了 max 语义, 这里复用它而不是重算一遍, 防止两处漂移。
     */
    public static function predictMs(RuntimeStat $s, Source $src, int $bytes, Config $cfg, string $regionPriorKey): float
    {
        $prior = self::regionPrior($cfg, $regionPriorKey !== '' ? $regionPriorKey : $src->region);

        $ttfb = $s->conservativeTtfbMs();
        if ($ttfb <= 0.0) {
            // 完全没有实测: 用区域先验兜底, 再加该源声明的连接预算。冷启动期这是唯一能
            // 给出的估计, 面板必须同时标注"冷启动中"。
            $ttfb = $prior['ttfb_ms'] + $src->connectTimeoutMs * 0.25;
        }

        $minSamples = max(1, $cfg->int('algo.ewma.min_obs_for_thr', 3));
        $thr = 0.0;
        if ($s->sampleCount >= $minSamples && $s->thrLogEwma > 0.0) {
            $thr = $s->throughputBps();
            if ($s->thrP10Bps > 0.0) {
                $thr = min($thr, $s->thrP10Bps);
            }
        } elseif ($s->thrP10Bps > 0.0) {
            $thr = $s->thrP10Bps;
        } else {
            $thr = $prior['thr_bps'];
        }

        if ($bytes <= 0) {
            return max(1.0, $ttfb);
        }

        $floorBps = max(1024.0, $cfg->float('algo.ewma.thr_floor_kbps', 20.0) * 1024.0);

        return max(1.0, $ttfb + ($bytes / max($thr, $floorBps)) * 1000.0);
    }

    /** 区域先验读取, 未知区域回落到 unknown 条目而不是报错。 */
    public static function regionPrior(Config $cfg, string $key): array
    {
        $table = $cfg->arr('algo.region_prior', []);
        $row = (array) ($table[$key] ?? $table['unknown'] ?? []);

        return [
            'ttfb_ms' => (float) ($row['ttfb_ms'] ?? 800.0),
            'thr_bps' => (float) ($row['thr_bps'] ?? 1048576.0),
        ];
    }
}
