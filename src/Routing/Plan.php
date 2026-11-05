<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 一次选路的完整决策结果。excluded 与 ranked 同等重要: 决策视图靠它回答
 *             "为什么没选那个源", 这是打分体系唯一可调试的入口。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Routing;

final class Plan
{
    public function __construct(
        /** 按分数降序的候选, 长度即 failover 深度上限 */
        public array $ranked = [],
        /** [{id, code, detail}] L0 剔除及原因 */
        public array $excluded = [],
        /** 本轮放宽过的硬约束 */
        public array $relaxedFlags = [],
        /** top1 与 top2 的分数间隙, Dispatcher 用它判断是否值得并发试探 */
        public float $scoreGap = 1.0,
        /** 冷启动标记: 全局样本不足时打分实质退化为人工先验, 必须让运维看见 */
        public bool $coldStart = false,
        public int $totalSources = 0,
        public float $elapsedMs = 0.0,
    ) {
    }

    public function hasCandidates(): bool
    {
        return $this->ranked !== [];
    }

    public function top(): ?Candidate
    {
        return $this->ranked[0] ?? null;
    }

    /** 前 k 个候选的 id, 供 failover 与面板显示。 */
    public function topIds(int $k = 4): array
    {
        return array_map(
            static fn (Candidate $c): string => $c->id(),
            array_slice($this->ranked, 0, $k)
        );
    }

    public function toArray(): array
    {
        return [
            'ranked' => array_map(static fn (Candidate $c): array => [
                'id'          => $c->id(),
                'score'       => round($c->score, 4),
                'predicted_ms'=> round($c->predictedMs, 0),
                'breakdown'   => $c->breakdown,
                'relaxed'     => $c->relaxed,
            ], $this->ranked),
            'excluded'      => $this->excluded,
            'relaxed_flags' => $this->relaxedFlags,
            'score_gap'     => round($this->scoreGap, 4),
            'cold_start'    => $this->coldStart,
            'total_sources' => $this->totalSources,
            'elapsed_ms'    => round($this->elapsedMs, 2),
        ];
    }
}
