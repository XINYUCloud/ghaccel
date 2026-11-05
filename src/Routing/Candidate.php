<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 选路输出的候选项, 必须自带可解释的分数分解。不可解释的排序在这个项目里
 *             等于不可运维 —— 运维看到"选了这个慢源"却查不到为什么, 就会开始乱改权重。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Routing;

use GhAccel\Source\RuntimeStat;
use GhAccel\Source\Source;

final class Candidate
{
    public function __construct(
        public readonly Source $source,
        public readonly RuntimeStat $stat,
        public readonly float $score,
        /** 每项因子的权重、归一化值与贡献, 面板与诊断 JSON 原样展示 */
        public readonly array $breakdown,
        /** 预测到拿到全部字节的耗时, 毫秒 */
        public readonly float $predictedMs,
        /** 是否属于放宽硬约束后被放进来的 */
        public readonly array $relaxed = [],
    ) {
    }

    public function id(): string
    {
        return $this->source->id;
    }
}
