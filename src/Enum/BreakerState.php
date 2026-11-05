<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 熔断状态机三态定义。状态迁移逻辑在 Routing/Breaker.php, 这里只放语义。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Enum;

/**
 * 半开状态机的三个状态。
 *
 * 之所以不用令牌桶做熔断: 令牌桶是准入限流, 表达的是"速率", 表达不了
 * "坏了要隔离、冷却后放几个探测、连续合格才恢复"这套状态语义。
 * 令牌桶在本项目里只有一个用途 —— 给 HALF_OPEN 的探测配额做预算。
 */
enum BreakerState: string
{
    case Closed = 'closed';
    case Open = 'open';
    case HalfOpen = 'half_open';

    /** 该状态下是否允许承接正常用户流量。 */
    public function acceptsTraffic(): bool
    {
        return $this === self::Closed;
    }

    /** 该状态下是否允许占用探测配额。OPEN 冷却到期后由压实/选路转入 HALF_OPEN。 */
    public function allowsProbe(): bool
    {
        return $this === self::HalfOpen || $this === self::Open;
    }

    /** 面板展示用的中文态名。 */
    public function label(): string
    {
        return match ($this) {
            self::Closed   => '健康',
            self::Open     => '熔断中',
            self::HalfOpen => '半开试探',
        };
    }
}
