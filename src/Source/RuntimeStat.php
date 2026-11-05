<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 源的运行时观测状态。在线路径只读它、不重算分位数 —— 直方图与 P85/P95 是
 *             压实器离线算好后落到这里的标量, 每请求反序列化上万个数字只为取两个分位数
 *             是纯浪费。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Source;

use GhAccel\Enum\BreakerState;

/**
 * 可变运行时状态(与不可变的 Source 配置分离)。
 *
 * 时间戳一律用 observed_at 而不是 now: 慢请求会在响应结束后很晚才回写观测, 用 now 做
 * 衰减会让 EWMA 的时间轴抖动, 也让并发回写出现"未来数据"。
 */
final class RuntimeStat
{
    public function __construct(
        /** TTFB 的时间衰减 EWMA, 毫秒。线性域, 因为是加性量 */
        public float $ttfbEwmaMs = 0.0,
        /** 吞吐 EWMA, ln(bytes/s)。必须在对数域, 线性 EWMA 会被一次突发严重污染 */
        public float $thrLogEwma = 0.0,
        /** 压实器离线算好的保守分位数 */
        public float $ttfbP85Ms = 0.0,
        public float $thrP10Bps = 0.0,
        /** Wilson 下界的输入 */
        public int $successes = 0,
        public int $failures = 0,
        public int $sampleCount = 0,
        /** 熔断 */
        public BreakerState $breaker = BreakerState::Closed,
        public int $consecHardFail = 0,
        public int $consecProbeOk = 0,
        public int $tripCount = 0,
        public float $openedAt = 0.0,
        public float $cooldownUntil = 0.0,
        /** 节流与记账 */
        public float $lastRequestAt = 0.0,
        public float $lastProbeAt = 0.0,
        public int $hourBytes = 0,
        public int $hourRequests = 0,
        public float $updatedAt = 0.0,
        /** 失败分型累计, 面板展示用 */
        public array $failBreakdown = [],
        /** 最近一次失败的类型与 curl 错误码 */
        public string $lastFailureKind = '',
        public int $lastHttpStatus = 0,
        public string $lastError = '',
        /** 能力位由探测纠正后的实测值 */
        public array $measuredCaps = [],
        /** 连续被判定 wrong_content 的次数, 达阈值降级 trust */
        public int $wrongContentStreak = 0,
        /** 因探测未达标被打上的低样本标记, 面板据此显示"冷启动中" */
        public bool $coldStart = true,
    ) {
    }

    public static function fromArray(array $a): self
    {
        return new self(
            ttfbEwmaMs: (float) ($a['ttfb_ewma_ms'] ?? 0.0),
            thrLogEwma: (float) ($a['thr_log_ewma'] ?? 0.0),
            ttfbP85Ms: (float) ($a['ttfb_p85_ms'] ?? 0.0),
            thrP10Bps: (float) ($a['thr_p10_bps'] ?? 0.0),
            successes: (int) ($a['successes'] ?? 0),
            failures: (int) ($a['failures'] ?? 0),
            sampleCount: (int) ($a['sample_count'] ?? 0),
            breaker: BreakerState::tryFrom((string) ($a['breaker'] ?? 'closed')) ?? BreakerState::Closed,
            consecHardFail: (int) ($a['consec_hard_fail'] ?? 0),
            consecProbeOk: (int) ($a['consec_probe_ok'] ?? 0),
            tripCount: (int) ($a['trip_count'] ?? 0),
            openedAt: (float) ($a['opened_at'] ?? 0.0),
            cooldownUntil: (float) ($a['cooldown_until'] ?? 0.0),
            lastRequestAt: (float) ($a['last_request_at'] ?? 0.0),
            lastProbeAt: (float) ($a['last_probe_at'] ?? 0.0),
            hourBytes: (int) ($a['hour_bytes'] ?? 0),
            hourRequests: (int) ($a['hour_requests'] ?? 0),
            updatedAt: (float) ($a['updated_at'] ?? 0.0),
            failBreakdown: (array) ($a['fail_breakdown'] ?? []),
            lastFailureKind: (string) ($a['last_failure_kind'] ?? ''),
            lastHttpStatus: (int) ($a['last_http_status'] ?? 0),
            lastError: (string) ($a['last_error'] ?? ''),
            measuredCaps: (array) ($a['measured_caps'] ?? []),
            wrongContentStreak: (int) ($a['wrong_content_streak'] ?? 0),
            coldStart: (bool) ($a['cold_start'] ?? true),
        );
    }

    public function toArray(): array
    {
        return [
            'ttfb_ewma_ms'      => round($this->ttfbEwmaMs, 1),
            'thr_log_ewma'      => round($this->thrLogEwma, 4),
            'ttfb_p85_ms'       => round($this->ttfbP85Ms, 1),
            'thr_p10_bps'       => round($this->thrP10Bps, 1),
            'successes'         => $this->successes,
            'failures'          => $this->failures,
            'sample_count'      => $this->sampleCount,
            'breaker'           => $this->breaker->value,
            'consec_hard_fail'  => $this->consecHardFail,
            'consec_probe_ok'   => $this->consecProbeOk,
            'trip_count'        => $this->tripCount,
            'opened_at'         => $this->openedAt,
            'cooldown_until'    => $this->cooldownUntil,
            'last_request_at'   => $this->lastRequestAt,
            'last_probe_at'     => $this->lastProbeAt,
            'hour_bytes'        => $this->hourBytes,
            'hour_requests'     => $this->hourRequests,
            'updated_at'        => $this->updatedAt,
            'fail_breakdown'    => $this->failBreakdown,
            'last_failure_kind' => $this->lastFailureKind,
            'last_http_status'  => $this->lastHttpStatus,
            'last_error'        => substr($this->lastError, 0, 200),
            'measured_caps'     => $this->measuredCaps,
            'wrong_content_streak' => $this->wrongContentStreak,
            'cold_start'        => $this->coldStart,
        ];
    }

    /** 综合配置声称与实测, 实测优先。未知不等于支持。 */
    public function capOr(Source $source, string $name, bool $default = false): bool
    {
        if (array_key_exists($name, $this->measuredCaps)) {
            return (bool) $this->measuredCaps[$name];
        }

        return $source->cap($name) ? true : $default;
    }

    /** 吞吐 EWMA 还原成 bytes/s。 */
    public function throughputBps(): float
    {
        return $this->thrLogEwma > 0.0 ? exp($this->thrLogEwma) : 0.0;
    }

    /** TTFB 的保守估计: EWMA 与离线 P85 取大。用户超时的直接原因是长尾不是均值。 */
    public function conservativeTtfbMs(): float
    {
        return max($this->ttfbEwmaMs, $this->ttfbP85Ms);
    }

    /** 累计硬故障比例, 熔断触发判据的输入。 */
    public function hardFailRatio(): float
    {
        return $this->sampleCount > 0 ? $this->failures / $this->sampleCount : 0.0;
    }
}
