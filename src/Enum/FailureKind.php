<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 失败分型及其权重。这是选路可信度的地基 —— 把所有失败混为一谈会被两类
 *             事故击穿: 镜像返回"假 200 + HTML 限流页"会被记成成功, 用户请求超大文件
 *             被本地截断会被记成源的错从而误熔断一个新上线的镜像。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Enum;

/**
 * 一次上游交互的结局类型。
 *
 * 两条铁律, 改动前请三思:
 *  1. weight() 只影响打分与面板展示, countsForBreaker() 决定能否累积成熔断。
 *     分型权重绝不进熔断计数, 否则 wrong_content/integrity 一次就能把新源判死。
 *  2. RateLimited 与 Blocked 必须终止整条 failover 链, 不得换源重试。把 GitHub 或
 *     镜像的限速信号当成"这个源不行换一个", 结局是短时间内全源同时被封。
 */
enum FailureKind: string
{
    /** 成功 */
    case None = 'none';

    /** DNS 解析失败 / TCP 连接被拒 / 连接超时 */
    case Connect = 'connect';

    /** 首字节超时, 连上了但没开始回数据 */
    case TimeoutTtfb = 'timeout_ttfb';

    /** 传输中途卡死, 字节间隔超过 stall 阈值 */
    case Stall = 'stall';

    /** TLS 证书校验失败, 可能是镜像证书链坏了或被中间人 */
    case TlsVerify = 'tls_verify';

    /** 源或上游回 4xx。URL 本身错了也会落这里, 所以不该重罚源。 */
    case Http4xx = 'http_4xx';

    /** 源侧 5xx */
    case Http5xx = 'http_5xx';

    /**
     * 假 200: 状态码好看但内容是 HTML 错误页/验证码页。
     * 公共镜像限流或失效时的典型行为, 只统计状态码的话该源成功率会算成 100%。
     */
    case WrongContent = 'wrong_content';

    /** sha256 与客户端或服务端已知值不符。最高惩罚, 且直接降级 trust。 */
    case Integrity = 'integrity';

    /** 超过单请求字节上限被本地截断。这是部署者的保护, 不是源的错。 */
    case Oversize = 'oversize';

    /** 客户端主动断开。Agent 超时中断极常见, 绝不能计入源失败。 */
    case ClientAbort = 'client_abort';

    /** 上游或源明确回 429 / X-RateLimit-Remaining 归零。禁止换源重试。 */
    case RateLimited = 'rate_limited';

    /** 源明确拒绝该类资源(扩展名黑名单/体积策略)。是策略不是健康度。 */
    case Blocked = 'blocked';

    /** 安全判定链拒绝(SSRF/host 不合法)。与源无关。 */
    case GuardRejected = 'guard_rejected';

    /** 所有加速源被 L0 过滤光。部署配置问题, 不计入任何源的失败。 */
    case NoEligibleSource = 'no_eligible_source';

    /**
     * 对源健康度的影响权重。0 表示与源无关, 不进 EWMA、不进成功率分子分母。
     */
    public function weight(): float
    {
        return match ($this) {
            self::None           => 0.0,
            self::Connect        => 1.0,
            self::TimeoutTtfb    => 1.0,
            self::Stall          => 1.0,
            self::TlsVerify      => 1.5,
            self::Http4xx        => 0.4,
            self::Http5xx        => 1.0,
            self::WrongContent   => 1.5,
            self::Integrity      => 3.0,
            self::Oversize       => 0.0,
            self::ClientAbort    => 0.0,
            self::RateLimited    => 0.8,
            self::Blocked        => 0.0,
            self::GuardRejected  => 0.0,
            self::NoEligibleSource => 0.0,
        };
    }

    /** 是否算"硬故障", 即累积到熔断触发阈值。 */
    public function countsForBreaker(): bool
    {
        return match ($this) {
            self::Connect, self::TimeoutTtfb, self::Stall, self::Http5xx, self::TlsVerify => true,
            default => false,
        };
    }

    /** 是否必须中止 failover 链, 不再尝试下一个源。 */
    public function mustStopFailover(): bool
    {
        return match ($this) {
            self::RateLimited, self::Integrity, self::GuardRejected, self::Oversize => true,
            default => false,
        };
    }

    /** 是否计入成功率的分母(即"这是一次真实的尝试")。 */
    public function countsForSuccess(): bool
    {
        return $this->weight() > 0.0;
    }

    /** 该失败是否应当让源的 trust 直接降到最低档。 */
    public function shouldDemoteTrust(): bool
    {
        return $this === self::Integrity || $this === self::TlsVerify;
    }

    public function isFailure(): bool
    {
        return $this !== self::None;
    }
}
