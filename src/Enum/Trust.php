<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 源的信任档位。第三方公益镜像可以中间人篡改字节, 而本项目的用户里有相当
 *             比例是会自动执行下载产物的 AI Agent —— 篡改风险必须在算法层解决, 而不是
 *             在 README 里写一句"请自行判断"。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Enum;

enum Trust: string
{
    /** 部署者自建(Worker / Nginx / 本机代理), 唯一可以完全信任的一类 */
    case SelfHosted = 'self';

    /** 社区长期已知的公共反代 */
    case CommunityKnown = 'community';

    /** 用户临时加的、来源不明的域名 */
    case Unknown = 'unknown';

    /** 曾因完整性校验或 TLS 校验失败被打入, 默认不参与选路 */
    case Suspect = 'suspect';

    /** 打分因子 f_t 直接取这个值。 */
    public function value(): float
    {
        return match ($this) {
            self::SelfHosted     => 1.0,
            self::CommunityKnown => 0.85,
            self::Unknown        => 0.6,
            self::Suspect        => 0.0,
        };
    }

    /**
     * 无权威摘要时, 该信任档位的源能否让字节进入 EDGE 缓存。
     *
     * 取不到权威摘要又低信任 -> 只流式转发或 302, 不落地。理由: 一旦缓存, 之后就是
     * 由本机域名、带本机 TLS 证书、向国内用户持续分发那份可能被篡改的字节, 声誉与
     * 法律责任都在部署者这边。
     */
    public function mayEdgeWithoutDigest(): bool
    {
        return $this === self::SelfHosted;
    }

    /** 冷启动成功率先验: 公共源偏悲观, 因为它随时可能整个失效。 */
    public function priorAlpha(): int
    {
        return match ($this) {
            self::SelfHosted     => 2,
            self::CommunityKnown => 1,
            self::Unknown        => 1,
            self::Suspect        => 1,
        };
    }

    public function priorBeta(): int
    {
        return match ($this) {
            self::SelfHosted     => 1,
            self::CommunityKnown => 4,
            self::Unknown        => 4,
            self::Suspect        => 8,
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::SelfHosted     => '自建',
            self::CommunityKnown => '社区已知',
            self::Unknown        => '未知来源',
            self::Suspect        => '不可信',
        };
    }
}
