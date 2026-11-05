<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 投递模式枚举。同一套选路算法可以配两种投递语义, 这是本项目最重要的一条
 *             架构取舍 —— 让本机只当决策者、不当数据管道。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Enum;

enum ExecMode: string
{
    /** 命中本地缓存直出, 零上游往返 */
    case Edge = 'edge';

    /**
     * 302 到最优镜像源的 URL。
     *
     * 注意目标是"镜像源 URL"而不是 GitHub 上游, 所以既过了 0 本机带宽、又没泄露上游域名、
     * 而且真的在加速。反过来若 302 到 github.com, 国内客户端自己跳回跨洋直连, 加速即失败。
     */
    case Redirect = 'redirect';

    /** 本机流式转发 + 按 ranked 顺序回退, v1 默认 */
    case Failover = 'failover';

    /**
     * 竞速: 并发发起多源, 取最先通过嗅探门者。v1 明确不实现。
     *
     * 阻碍不在并发语义(curl_multi 是用户态单线程轮询, 三种运行时都成立), 而在
     * "响应头一旦发出即固化"与部署侧缓冲链; 其收益可用短 connect_timeout + Redirect
     * 以约十分之一复杂度换到, 而成本是多个源同时全量拉同一文件 —— 对反代是滥用放大器。
     * 保留枚举是为了接口稳定, 运行到此处必须返回 mode_not_supported_in_v1。
     */
    case Hedge = 'hedge';

    /** 客户端请求的 ?part=i/of=n 分片, 只对已完整缓存的条目开放 */
    case Split = 'split';

    public function label(): string
    {
        return match ($this) {
            self::Edge     => '缓存直出',
            self::Redirect => '302 到最优源',
            self::Failover => '流式回退',
            self::Hedge    => '竞速(v2 未实现)',
            self::Split    => '分片续取',
        };
    }

    /** 该模式是否会让字节流经本机, 用于带宽与配额记账。 */
    public function consumesLocalBandwidth(): bool
    {
        return $this === self::Failover || $this === self::Split || $this === self::Hedge;
    }
}
