<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: L0 硬过滤的拒绝原因码。"为什么没选它"与"为什么选它"同等重要, 所以拒绝
 *             必须带原因一路传到决策视图与诊断 JSON, 不允许静默丢弃。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Enum;

enum RejectCode: string
{
    case SceneUnsupported   = 'scene_unsupported';
    case HostNotCovered     = 'host_not_covered';
    case RedirectLoss       = 'redirect_loss';
    case TooBig             = 'too_big';
    case ExtBlocked         = 'ext_blocked';
    case NoRange            = 'no_range';
    case BreakerOpen        = 'breaker_open';
    case NoApiSupport       = 'no_api_support';
    case Disabled           = 'disabled';
    case SuspectTrust       = 'suspect_trust';
    case PoliteCooldown     = 'polite_cooldown';
    case NotYetProbed       = 'not_yet_probed';
    case SchemeMismatch     = 'scheme_mismatch';

    /**
     * 放宽顺序。保留源不足时按此顺序逐级放行, 每放宽一项都要记进 relaxed_flags,
     * 让面板与 Agent 知道"这次是勉强凑出来的路由", 而不是悄悄降级。
     */
    public static function relaxationOrder(): array
    {
        return [self::NotYetProbed, self::PoliteCooldown, self::BreakerOpen];
    }

    public function detail(): string
    {
        return match ($this) {
            self::SceneUnsupported => '该源不支持此资源场景',
            self::HostNotCovered   => '该源不覆盖目标上游域名',
            self::RedirectLoss     => 'Release 资产会把 302 原样回吐给客户端, 等于不加速',
            self::TooBig           => '超过该源声明的单文件体积上限',
            self::ExtBlocked       => '该源屏蔽此类扩展名(常见于公益镜像挡 exe/zip/apk)',
            self::NoRange          => '客户端请求 Range 但该源不实测支持 Range',
            self::BreakerOpen      => '熔断 OPEN 且冷却未到',
            self::NoApiSupport     => '该源不代理 api.github.com',
            self::Disabled         => '面板或配置中已手动停用',
            self::SuspectTrust     => '曾因完整性校验失败被降为不可信',
            self::PoliteCooldown   => '未达该源的最小请求间隔',
            self::NotYetProbed     => '尚无实测能力位, 不冒险承接',
            self::SchemeMismatch   => '源协议形态与目标 URL 不匹配',
        };
    }
}
