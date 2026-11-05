<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 定义资源场景枚举, 它是源能力位掩码、缓存 TTL 策略与打分权重表三处共同
 *             使用的唯一键。加场景必须同时改 SCENE_BIT 与 config 里的权重/TTL 表。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Enum;

/**
 * 加速场景。对应四类上游形态, 它们的 URL 重写规则、Range 语义与缓存资格各不相同。
 */
enum Scene: string
{
    /** raw.githubusercontent.com 上的文本或二进制单文件 */
    case Raw = 'raw';

    /** Release 资产, 真实落点是带一次性签名的 objects.githubusercontent.com */
    case ReleaseAsset = 'release_asset';

    /** 仓库归档 zip/tar.gz, 真实服务端是 codeload.github.com */
    case Archive = 'archive';

    /** api.github.com 的 JSON 元数据 */
    case ApiJson = 'api_json';

    /** gist 的 raw 文件 */
    case GistRaw = 'gist_raw';

    /** 解析失败的兜底值, 只用于产生结构化 400, 绝不进入转发 */
    case Unknown = 'unknown';

    /**
     * 能力位, 用于 Source::scenes 的位掩码比对。
     * L0 硬过滤要求 ($src->scenes & $need) === $need, 所以每个场景必须独占一位。
     */
    public function bit(): int
    {
        return match ($this) {
            self::Raw          => 1 << 0,
            self::ReleaseAsset => 1 << 1,
            self::Archive      => 1 << 2,
            self::ApiJson      => 1 << 3,
            self::GistRaw      => 1 << 4,
            self::Unknown      => 0,
        };
    }

    public static function fromBit(int $bit): ?self
    {
        foreach (self::cases() as $case) {
            if ($case->bit() === $bit && $bit !== 0) {
                return $case;
            }
        }

        return null;
    }

    /** 位掩码的可读展开, 供面板源池列显示。 */
    public static function bitsToScenes(int $bits): array
    {
        $out = [];
        foreach (self::cases() as $case) {
            if ($case->bit() !== 0 && ($bits & $case->bit()) === $case->bit()) {
                $out[] = $case->value;
            }
        }

        return $out;
    }

    /** 是否按字节流对待: 决定 Content-Disposition、嗅探规则与是否允许 sha256 校验。 */
    public function isBinaryStream(): bool
    {
        return $this === self::ReleaseAsset || $this === self::Archive;
    }

    /**
     * 该场景在 v1 是否允许 EDGE 缓存直出。
     * ApiJson 一律拒绝: 响应本身可变, 缓存过期等于替用户伪造了仓库状态。
     */
    public function edgeCapable(): bool
    {
        return $this !== self::ApiJson && $this !== self::Unknown;
    }

    /** 权重表与 TTL 表里取配置用的键名。 */
    public function configKey(): string
    {
        return $this->value;
    }
}
