<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 缓存条目元数据契约。identity_kind 是缓存资格与 TTL 的唯一判定源 —— 不允许
 *             靠"键前缀看起来像不可变"来猜, 脏缓存被长期服务的具体路径就是拿 (tag,
 *             filename) 当身份: 同名资产被作者重新上传时 asset_id 变了而文件名没变。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Cache;

use GhAccel\Enum\IdentityKind;
use GhAccel\Enum\Scene;

final class Entry
{
    public function __construct(
        public readonly string $key,
        public readonly Scene $scene,
        public readonly IdentityKind $identityKind,
        /** 落盘字节数, 必须与 filesize 一致, 不一致即判废删除 */
        public readonly int $bytes = 0,
        public readonly float $storedAt = 0.0,
        public readonly float $freshUntil = 0.0,
        public readonly float $staleUntil = 0.0,
        /** 自造 ETag。透传源的 ETag 会在换源后让客户端永远拿不到 304, 是此类项目最高频的错误。 */
        public readonly string $etag = '',
        public readonly string $lastModified = '',
        public readonly string $contentType = '',
        /** 缓存时记录的 upstream ETag, 只用于对上游发条件请求, 绝不对客户端复用 */
        public readonly string $upstreamEtag = '',
        public readonly string $upstreamLastModified = '',
        /** 权威摘要: 来自 GitHub 本体或客户端提供, 不是来自镜像 */
        public readonly string $sha256 = '',
        public readonly bool $verified = false,
        public readonly string $verifiedAgainst = '',
        public readonly float $verifiedAt = 0.0,
        /** 取到这份字节的那个源, 只作元数据; 缓存键里绝不含镜像域名 */
        public readonly string $sourceId = '',
        public readonly string $rangeSpec = '',
        public readonly int $hits = 0,
        public readonly float $lastAccessAt = 0.0,
        public readonly int $status = 200,
    ) {
    }

    public static function fromArray(array $a): self
    {
        return new self(
            key: (string) ($a['key'] ?? ''),
            scene: Scene::tryFrom((string) ($a['scene'] ?? '')) ?? Scene::Unknown,
            identityKind: IdentityKind::tryFrom((string) ($a['identity_kind'] ?? '')) ?? IdentityKind::Ambiguous,
            bytes: (int) ($a['bytes'] ?? 0),
            storedAt: (float) ($a['stored_at'] ?? 0.0),
            freshUntil: (float) ($a['fresh_until'] ?? 0.0),
            staleUntil: (float) ($a['stale_until'] ?? 0.0),
            etag: (string) ($a['etag'] ?? ''),
            lastModified: (string) ($a['last_modified'] ?? ''),
            contentType: (string) ($a['content_type'] ?? ''),
            upstreamEtag: (string) ($a['upstream_etag'] ?? ''),
            upstreamLastModified: (string) ($a['upstream_last_modified'] ?? ''),
            sha256: (string) ($a['sha256'] ?? ''),
            verified: (bool) ($a['verified'] ?? false),
            verifiedAgainst: (string) ($a['verified_against'] ?? ''),
            verifiedAt: (float) ($a['verified_at'] ?? 0.0),
            sourceId: (string) ($a['source_id'] ?? ''),
            rangeSpec: (string) ($a['range_spec'] ?? ''),
            hits: (int) ($a['hits'] ?? 0),
            lastAccessAt: (float) ($a['last_access_at'] ?? 0.0),
            status: (int) ($a['status'] ?? 200),
        );
    }

    public function toArray(): array
    {
        return [
            'key' => $this->key,
            'scene' => $this->scene->value,
            'identity_kind' => $this->identityKind->value,
            'bytes' => $this->bytes,
            'stored_at' => $this->storedAt,
            'fresh_until' => $this->freshUntil,
            'stale_until' => $this->staleUntil,
            'etag' => $this->etag,
            'last_modified' => $this->lastModified,
            'content_type' => $this->contentType,
            'upstream_etag' => $this->upstreamEtag,
            'upstream_last_modified' => $this->upstreamLastModified,
            'sha256' => $this->sha256,
            'verified' => $this->verified,
            'verified_against' => $this->verifiedAgainst,
            'verified_at' => $this->verifiedAt,
            'source_id' => $this->sourceId,
            'range_spec' => $this->rangeSpec,
            'hits' => $this->hits,
            'last_access_at' => $this->lastAccessAt,
            'status' => $this->status,
        ];
    }

    public function isFresh(float $now): bool
    {
        return $now < $this->freshUntil;
    }

    /** stale 但仍在可容忍窗口内, 可先服务再后台校验。 */
    public function isServeableStale(float $now): bool
    {
        return $now < $this->staleUntil;
    }

    /** 内容寻址条目命中即绝对正确, 跳过一切 revalidate。 */
    public function isImmutable(): bool
    {
        return $this->identityKind->isContentImmutable() && $this->verified;
    }

    /** 派生新条目, 保持不可变。字段全列出以免命名参数写错时静默丢字段。 */
    private function copy(array $o): self
    {
        return new self(
            key: $o['key'] ?? $this->key,
            scene: $o['scene'] ?? $this->scene,
            identityKind: $o['identity_kind'] ?? $this->identityKind,
            bytes: $o['bytes'] ?? $this->bytes,
            storedAt: $o['stored_at'] ?? $this->storedAt,
            freshUntil: $o['fresh_until'] ?? $this->freshUntil,
            staleUntil: $o['stale_until'] ?? $this->staleUntil,
            etag: $o['etag'] ?? $this->etag,
            lastModified: $o['last_modified'] ?? $this->lastModified,
            contentType: $o['content_type'] ?? $this->contentType,
            upstreamEtag: $o['upstream_etag'] ?? $this->upstreamEtag,
            upstreamLastModified: $o['upstream_last_modified'] ?? $this->upstreamLastModified,
            sha256: $o['sha256'] ?? $this->sha256,
            verified: $o['verified'] ?? $this->verified,
            verifiedAgainst: $o['verified_against'] ?? $this->verifiedAgainst,
            verifiedAt: $o['verified_at'] ?? $this->verifiedAt,
            sourceId: $o['source_id'] ?? $this->sourceId,
            rangeSpec: $o['range_spec'] ?? $this->rangeSpec,
            hits: $o['hits'] ?? $this->hits,
            lastAccessAt: $o['last_access_at'] ?? $this->lastAccessAt,
            status: $o['status'] ?? $this->status,
        );
    }

    public function withHit(float $now): self
    {
        return $this->copy(['hits' => $this->hits + 1, 'last_access_at' => $now]);
    }

    /**
     * 只刷新时效而不重写数据文件。
     *
     * 上游回 304 时走这条。对 GB 级条目重写文件是纯灾难, 而"304 之后还去 touch 数据文件"
     * 是这类实现最常见的隐性性能事故。
     */
    public function revalidated(float $now, int $freshSeconds, int $staleSeconds): self
    {
        return $this->copy([
            'fresh_until' => $now + $freshSeconds,
            'stale_until' => $now + $freshSeconds + $staleSeconds,
            'last_access_at' => $now,
        ]);
    }
}
