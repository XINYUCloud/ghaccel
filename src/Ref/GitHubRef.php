<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 资源引用的不可变值对象, 是整个系统的中心契约。URL 先解析成它, 转发、缓存
 *             键、TTL、选路入参全部只读它 —— 绝不直接哈希 URL 字符串, 因为字符串归一化
 *             永远补不完。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Ref;

use GhAccel\Enum\IdentityKind;
use GhAccel\Enum\Scene;

/**
 * 一条已解析、已归一化的 GitHub 资源引用。
 *
 * 约定: owner/repo 一律小写(GitHub 对二者大小写不敏感), path 保留原大小写(GitHub 文件名
 * 大小写敏感)。这两条搞反会导致同一资源产生两份缓存并让命中率虚低。
 */
final class GitHubRef
{
    private function __construct(
        public readonly Scene $scene,
        public readonly IdentityKind $identityKind,
        /** 上游绝对 URL, query 逐字节保留; objects 签名参数含 %2B/%2F, 二次编解码就 403 */
        public readonly string $upstreamUrl,
        public readonly string $upstreamHost,
        public readonly string $owner,
        public readonly string $repo,
        /** 分支名或 tag 名, 未做 refs/ 前缀展开 */
        public readonly string $ref = '',
        /** 已解析出的 40 位 commit sha, 未知为空 */
        public readonly string $sha = '',
        /** raw/gist 的文件路径 */
        public readonly string $path = '',
        /** Release 资产的数字 id, 比 (tag, filename) 稳 */
        public readonly ?int $assetId = null,
        /** Release 资产文件名 */
        public readonly string $assetName = '',
        /** 归档格式: zip | tar.gz */
        public readonly string $archiveFmt = '',
        /** api 端点路径, 不含 host */
        public readonly string $apiEndpoint = '',
        /** 已按场景白名单过滤并排序的 query */
        public readonly array $apiQuery = [],
        /** 用于 Content-Disposition 兜底的下载文件名 */
        public readonly string $downloadName = '',
        /** 是否已知支持 Range; 由实测能力位决定, 不由场景推断 */
        public readonly bool $allowRange = true,
        /** 需要先把 302 跟到最终地址才能取字节 */
        public readonly bool $needsRedirectResolve = false,
        /** 已知的资源体积, 0 表示未知 */
        public readonly int $sizeHint = 0,
        /** 客户端要求的 ETag 校验值, 仅用于缓存层第一协商 */
        public readonly string $clientEtag = '',
        public readonly string $clientIfModifiedSince = '',
        /** 客户端显式传入的期望 sha256, 流式增量校验 */
        public readonly string $expectedSha256 = '',
        /** 归一化过程中的告警, 透传到诊断 JSON, 便于用户发现写错了 */
        public readonly array $warnings = [],
    ) {
    }

    public static function make(
        Scene $scene,
        IdentityKind $identityKind,
        string $upstreamUrl,
        string $owner,
        string $repo,
        array $opts = []
    ): self {
        $host = (string) (parse_url($upstreamUrl, PHP_URL_HOST) ?: '');

        return new self(
            scene: $scene,
            identityKind: $identityKind,
            upstreamUrl: $upstreamUrl,
            upstreamHost: strtolower($host),
            owner: strtolower($owner),
            repo: strtolower($repo),
            ref: (string) ($opts['ref'] ?? ''),
            sha: strtolower((string) ($opts['sha'] ?? '')),
            path: (string) ($opts['path'] ?? ''),
            assetId: isset($opts['asset_id']) ? (int) $opts['asset_id'] : null,
            assetName: (string) ($opts['asset_name'] ?? ''),
            archiveFmt: (string) ($opts['archive_fmt'] ?? ''),
            apiEndpoint: (string) ($opts['api_endpoint'] ?? ''),
            apiQuery: (array) ($opts['api_query'] ?? []),
            downloadName: (string) ($opts['download_name'] ?? ''),
            allowRange: (bool) ($opts['allow_range'] ?? true),
            needsRedirectResolve: (bool) ($opts['needs_redirect_resolve'] ?? false),
            sizeHint: (int) ($opts['size_hint'] ?? 0),
            clientEtag: (string) ($opts['client_etag'] ?? ''),
            clientIfModifiedSince: (string) ($opts['client_if_modified_since'] ?? ''),
            expectedSha256: strtolower((string) ($opts['expected_sha256'] ?? '')),
            warnings: (array) ($opts['warnings'] ?? []),
        );
    }

    /** 只替换少数字段的通用派生, 保持不可变。 */
    public function with(array $overrides): self
    {
        return new self(
            scene: $overrides['scene'] ?? $this->scene,
            identityKind: $overrides['identity_kind'] ?? $this->identityKind,
            upstreamUrl: $overrides['upstream_url'] ?? $this->upstreamUrl,
            upstreamHost: $overrides['upstream_host'] ?? $this->upstreamHost,
            owner: $overrides['owner'] ?? $this->owner,
            repo: $overrides['repo'] ?? $this->repo,
            ref: $overrides['ref'] ?? $this->ref,
            sha: $overrides['sha'] ?? $this->sha,
            path: $overrides['path'] ?? $this->path,
            assetId: array_key_exists('asset_id', $overrides) ? $overrides['asset_id'] : $this->assetId,
            assetName: $overrides['asset_name'] ?? $this->assetName,
            archiveFmt: $overrides['archive_fmt'] ?? $this->archiveFmt,
            apiEndpoint: $overrides['api_endpoint'] ?? $this->apiEndpoint,
            apiQuery: $overrides['api_query'] ?? $this->apiQuery,
            downloadName: $overrides['download_name'] ?? $this->downloadName,
            allowRange: $overrides['allow_range'] ?? $this->allowRange,
            needsRedirectResolve: $overrides['needs_redirect_resolve'] ?? $this->needsRedirectResolve,
            sizeHint: $overrides['size_hint'] ?? $this->sizeHint,
            clientEtag: $overrides['client_etag'] ?? $this->clientEtag,
            clientIfModifiedSince: $overrides['client_if_modified_since'] ?? $this->clientIfModifiedSince,
            expectedSha256: $overrides['expected_sha256'] ?? $this->expectedSha256,
            warnings: $overrides['warnings'] ?? $this->warnings,
        );
    }

    /** 是否已经具备 EDGE 缓存资格。 */
    public function cacheEligible(): bool
    {
        return $this->scene->edgeCapable() && $this->identityKind->cacheEligible();
    }

    /** 人类可读引用, 日志与面板展示用。落盘时按配置可截成摘要, 避免记录谁在下什么。 */
    public function display(): string
    {
        return match ($this->scene) {
            Scene::Raw          => sprintf('%s/%s@%s:%s', $this->owner, $this->repo, $this->ref ?: $this->sha, $this->path),
            Scene::ReleaseAsset => sprintf('%s/%s %s -> %s', $this->owner, $this->repo, $this->ref, $this->assetName),
            Scene::Archive      => sprintf('%s/%s archive(%s) %s', $this->owner, $this->repo, $this->archiveFmt, $this->ref ?: $this->sha),
            Scene::ApiJson      => sprintf('api %s', $this->apiEndpoint),
            Scene::GistRaw      => sprintf('gist %s/%s', $this->owner, $this->path),
            Scene::Unknown      => '(unparsed)',
        };
    }

    /**
     * 缓存身份的规范化串。
     *
     * 三个要点:
     *  - 绝不含镜像域名。缓存的是"资源"不是"从哪取的", 否则每个源各存一份, 切源等于换缓存。
     *  - 单元分隔符 \x1f, 防止字段拼接产生歧义(路径里出现 '-' 或 '/' 就会撞键)。
     *  - asset_id 优先于文件名, 因为同名资产重传时文件名不变而 id 变。
     */
    public function canonical(): string
    {
        $segs = [
            'v3',
            $this->scene->value,
            $this->identityKind->value,
            $this->owner,
            $this->repo,
            $this->sha !== '' ? 'sha:' . $this->sha : 'ref:' . $this->normalizeRef($this->ref),
            $this->path !== '' ? self::normPath($this->path) : '-',
            $this->assetId !== null ? 'id:' . $this->assetId : ($this->assetName !== '' ? 'name:' . $this->assetName : '-'),
            $this->archiveFmt !== '' ? $this->archiveFmt : '-',
            $this->apiEndpoint !== '' ? $this->apiEndpoint : '-',
            self::canonQuery($this->apiQuery),
        ];

        return implode("\x1f", $segs);
    }

    /**
     * 把可确定的写法合并到全限定形态: heads/main 与 refs/heads/main 同键。
     *
     * 裸名 main 故意不与 refs/heads/main 合并。branch 与 tag 可以同名, 而 GitHub 在
     * raw 与 archive 两条链路上的优先级并不一致 —— 合并会让一次 tag 发布把另一个
     * 身份的陈旧内容继续供出去, 那是错误内容而不只是少一次命中。
     */
    public static function normalizeRef(string $ref): string
    {
        foreach (['heads/', 'tags/', 'pull/'] as $short) {
            if (str_starts_with($ref, $short)) {
                return 'refs/' . $ref;
            }
        }

        return $ref;
    }

    /**
     * 逐段规范化: 先按字面 '/' 切段, 再对每段 decode 后按 RFC3986 重编码。
     *
     * 顺序很关键。整串先解码会把段名里的 %2F 变成一个真分隔符, 于是 "a%2Fb" 与 "a/b"
     * 归一到同一个缓存键 —— 而它们在 GitHub 上是两个不同对象。
     */
    public static function normPath(string $path): string
    {
        $parts = explode('/', $path);
        foreach ($parts as $i => $seg) {
            // rawurlencode 已产生大写十六进制与 %20(而非 '+'), 正好是我们要的规范形态。
            $parts[$i] = rawurlencode(rawurldecode($seg));
        }

        return implode('/', $parts);
    }

    /** query 按键排序后拼接; access_token 一类凭据绝不在这里出现(上游解析时已丢弃)。 */
    public static function canonQuery(array $query): string
    {
        if ($query === []) {
            return '-';
        }
        ksort($query);
        $out = [];
        foreach ($query as $k => $v) {
            $out[] = $k . '=' . (is_array($v) ? implode(',', $v) : (string) $v);
        }

        return implode('&', $out);
    }

    /** 40 位十六进制即 commit sha。 */
    public static function looksLikeSha(string $s): bool
    {
        return (bool) preg_match('/\A[0-9a-f]{40}\z/', strtolower($s));
    }
}
