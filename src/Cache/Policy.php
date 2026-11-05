<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 缓存资格与 TTL。资格只由 IdentityKind 决定, 不允许靠键前缀"看起来像不可变"
 *             来猜 —— 那是脏缓存被长期服务的起点。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Cache;

use GhAccel\Config;
use GhAccel\Enum\Scene;
use GhAccel\Ref\GitHubRef;
use GhAccel\Source\Source;

final class Policy
{
    public function __construct(private readonly Config $cfg)
    {
    }

    /**
     * 一条引用的 fresh/stale/immutable。
     *
     * fresh TTL 取"场景表"和"身份上限"的较小值: 场景表说 raw 可以缓存 120s, 但 sha 级引用
     * 事实上永远不变, 于是身份上限(7/14 天)成为真正决定项; 反过来分支名引用即使场景表写了
     * 更长, 也会被 IdentityKind::maxTtl() 死死压在 120s —— 陈旧分支内容对 Agent 是误导。
     *
     * @return array{fresh:int, stale:int, immutable:bool}
     */
    public function ttlFor(GitHubRef $ref): array
    {
        $table = $this->cfg->arr('cache.ttl', []);
        $sceneTtl = (int) ($table[$ref->scene->configKey()] ?? $this->cfg->int('cache.ttl.raw', 120));
        $cap = $ref->identityKind->maxTtl();

        $immutable = $ref->identityKind->isContentImmutable() && $ref->scene->edgeCapable();
        if ($immutable) {
            // 内容寻址的条目不需要 revalidate 窗口: 要么是对的要么是整条作废, 没有"略旧"这回事。
            $fresh = min($cap, max($sceneTtl, $cap));
        } else {
            $fresh = max(1, min($sceneTtl > 0 ? $sceneTtl : $cap, $cap));
        }

        $stale = $this->cfg->int('cache.stale_while_revalidate_s', 300);
        if ($ref->scene === Scene::ApiJson) {
            // v1 一律不缓存 API JSON, 这里返回 0 只是让"万一被误调"显式失败。
            $fresh = 0;
            $stale = 0;
        }

        return ['fresh' => $fresh, 'stale' => $stale, 'immutable' => $immutable];
    }

    /**
     * 能不能缓存这条字节。三道路障, 顺序即优先级。
     *
     *  1. 身份与场景: ApiJson / MutableApi / Ambiguous 直接否。响应本身可变, 缓存过期等于
     *     替用户伪造仓库状态。
     *  2. 体积: 超过单条上限或全局单请求上限不落地 —— 一次中断就白占满水位。
     *  3. 篡改风险: 低信任源 + 无权威摘要 + 二进制场景 => 拒绝缓存。理由不是性能而是责任:
     *     一旦缓存, 之后就是由本机域名、带本机 TLS 证书、向国内用户持续分发那份可能被篡改的
     *     字节, 而我们的用户里有人会自动执行下载产物。只允许流式转发或 302。
     */
    public function mayCache(GitHubRef $ref, Source $src, int $bytes): bool
    {
        if (!$this->cfg->bool('cache.enabled', true)) {
            return false;
        }
        if (!$ref->cacheEligible()) {
            return false;
        }
        if ($ref->scene === Scene::ApiJson) {
            return false;
        }
        if ($bytes <= 0) {
            // 体积未知(chunked)时不落地: 不知道要写多少就没法校验 filesize == meta.bytes。
            return false;
        }

        $maxEntry = max(0, $this->cfg->int('cache.max_entry_bytes', 0));
        if ($maxEntry > 0 && $bytes > $maxEntry) {
            return false;
        }
        $perRequest = max(0, $this->cfg->int('limits.per_request_bytes', 0));
        if ($perRequest > 0 && $bytes > $perRequest) {
            return false;
        }
        if ($src->maxSizeBytes > 0 && $bytes > $src->maxSizeBytes) {
            return false;
        }

        // 权威摘要只认"这份字节的 sha256": commit sha 与 asset id 是身份不是摘要, 它们能保证
        // "同一引用内容不变", 保证不了"镜像这次回的就是那个内容"。
        $hasDigest = $ref->expectedSha256 !== '';
        if ($ref->scene->isBinaryStream() && !$hasDigest && !$src->trust->mayEdgeWithoutDigest()) {
            // 部署者可以显式关掉 Release 的这条要求(自建源、内网环境), 默认不关。
            $strict = $this->cfg->bool('integrity.require_for_release_from_low_trust', true);
            if ($ref->scene !== Scene::ReleaseAsset || $strict) {
                return false;
            }
        }

        return true;
    }

    /** 自造 ETag: "gha-<key 前 16>-<variant>"。透传源的 ETag 会在换源后让客户端永远拿不到 304。 */
    public function etagFor(string $key, string $variant = 'full'): string
    {
        $k = preg_match('#\A[0-9a-f]{64}\z#', $key) ? substr($key, 0, 16) : substr(hash('sha256', $key), 0, 16);

        return '"gha-' . $k . '-' . preg_replace('#[^a-z0-9]#', '', strtolower($variant)) . '"';
    }

    /** 小条目合并落盘的阈值。 */
    public function inlineThreshold(): int
    {
        return max(0, $this->cfg->int('cache.small_entry_inline_bytes', 65536));
    }

    /**
     * 淘汰用的价值密度: hits * freshness / bytes^alpha。
     *
     * 不用纯 LRU: 一个 800MB 只下载一次的资产重取要 20 分钟, 一堆 2KB 的 API JSON 重取只要
     * 0.3 秒, LRU 会先踢前者, 方向完全反了。
     */
    public function valueDensity(Entry $e, float $now): float
    {
        $alpha = max(0.0, $this->cfg->float('cache.evict_alpha', 0.6));
        $bytes = max(1, $e->bytes);
        $life = max(1.0, $e->staleUntil - $e->freshUntil);
        $remain = max(0.0, min($life, $e->staleUntil - $now));
        $freshness = ($life > 0.0 ? $remain / $life : 0.0);
        if ($e->identityKind->isContentImmutable()) {
            // 内容寻址条目永远"新鲜", 但重取它要真的走一次跨洋, 所以新鲜度按 1 算。
            $freshness = 1.0;
        }
        // 至少给一次命中留权重, 否则 hits=0 的新条目密度恒为 0, 会被下一轮淘汰立刻踢掉。
        $hits = $e->hits + 1;

        return $hits * (0.05 + 0.95 * $freshness) / ($bytes ** $alpha);
    }

    /** .part 的独立 TTL(它计入水位, 所以必须有寿命)。 */
    public function partialTtl(): int
    {
        return max(60, $this->cfg->int('cache.partial_ttl_s', 1800));
    }

    public function maxResume(): int
    {
        return max(0, $this->cfg->int('cache.partial_max_resume', 3));
    }

    public function quarantineTtl(): int
    {
        return max(60, $this->cfg->int('cache.quarantine_ttl_s', 86400));
    }

    public function headHashBytes(): int
    {
        return max(4096, $this->cfg->int('integrity.head_hash_bytes', 1048576));
    }
}
