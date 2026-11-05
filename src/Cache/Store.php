<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 缓存的读写与治理。命中判定、Range 由完整条目切片服务、.part 原子落地、
 *             水位淘汰与清理。所有路径都从 Cache\Key 派生, 不在这里拼字符串。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Cache;

use GhAccel\Config;
use GhAccel\Ref\GitHubRef;
use GhAccel\Source\Source;

/**
 * 布局:
 *   var/cache/{k[0..1]}/{k[2..4]}/{key}.bin      大条目数据
 *   var/cache/.../{key}.meta.json                大条目元数据
 *   var/cache/.../{key}.entry                    小条目: 首行 JSON 头 + \n + 原始字节
 *   var/cache/.../{key}.part (+ .part.meta.json) 连续前缀半成品, 永不参与命中
 *   var/cache/_quarantine/                       反复中断的半成品隔离区
 *
 * 一条铁律: 落盘文件名永远是 <sha256> 派生, 绝不掺入原始文件名或镜像域名。
 */
final class Store
{
    private ?array $epoch = null;

    public function __construct(
        private readonly string $root,
        private readonly Config $cfg,
        private readonly Policy $policy
    ) {
    }

    public function cacheDir(): string
    {
        $dir = rtrim(str_replace('\\', '/', $this->cfg->str('cache.dir', 'var/cache')), '/');
        if (!str_starts_with($dir, '/') && !preg_match('#\A[a-z]:[\\\\/]#i', $dir)) {
            $dir = rtrim(str_replace('\\', '/', $this->root), '/') . '/' . $dir;
        }

        return $dir;
    }

    /** 命中判定。任何校验不过都返回 null(按未命中处理)并把坏文件删掉, 不抛异常。 */
    public function lookup(GitHubRef $ref): ?Entry
    {
        if (!$this->cfg->bool('cache.enabled', true)) {
            return null;
        }
        $key = Key::of($ref);
        $entry = $this->readEntry($key);
        if ($entry === null) {
            return null;
        }

        $now = microtime(true);
        if (!$entry->isServeableStale($now)) {
            // 连 stale 窗口都过了: 这条已经不表示"略旧", 而是"可能是另一个内容"。
            $this->drop($key);

            return null;
        }
        // 场景与身份都编进了键(canonical 的第一段就是 scene), 所以这里不需要再比对一遍;
        // stale 与否由调用方按"先服务再后台校验"的三层协商决定, 存储层不替它做决定。
        return $entry;
    }

    /**
     * 打开数据文件(已定位到数据起点)。
     *
     * @return array{handle: resource|null, size: int}
     */
    public function openForRead(Entry $e): array
    {
        $loc = $this->resolve($e->key);
        if ($loc === null) {
            return ['handle' => null, 'size' => 0];
        }
        $fh = @fopen($loc[0], 'rb');
        if ($fh === false) {
            return ['handle' => null, 'size' => 0];
        }
        if ($loc[1] > 0) {
            fseek($fh, $loc[1]);
        }

        return ['handle' => $fh, 'size' => $e->bytes];
    }

    /**
     * 把条目的 [start, end] 闭区间切片写到输出流, 返回写出的字节数。
     *
     * 恒定内存: fseek + 分块 fread + fwrite, 绝不 file_get_contents 整读。一个 800MB 的
     * 资产服务一个 1KB 的 Range 时, 整读会把进程直接打死, 而分块只占一个 chunk。
     */
    public function sliceToOutput(Entry $e, $out, int $start, ?int $end = null): int
    {
        $loc = $this->resolve($e->key);
        if ($loc === null || !is_resource($out)) {
            return 0;
        }
        $size = $e->bytes;
        $start = max(0, $start);
        $end = $end === null ? $size - 1 : min($size - 1, $end);
        if ($start > $end || $size <= 0) {
            return 0;
        }

        $fh = @fopen($loc[0], 'rb');
        if ($fh === false) {
            return 0;
        }
        $chunk = max(4096, min(1048576, $this->cfg->int('cache.slice_chunk_bytes', 65536)));
        // 从 start 开始分块读; 定位用 fseek 而不是读完再丢, 大文件才有意义。
        if (@fseek($fh, $loc[1] + $start) !== 0) {
            fclose($fh);

            return 0;
        }
        $remaining = $end - $start + 1;
        $written = 0;
        while ($remaining > 0) {
            $want = (int) min($chunk, $remaining);
            $buf = fread($fh, $want);
            if ($buf === false || $buf === '') {
                break;
            }
            $len = strlen($buf);
            $ok = @fwrite($out, $buf);
            if ($ok === false || $ok < $len) {
                // 客户端断开: 立即停, 已写的字节就是本次结果, 由调用方决定记账。
                $written += (int) max(0, $ok === false ? 0 : $ok);
                break;
            }
            $written += $len;
            $remaining -= $len;
            unset($buf);
        }
        fclose($fh);

        return $written;
    }

    /**
     * 开始一次写入(或续传已有 .part)。返回 null 表示"这次不缓存", 调用方照常流式转发。
     *
     * 前置: 调用方必须已经问过 Policy::mayCache(), 这里只做空间与治理判定。
     */
    /**
     * 只读探查某个引用是否已有可用的 .part 前缀, 不删除、不隔离、不写任何东西。
     *
     * 存在这个方法的理由: 续传必须在**发请求之前**就知道要从哪个偏移接着要
     * (Range: bytes={prefix}-), 而那时还没有响应头、拿不到总体积。若直接用 begin(),
     * 它会把 expected_size=0 与已有 meta 判成"身份不符"而删掉那个攒了半天的前缀。
     *
     * @return array<string,mixed>|null
     */
    public function peekPartial(GitHubRef $ref): ?array
    {
        $paths = Key::paths(Key::of($ref), $this->cacheDir());
        $meta = $this->readPartMeta($paths['partMeta']);
        if ($meta === null || !is_readable($paths['part'])) {
            return null;
        }
        $received = (int) ($meta['received_bytes'] ?? 0);
        $expected = (int) ($meta['expected_size'] ?? 0);
        if ($received <= 0 || $expected <= 0 || $received > $expected) {
            return null;
        }
        if ((microtime(true) - (float) ($meta['updated_at'] ?? 0.0)) > $this->policy->partialTtl()) {
            return null;
        }
        if ((int) ($meta['resume_count'] ?? 0) >= $this->policy->maxResume()) {
            return null;
        }
        clearstatcache(true, $paths['part']);
        if ((int) @filesize($paths['part']) !== $received) {
            return null;
        }

        return $meta;
    }

    public function begin(GitHubRef $ref, array $meta): ?PartialWriter
    {
        return $this->beginInner($ref, $meta, 0);
    }

    private function beginInner(GitHubRef $ref, array $meta, int $attempt): ?PartialWriter
    {
        if (!$this->cfg->bool('cache.enabled', true)) {
            return null;
        }
        $key = Key::of($ref);
        $expected = max(0, (int) ($meta['expected_size'] ?? $ref->sizeHint));

        $minFree = max(0, $this->cfg->int('cache.min_free_bytes', 0));
        $wm = $this->watermark();
        // 宁可慢不可炸盘: 磁盘剩余不足直接拒写。
        if ($wm['disk_free'] >= 0 && $minFree > 0 && $wm['disk_free'] < $minFree) {
            return null;
        }
        if ($wm['ratio'] >= $this->cfg->float('cache.stop_watermark', 0.95)) {
            return null;
        }
        $wm = $this->ensureRoom($expected);
        if ($wm === null) {
            return null;
        }

        $paths = Key::paths($key, $this->cacheDir());
        if (!is_dir($paths['dir'])) {
            @mkdir($paths['dir'], 0770, true);
        }

        $ttl = $this->policy->ttlFor($ref);
        $variant = $ref->allowRange ? 'full' : 'norng';
        $entryMeta = [
            'key' => $key,
            'scene' => $ref->scene->value,
            'identity_kind' => $ref->identityKind->value,
            'content_type' => (string) ($meta['content_type'] ?? ''),
            'status' => (int) ($meta['status'] ?? 200),
            'etag' => $this->policy->etagFor($key, $variant),
            'last_modified' => (string) ($meta['last_modified'] ?? gmdate('D, d M Y H:i:s') . ' GMT'),
            'upstream_etag' => (string) ($meta['upstream_etag'] ?? ''),
            'upstream_last_modified' => (string) ($meta['upstream_last_modified'] ?? ''),
            'fresh_s' => $ttl['fresh'],
            'stale_s' => $ttl['stale'],
            'immutable' => $ttl['immutable'],
            'verified_against' => $ref->expectedSha256 !== '' ? 'client' : (string) ($meta['verified_against'] ?? 'none'),
            'expected_sha256' => $ref->expectedSha256,
            'source_id' => (string) ($meta['source_id'] ?? ''),
            'range_spec' => (string) ($meta['range_spec'] ?? ''),
            'display' => $ref->display(),
            'ref_digest' => substr($key, 0, 16),
        ];

        $resumeCount = 0;
        $existing = $this->readPartMeta($paths['partMeta']);
        $reusedPrefix = 0;
        if ($existing !== null && is_readable($paths['part'])) {
            $age = microtime(true) - (float) ($existing['updated_at'] ?? 0.0);
            $sameIdentity = (string) ($existing['expected_size'] ?? '-1') === (string) $expected;
            if ($age > $this->policy->partialTtl() || !$sameIdentity) {
                @unlink($paths['part']);
                @unlink($paths['partMeta']);
                $existing = null;
            } else {
                $resumeCount = (int) ($existing['resume_count'] ?? 0);
                if ($resumeCount >= $this->policy->maxResume()) {
                    // 反复中断的文件不是"再试一次就能好", 而是这台机器与这个源之间有问题。
                    // 移到隔离区保留证据, 磁盘上不再占水位。
                    $this->quarantine($paths['part'], $paths['partMeta']);
                    $existing = null;
                    $resumeCount = 0;
                } else {
                    $reusedPrefix = (int) (filesize($paths['part']) ?: 0);
                    // meta 里的 received_bytes 是"写这份 meta 时的连续前缀长度"。之后只会变长
                    // (正常追加), 绝不会变短 —— 变短就是被截断/被别的进程动过, 判废。
                    // 长度之外的一致性由 head_sha256 + head_bytes 负责, 不靠长度相等去猜。
                    if ($reusedPrefix < (int) ($existing['received_bytes'] ?? 0)) {
                        @unlink($paths['part']);
                        @unlink($paths['partMeta']);
                        $existing = null;
                        $reusedPrefix = 0;
                    }
                }
            }
        }

        $w = new PartialWriter(
            key: $key,
            partPath: $paths['part'],
            partMetaPath: $paths['partMeta'],
            finalPath: $paths['bin'],
            dir: $paths['dir'],
            expectedSize: $expected,
            receivedBytes: 0,
            resumeCount: $resumeCount + 1,
            startedAt: (float) ($existing['started_at'] ?? microtime(true)),
            headHashBytes: $this->policy->headHashBytes(),
            headSha256: (string) ($existing['head_sha256'] ?? ''),
            headBytes: (int) ($existing['head_bytes'] ?? 0),
            rangeSpec: (string) ($meta['range_spec'] ?? ''),
            sourceId: (string) ($meta['source_id'] ?? ''),
            entryMeta: $entryMeta,
        );

        $append = $reusedPrefix > 0 && $expected > 0 && $reusedPrefix <= $expected;
        if ($append) {
            $fh = @fopen($paths['part'], 'r+b');
            if ($fh === false) {
                return null;
            }
            // head 校验按"记录时的那个长度"重算, 窗口长度与摘要必须成对使用。
            $verifyBytes = (int) ($existing['head_bytes'] ?? 0);
            $verifySha = (string) ($existing['head_sha256'] ?? '');
            $replay = $w->replayPrefix($paths['part'], $reusedPrefix, $verifyBytes, $verifySha);
            if (!$replay['ok'] || !$replay['head_ok']) {
                // 前缀与记录不一致(被并发写坏 / 磁盘问题): 整条作废, 绝不"接着写"。
                fclose($fh);
                @unlink($paths['part']);
                @unlink($paths['partMeta']);
                // 只重试一次: 删不掉(权限问题)时递归会变成栈溢出。
                return $attempt < 1 ? $this->beginInner($ref, $meta, $attempt + 1) : null;
            }
            // 重放之后把指针拨回尾部继续追加。
            fseek($fh, $reusedPrefix);
            $w->handle = $fh;
            $w->receivedBytes = $reusedPrefix;
            $w->resumed = true;
            $w->headSha256 = $replay['new_head'];
            $w->headBytes = $replay['new_head_bytes'];
            $this->writePartMeta($w);
        } else {
            $fh = @fopen($paths['part'], 'wb');
            if ($fh === false) {
                return null;
            }
            $w->handle = $fh;
            // 全新开始: head 窗口还没有可信的参考值, 由 commit 时再从文件算一次。
            $w->headSha256 = '';
            $w->headBytes = 0;
            $this->writePartMeta($w);
        }

        return $w;
    }

    /**
     * 落地: 校验 filesize -> rename -> 写 Entry。
     *
     * 校验不过返回 null 并删除 .part —— 半成品被当成完整条目服务是此类系统最恶劣的故障
     * (用户拿到一个"看起来下载成功"的坏 zip)。
     */
    public function commit(PartialWriter $w, string $sha256, bool $verified): ?Entry
    {
        $w->close();
        $actual = @filesize($w->partPath);
        if ($actual === false) {
            $w->discard();

            return null;
        }
        if ($w->expectedSize > 0 && $actual !== $w->expectedSize) {
            $w->discard();

            return null;
        }
        if ($sha256 === '') {
            // 调用方没给出摘要时由这里补算一次(常数内存流式), 保证 meta 里永远有 sha256。
            $h = @hash_file('sha256', $w->partPath);
            $sha256 = is_string($h) ? $h : '';
        }

        $meta = $w->entryMeta;
        $now = microtime(true);
        $fresh = max(0, (int) ($meta['fresh_s'] ?? 0));
        $stale = max(0, (int) ($meta['stale_s'] ?? 0));
        if ($fresh === 0) {
            $w->discard();

            return null;
        }

        // head_sha256: 续传路径已有; 全新写入则在这里对前 N 字节单独算一次, 供以后的续传校验。
        $headBytes = $w->headBytes > 0 ? $w->headBytes : (int) min($w->headHashBytes, $actual);
        $head = $w->headSha256 !== '' ? $w->headSha256 : $this->headHashOf($w->partPath, $headBytes);

        $entry = new Entry(
            key: $w->key,
            scene: \GhAccel\Enum\Scene::tryFrom((string) ($meta['scene'] ?? '')) ?? \GhAccel\Enum\Scene::Unknown,
            identityKind: \GhAccel\Enum\IdentityKind::tryFrom((string) ($meta['identity_kind'] ?? '')) ?? \GhAccel\Enum\IdentityKind::Ambiguous,
            bytes: $actual,
            storedAt: $now,
            freshUntil: $now + $fresh,
            staleUntil: $now + $fresh + $stale,
            etag: (string) ($meta['etag'] ?? $this->policy->etagFor($w->key)),
            lastModified: (string) ($meta['last_modified'] ?? ''),
            contentType: (string) ($meta['content_type'] ?? ''),
            upstreamEtag: (string) ($meta['upstream_etag'] ?? ''),
            upstreamLastModified: (string) ($meta['upstream_last_modified'] ?? ''),
            sha256: $sha256,
            verified: $verified,
            verifiedAgainst: (string) ($meta['verified_against'] ?? 'none'),
            verifiedAt: $verified ? $now : 0.0,
            sourceId: (string) ($meta['source_id'] ?? $w->sourceId),
            rangeSpec: (string) ($meta['range_spec'] ?? $w->rangeSpec),
            hits: 0,
            lastAccessAt: $now,
            status: (int) ($meta['status'] ?? 200),
        );

        // 未经校验的条目不许被当作"内容寻址": Entry::isImmutable() 已经要求 verified,
        // 所以 verified=false 时它自动失去 immutable 直出资格, 这里不需要再造一个标志位。
        $payload = $entry->toArray();
        $payload['head_sha256'] = $head;
        $payload['head_bytes'] = $headBytes;
        $payload['resumed'] = $w->resumed ? 1 : 0;
        $payload['display'] = (string) ($meta['display'] ?? '');
        $payload['ref_digest'] = (string) ($meta['ref_digest'] ?? substr($w->key, 0, 16));

        $ok = $actual <= $this->policy->inlineThreshold()
            ? $this->writeInline($w, $payload, $actual)
            : $this->writeSeparated($w, $payload);
        if (!$ok) {
            $w->discard();

            return null;
        }

        @unlink($w->partMetaPath);
        // 纪元增量按实际占盘体积算, 与 collectEntries/rescan 同一口径, 否则水位会越估越准
        // 但每次都偏低, 导致写前淘汰永远"差一点点"。
        $loc = $this->resolve($w->key);
        $onDisk = $loc === null ? $actual : (int) (@filesize($loc[0]) ?: $actual);
        $this->bumpEpoch($onDisk, 1);

        return $entry;
    }

    /**
     * 命中计数。
     *
     * 关键: 增量必须从**已存的 meta** 上算, 不能从调用方传进来的 Entry 上算 —— Entry 是不可变
     * 值对象, 同一请求里拿到的那份 hits 永远是同一个数, 用它自增会得到"hits 恒为 1"。
     * 上一版的这个错误让价值密度淘汰彻底失去区分度, 结果就是先踢掉最该留的大文件。
     *
     * inline 条目每次命中都重写(整文件, 但体积上限就是 small_entry_inline_bytes, 默认 64KB):
     * 比"每 N 次才落盘"多写一点, 但省下的是一个会悄悄丢命中数的计数器。
     */
    public function noteHit(Entry $e): void
    {
        $key = $e->key;
        $paths = Key::paths($key, $this->cacheDir());
        $now = microtime(true);
        $payload = null;
        if (is_readable($paths['meta'])) {
            $payload = $this->decode($paths['meta']);
        } elseif (is_readable($paths['inline'])) {
            [$payload] = $this->readInlineHeader($paths['inline']);
        }
        if (!is_array($payload)) {
            return;
        }

        $stored = Entry::fromArray($payload);
        $updated = $stored->withHit($now);
        $out = $updated->toArray();
        foreach (['head_sha256', 'display', 'ref_digest'] as $k) {
            if (isset($payload[$k])) {
                $out[$k] = $payload[$k];
            }
        }

        if (is_readable($paths['meta'])) {
            $this->atomicJson($paths['meta'], $out);
        } else {
            $this->rewriteInlineMeta($paths['inline'], $out, $updated->bytes);
        }
        $this->bumpEpoch(0, 0, 1);
    }

    /**
     * 容量水位。
     *
     * 30 秒一次纪元检查(以及压实器)才真正扫目录与查磁盘: 每请求查 disk_free_space 在
     * 网络盘上能到几十毫秒, 那是白送的首字节延迟。
     *
     * @return array{used:int, partial:int, entries:int, max:int, ratio:float, soft:float, hard:float, disk_free:int, stop:bool}
     */
    public function watermark(): array
    {
        $epochTtl = max(1, $this->cfg->int('cache.watermark_epoch_s', 30));
        if ($this->epoch !== null && (microtime(true) - $this->epoch['at']) < $epochTtl) {
            return $this->epoch;
        }

        return $this->rescan();
    }

    /**
     * 按价值密度淘汰到至少腾出 needBytes, 返回实际释放的字节数。
     *
     * 排序键 = hits × freshness / bytes^alpha —— 不是 LRU: 一个只下过一次但重取要 20 分钟的
     * 800MB 资产, 价值高于一堆重取只要 0.3 秒的 2KB JSON。
     */
    public function evict(int $needBytes): int
    {
        $entries = $this->collectEntries();
        if ($entries === []) {
            return 0;
        }
        $now = microtime(true);
        $scored = [];
        foreach ($entries as [$entry, $size]) {
            $scored[$entry->key] = [$this->policy->valueDensity($entry, $now), $size];
        }
        uasort($scored, static fn (array $a, array $b): int => $a[0] <=> $b[0]);

        $need = max(0, $needBytes);
        if ($need === 0) {
            return 0;
        }
        // 单请求最多淘汰 evict_batch 条: 一次写请求不该顺手把整个缓存清库。真装不下时
        // begin() 会返回 null, 退化成流式转发 —— 宁可慢, 也不让一次请求卡几十秒。
        $maxDelete = max(1, $this->cfg->int('cache.evict_batch', 20));
        $freed = 0;
        $deleted = 0;
        foreach (array_keys($scored) as $key) {
            $this->drop((string) $key);
            $freed += (int) $scored[$key][1];
            if (++$deleted >= $maxDelete || $freed >= $need) {
                break;
            }
        }
        $this->epoch = null;
        $this->persistUsage($freed);

        return $freed;
    }

    /**
     * 清理。scope:
     *  - all      整个缓存
     *  - expired  过期条目(含 .part / 隔离区)
     *  - partial  只清半成品
     *  - scene    target = 场景值, 如 release_asset
     *  - source   target = sourceId
     *  - ref      target = GitHubRef 的 canonical 串或完整 64 位键
     * @return int 删除的条目数
     */
    public function purge(string $scope, ?string $target): int
    {
        $n = 0;
        $dir = $this->cacheDir();
        switch ($scope) {
            case 'all':
                foreach ($this->listKeys($dir) as $key) {
                    $this->drop($key);
                    $n++;
                }
                $this->purgeDir(Key::partialDir($dir));
                $this->purgeDir(Key::quarantineDir($dir));
                break;

            case 'expired':
                $now = microtime(true);
                foreach ($this->collectEntries(true) as [$entry, $size]) {
                    if ($entry->isServeableStale($now)) {
                        continue;
                    }
                    $this->drop($entry->key);
                    $n++;
                }
                foreach ($this->listPartMetas($dir) as $metaPath) {
                    $meta = $this->decode($metaPath);
                    $age = $now - (float) ($meta['updated_at'] ?? 0.0);
                    $ttl = $this->policy->partialTtl();
                    if ($meta === null || $age > $ttl) {
                        @unlink(substr($metaPath, 0, -strlen('.part.meta.json')) . '.part');
                        @unlink($metaPath);
                        $n++;
                    }
                }
                $this->purgeDir(Key::quarantineDir($dir), $this->policy->quarantineTtl());
                break;

            case 'partial':
                foreach ($this->listPartMetas($dir) as $metaPath) {
                    @unlink(substr($metaPath, 0, -strlen('.part.meta.json')) . '.part');
                    @unlink($metaPath);
                    $n++;
                }
                break;

            case 'scene':
            case 'source':
                $needle = strtolower((string) $target);
                foreach ($this->collectEntries(true) as [$entry, $size]) {
                    $hit = $scope === 'scene'
                        ? $entry->scene->value === $needle
                        : $entry->sourceId === $needle;
                    if ($hit) {
                        $this->drop($entry->key);
                        $n++;
                    }
                }
                break;

            case 'ref':
            case 'key':
                $t = (string) $target;
                $key = preg_match('#\A[0-9a-f]{64}\z#', $t) ? $t : hash('sha256', $t);
                $existed = is_readable(Key::paths($key, $dir)['meta']) || is_readable(Key::paths($key, $dir)['inline']);
                $this->drop($key);
                $n = $existed ? 1 : 0;
                break;

            default:
                return 0;
        }

        $this->epoch = null;
        $this->persistUsage(0);

        return $n;
    }

    // ---------------------------------------------------------------- 内部实现

    /**
     * 写前腾地方: 反复按价值密度淘汰, 直到 (已用 + 预计写入) 落回硬水位以下。
     *
     * 只淘汰一轮是不够的: 单轮上限是 evict_batch 条, 而条目的真实占盘体积含 meta/头部字节,
     * 与 meta.bytes 不完全相等。轮数上限防呆, 腾不出来就返回 null 让调用方退化成流式转发。
     *
     * @return array|null 刷新后的水位, null 表示装不下
     */
    private function ensureRoom(int $expected): ?array
    {
        $max = max(1, $this->cfg->int('cache.max_bytes', 10737418240));
        $hard = $this->cfg->float('cache.hard_watermark', 0.85);
        $stop = $this->cfg->float('cache.stop_watermark', 0.95);
        $rounds = max(1, $this->cfg->int('cache.evict_rounds', 4));

        $wm = $this->watermark();
        for ($i = 0; $i < $rounds; $i++) {
            $projected = ($wm['used'] + $expected) / $max;
            if ($projected < $hard) {
                return $wm;
            }
            $need = max(1, (int) ceil($wm['used'] + $expected - $hard * $max));
            $freed = $this->evict($need);
            if ($freed <= 0) {
                break;
            }
            $wm = $this->watermark();
        }

        // 淘汰到头仍然越过停写水位 -> 拒写。落在 hard 与 stop 之间则放行这一次:
        // 否则小容量部署(或刚清过库)会永远写不进任何条目, 那不是保护而是自废。
        return (($wm['used'] + $expected) / $max) >= $stop ? null : $wm;
    }

    /** @return array{0:string,1:int}|null [数据文件路径, 数据起始偏移] */
    private function resolve(string $key): ?array
    {
        // 故意不做进程内缓存: 缓存过一次位置, 后面"bin 被换成了半写文件 / inline 与 meta 并存"
        // 这类不一致就检不出来了, 而两次 is_readable 的代价远比服务一份坏字节便宜。
        $paths = Key::paths($key, $this->cacheDir());
        if (is_readable($paths['bin'])) {
            return [$paths['bin'], 0];
        }
        if (is_readable($paths['inline'])) {
            $offset = $this->inlineHeaderLength($paths['inline']);

            return $offset === null ? null : [$paths['inline'], $offset];
        }

        return null;
    }

    private function readEntry(string $key): ?Entry
    {
        $paths = Key::paths($key, $this->cacheDir());
        $payload = $this->decode($paths['meta']);
        if ($payload === null) {
            [$head, $offset] = $this->readInlineHeader($paths['inline']);
            if ($head === null) {
                return null;
            }
            $payload = $head;
        }

        $entry = Entry::fromArray($payload);
        if ($entry->key === '' || $entry->key !== $key) {
            // meta 里的 key 与文件名不一致 = 目录被人工搬动过或写坏了, 不能信。
            $this->drop($key);

            return null;
        }

        $loc = $this->resolve($key);
        if ($loc === null) {
            $this->drop($key);

            return null;
        }
        $size = @filesize($loc[0]);
        if ($size === false || $size - $loc[1] !== $entry->bytes) {
            // filesize != meta.bytes 直接判废并删: 半写的文件永远不该被当成完整条目服务。
            $this->drop($key);

            return null;
        }

        return $entry;
    }

    private function drop(string $key): void
    {
        $paths = Key::paths($key, $this->cacheDir());
        foreach (['bin', 'meta', 'inline', 'part', 'partMeta'] as $k) {
            $f = $paths[$k];
            if ($f !== '' && @file_exists($f)) {
                @unlink($f);
            }
        }
    }

    private function writeSeparated(PartialWriter $w, array $payload): bool
    {
        $metaPath = Key::paths($w->key, $this->cacheDir())['meta'];
        // 先落 meta 再 rename 数据: 反过来会留下"有 bin 没 meta"的孤儿(永远读不到又占水位)。
        // 现在这个顺序下最坏情况是 meta 先到了但 bin 还没落地, 读者 filesize 失败 -> 判废删除。
        if (!$this->atomicJson($metaPath, $payload)) {
            return false;
        }
        if (!@rename($w->partPath, $w->finalPath)) {
            @unlink($metaPath);

            return false;
        }
        @unlink($w->partMetaPath);

        return true;
    }

    /**
     * 小条目: 单文件 = 一行 JSON 头 + "\n" + 原始字节。
     * 头部以 \n 结束且 JSON 里不含裸换行(json_encode 默认转义), 所以偏移量可以安全地
     * 用"首行字节数"表达。
     */
    private function writeInline(PartialWriter $w, array $payload, int $dataBytes): bool
    {
        $paths = Key::paths($w->key, $this->cacheDir());
        $header = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($header)) {
            return false;
        }
        $tmp = $paths['inline'] . '.tmp';
        $in = @fopen($w->partPath, 'rb');
        $out = @fopen($tmp, 'wb');
        if ($in === false || $out === false) {
            if (is_resource($out)) {
                fclose($out);
            }
            if (is_resource($in)) {
                fclose($in);
            }
            @unlink($tmp);

            return false;
        }
        fwrite($out, $header . "\n");
        $chunk = 65536;
        $pumped = 0;
        while (!feof($in) && $pumped < $dataBytes) {
            $buf = fread($in, min($chunk, $dataBytes - $pumped));
            if ($buf === false || $buf === '') {
                break;
            }
            fwrite($out, $buf);
            $pumped += strlen($buf);
        }
        fclose($in);
        fclose($out);
        if ($pumped !== $dataBytes) {
            @unlink($tmp);

            return false;
        }
        if (!@rename($tmp, $paths['inline'])) {
            @unlink($tmp);

            return false;
        }
        @unlink($w->partPath);
        @unlink($w->partMetaPath);
        @unlink($paths['bin']);
        @unlink($paths['meta']);

        return true;
    }

    private function rewriteInlineMeta(string $file, array $payload, int $dataBytes): bool
    {
        $header = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($header)) {
            return false;
        }
        $tmp = $file . '.tmp';
        $in = @fopen($file, 'rb');
        $out = @fopen($tmp, 'wb');
        if ($in === false || $out === false) {
            if (is_resource($out)) {
                fclose($out);
            }
            if (is_resource($in)) {
                fclose($in);
            }
            @unlink($tmp);

            return false;
        }
        $offset = $this->inlineHeaderLength($file) ?? 0;
        fseek($in, $offset);
        fwrite($out, $header . "\n");
        $total = $dataBytes;
        $chunk = 65536;
        $pumped = 0;
        while ($pumped < $total) {
            $buf = fread($in, min($chunk, $total - $pumped));
            if ($buf === false || $buf === '') {
                break;
            }
            fwrite($out, $buf);
            $pumped += strlen($buf);
        }
        fclose($in);
        fclose($out);
        if ($pumped !== $total) {
            @unlink($tmp);

            return false;
        }
        @rename($tmp, $file);

        return true;
    }

    /** @return array{0:array|null,1:int} [头部数组, 数据偏移] */
    private function readInlineHeader(string $file): array
    {
        $fh = @fopen($file, 'rb');
        if ($fh === false) {
            return [null, 0];
        }
        $cap = max(4096, $this->cfg->int('cache.inline_header_max_bytes', 262144));
        $line = stream_get_line($fh, $cap, "\n");
        fclose($fh);
        if ($line === false || $line === '') {
            return [null, 0];
        }
        $head = json_decode($line, true);

        return [is_array($head) ? $head : null, strlen($line) + 1];
    }

    private function inlineHeaderLength(string $file): ?int
    {
        $fh = @fopen($file, 'rb');
        if ($fh === false) {
            return null;
        }
        $cap = max(4096, $this->cfg->int('cache.inline_header_max_bytes', 262144));
        $line = stream_get_line($fh, $cap, "\n");
        fclose($fh);
        if ($line === false || $line === '') {
            return null;
        }

        return strlen($line) + 1;
    }

    private function headHashOf(string $file, int $bytes): string
    {
        $fh = @fopen($file, 'rb');
        if ($fh === false) {
            return '';
        }
        $ctx = hash_init('sha256');
        $left = max(0, $bytes);
        while ($left > 0 && !feof($fh)) {
            $buf = fread($fh, (int) min(65536, $left));
            if ($buf === false || $buf === '') {
                break;
            }
            hash_update($ctx, $buf);
            $left -= strlen($buf);
        }
        fclose($fh);

        return hash_final($ctx);
    }

    private function decode(string $file): ?array
    {
        if (!is_readable($file)) {
            return null;
        }
        $json = @file_get_contents($file);
        if ($json === false) {
            return null;
        }
        $data = json_decode($json, true);

        return is_array($data) ? $data : null;
    }

    private function atomicJson(string $file, array $data): bool
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES);

        return is_string($json) && Config::atomicWrite($file, $json);
    }

    private function readPartMeta(string $file): ?array
    {
        return $this->decode($file);
    }

    private function writePartMeta(PartialWriter $w): void
    {
        $this->atomicJson($w->partMetaPath, $w->metaArray());
    }

    private function quarantine(string $partPath, string $metaPath): void
    {
        $qdir = Key::quarantineDir($this->cacheDir());
        if (!is_dir($qdir)) {
            @mkdir($qdir, 0770, true);
        }
        $base = basename($partPath);
        @rename($partPath, $qdir . '/' . $base);
        @rename($metaPath, $qdir . '/' . str_replace('.part', '.part.meta.json', $base));
    }

    private function purgeDir(string $dir, int $olderThan = 0): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $now = microtime(true);
        foreach ((array) @scandir($dir) as $name) {
            if (!is_string($name) || $name === '.' || $name === '..') {
                continue;
            }
            $f = $dir . '/' . $name;
            if (!is_file($f)) {
                continue;
            }
            if ($olderThan > 0 && ($now - (float) @filemtime($f)) < $olderThan) {
                continue;
            }
            @unlink($f);
        }
    }

    /**
     * 目录扫描: 只统计已完成的条目。
     *
     * 体积用**实际占盘字节**(含 inline 条目的 JSON 头), 不用 meta.bytes: 水位算的是磁盘,
     * 用数据长度会让淘汰"看起来腾了地方但实际没腾", 于是反复空转。
     *
     * @return list<array{0:Entry,1:int}>
     */
    private function collectEntries(bool $includeExpired = true): array
    {
        $out = [];
        $now = microtime(true);
        foreach ($this->listKeys($this->cacheDir()) as $key) {
            $entry = $this->readEntry($key);
            if ($entry === null) {
                continue;
            }
            if (!$includeExpired && !$entry->isServeableStale($now)) {
                continue;
            }
            $loc = $this->resolve($key);
            $size = $loc === null ? $entry->bytes : (int) (@filesize($loc[0]) ?: $entry->bytes);
            $out[] = [$entry, $size];
        }

        return $out;
    }

    /** @return list<string> 缓存目录里出现过的键(从文件名反推, 不解析内容)。 */
    private function listKeys(string $dir): array
    {
        $keys = [];
        foreach ($this->candidateFiles($dir) as $file) {
            $base = basename((string) $file);
            foreach (['.bin', '.meta.json', '.entry'] as $suffix) {
                if (str_ends_with($base, $suffix)) {
                    $k = substr($base, 0, -strlen($suffix));
                    if (preg_match('#\A[0-9a-f]{64}\z#', $k)) {
                        $keys[$k] = true;
                    }
                    break;
                }
            }
        }

        return array_keys($keys);
    }

    /** @return list<string> */
    private function listPartMetas(string $dir): array
    {
        $out = [];
        foreach ($this->candidateFiles($dir, 3) as $file) {
            if (str_ends_with(basename((string) $file), '.part.meta.json')) {
                $out[] = (string) $file;
            }
        }

        return $out;
    }

    /**
     * 两级目录遍历。深度限制是防呆: 缓存目录被误指向别处时不至于把整块盘扫完。
     *
     * @return list<string>
     */
    private function candidateFiles(string $dir, int $maxDepth = 3): array
    {
        if (!is_dir($dir)) {
            return [];
        }
        $out = [];
        $stack = [[$dir, 0]];
        while ($stack !== []) {
            [$current, $depth] = array_pop($stack);
            $items = @scandir($current);
            if ($items === false) {
                continue;
            }
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') {
                    continue;
                }
                $full = $current . '/' . $item;
                if (is_dir($full)) {
                    if ($depth < $maxDepth && !in_array($item, ['_quarantine', '_partial'], true)) {
                        $stack[] = [$full, $depth + 1];
                    }
                    continue;
                }
                // 以 . 开头的是治理用的旁路文件(.usage.json / *.tmp), 不计入条目也不参与扫描。
                if (str_starts_with($item, '.')) {
                    continue;
                }
                $out[] = $full;
            }
        }

        return $out;
    }

    /** 扫描目录得到用量与磁盘余量, 并把结果写回纪元缓存与快照侧的用量文件。 */
    private function rescan(): array
    {
        $max = max(1, $this->cfg->int('cache.max_bytes', 10737418240));
        $used = 0;
        $partial = 0;
        $entries = 0;
        foreach ($this->candidateFiles($this->cacheDir()) as $file) {
            $base = basename((string) $file);
            $size = (int) (@filesize($file) ?: 0);
            if (str_ends_with($base, '.part')) {
                $partial += $size;
                $used += $size;
            } elseif (str_ends_with($base, '.bin') || str_ends_with($base, '.entry')) {
                $used += $size;
                $entries++;
            } else {
                $used += $size;
            }
        }
        // .part 体积计入水位: 不算进去的话, 大文件反复中断会悄悄吃满磁盘而面板显示一切正常。
        $diskFree = -1;
        $f = @disk_free_space($this->cacheDir());
        if ($f !== false) {
            $diskFree = (int) $f;
        }

        $wm = [
            'used'      => $used,
            'partial'   => $partial,
            'entries'   => $entries,
            'max'       => $max,
            'ratio'     => min(1.0, $used / $max),
            'soft'      => $this->cfg->float('cache.soft_watermark', 0.70),
            'hard'      => $this->cfg->float('cache.hard_watermark', 0.85),
            'disk_free' => $diskFree,
            'stop'      => min(1.0, $used / $max) >= $this->cfg->float('cache.stop_watermark', 0.95),
            'at'        => microtime(true),
        ];
        $this->epoch = $wm;
        $this->persistUsage(0, $wm);

        return $wm;
    }

    /** 增量更新纪元, 避免每次 commit 都重扫目录。 */
    private function bumpEpoch(int $addedBytes, int $addedEntries, int $addedHits = 0): void
    {
        if ($this->epoch === null) {
            return;
        }
        $this->epoch['used'] += $addedBytes;
        $this->epoch['entries'] += $addedEntries;
        $this->epoch['ratio'] = min(1.0, $this->epoch['used'] / max(1, $this->epoch['max']));
        if ($addedHits > 0) {
            $this->epoch['hits'] = (int) ($this->epoch['hits'] ?? 0) + $addedHits;
        }
    }

    /** 用量文件: 压实器与面板都读它, 这样"磁盘余量"这类昂贵查询只发生一次。 */
    private function usageFile(): string
    {
        return $this->cacheDir() . '/.usage.json';
    }

    private function persistUsage(int $freed, ?array $wm = null): void
    {
        $wm ??= $this->epoch;
        if ($wm === null) {
            return;
        }
        $payload = $wm;
        $payload['freed_last'] = $freed;
        $existing = $this->decode($this->usageFile());
        if (is_array($existing)) {
            $payload['total_evicted'] = (int) ($existing['total_evicted'] ?? 0) + $freed;
            $payload['total_hits'] = (int) ($existing['total_hits'] ?? 0) + (int) ($wm['hits'] ?? 0);
        }
        $this->atomicJson($this->usageFile(), $payload);
    }
}
