<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: .part 连续前缀写入器。写入一律 .part -> 校验 filesize -> rename 原子落地,
 *             中断时保留 .part 供下次续传。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Cache;

/**
 * 连续前缀模型:
 *   receivedBytes 恒等于"文件里已写好的连续前缀长度", 不是"总共收到的字节数"。
 *   于是续传只需要 `Range: bytes={prefix}-`, 不需要稀疏拼接与位图 —— 后者会让每次中断
 *   都要读回整份文件对缺口, 而且 .part 的体积能悄悄翻倍。
 *
 * hash_init 的状态资源不可序列化, 所以续传时把已存在的前缀重新喂进新的 hash 上下文
 * (常数内存的流式重放)。代价是一次顺序读, 换掉的是"跨请求保存 hash 状态"这个不可能的需求。
 */
final class PartialWriter
{
    /** @var resource|null */
    public $handle;

    public \HashContext $hash;

    public function __construct(
        public readonly string $key,
        public readonly string $partPath,
        public readonly string $partMetaPath,
        public readonly string $finalPath,
        public readonly string $dir,
        /** 期望总体积(来自上游 Content-Length), 0 表示未知 */
        public int $expectedSize = 0,
        /** 连续前缀长度 */
        public int $receivedBytes = 0,
        public int $resumeCount = 0,
        public readonly float $startedAt = 0.0,
        public int $headHashBytes = 1048576,
        public string $headSha256 = '',
        /** head_sha256 实际覆盖的字节数 —— 必须与摘要一起记录, 否则前缀变长后会误判 */
        public int $headBytes = 0,
        public readonly string $rangeSpec = '',
        public readonly string $sourceId = '',
        /**
         * begin() 时就把 Entry 需要的全部字段定下来, commit() 因此不需要再拿到 GitHubRef
         * (契约里 commit 的入参没有 ref)。内容: scene / identity_kind / content_type /
         * etag / fresh / stale / verified_against / upstream_etag / range_spec 等。
         */
        public array $entryMeta = [],
        /** 是否已经把 .part 的前缀重放进 hash 上下文(续传路径) */
        public bool $resumed = false,
    ) {
        $this->hash = hash_init('sha256');
    }

    /**
     * 顺序写入。任何一次乱序/短写都把状态标记为不可信并返回 false:
     * 连续前缀模型的前提是"只往尾部追加", 一旦前提破了就只能整条作废, 不能留半成品。
     */
    public function write(string $chunk): bool
    {
        if ($chunk === '' || !is_resource($this->handle)) {
            return $chunk === '';
        }
        $written = @fwrite($this->handle, $chunk);
        if ($written !== strlen($chunk)) {
            return false;
        }
        hash_update($this->hash, $chunk);
        $this->receivedBytes += $written;
        if ($this->expectedSize > 0 && $this->receivedBytes > $this->expectedSize) {
            // 上游多给了声明之外的字节: 内容不可信(截断或伪造), 由调用方判失败。
            return false;
        }

        return true;
    }

    /**
     * 续传前流式重放已有前缀。三件事一趟做完:
     *  1. 把前缀喂进新的 hash 上下文 —— hash_init 的状态资源不可序列化, 只能重放;
     *     代价是一次顺序读, 换来的是"中断后不必整条重下"。
     *  2. 校验 meta 记录的 head_sha256(它只覆盖 head_bytes 个字节)。窗口必须带长度记录:
     *     否则前缀从 100B 长到 200B 之后再算 head 必然与旧值不符, 好文件会被误判成写坏。
     *  3. 计算新的 head 窗口(覆盖 min(headHashBytes, 前缀长度) 个字节)供下一次续传核对。
     *
     * 前缀长度必须与 meta.received_bytes 完全一致 —— 这是发现"另一个进程动过这个 .part"
     * 的最直接证据。
     *
     * @return array{ok:bool, size:int, head_ok:bool, new_head:string, new_head_bytes:int}
     */
    public function replayPrefix(string $partPath, int $size, int $verifyBytes, string $verifySha): array
    {
        $fh = @fopen($partPath, 'rb');
        if ($fh === false) {
            return ['ok' => false, 'size' => 0, 'head_ok' => false, 'new_head' => '', 'new_head_bytes' => 0];
        }
        $verifyCtx = hash_init('sha256');
        $newLimit = (int) max(0, min($this->headHashBytes, $size));
        $newCtx = hash_init('sha256');
        $read = 0;
        $verified = 0;
        $chunkSize = 65536;
        while (!feof($fh)) {
            $buf = fread($fh, $chunkSize);
            if ($buf === false || $buf === '') {
                break;
            }
            $len = strlen($buf);
            $read += $len;
            if ($verified < $verifyBytes) {
                $take = min($verifyBytes - $verified, $len);
                hash_update($verifyCtx, substr($buf, 0, $take));
                $verified += $take;
            }
            if ($read <= $newLimit) {
                hash_update($newCtx, $buf);
            } else {
                $overflow = $read - $newLimit;
                if ($overflow < $len) {
                    hash_update($newCtx, substr($buf, 0, $len - $overflow));
                }
            }
            hash_update($this->hash, $buf);
        }
        fclose($fh);

        $gotSha = $verifySha !== '' ? hash_final($verifyCtx) : '';
        $headOk = $verifySha === '' || $verifyBytes <= 0 || hash_equals($verifySha, $gotSha);
        $newHead = $newLimit > 0 ? hash_final($newCtx) : '';

        return [
            'ok' => $read === $size,
            'size' => $read,
            'head_ok' => $headOk,
            'new_head' => $newHead,
            'new_head_bytes' => $newLimit,
        ];
    }

    /** 数据文件落地(rename 原子), 返回最终路径。调用方负责先确认 filesize == expected。 */
    public function renameTo(string $target): bool
    {
        $this->close();
        if (!@is_dir(dirname($target))) {
            @mkdir(dirname($target), 0770, true);
        }

        return @rename($this->partPath, $target);
    }

    public function close(): void
    {
        if (is_resource($this->handle)) {
            @fflush($this->handle);
            @fclose($this->handle);
            $this->handle = null;
        }
    }

    /** 丢弃半成品(校验失败/超限/进隔离区)。 */
    public function discard(): void
    {
        $this->close();
        @unlink($this->partPath);
        @unlink($this->partMetaPath);
    }

    /** .part 的旁路元数据: 没有它就无法知道 expected_size / head_sha256 / resume_count。 */
    public function metaArray(): array
    {
        return [
            'key'            => $this->key,
            'expected_size'  => $this->expectedSize,
            'received_bytes' => $this->receivedBytes,
            'resume_count'   => $this->resumeCount,
            'started_at'     => $this->startedAt,
            'updated_at'     => microtime(true),
            'head_sha256'    => $this->headSha256,
            'head_bytes'     => $this->headBytes,
            'head_hash_bytes'=> $this->headHashBytes,
            'range_spec'     => $this->rangeSpec,
            'source_id'      => $this->sourceId,
            // 续传发生在另一个请求里, 它拿不到本次的 GitHubRef, 所以 Entry 需要的字段必须在
            // 旁路元数据里自包含, 否则第二次请求只能丢弃 .part 从头再下。
            'entry'          => $this->entryMeta,
        ];
    }

    public function finalHash(): string
    {
        return hash_final($this->hash);
    }
}
