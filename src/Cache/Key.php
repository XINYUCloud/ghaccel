<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 缓存键与落盘路径。键 = sha256(GitHubRef::canonical()), 绝不含镜像域名,
 *             也绝不直接哈希 URL 字符串。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Cache;

use GhAccel\Ref\GitHubRef;

final class Key
{
    /**
     * canonical() 与归一化已经在 GitHubRef 里实现(大小写、.git、refs/heads 展开、逐段
     * percent 规范化、query 排序), 这里只负责哈希。字符串级归一化永远补不完, 所以键必须
     * 从值对象派生 —— 这是唯一能保证"同一资源同一个键"的地方。
     */
    public static function of(GitHubRef $ref): string
    {
        return hash('sha256', $ref->canonical());
    }

    /**
     * 两级目录打散: var/cache/{k[0..1]}/{k[2..4]}/{key}.bin
     *
     * 文件名一律 <sha256>.bin: 永远不含 .php, 也不含原始文件名的任何片段。很多实现会
     * "顺手"把下载文件名拼进缓存路径, 那是 webshell 的落地点(名字由攻击者全控)。
     *
     * @return array{dir:string, bin:string, meta:string, inline:string, part:string, partMeta:string}
     */
    public static function paths(string $key, string $cacheDir): array
    {
        $key = self::assertKey($key);
        $d1 = substr($key, 0, 2);
        $d2 = substr($key, 2, 3);
        $dir = rtrim(str_replace('\\', '/', $cacheDir), '/') . '/' . $d1 . '/' . $d2;

        return [
            'dir'      => $dir,
            'bin'      => $dir . '/' . $key . '.bin',
            'meta'     => $dir . '/' . $key . '.meta.json',
            // 小条目把 meta 与字节合并成单文件: 命中路径的开销主要是磁盘往返, inode 减半
            // 就是延迟减半。
            'inline'   => $dir . '/' . $key . '.entry',
            'part'     => $dir . '/' . $key . '.part',
            'partMeta' => $dir . '/' . $key . '.part.meta.json',
        ];
    }

    /** 校验键形态: 只有 64 位小写十六进制才允许进路径拼接, 其他一律拒绝。 */
    public static function assertKey(string $key): string
    {
        if (!preg_match('#\A[0-9a-f]{64}\z#', $key)) {
            throw new \InvalidArgumentException('非法缓存键: 必须是 64 位小写十六进制 sha256');
        }

        return $key;
    }

    /**
     * 客户端 Range 与已缓存条目 Range 是否有交集(即能否由这条完整/partial 条目满足)。
     *
     * 完整条目(rangeSpec 为空或 `bytes=0-(n-1)` 且等于总长)能覆盖任意单段 Range, 这是
     * 命中率的大头: Range 优先由完整条目切片满足, 不给每个 Range 单独建条目。
     * 多段 Range(multipart/byteranges)只由完整条目满足, 由调用方按透传处理。
     */
    public static function rangeOverlaps(string $range, string $entryRange): bool
    {
        $req = self::parseSingle($range);
        if ($req === null) {
            // 多段或非法 Range: 只有完整条目能满足, 而完整条目的 rangeSpec 为空。
            return trim($entryRange) === '' || self::isFull($entryRange);
        }
        if (trim($entryRange) === '' || self::isFull($entryRange)) {
            return true;
        }
        $have = self::parseSingle($entryRange);
        if ($have === null) {
            return false;
        }
        [$rs, $re] = $req;
        [$hs, $he] = $have;

        return $rs <= $he && $hs <= $re;
    }

    /**
     * 解析单段 Range 成闭区间 [start, end](end 未知时给 -1 表示到文件尾)。
     * 多段/后缀式(bytes=-500)在需要绝对偏移的场景返回 null, 由调用方决定退化策略。
     *
     * @return array{0:int,1:int}|null
     */
    public static function parseSingle(string $range): ?array
    {
        $r = strtolower(trim($range));
        if ($r === '') {
            return null;
        }
        if (str_starts_with($r, 'bytes=')) {
            $r = substr($r, 6);
        }
        if (str_contains($r, ',')) {
            return null;
        }
        if (!preg_match('#\A(\d*)\s*-\s*(\d*)\z#', $r, $m)) {
            return null;
        }
        $start = $m[1] === '' ? null : (int) $m[1];
        $end = $m[2] === '' ? null : (int) $m[2];
        if ($start === null && $end === null) {
            return null;
        }
        if ($start === null) {
            // 后缀 Range: 需要总体积才能定位, 这里返回负 start 标记, 由调用方换算。
            return [-1, -$end];
        }
        if ($end === null) {
            return [$start, -1];
        }
        if ($end < $start) {
            return null;
        }

        return [$start, $end];
    }

    /**
     * 是否覆盖整份资源。
     *
     * 只承认"rangeSpec 为空"这一种完整条目的约定。故意不把 `bytes=0-N` 当完整: 两个参数的
     * 签名里没有总体积, 任何凭 range 文本猜"这就是整个文件"的做法都会在 partial 条目上
     * 判错, 而那种条目被当完整条目服务就是脏数据。区间相交本身由 rangeOverlaps 处理。
     */
    public static function isFull(string $entryRange): bool
    {
        $r = strtolower(trim($entryRange));
        if ($r === '') {
            return true;
        }

        return (bool) preg_match('#\Abytes=0-\*\z#', $r);
    }

    /** 目录名安全: 键派生出的两级目录只可能是十六进制, 不需要额外过滤。 */
    public static function quarantineDir(string $cacheDir): string
    {
        return rtrim(str_replace('\\', '/', $cacheDir), '/') . '/_quarantine';
    }

    public static function partialDir(string $cacheDir): string
    {
        return rtrim(str_replace('\\', '/', $cacheDir), '/') . '/_partial';
    }
}
