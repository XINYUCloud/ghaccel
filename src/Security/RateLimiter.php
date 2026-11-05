<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 多桶令牌桶限流。桶状态落盘(每桶一个单行 JSON), 用 flock 做同机互斥,
 *             抢不到锁就降级放行 —— 限流器绝不能变成请求链上的串行点。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Security;

use GhAccel\Config;

/**
 * 三条来自实测与事故的设计约束:
 *  1. 桶键 = sha256(clientKey|salt) 派生。IPv6 含 ':' 直接当文件名在 Windows 上炸;
 *     同时用户 IP 明文落盘本身就是隐私义务(一台公开 GitHub 反代 = 谁在下什么的时间序列)。
 *  2. flock(LOCK_EX|LOCK_NB) 抢不到即"允许但 contended=true"。阻塞等锁会把所有限程
 *     变成一把全局锁, 高并发下限流器自己就是第一个被打死的组件。
 *  3. 回填必须在拿到锁之后按实际流逝时间算, 且 clamp 到 cap: 否则一个空闲一夜的桶
 *     会攒出天文数字配额, 限流形同不存在。
 */
final class RateLimiter
{
    /** scope 缺省参数: 配置漏写一个桶不能让限流崩溃, 也不能默认放开。 */
    private const FALLBACK = ['cap' => 60.0, 'rate' => 10.0];

    /** @var array<string, array{cap:float, rate:float}> */
    private array $buckets = [];

    private string $dir;

    private string $salt;

    public function __construct(private readonly Config $cfg, string $root)
    {
        $conf = (array) $cfg->arr('limits.buckets');
        foreach ($conf as $scope => $b) {
            if (!is_array($b) || !is_string($scope) || $scope === '') {
                continue;
            }
            $this->buckets[$scope] = [
                'cap' => max(0.0001, (float) ($b['cap'] ?? self::FALLBACK['cap'])),
                'rate' => max(0.0001, (float) ($b['rate'] ?? self::FALLBACK['rate'])),
            ];
        }

        $this->dir = rtrim($root, '/\\') . '/var/ratelimit';
        // salt 变了就换一批文件名: 既支持定期轮换使历史桶作废, 也让 overlay 里的
        // salt_rotate_at 成为"面板一键清空限流状态"的手段。
        $this->salt = substr(hash('sha256', $root . '|' . $cfg->str('limits.bucket_salt') . '|' . $cfg->int('limits.salt_rotate_at')), 0, 16);
    }

    /**
     * 消费 $cost 个令牌。
     *
     * @param string $scope     ip|panel|ipday|login|suspect_ua(未在配置里则用兜底参数)
     * @param string $clientKey 通常是客户端 IP, 也可以是 (ip|ref) 之类的组合键
     * @return array{allowed:bool,retry_after:int,limit:float,remaining:float,contended:bool}
     */
    public function consume(string $scope, string $clientKey, float $cost = 1.0): array
    {
        $b = $this->buckets[$scope] ?? self::FALLBACK;
        $cap = (float) $b['cap'];
        $rate = (float) $b['rate'];
        $cost = max(0.0, $cost);

        // 成本超过整桶容量: 不可能满足, 直接拒。不这样做的话一个超大请求会让它自己
        // 和后来者一起等到天荒地老(retry_after 算出来是几十小时)。
        if ($cost > $cap) {
            return $this->result(false, $cap, 0.0, (int) ceil(($cost - $cap) / $rate), false);
        }

        $file = $this->path($scope, $clientKey);
        $dir = dirname($file);
        if (!is_dir($dir) && !@mkdir($dir, 0770, true) && !is_dir($dir)) {
            // 建不了目录就放行: 限流是保护, 不是功能开关, 它坏了不能拖垮正常请求。
            return $this->result(true, $cap, $cap, 0, true);
        }

        // 'c+' 而不是 'w'/'c': 'w' 会在别人已持锁时清空文件, 'c' 是只写模式(Windows 上
        // fread 直接 EBADF)。'c+' 读写打开且不截断, 读得到自己刚写的行。
        $fh = @fopen($file, 'c+');
        if ($fh === false) {
            return $this->result(true, $cap, $cap, 0, true);
        }

        if (@flock($fh, LOCK_EX | LOCK_NB) === false) {
            fclose($fh);

            return $this->result(true, $cap, $cap, 0, true);
        }

        $now = microtime(true);
        $raw = '';
        clearstatcache(true, $file);
        $size = filesize($file);
        if ($size !== false && $size > 0) {
            $raw = (string) fread($fh, (int) min($size, 65536));
        }

        $state = $raw === '' ? null : json_decode($raw, true);
        // 文件损坏(断电/并发截断/有人手改)则重建满桶, 不报错也不清零: 一次读坏不该让
        // 客户端被拒一小时。
        if (!is_array($state) || !isset($state['tokens'], $state['updated'])) {
            $state = ['tokens' => $cap, 'updated' => $now];
        }

        $tokens = max(0.0, min($cap, (float) $state['tokens']));
        $updated = (float) $state['updated'];
        if ($updated > $now) {
            // 时钟回拨(或别的进程写了未来时间)会让回填变成扣费, 直接重置基准。
            $updated = $now;
        }
        $refill = min($cap, $tokens + $rate * ($now - $updated));

        if ($refill >= $cost) {
            $refill -= $cost;
            $allowed = true;
            $retry = 0;
        } else {
            $retry = $rate > 0 ? (int) ceil(($cost - $refill) / $rate) : 0;
            $allowed = false;
        }

        $payload = json_encode(
            ['tokens' => round($refill, 4), 'updated' => round($now, 3), 'scope' => $scope],
            JSON_UNESCAPED_SLASHES
        );
        // 就地重写而不是 rename: 我们已持有排他锁, rename 会让并发方的 fd 指向旧 inode,
        // 于是它的锁形同虚设。
        rewind($fh);
        ftruncate($fh, 0);
        fwrite($fh, (string) $payload);
        fflush($fh);
        flock($fh, LOCK_UN);
        fclose($fh);

        return $this->result($allowed, $cap, $refill, $retry, false);
    }

    /**
     * 只读地看一眼余量, 不扣令牌。面板与诊断用。
     *
     * @return array{limit:float,remaining:float,known:bool}
     */
    public function peek(string $scope, string $clientKey): array
    {
        $b = $this->buckets[$scope] ?? self::FALLBACK;
        $cap = (float) $b['cap'];
        $rate = (float) $b['rate'];
        $file = $this->path($scope, $clientKey);
        if (!is_readable($file)) {
            return ['limit' => $cap, 'remaining' => $cap, 'known' => false];
        }
        $state = json_decode((string) @file_get_contents($file), true);
        if (!is_array($state) || !isset($state['tokens'], $state['updated'])) {
            return ['limit' => $cap, 'remaining' => $cap, 'known' => false];
        }
        $tokens = min($cap, max(0.0, (float) $state['tokens']) + $rate * max(0.0, microtime(true) - (float) $state['updated']));

        return ['limit' => $cap, 'remaining' => $tokens, 'known' => true];
    }

    /** 清理陈旧桶文件。压实器调用, 不在热路径。 */
    public function prune(int $maxAgeS = 86400): int
    {
        if (!is_dir($this->dir)) {
            return 0;
        }
        $cut = time() - max(60, $maxAgeS);
        $n = 0;
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $f) {
            if ($f instanceof \SplFileInfo && $f->isFile() && str_ends_with($f->getFilename(), '.json') && $f->getMTime() < $cut) {
                if (@unlink($f->getPathname())) {
                    $n++;
                }
            }
        }

        return $n;
    }

    /**
     * 两级目录分片: 4096 个子目录足够让单目录条目数保持在几百, 而 NTFS/ext4 的
     * 目录扫描都是线性的 —— 一个目录下堆几万个文件会让每次 open 都变成一次慢 IO。
     */
    private function path(string $scope, string $clientKey): string
    {
        $h = hash('sha256', $scope . '|' . $clientKey . '|' . $this->salt);

        return $this->dir . '/' . substr($h, 0, 2) . '/' . substr($h, 2, 2) . '/' . substr($h, 4, 24) . '.json';
    }

    private function result(bool $allowed, float $limit, float $remaining, int $retry, bool $contended): array
    {
        return [
            'allowed' => $allowed,
            'retry_after' => max(0, $retry),
            'limit' => $limit,
            'remaining' => round(max(0.0, $remaining), 3),
            'contended' => $contended,
        ];
    }
}
