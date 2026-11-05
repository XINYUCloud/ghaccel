<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 单写者压实。轮转日志 -> 全量重放 -> 离线算分位数落标量 -> 原子写快照 ->
 *             按价值密度淘汰过期缓存。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Store;

use GhAccel\Cache\Policy;
use GhAccel\Config;
use GhAccel\Enum\BreakerState;
use GhAccel\Enum\FailureKind;
use GhAccel\Routing\Breaker;
use GhAccel\Routing\Latency;
use GhAccel\Routing\Success;
use GhAccel\Source\RuntimeStat;

/**
 * 并发模型: var/lock/compact.lock 上 flock(LOCK_EX|LOCK_NB), 抢不到立刻返回, 绝不阻塞。
 * 请求侧概率触发与 cron 因此可以随便撞, 输的那个继续服务请求。
 *
 * 明确没有做的事: inode / generation 双校验。rename 的原子性 + 观测里 (source,seq) 幂等
 * 重放已经足够, 剩下的代价是个别观测丢失 —— 指标丢一条不影响决策, 加那套校验的代码却会
 * 长期影响可读性。
 */
final class Compactor
{
    private const CONTROL_RESET = 'breaker_reset';

    public function __construct(private readonly string $root, private readonly Config $cfg)
    {
    }

    /**
     * @return array{locked:bool, obs:int, sources:int, freed:int, rotated:int, error?:string}
     *   locked=true 表示锁被别人持有, 本次直接放弃(不是失败)。
     */
    public function run(bool $force = false): array
    {
        $lockFile = $this->root . '/var/lock/compact.lock';
        if (!is_dir(dirname($lockFile))) {
            @mkdir(dirname($lockFile), 0770, true);
        }
        $lh = @fopen($lockFile, 'c');
        if ($lh === false) {
            return ['locked' => true, 'obs' => 0, 'sources' => 0, 'freed' => 0, 'rotated' => 0, 'error' => 'lock_unopenable'];
        }
        if (!@flock($lh, LOCK_EX | LOCK_NB)) {
            fclose($lh);

            // 已有单写者在跑: 立即返回, 不排队。压实晚一轮没有任何后果。
            return ['locked' => true, 'obs' => 0, 'sources' => 0, 'freed' => 0, 'rotated' => 0];
        }

        try {
            $result = $this->compact($force);
        } finally {
            @flock($lh, LOCK_UN);
            fclose($lh);
        }

        return $result;
    }

    private function compact(bool $force): array
    {
        $rotated = $this->rotate();
        $observations = $this->replayRows();

        $snapshot = new Snapshot($this->root, $this->cfg);
        $previous = $snapshot->statsMap();

        // 有观测的源从零重建(口径唯一、可复现、重放幂等), 没有观测的源沿用上一版快照:
        // 否则日志一过期, 一个"上周很健康、这周没流量"的源会被清零并显示成未知。
        $stats = $previous;
        $samples = [];
        $thrSamples = [];
        $touched = [];
        $started = [];
        $seen = [];
        $count = 0;
        $nowRef = microtime(true);

        foreach ($observations as $row) {
            $id = (string) ($row['source'] ?? $row['source_id'] ?? '');
            if ($id === '') {
                continue;
            }
            $seq = (int) ($row['seq'] ?? 0);
            $dedupe = $id . '|' . $seq . '|' . (int) (1000 * (float) ($row['observed_at'] ?? 0.0));
            if (isset($seen[$dedupe])) {
                continue;
            }
            $seen[$dedupe] = true;
            $count++;

            if (isset($started[$id])) {
                $stat = $stats[$id];
            } else {
                // 首次遇到该源: 从空白重建。上一版快照里已经有这批观测的效果了, 在旧值上
                // 再累加一次就是双重计数 —— 压实必须可重复执行。
                $stat = new RuntimeStat();
                $started[$id] = true;
            }
            $at = (float) ($row['observed_at'] ?? 0.0);
            if ($at <= 0.0) {
                // 缺时间戳的观测按"现在"处理: 让 EWMA 的单调保护来决定它是否还有意义,
                // 而不是把它塞进 1970 年那个小时桶里污染计数。
                $at = $nowRef;
            }
            $kind = FailureKind::tryFrom((string) ($row['kind'] ?? '')) ?? FailureKind::None;
            $sceneKey = (string) ($row['scene'] ?? '');

            $type = (string) ($row['type'] ?? 'outcome');
            if ($type === self::CONTROL_RESET) {
                $stat = Breaker::manualReset($stat, $at > 0 ? $at : microtime(true));
                $stats[$id] = $stat;
                $touched[$id] = true;
                continue;
            }

            // 能力位也走观测流, 否则日志轮转一次就把探测结果全丢了, 而选路的 L0 恰恰只信实测。
            if (isset($row['caps']) && is_array($row['caps'])) {
                foreach ($row['caps'] as $cap => $v) {
                    $stat->measuredCaps[(string) $cap] = (bool) $v;
                }
            }

            $stat = Success::record($stat, $kind, $this->cfg);
            $ttfb = (float) ($row['ttfb_ms'] ?? 0.0);
            $thr = (float) ($row['thr_bps'] ?? 0.0);
            if ($ttfb > 0.0 || $thr > 0.0) {
                $stat = Latency::update($stat, $ttfb, $thr, $at, $this->cfg);
            }
            $stat = Breaker::recordOutcome($stat, $kind, $ttfb, $at, $this->cfg, $sceneKey);
            // 状态迁移在每条观测后跑一次, 冷却到期 -> HALF_OPEN 的推进因此不需要请求触发。
            $stat = Breaker::evaluate($stat, $at > 0 ? $at : microtime(true), $this->cfg);

            // 小时窗口计数: lastRequestAt 与当前观测不在同一小时就重新起算, 否则源上线
            // 三小时后 hour_bytes 还挂着最早的量, 礼貌因子的折扣会永久生效。
            $hourStart = floor($at / 3600.0) * 3600.0;
            if ($stat->lastRequestAt <= 0.0 || floor($stat->lastRequestAt / 3600.0) * 3600.0 !== $hourStart) {
                $stat->hourBytes = 0;
                $stat->hourRequests = 0;
            }
            $stat->hourRequests++;
            $stat->hourBytes += max(0, (int) ($row['bytes'] ?? 0));
            $stat->lastRequestAt = max($stat->lastRequestAt, $at);

            $stats[$id] = $stat;
            $touched[$id] = true;

            if ($kind === FailureKind::None && $ttfb > 0.0) {
                $samples[$id][] = $ttfb;
                if ($thr > 0.0) {
                    $thrSamples[$id][] = $thr;
                }
            }
        }

        if ($count === 0 && $rotated === 0 && !$force) {
            // 没新东西也不写快照: 每次压实都会产生一个新版本文件, 空转会把 var/state 变成垃圾场。
            return ['locked' => false, 'obs' => 0, 'sources' => count($stats), 'freed' => 0, 'rotated' => 0, 'skipped' => 'no_new_data'];
        }

        // 在线路径绝不计算分位数: P85/P10 在这里从 NDJSON 一次性算好, 落成两个标量。
        $minRank = max(1, $this->cfg->int('algo.explore.min_sample_for_rank', 30));
        foreach ($touched as $id => $_) {
            $stat = $stats[$id];
            if (isset($samples[$id]) && $samples[$id] !== []) {
                $stat->ttfbP85Ms = self::percentile($samples[$id], 0.85);
            }
            if (isset($thrSamples[$id]) && $thrSamples[$id] !== []) {
                $stat->thrP10Bps = self::percentile($thrSamples[$id], 0.10);
            }
            $stat->coldStart = $stat->sampleCount < $minRank;
            if ($stat->breaker === BreakerState::Open && microtime(true) >= $stat->cooldownUntil) {
                $stat = Breaker::evaluate($stat, microtime(true), $this->cfg);
            }
            $stats[$id] = $stat;
        }

        $freed = $this->sweepCache();
        $this->pruneOldJournals();

        $extra = [
            'compacted_at'    => microtime(true),
            'observations'    => $count,
            'rotated_files'   => $rotated,
            'sources'         => count($stats),
            'cache_freed'     => $freed,
            'disk_free_bytes' => $this->diskFree(),
            'global_samples'  => array_sum(array_map(static fn (RuntimeStat $s): int => $s->sampleCount, $stats)),
        ];
        $ok = $snapshot->replace($stats, $extra);

        return [
            'locked' => false,
            'obs' => $count,
            'sources' => count($stats),
            'freed' => $freed,
            'rotated' => $rotated,
            'written' => $ok,
        ];
    }

    /**
     * 轮转: 把当前活动日志改名成 .rotated-<ts>。
     *
     * 其他 worker 每次 flush 都自己 fopen('a'), 没有长驻句柄, 所以改名之后它们下一次写
     * 就会落到新文件里。窗口内可能有一条观测写进已被读走的旧文件 —— 按 §6 的取舍接受。
     */
    private function rotate(): int
    {
        $files = $this->journalFiles(false);
        $n = 0;
        foreach ($files as $f) {
            $target = $f . '.rotated-' . date('YmdHis') . '-' . bin2hex(random_bytes(2));
            if (@rename($f, $target)) {
                $n++;
            }
        }

        return $n;
    }

    /** 读日志目录里所有行, 展开 batch, 按 (observed_at, seq) 排序。 */
    private function replayRows(): array
    {
        $rows = [];
        foreach ($this->journalFiles(true) as $f) {
            $fh = @fopen($f, 'rb');
            if ($fh === false) {
                continue;
            }
            while (($line = fgets($fh)) !== false) {
                $line = trim($line);
                if ($line === '' || $line[0] !== '{') {
                    continue;
                }
                $obj = json_decode($line, true);
                if (!is_array($obj)) {
                    continue;
                }
                if (isset($obj['obs']) && is_array($obj['obs'])) {
                    foreach ($obj['obs'] as $one) {
                        if (is_array($one)) {
                            $rows[] = $one;
                        }
                    }
                } else {
                    $rows[] = $obj;
                }
            }
            fclose($fh);
        }

        usort($rows, static fn (array $a, array $b): int => [
            (float) ($a['observed_at'] ?? 0.0), (int) ($a['seq'] ?? 0),
        ] <=> [
            (float) ($b['observed_at'] ?? 0.0), (int) ($b['seq'] ?? 0),
        ]);

        return $rows;
    }

    /** @return list<string> */
    private function journalFiles(bool $includeRotated): array
    {
        $dir = $this->journalDir();
        if (!is_dir($dir)) {
            return [];
        }
        $pattern = $dir . '/obs-*.ndjson' . ($includeRotated ? '*' : '');
        $files = glob($pattern);
        if ($files === false) {
            return [];
        }
        $out = [];
        foreach ($files as $f) {
            if (is_file($f)) {
                $out[] = (string) $f;
            }
        }
        sort($out);

        return $out;
    }

    private function journalDir(): string
    {
        $dir = rtrim(str_replace('\\', '/', $this->cfg->str('logging.journal_dir', 'var/journal')), '/');
        if (!str_starts_with($dir, '/') && !preg_match('#\A[a-z]:[\\\\/]#i', $dir)) {
            $dir = rtrim(str_replace('\\', '/', $this->root), '/') . '/' . $dir;
        }
        if (!is_dir($dir)) {
            @mkdir($dir, 0770, true);
        }

        return $dir;
    }

    /** 日志保留: 隐私义务(谁在下什么)与磁盘的折中, 默认 14 天。 */
    private function pruneOldJournals(): void
    {
        $days = max(1, $this->cfg->int('logging.access_days', 14));
        $cutoff = time() - $days * 86400;
        foreach ($this->journalFiles(true) as $f) {
            if ((int) @filemtime($f) < $cutoff) {
                @unlink($f);
            }
        }
        // 轮转后已经被完整重放并进快照的文件可以按 compact 的年龄阈值删除。
        $age = max(1, $this->cfg->int('logging.compact.rotated_grace_s', 120));
        foreach ($this->journalFiles(true) as $f) {
            if (str_contains(basename($f), '.rotated-') && (microtime(true) - (float) @filemtime($f)) > $age) {
                @unlink($f);
            }
        }
    }

    /**
     * 缓存清扫: 删过期条目与陈旧 .part, 并把磁盘余量/用量写进纪元文件。
     *
     * "按价值密度淘汰过期缓存条目"里的"过期"是主判据, 价值密度只用于空间仍不足时的排序 ——
     * 无脑按 LRU 删会把 20 分钟才能重取的大资产先踢掉。
     */
    private function sweepCache(): int
    {
        $cacheDir = $this->cfg->str('cache.dir', 'var/cache');
        if (!str_starts_with($cacheDir, '/') && !preg_match('#\A[a-z]:[\\\\/]#i', $cacheDir)) {
            $cacheDir = rtrim(str_replace('\\', '/', $this->root), '/') . '/' . trim($cacheDir, '/');
        }

        $store = new \GhAccel\Cache\Store($this->root, $this->cfg, new Policy($this->cfg));
        $freed = 0;

        // 过期条目
        $before = $store->purge('expired', null);

        // 用量与磁盘: 只有压实(和 30s 纪元)才查一次 disk_free_space。
        $wm = $store->watermark();
        $max = max(1, (int) $wm['max']);
        $hard = $this->cfg->float('cache.hard_watermark', 0.85);
        if ($wm['used'] / $max >= $hard) {
            $freed += $store->evict((int) ($wm['used'] - $hard * $max));
        }
        $minFree = max(0, $this->cfg->int('cache.min_free_bytes', 0));
        if ($minFree > 0 && $wm['disk_free'] >= 0 && $wm['disk_free'] < $minFree) {
            // 磁盘真的紧了: 不管容量水位, 按价值密度一路淘汰到腾出足够余量。
            $freed += $store->evict((int) ($minFree - $wm['disk_free']) + $max / 50);
        }
        $after = $store->watermark();

        $this->writeCacheUsage($cacheDir, $after, $before);

        return max(0, (int) $wm['used'] - (int) $after['used']);
    }

    private function writeCacheUsage(string $cacheDir, array $wm, int $expiredEntries): void
    {
        $payload = $wm;
        $payload['expired_entries_purged'] = $expiredEntries;
        $payload['written_at'] = microtime(true);
        if (!is_dir($cacheDir)) {
            @mkdir($cacheDir, 0770, true);
        }
        Config::atomicWrite($cacheDir . '/.usage.json', json_encode($payload, JSON_UNESCAPED_SLASHES));
    }

    private function diskFree(): int
    {
        $f = @disk_free_space($this->root . '/var');

        return $f === false ? -1 : (int) $f;
    }

    /**
     * 最近秩分位数(nearest-rank)。
     *
     * 不用线性插值: 这里要的只是"保守的那一档"(TTFB 取 P85, 吞吐取 P10), 插值带来的 0.5 个
     * 样本的差别对决策毫无影响, 却会让单测对边界敏感。
     */
    public static function percentile(array $values, float $q): float
    {
        if ($values === []) {
            return 0.0;
        }
        sort($values);
        $n = count($values);
        $idx = (int) ceil($q * $n);
        $idx = max(1, min($n, $idx));

        return (float) $values[$idx - 1];
    }
}
