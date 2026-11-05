<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 观测的写入侧。热路径预算是"1 次读 + 1 次追加 + 0 次阻塞写", 这个类负责
 *             其中的"1 次追加": 进程内缓冲多条观测, 请求末尾合并成一行 NDJSON 落盘。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Store;

use GhAccel\Config;

/**
 * 为什么是 NDJSON 追加而不是"读改写一个 JSON 状态文件":
 * 后者每次请求都要拿排他锁读全量再写全量, 并发一高就把自己变成串行点。追加写只有
 * O_APPEND 的内核原子性, 不需要 fsync —— 指标丢了无所谓, 请求变慢才有所谓。
 *
 * 每条观测带 seq 与 observed_at: 压实器重放时靠它们做到幂等与单调, 所以这里的顺序与
 * 时间戳必须在写入侧就固定下来, 不留给读取侧猜。
 */
final class Observatory
{
    /** @var list<array<string, mixed>> */
    private array $buffer = [];
    private int $seq;

    public function __construct(private readonly string $root, private readonly Config $cfg)
    {
        // 进程内自增即可: seq 只要求"同一 worker 对同一源单调", 压实器按 (source,seq) 去重。
        $this->seq = random_int(1, 100000);
    }

    /**
     * 缓冲一条观测。字段缺失时在这里补齐而不是让调用方各自决定默认值, 保证所有观测同构。
     *
     * 隐私: 不接收明文 IP(限流层已经存哈希派生 key), ref 只存 16 位摘要。一台公开反代的
     * 日志事实上就是"哪些项目正在被国内下载"的时间序列, 这是义务不是形式。
     */
    public function record(array $observation): void
    {
        $now = microtime(true);
        $obs = $observation;
        $obs['seq'] = (int) ($obs['seq'] ?? ++$this->seq);
        $obs['observed_at'] = (float) ($obs['observed_at'] ?? $now);
        $obs['logged_at'] = (float) ($obs['logged_at'] ?? $now);
        if (isset($obs['ref']) && is_string($obs['ref']) && strlen($obs['ref']) > 16) {
            $obs['ref'] = substr($obs['ref'], 0, 16);
        }
        if (isset($obs['ref_display']) && is_string($obs['ref_display'])) {
            $obs['ref_display'] = $this->scrubRef($obs['ref_display']);
        }

        $this->buffer[] = $obs;

        // 观测缓冲的上限: 单个请求可能产生几十条(failover 逐源), 而长驻的 CLI 脚本一次跑
        // 几万次。超过阈值提前 flush, 内存曲线才是平的。
        $maxBuffer = max(1, $this->cfg->int('logging.obs_buffer_max', 64));
        if (count($this->buffer) >= $maxBuffer) {
            $this->flush();
        }
    }

    /**
     * 请求末尾调用一次: 多条观测合并成 1 行 batch 追加。
     * 不 fsync —— 掉电丢几条指标可以接受, 每个请求多一次同步写不能接受。
     */
    public function flush(): void
    {
        if ($this->buffer === []) {
            return;
        }
        $batch = $this->buffer;
        $this->buffer = [];

        $line = json_encode([
            'batch'   => 1,
            'pid'     => getmypid(),
            'count'   => count($batch),
            'obs'     => $batch,
        ], JSON_UNESCAPED_SLASHES);
        if (!is_string($line)) {
            return;
        }

        $file = $this->journalFile();
        $dir = dirname($file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0770, true);
        }

        $fh = @fopen($file, 'a');
        if ($fh === false) {
            return;
        }
        // LOCK_EX 只在写这几 KB 的期间持有; 与其他 worker 的追加互相序列化的是写这一下,
        // 不是整个请求。非阻塞版本会让高并发下大量观测直接丢, 反而更糟。
        if (@flock($fh, LOCK_EX)) {
            @fwrite($fh, $line . "\n");
            @flock($fh, LOCK_UN);
        }
        @fclose($fh);
    }

    /** 自动兜底: 请求结束时即使调用方忘了 flush 也不该丢观测。 */
    public function __destruct()
    {
        try {
            $this->flush();
        } catch (\Throwable) {
            // 析构里任何异常都不该冒出去, 那会让响应变成 500。
        }
    }

    /**
     * 概率触发压实。抢不到锁立即返回 false, 绝不阻塞请求。
     *
     * 三个压实触发源之一(其余: cron 的 bin/compact.php --once、面板手动)。
     */
    public function maybeCompact(): bool
    {
        $divisor = max(1, $this->cfg->int('logging.compact.prob_divisor', 200));
        if ($divisor > 1 && random_int(1, $divisor) !== 1) {
            return false;
        }

        return (new Compactor($this->root, $this->cfg))->run(false)['locked'] === false;
    }

    public function buffered(): int
    {
        return count($this->buffer);
    }

    /** 当日活动日志文件名(UTC 日期, 与压实器的轮转口径一致)。 */
    public function journalFile(?int $at = null): string
    {
        $dir = rtrim($this->cfg->str('logging.journal_dir', 'var/journal'), '/');
        if (!str_starts_with($dir, '/') && !preg_match('#\A[a-z]:[\\\\/]#i', $dir)) {
            $dir = $this->root . '/' . $dir;
        }

        return $dir . '/obs-' . gmdate('Ymd', $at ?? time()) . '.ndjson';
    }

    private function scrubRef(string $display): string
    {
        // 日志保留模式: 默认只留 16 位摘要, 原始 owner/repo/path 不进磁盘。
        if ($this->cfg->str('logging.ref_display', 'hash') === 'plain') {
            return substr($display, 0, 120);
        }

        return substr(hash('sha256', $display), 0, 16);
    }
}
