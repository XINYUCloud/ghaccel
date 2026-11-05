<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 运行时状态的快照读写。用"纯文本版本指针 + 版本化 JSON 文件名"而不是
 *             var_export 出来的 PHP 文件 —— 这条取舍写在计划 §6, 是实测结论。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Store;

use GhAccel\Config;
use GhAccel\Source\RuntimeStat;

/**
 * 为什么不用 var_export 的 PHP 文件:
 *  1. 本机实测没有 opcache, include 一份 PHP 数组文件与读一份 JSON 一样要解析, 却没有
 *     JSON 的可检视性。
 *  2. 更致命的是即使生产机有 opcache, CLI 与 FPM 也不共享 OPcache SHM。cron 以 CLI 身份
 *     跑压实器时无法让 FPM 丢弃旧编译缓存 —— 后果不是"面板数字新不新", 而是熔断 OPEN 在
 *     旧快照里还是 CLOSED, 路由会持续把流量喂给已经打死的源, 自适应冷却完全失效。
 *     纯文本指针与 .json 数据文件都不进任何编译缓存, 从根上没有这个问题。
 *  3. var_export 对含 readonly 属性的对象需要 __set_state, 路径受限且极易写错。
 *
 * 文件布局:
 *   var/state/snap.ver           一行文本: 当前版本号(不含扩展名), 体积几十字节
 *   var/state/snap.<ver>.json    版本化数据文件, 写新 -> rename -> 再切指针
 * 先读 ver 再按名读, 保证读者永远只会看到某一个完整版本, 不会读到半写文件。
 */
final class Snapshot
{
    private ?string $cachedVersion = null;
    private ?array $cachedRaw = null;

    public function __construct(private readonly string $root, private readonly Config $cfg)
    {
    }

    /** @return array<string, RuntimeStat> */
    public function statsMap(): array
    {
        $raw = $this->raw();
        $out = [];
        foreach ((array) ($raw['stats'] ?? []) as $id => $row) {
            if (is_array($row)) {
                $out[(string) $id] = RuntimeStat::fromArray($row);
            }
        }

        return $out;
    }

    /** 整个快照数组; 无快照时返回带空 stats 的骨架, 调用方不必判 null。 */
    public function raw(): array
    {
        $ver = $this->version();
        if ($ver === '') {
            return ['schema' => self::SCHEMA, 'version' => '', 'stats' => [], 'meta' => []];
        }
        if ($this->cachedVersion === $ver && is_array($this->cachedRaw)) {
            return $this->cachedRaw;
        }

        $file = $this->dataFile($ver);
        $json = @file_get_contents($file);
        if ($json === false) {
            // 指针指向的文件不见了(压实器刚被杀 / 磁盘问题): 当作无快照而不是抛错,
            // 数据面降级为"全部冷启动"仍能用, 挂掉才是更大的事故。
            $this->cachedVersion = null;
            $this->cachedRaw = null;

            return ['schema' => self::SCHEMA, 'version' => '', 'stats' => [], 'meta' => [], 'error' => 'snapshot_missing'];
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            return ['schema' => self::SCHEMA, 'version' => '', 'stats' => [], 'meta' => [], 'error' => 'snapshot_corrupt'];
        }
        $this->cachedVersion = $ver;
        $this->cachedRaw = $data;

        return $data;
    }

    /**
     * 原子替换整个快照。
     *
     * 顺序很关键: 先写新版本数据文件(rename 落地), 再切 snap.ver 指针。反过来的话读者会
     * 有一个窗口指向还不存在的文件。旧版本保留若干份后清理, 便于压实失败时人工回滚。
     *
     * @param array<string, RuntimeStat> $stats
     */
    public function replace(array $stats, array $extra = []): bool
    {
        $this->ensureDir();
        $ver = $this->newVersion();
        $payload = [
            'schema'    => self::SCHEMA,
            'version'   => $ver,
            'written_at'=> $extra['written_at'] ?? microtime(true),
            'stats'     => [],
            'meta'      => $extra,
        ];
        foreach ($stats as $id => $stat) {
            if ($stat instanceof RuntimeStat) {
                $payload['stats'][(string) $id] = $stat->toArray();
            } elseif (is_array($stat)) {
                $payload['stats'][(string) $id] = $stat;
            }
        }
        ksort($payload['stats']);

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            return false;
        }

        $dataFile = $this->dataFile($ver);
        $tmp = $dataFile . '.tmp';
        if (@file_put_contents($tmp, $json) === false) {
            return false;
        }
        if (!@rename($tmp, $dataFile)) {
            // Windows 上 rename 到已存在文件会失败, 但这里目标是全新版本号, 失败说明目录
            // 不可写或权限问题 —— 留 tmp 不删是为了让运维看见半成品。
            @unlink($tmp);

            return false;
        }

        if (!Config::atomicWrite($this->verFile(), $ver . "\n")) {
            @unlink($dataFile);

            return false;
        }

        $this->cachedVersion = null;
        $this->cachedRaw = null;
        $this->pruneOld();

        return true;
    }

    public function version(): string
    {
        if ($this->cachedVersion !== null) {
            return $this->cachedVersion;
        }
        $v = @file_get_contents($this->verFile());
        if ($v === false) {
            return '';
        }
        $v = trim($v);
        // 版本号只允许安全字符: 它直接参与拼文件名, 不能是任意文本。
        if ($v !== '' && !preg_match('#\A[0-9A-Za-z._-]{1,64}\z#', $v)) {
            return '';
        }
        $this->cachedVersion = $v;

        return $v;
    }

    /** 读一次磁盘才刷新进程内缓存: 热路径每个请求读 1 次 ver 就够, 不重复 stat。 */
    public function reload(): array
    {
        $this->cachedVersion = null;
        $this->cachedRaw = null;

        return $this->raw();
    }

    public function dataFile(string $ver): string
    {
        return $this->dir() . '/snap.' . $ver . '.json';
    }

    private const SCHEMA = 1;

    private function dir(): string
    {
        return $this->root . '/var/state';
    }

    private function verFile(): string
    {
        return $this->dir() . '/snap.ver';
    }

    private function newVersion(): string
    {
        // 版本号带时间戳与随机后缀: 同一秒内两次压实也不会覆盖同名文件。
        return date('YmdHis') . '-' . bin2hex(random_bytes(3));
    }

    private function ensureDir(): void
    {
        if (!is_dir($this->dir())) {
            @mkdir($this->dir(), 0770, true);
        }
    }

    private function pruneOld(): void
    {
        $keep = max(2, $this->cfg->int('logging.snapshot_keep', 3));
        $files = glob($this->dir() . '/snap.*.json');
        if ($files === false || count($files) <= $keep) {
            return;
        }
        usort($files, static fn (string $a, string $b): int => (int) filemtime($b) <=> (int) filemtime($a));
        foreach (array_slice($files, $keep) as $f) {
            if (basename((string) $f) !== basename($this->dataFile($this->version()))) {
                @unlink($f);
            }
        }
    }
}
