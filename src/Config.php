<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 配置装载与分层合并。四级覆盖, 后者胜:
 *   config/config.dist.php  ->  config/config.php  ->  config/config.local.php  ->  var/state/overlay.json
 * 最后一层是面板在线改动落的, 所以"手改配置文件"与"面板点两下"不会互相冲掉。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel;

final class Config
{
    private static ?self $instance = null;

    /** @var array<string, mixed> */
    private array $data = [];

    private function __construct(array $data)
    {
        $this->data = $data;
    }

    public static function load(string $root, bool $force = false): self
    {
        if (self::$instance !== null && !$force) {
            return self::$instance;
        }

        $layers = [
            $root . '/config/config.dist.php',
            $root . '/config/config.php',
            $root . '/config/config.local.php',
        ];

        $data = [];
        foreach ($layers as $file) {
            if (is_readable($file)) {
                $loaded = include $file;
                if (is_array($loaded)) {
                    $data = self::mergeDeep($data, $loaded);
                }
            }
        }

        // 面板在线覆盖层。它必须最后应用, 且只允许覆盖白名单路径, 否则一次面板写入
        // 就能改掉 security 根基金线。
        $overlay = $root . '/var/state/overlay.json';
        if (is_readable($overlay)) {
            $ov = json_decode((string) file_get_contents($overlay), true);
            if (is_array($ov)) {
                $data = self::mergeDeep($data, self::filterOverlay($ov));
            }
        }

        $data['__root'] = $root;

        return self::$instance = new self($data);
    }

    /** 面板可改的路径白名单。安全基线一律只能改配置文件, 防止一次面板妥协变成永久开放代理。 */
    private static function filterOverlay(array $ov): array
    {
        $allow = ['algo', 'cache', 'limits', 'budgets', 'panel', 'logging', 'routing'];
        $out = [];
        foreach ($ov as $k => $v) {
            if (in_array($k, $allow, true) && is_array($v)) {
                $out[$k] = $v;
            }
        }

        return $out;
    }

    private static function mergeDeep(array $base, array $over): array
    {
        foreach ($over as $k => $v) {
            if (is_array($v) && isset($base[$k]) && is_array($base[$k]) && self::isAssoc($v) && self::isAssoc($base[$k])) {
                $base[$k] = self::mergeDeep($base[$k], $v);
            } else {
                $base[$k] = $v;
            }
        }

        return $base;
    }

    private static function isAssoc(array $a): bool
    {
        return $a !== [] && array_keys($a) !== range(0, count($a) - 1);
    }

    /** 点号路径读取, 缺省返回 $default。 */
    public function get(string $path, mixed $default = null): mixed
    {
        $seg = explode('.', $path);
        $cur = $this->data;
        foreach ($seg as $s) {
            if (!is_array($cur) || !array_key_exists($s, $cur)) {
                return $default;
            }
            $cur = $cur[$s];
        }

        return $cur;
    }

    public function int(string $path, int $default = 0): int
    {
        $v = $this->get($path, $default);

        return is_numeric($v) ? (int) $v : $default;
    }

    public function float(string $path, float $default = 0.0): float
    {
        $v = $this->get($path, $default);

        return is_numeric($v) ? (float) $v : $default;
    }

    public function bool(string $path, bool $default = false): bool
    {
        $v = $this->get($path, $default);

        return is_bool($v) ? $v : (in_array((string) $v, ['1', 'true', 'yes', 'on'], true));
    }

    public function arr(string $path, array $default = []): array
    {
        $v = $this->get($path, $default);

        return is_array($v) ? $v : $default;
    }

    public function str(string $path, string $default = ''): string
    {
        $v = $this->get($path, $default);

        return is_scalar($v) ? (string) $v : $default;
    }

    public function root(): string
    {
        return (string) ($this->data['__root'] ?? '.');
    }

    public function all(): array
    {
        $d = $this->data;
        unset($d['__root']);

        return $d;
    }

    /** 运行时覆盖并落盘, 供面板写接口调用。写的是 overlay 而不是配置文件本体。 */
    public function persistOverlay(array $patch): void
    {
        $file = $this->root() . '/var/state/overlay.json';
        $cur = is_readable($file) ? (array) json_decode((string) file_get_contents($file), true) : [];
        $merged = self::mergeDeep($cur, self::filterOverlay($patch));
        self::atomicWrite($file, json_encode($merged, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
        self::load($this->root(), true);
    }

    public static function atomicWrite(string $file, string $contents): bool
    {
        $dir = dirname($file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0770, true);
        }
        $tmp = $dir . '/' . basename($file) . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, $contents) === false) {
            return false;
        }

        // 同目录 rename 才是原子的; 跨设备会失败, 所以临时文件必须与目标同目录。
        if (!@rename($tmp, $file)) {
            @unlink($tmp);

            return false;
        }

        return true;
    }
}
