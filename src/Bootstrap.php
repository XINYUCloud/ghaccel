<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 零依赖自动加载 + 运行环境自检。自检不是可选的装饰 —— 宝塔的"PHP 禁用函数"
 *             列表、缺失的 CA 根证书、被开启的 zlib.output_compression 这三类问题会让整套
 *             流式转发静默失效且极难排查, 所以每一项都必须在入口查出来并显示在面板上。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel;

use GhAccel\Errors\GhpError;

final class Bootstrap
{
    public const MIN_PHP = 80100;
    public const VERSION = '1.0.0';
    public const NAMESPACE_PREFIX = 'GhAccel\\';

    public static function autoload(string $class): void
    {
        if (!str_starts_with($class, self::NAMESPACE_PREFIX)) {
            return;
        }
        $rel = substr($class, strlen(self::NAMESPACE_PREFIX));
        $file = __DIR__ . '/' . str_replace('\\', '/', $rel) . '.php';
        if (is_readable($file)) {
            require $file;
        }
    }

    public static function register(): void
    {
        spl_autoload_register([self::class, 'autoload']);
    }

    /**
     * 环境自检。critical 非空时入口必须直接返回纯文本 500, 不能继续跑出一个"看起来能用
     * 但每个大文件都失败"的半死实例。
     *
     * @return array{critical: array<string,string>, warnings: array<string,string>, info: array<string,mixed>}
     */
    public static function selfCheck(string $root): array
    {
        $critical = [];
        $warnings = [];
        $info = [];

        if (PHP_VERSION_ID < self::MIN_PHP) {
            $critical['php_version'] = sprintf(
                '需要 PHP >= 8.1(用到 enum 与 readonly), 当前 %s',
                PHP_VERSION
            );
        }
        $info['php_version'] = PHP_VERSION;

        foreach (['curl', 'json', 'openssl', 'hash'] as $ext) {
            if (!extension_loaded($ext)) {
                $critical['ext_' . $ext] = "缺少 {$ext} 扩展";
            }
        }
        if (!extension_loaded('mbstring')) {
            $warnings['ext_mbstring'] = '缺少 mbstring, 长路径截断将退化为字节级';
        }
        if (!extension_loaded('intl')) {
            $warnings['ext_intl'] = '缺少 intl, 无法用 idn_to_ascii 暴露同形字域名(仍会拒绝, 只是告警较晚)';
        }
        // SQLite 是可选加速器, 本机实测就没有; 缺了只影响请求日志检索, 不影响正确性。
        $info['has_sqlite'] = extension_loaded('pdo_sqlite') || extension_loaded('sqlite3');

        $curl = function_exists('curl_version') ? curl_version() : null;
        if ($curl === null) {
            $critical['curl'] = 'curl 扩展不可用';
        } else {
            $info['curl_version'] = $curl['version'];
            $info['curl_ssl'] = $curl['ssl'] ?? null;
            $features = (int) ($curl['features'] ?? 0);
            if (($features & CURL_VERSION_SSL) === 0) {
                $critical['curl_ssl'] = 'curl 未编译 SSL 支持, 无法访问 https 上游';
            }
            if (($features & CURL_VERSION_HTTP2) === 0) {
                $warnings['curl_http2'] = 'curl 无 HTTP2, 单连接吞吐可能偏低';
            }
            if (($features & CURL_VERSION_IPV6) !== 0) {
                $info['curl_ipv6'] = 'curl 支持 IPv6, 但本部署默认锁 IPv4 出站';
            }
        }

        // CA: 本机便携 PHP 就是栽在这条上 —— TLS 握手成功却验不过根证书, 所有请求静默失败。
        $ca = (string) (ini_get('curl.cainfo') ?: '');
        if ($ca === '' && !is_readable($root . '/config/cacert.pem')) {
            $warnings['ca_bundle'] = '未配置 curl.cainfo, 若报 unable to get local issuer certificate 请指定 CA bundle';
        }
        $info['curl_cainfo'] = $ca;

        // 会静默破坏 Range / 断点续传 / sha256 流式校验的两个开关。
        if ((bool) ini_get('zlib.output_compression')) {
            $critical['zlib_output_compression'] = 'zlib.output_compression 必须关闭: 它会重新分块并让 Content-Length 与实际字节不符';
        }
        if ((bool) ini_get('output_buffering')) {
            $warnings['output_buffering'] = 'output_buffering 开启会增加首字节延迟';
        }
        $info['allow_url_fopen'] = (bool) ini_get('allow_url_fopen');

        // 宝塔会在"PHP 禁用函数"里禁掉这些, 而它们是限流/锁/IPv6 判定的地基。
        $disabled = strtolower((string) ini_get('disable_functions'));
        $disabledSet = array_map('trim', array_filter(explode(',', $disabled)));
        foreach (['flock', 'popen', 'curl_multi_exec', 'hash_hmac', 'inet_pton', 'disk_free_space'] as $fn) {
            if (in_array($fn, $disabledSet, true)) {
                $key = 'disabled_' . $fn;
                $msg = "函数 {$fn} 被 disable_functions 禁用";
                if (in_array($fn, ['flock', 'curl_multi_exec', 'hash_hmac'], true)) {
                    $critical[$key] = $msg;
                } else {
                    $warnings[$key] = $msg;
                }
            }
        }

        $memLimit = self::bytes((string) ini_get('memory_limit'));
        $info['memory_limit'] = $memLimit;
        if ($memLimit > 0 && $memLimit < 64 * 1024 * 1024) {
            $warnings['memory_limit'] = 'memory_limit 偏低, 流式本身恒定内存但观测缓冲可能超限';
        }

        foreach (['cache', 'state', 'journal', 'log', 'sessions', 'ratelimit', 'accounting', 'concurrency', 'lock'] as $d) {
            $path = $root . '/var/' . $d;
            if (!is_dir($path) || !is_writable($path)) {
                $critical['var_' . $d] = "var/{$d} 不存在或不可写";
            }
        }

        $free = @disk_free_space($root . '/var/cache');
        if ($free === false) {
            $warnings['disk_free_unknown'] = 'disk_free_space 不可用, 水位保护将退化为保守模式';
        } else {
            $info['var_free_bytes'] = (int) $free;
        }

        $info['sapi'] = PHP_SAPI;
        $info['opcache'] = function_exists('opcache_get_status');
        if (!$info['opcache']) {
            $warnings['opcache'] = '无 OPcache; 状态快照因此改用"版本化文件名 + 纯文本指针"而不是 include PHP 文件';
        }

        return ['critical' => $critical, 'warnings' => $warnings, 'info' => $info];
    }

    /** 若某项自检失败则抛出, 供需要硬性保证的路径调用。 */
    public static function requireFunctions(array $names): void
    {
        foreach ($names as $fn) {
            if (!function_exists($fn)) {
                throw GhpError::make(GhpError::UPSTREAM_FAILED, "缺少必需函数 {$fn}");
            }
        }
    }

    private static function bytes(string $v): int
    {
        $v = trim($v);
        if ($v === '' || $v === '-1') {
            return -1;
        }
        $unit = strtolower(substr($v, -1));
        $num = (int) $v;

        return match ($unit) {
            'g' => $num * 1024 * 1024 * 1024,
            'm' => $num * 1024 * 1024,
            'k' => $num * 1024,
            default => $num,
        };
    }
}
