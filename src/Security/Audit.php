<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 写操作审计。一行一 JSON 追加到 var/log/audit.ndjson, 只留可事后追责所需的
 *             最小集合: 谁、从哪、用了什么方法、动了哪个路径、结果如何。
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
 * 一条硬性红线: 不得记录 body 明文。
 *
 * 面板写接口里流转的是源 URL(可能是自建代理的地址, 带 token 查询参数)与人工填的备注,
 * 管理员还可能把 Token 粘进 label 字段。审计日志的读者比请求者更广(运维、日志采集、
 * 备份), 所以 body 只进 sha256 —— 足以证明"这条记录没被改过", 不泄露内容。
 * IP 同样只留哈希派生: 一台公开 GitHub 反代的访问日志事实上是"哪些项目正在被谁下载"
 * 的时间序列, 这是真实义务而不是形式。
 */
final class Audit
{
    public const FILE_NAME = 'audit.ndjson';

    /**
     * 追加一条审计记录。写失败返回 false 而不抛: 审计是事后证据, 不能让磁盘问题把
     * 已经完成的合法操作回滚成 500(那样运维只会看到"点了没反应", 更查不到原因)。
     *
     * @param string $actor    操作者标识, 必须是派生值(Token selector 前 8 位), 不是明文凭据
     * @param string $clientIp 明文 IP, 内部立即哈希, 不落盘
     * @param mixed  $body     请求体: 只取 sha256
     * @param string $result   ok|rejected|error|denied
     */
    public static function log(
        string $actor,
        string $method,
        string $path,
        mixed $body = null,
        string $result = 'ok',
        string $clientIp = '',
        ?Config $cfg = null
    ): bool {
        $cfg ??= self::cfg();
        $dir = self::logDir($cfg);
        $file = $dir . '/' . self::FILE_NAME;

        $row = [
            'ts' => round(microtime(true), 3),
            'actor' => substr(preg_replace('/[^0-9a-fA-F]/', '', $actor) ?? '', 0, 16),
            'ip_hash' => $clientIp === '' ? '' : self::ipHash($clientIp, (string) $cfg->str('limits.bucket_salt')),
            'method' => strtoupper(substr($method, 0, 8)),
            'path' => substr(preg_replace('/[\x00-\x20\x7F]/', '', $path) ?? '', 0, 512),
            'body_sha256' => self::bodySha256($body),
            'result' => substr($result, 0, 32),
        ];

        $line = json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if (!is_string($line)) {
            return false;
        }

        if (!is_dir($dir) && !@mkdir($dir, 0770, true) && !is_dir($dir)) {
            return false;
        }

        $fh = @fopen($file, 'ab');
        if ($fh === false) {
            return false;
        }
        // 这里的 flock 是阻塞的: 写操作每小时个位数, 换"审计一定落全"比换"永不等待"值。
        @flock($fh, LOCK_EX);
        $ok = @fwrite($fh, $line . "\n") !== false;
        @fflush($fh);
        @flock($fh, LOCK_UN);
        @fclose($fh);
        if ($ok) {
            @chmod($file, 0600);
        }

        return $ok;
    }

    /** 读最近 N 条(面板用)。文件不存在返回空数组, 路径只由配置拼出, 不接受外部输入。 */
    public static function tail(int $limit = 50, ?Config $cfg = null): array
    {
        $cfg ??= self::cfg();
        $file = self::logDir($cfg) . '/' . self::FILE_NAME;
        if (!is_readable($file)) {
            return [];
        }

        $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines)) {
            return [];
        }
        $out = [];
        foreach (array_slice($lines, max(0, $limit > 0 ? -$limit : -50)) as $l) {
            $row = json_decode($l, true);
            if (is_array($row)) {
                $out[] = $row;
            }
        }

        return $out;
    }

    /** actor 取 selector 前 8 位: 够区分是哪个 Token 干的, 又不足以参与重放。 */
    public static function actorFromSelector(string $selector): string
    {
        return substr(preg_replace('/[^0-9a-fA-F]/', '', $selector) ?? '', 0, 8);
    }

    /** 同 IP 同 salt 恒定同值, 便于跨日志关联; salt 轮换即历史作废。 */
    public static function ipHash(string $ip, string $salt = ''): string
    {
        $norm = IpRange::normalizeIp($ip) ?? strtolower(trim($ip));

        return substr(hash('sha256', $norm . '|' . $salt), 0, 16);
    }

    /** body 只留摘要: 规范串排序后哈希, 让键序不同的同一份 body 得到同一个值。 */
    public static function bodySha256(mixed $body): string
    {
        if ($body === null || $body === '' || $body === []) {
            return '';
        }
        $canonical = is_array($body) ? json_encode(self::sortKeys($body), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
                                     : (string) (is_scalar($body) ? (string) $body : json_encode($body));

        return hash('sha256', (string) $canonical);
    }

    private static function sortKeys(array $a): array
    {
        ksort($a);
        foreach ($a as $k => $v) {
            if (is_array($v)) {
                $a[$k] = self::sortKeys($v);
            }
        }

        return $a;
    }

    /** Config 是单例: 入口已经 load 过, 这里取回同一个实例, 空 root 不会触发重读。 */
    private static function cfg(): Config
    {
        return Config::load('');
    }

    /** 相对配置项一律按项目根展开; 已是绝对路径(含 Windows 盘符与 UNC)则原样用。 */
    private static function logDir(Config $cfg): string
    {
        $dir = rtrim((string) $cfg->str('logging.dir', 'var/log'), '/\\');
        if ($dir === '') {
            $dir = 'var/log';
        }
        $absolute = str_starts_with($dir, '/')
            || preg_match('#\A[a-zA-Z]:[\\\\/]#', $dir) === 1
            || str_starts_with($dir, '\\\\');
        if ($absolute) {
            return $dir;
        }
        $root = $cfg->root() !== '' ? $cfg->root() : dirname(__DIR__, 2);

        return rtrim($root, '/\\') . '/' . $dir;
    }
}
