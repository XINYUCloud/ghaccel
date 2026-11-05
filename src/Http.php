<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 请求捕获与响应输出原语。它是唯一允许触碰 $_SERVER/$_GET/header()/echo 的地方,
 *             其余代码全部通过它读写, 这样 CLI 自检与面板探活才能替换实现而不必起 HTTP 服务。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel;

final class Http
{
    private static ?string $requestId = null;
    private static ?array $capture = null;
    private static bool $bufferingCleared = false;

    /**
     * 已发出的状态码与响应头记录。
     *
     * CLI 下 header()/http_response_code() 是空操作, 于是"自造 ETag 有没有发出去"、
     * "304 是否真的没带 Content-Length"这类断言在测试里无从检查。记录一份副本, 让同一套
     * 输出代码既能在 fpm 下真实发头, 也能被 bin/selftest.php 断言 —— 不维护第二套实现。
     */
    private static int $sentStatus = 200;

    /** @var array<string, list<string>> 小写头名 -> 依次发出的值 */
    private static array $sentHeaders = [];

    private static ?Config $cfgRef = null;

    public static function setConfig(Config $cfg): void
    {
        self::$cfgRef = $cfg;
    }

    public static function config(): ?Config
    {
        return self::$cfgRef;
    }

    public static function resetResponse(): void
    {
        self::$sentStatus = 200;
        self::$sentHeaders = [];
    }

    public static function sentStatus(): int
    {
        return self::$sentStatus;
    }

    /** 取最后发出的那个值; 没发过返回空串。 */
    public static function sentHeader(string $name): string
    {
        $list = self::$sentHeaders[strtolower($name)] ?? [];

        return $list === [] ? '' : (string) $list[count($list) - 1];
    }

    public static function sentHeaders(): array
    {
        return self::$sentHeaders;
    }

    /**
     * 只读原始 REQUEST_URI, 并且**绝不对整段 urldecode**。
     *
     * objects.githubusercontent.com 的签名参数里含 %2B/%2F/%3D, 解码再编码就 403
     * SignatureDoesNotMatch。path 与 query 必须原样切成两段各自保留。
     */
    public static function capture(Config $cfg): array
    {
        if (self::$capture !== null) {
            return self::$capture;
        }

        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $pos = strpos($uri, '?');
        $rawPath = $pos === false ? $uri : substr($uri, 0, $pos);
        $rawQuery = $pos === false ? '' : substr($uri, $pos + 1);

        $headers = self::requestHeaders();
        $ua = (string) ($headers['user-agent'] ?? '');

        return self::$capture = [
            'method'              => strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')),
            'raw_path'            => $rawPath,
            'raw_query'           => $rawQuery,
            'client_ip'           => self::resolveClientIp($cfg, $headers),
            'ua'                  => $ua,
            'accept'              => (string) ($headers['accept'] ?? ''),
            'range'               => (string) ($headers['range'] ?? ''),
            'if_none_match'       => (string) ($headers['if-none-match'] ?? ''),
            'if_modified_since'   => (string) ($headers['if-modified-since'] ?? ''),
            'referer'             => (string) ($headers['referer'] ?? ''),
            'origin'              => (string) ($headers['origin'] ?? ''),
            'sec_fetch_site'      => (string) ($headers['sec-fetch-site'] ?? ''),
            'is_https'            => self::isHttps($cfg, $headers),
            'headers'             => $headers,
            'want_json'           => self::wantsJson($headers),
            'is_agent'            => self::isAgent($ua, $headers),
            'raw_post'            => (string) (file_get_contents('php://input') ?: ''),
        ];
    }

    /**
     * 小写键的请求头。
     *
     * 优先 getallheaders(), 它在 fpm 下最完整；但 php-cgi 与内置服务器可能没有这个函数,
     * 所以必须能从 $_SERVER 的 HTTP_* 重建, 否则面板的 Origin/Sec-Fetch-Site 校验会因为
     * "读不到头"而永远放行 —— 那是最坏的失败方向(静默通过而不是静默失败)。
     */
    private static function requestHeaders(): array
    {
        $out = [];
        if (function_exists('getallheaders')) {
            foreach ((array) getallheaders() as $k => $v) {
                $out[strtolower((string) $k)] = is_array($v) ? implode(',', $v) : (string) $v;
            }
        }
        foreach ($_SERVER as $k => $v) {
            if (!is_string($k) || !str_starts_with($k, 'HTTP_')) {
                continue;
            }
            $name = strtolower(str_replace('_', '-', substr($k, 5)));
            if (!isset($out[$name])) {
                $out[$name] = (string) $v;
            }
        }
        // 这两个不在 HTTP_* 里
        foreach (['CONTENT_TYPE' => 'content-type', 'CONTENT_LENGTH' => 'content-length'] as $k => $name) {
            if (isset($_SERVER[$k]) && !isset($out[$name])) {
                $out[$name] = (string) $_SERVER[$k];
            }
        }

        return $out;
    }

    public static function headerLine(string $name): string
    {
        $cap = self::$capture ?? [];

        return (string) (($cap['headers'] ?? [])[$name] ?? '');
    }

    /**
     * 客户端 IP。只有显式信任代理时才认 X-Forwarded-Proto / X-Forwarded-For,
     * 否则这两个头可由调用方伪造, 既污染限流桶也骗过 HTTPS 判定。
     */
    private static function resolveClientIp(Config $cfg, array $headers): string
    {
        $remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
        if (!$cfg->bool('security.trust_proxy_headers', false)) {
            return $remote;
        }
        $trusted = $cfg->arr('security.trusted_proxies', []);
        if ($trusted !== [] && !self::ipInCidrs($remote, $trusted)) {
            return $remote;
        }
        $xff = (string) ($headers['x-forwarded-for'] ?? '');
        if ($xff === '') {
            return $remote;
        }
        $first = trim(explode(',', $xff)[0]);

        return filter_var($first, FILTER_VALIDATE_IP) ? $first : $remote;
    }

    private static function ipInCidrs(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if (!str_contains((string) $cidr, '/')) {
                if ((string) $cidr === $ip) {
                    return true;
                }
                continue;
            }
            [$sub, $bits] = explode('/', (string) $cidr, 2);
            $binIp = @inet_pton($ip);
            $binSub = @inet_pton($sub);
            if ($binIp === false || $binSub === false || strlen($binIp) !== strlen($binSub)) {
                continue;
            }
            $bits = (int) $bits;
            $full = intdiv($bits, 8);
            if ($full > 0 && substr($binIp, 0, $full) !== substr($binSub, 0, $full)) {
                continue;
            }
            $rem = $bits % 8;
            if ($rem > 0) {
                $mask = chr((0xFF << (8 - $rem)) & 0xFF);
                if ((ord($binIp[$full]) & ord($mask)) !== (ord($binSub[$full]) & ord($mask))) {
                    continue;
                }
            }

            return true;
        }

        return false;
    }

    private static function isHttps(Config $cfg, array $headers): bool
    {
        $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
        if ($https) {
            return true;
        }
        if (!$cfg->bool('security.trust_proxy_headers', false)) {
            return false;
        }
        // 宝塔常见 "nginx 443 终结 -> 上游 80": PHP 看到 HTTPS 为空, 但浏览器其实在 https。
        return strtolower((string) ($headers['x-forwarded-proto'] ?? '')) === 'https';
    }

    /** Range 请求一定要 JSON, 见 Dispatcher/Failover 的注释: 否则 aria2 会把 HTML 写进分片。 */
    private static function wantsJson(array $headers): bool
    {
        $accept = strtolower((string) ($headers['accept'] ?? ''));
        $xrw = strtolower((string) ($headers['x-requested-with'] ?? ''));

        return str_contains($accept, 'application/json')
            || str_contains($accept, 'application/problem+json')
            || $xrw === 'xmlhttprequest'
            || isset($_GET['json']);
    }

    /**
     * Agent 判定: 宁可多判成 Agent(错误体更结构化、超时更可预测), 也不要少判。
     * 少判的代价是工具拿到一段 HTML 然后开始猜。
     */
    private static function isAgent(string $ua, array $headers): bool
    {
        if (isset($_GET['agent']) || ($headers['x-ghaccel-agent'] ?? '') !== '') {
            return true;
        }
        $low = strtolower($ua);
        foreach (['curl/', 'wget/', 'aria2/', 'python-requests', 'aiohttp', 'go-http-client',
                 'node-fetch', 'undici', 'okhttp', 'httpie', 'libdownload', 'unity', 'opencode',
                 'claude', 'qoder', 'agent', 'gptbot', 'cargo', 'pip/', 'npm/', 'gem ', 'packrat'] as $t) {
            if ($t !== '' && str_contains($low, $t)) {
                return true;
            }
        }

        return false;
    }

    public static function method(): string
    {
        return strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    }

    public static function clientIp(): string
    {
        return (string) ((self::$capture ?? [])['client_ip'] ?? ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'));
    }

    /**
     * 请求级唯一 id。ULID 风格: 40 位 hex, 前 16 位是毫秒时间戳, 后 24 位随机。
     * 带时间前缀是为了运维能一眼看出发生时间, 而不用去查日志。
     */
    public static function requestId(): string
    {
        if (self::$requestId !== null) {
            return self::$requestId;
        }
        $ms = (int) (microtime(true) * 1000);

        return self::$requestId = str_pad(dechex($ms), 16, '0', STR_PAD_LEFT) . bin2hex(random_bytes(12));
    }

    /**
     * 关掉所有会破坏流式的缓冲。
     *
     * 必须显式关 zlib.output_compression: 它开启后 PHP 会重新分块, 于是 Content-Length
     * 与实际字节不符 —— Range 切片、?sha256= 流式校验、aria2 断点续传三件事同时坏,
     * 而且症状分散、极难归因到这一个 ini 开关上。
     */
    public static function noBuffering(): void
    {
        if (self::$bufferingCleared) {
            return;
        }
        self::$bufferingCleared = true;

        while (ob_get_level() > 0) {
            // ob_end_clean() 成功返回 true; 某些 SAPI 会拒绝关闭最后一层, 那时必须跳出,
            // 否则会死循环。写反这个条件会让缓冲区只清掉一层, 症状是大文件仍然被整块缓冲。
            if (@ob_end_clean() === false) {
                break;
            }
        }
        @ini_set('zlib.output_compression', 'Off');
        @ini_set('output_buffering', 'Off');
        @ini_set('implicit_flush', '1');
    }

    /**
     * 输出目标句柄。
     *
     * php://output 而非 php://stdout: 后者在 fpm 下不是响应流, 用它会让所有字节都丢掉。
     */
    public static function out()
    {
        $h = fopen('php://output', 'wb');

        return $h === false ? STDOUT : $h;
    }

    public static function flush(): void
    {
        @flush();
    }

    public static function status(int $code): void
    {
        self::$sentStatus = $code;
        if (!headers_sent()) {
            http_response_code($code);
        }
    }

    public static function header(string $name, string $value, bool $replace = true): void
    {
        // 拒绝任何换行, 否则一个可控响应头值就成了响应头注入(进而成 XSS / 缓存投毒)。
        $clean = str_replace(["\r", "\n", "\0"], '', $value);
        $low = strtolower($name);
        if ($replace) {
            self::$sentHeaders[$low] = [$clean];
        } else {
            self::$sentHeaders[$low][] = $clean;
        }
        if (headers_sent()) {
            return;
        }
        header($name . ': ' . $clean, $replace);
    }

    public static function headersSent(): bool
    {
        return headers_sent();
    }

    public static function json(mixed $data, int $status = 200, array $headers = []): void
    {
        self::status($status);
        self::header('Content-Type', 'application/json; charset=utf-8');
        foreach ($headers as $k => $v) {
            if ($v !== null && $v !== '') {
                self::header((string) $k, (string) $v);
            }
        }
        echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
    }

    /** application/problem+json: Agent 需要它, 也要 Retry-After 与 X-RateLimit-* 在同一处。 */
    public static function problem(array $problem, array $headers = []): void
    {
        $status = (int) ($problem['status'] ?? 500);
        self::status($status);
        self::header('Content-Type', 'application/problem+json; charset=utf-8');
        self::header('Cache-Control', 'no-store');
        foreach ($headers as $k => $v) {
            if ($v !== null && $v !== '') {
                self::header((string) $k, (string) $v);
            }
        }
        echo json_encode($problem, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
    }

    public static function html(string $body, int $status = 200, array $headers = []): void
    {
        self::status($status);
        self::header('Content-Type', 'text/html; charset=utf-8');
        foreach ($headers as $k => $v) {
            if ($v !== null && $v !== '') {
                self::header((string) $k, (string) $v);
            }
        }
        echo $body;
    }

    /**
     * 纯文本响应。PHP 版本过低这类致命前置失败走这里 —— 白屏错误页会让人以为站点挂了,
     * 而一行明文会直接告诉部署者该装哪个版本。
     */
    public static function text(string $body, int $status = 200): void
    {
        self::status($status);
        self::header('Content-Type', 'text/plain; charset=utf-8');
        self::header('Cache-Control', 'no-store');
        echo $body;
    }

    public static function redirect(string $url, int $status = 302, array $headers = []): void
    {
        self::status($status);
        self::header('Location', str_replace(["\r", "\n"], '', $url));
        self::header('Cache-Control', 'no-store');
        foreach ($headers as $k => $v) {
            if ($v !== null && $v !== '') {
                self::header((string) $k, (string) $v);
            }
        }
    }

    public static function query(string $name, mixed $default = null): mixed
    {
        return $_GET[$name] ?? $default;
    }

    public static function queryStr(string $name): string
    {
        $v = $_GET[$name] ?? '';

        return is_scalar($v) ? (string) $v : '';
    }

    /** 提前断开客户端再收尾写观测, 否则用户要等我们的记账跑完才看到下载结束。 */
    public static function finishRequestEarly(): void
    {
        if (function_exists('fastcgi_finish_request')) {
            @fastcgi_finish_request();
        }
    }

    public static function reset(): void
    {
        self::$capture = null;
        self::$requestId = null;
        self::resetResponse();
    }
}
