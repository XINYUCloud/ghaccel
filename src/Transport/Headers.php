<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 响应/请求头的白名单透传、剥离与注入清单, Range 与 416/304 的头语义,
 *             Content-Disposition 的安全生成, OPTIONS 预检。状态码与"要不要发头"的
 *             时机由 Streamer 决定, 本类只负责头的**内容**正确。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Transport;

use GhAccel\Bootstrap;
use GhAccel\Cache\Policy;
use GhAccel\Config;
use GhAccel\Enum\Scene;
use GhAccel\Http;
use GhAccel\Ref\GitHubRef;
use GhAccel\Source\Source;

/**
 * 三个设计前提, 改本文件前请先读:
 *
 *  1. 白名单而不是黑名单。上游会回什么头不受我们控制(镜像自己加 X-Cache、Via、真实域名
 *     的 Location、甚至内部调试头), 只有列出的才透传, 其余一律丢 —— 黑名单永远少一条。
 *  2. ETag 必须自造。透传上游 ETag 后一旦换源, 客户端拿旧 ETag 来做 If-None-Match 会
 *     撞上不同源的另一个 tag, 于是永远 200 全量重下; 反过来用我们的 "gha-<key>-<variant>"
 *     就和取回它的是哪个源彻底无关。
 *  3. 绝不手工发 Transfer-Encoding。分块与否由 SAPI 决定, 自己发一次就是双重分块或
 *     协议错误, 而 aria2 会把它记成"这个源坏了"。
 */
final class Headers
{
    /** 透传白名单(小写)。content-encoding 只在未被本地解压时才透传, 见 response()。 */
    public const PASSTHROUGH = [
        'content-type',
        'content-length',
        'content-range',
        'accept-ranges',
        'etag',
        'last-modified',
        'cache-control',
        'content-disposition',
        'content-encoding',
    ];

    /** API 场景额外保留: Agent 依赖配额与分页头做决策, 剥掉就等于让脚本瞎跑。 */
    public const API_KEEP = [
        'x-ratelimit-limit',
        'x-ratelimit-remaining',
        'x-ratelimit-reset',
        'x-ratelimit-resource',
        'link',
    ];

    /**
     * 明确剥离(白名单之外仍有一批"看着像该透传其实必须剥"的)。列出来是为了可断言,
     * 而不是为了让黑名单生效 —— 生效的是白名单本身。
     */
    public const STRIP = [
        'set-cookie',
        'location',
        'connection',
        'keep-alive',
        'transfer-encoding',
        'upgrade',
        'server',
        'x-request-id',
        'x-github-request-id',
        'via',
        'x-cache',
        'x-powered-by',
        'x-frame-options',
        'content-security-policy',
        'strict-transport-security',
        'report-to',
        'nel',
    ];

    /** 请求方向必须剥掉的客户端头。小写。 */
    public const REQ_STRIP = [
        'cookie',
        'authorization',
        'proxy-authorization',
        'referer',
        'host',
        'accept-encoding',
        'x-forwarded-for',
        'x-forwarded-proto',
        'x-forwarded-host',
        'x-real-ip',
        'front-end-https',
        'connection',
        'keep-alive',
        'te',
        'trailer',
        'upgrade',
        'transfer-encoding',
        'range',
        'if-none-match',
        'if-modified-since',
        'if-range',
    ];

    public function __construct(
        private readonly Config $cfg,
        private readonly Policy $policy
    ) {
    }

    /** 单值安全化: 剥 CR/LF/NUL。任何来自上游或用户文件名的值拼进头之前都要过这一关。 */
    public static function sanitize(string $value): string
    {
        return trim(str_replace(["\r", "\n", "\0"], '', $value));
    }

    /** 上游头归一化: 输入可以是 "Name: value" 行列表或已解析的 map, 输出小写键 map。 */
    public function normalize(array $raw): array
    {
        $out = [];
        foreach ($raw as $k => $v) {
            if (is_int($k) && is_string($v)) {
                // HTTP 状态行与空行不进入 map: 状态由 curl_getinfo 给, 不靠解析状态行。
                if (preg_match('#\AHTTP/[0-9.]+\s+\d#i', $v) === 1 || !str_contains($v, ':')) {
                    continue;
                }
                [$name, $value] = explode(':', $v, 2);
                $k = strtolower(trim($name));
                $v = trim($value);
            } elseif (is_string($k)) {
                $k = strtolower($k);
                $v = is_array($v) ? implode(', ', array_map('strval', $v)) : (string) $v;
            } else {
                continue;
            }
            if ($k === '') {
                continue;
            }
            // 同名多值(罕见的多个 Link)合并, 因为我们的 emit 走单值 header()。
            $out[$k] = isset($out[$k]) ? $out[$k] . ', ' . trim($v) : trim($v);
        }

        return $out;
    }

    // ------------------------------------------------------------------
    // 请求方向
    // ------------------------------------------------------------------

    /**
     * 生成发给上游/镜像的 curl HTTPHEADER 行。
     *
     * $opts: method / range / upstream_etag / api(bool) / client_headers(map)
     *
     * 关键取舍:
     *  - Accept-Encoding 在流式场景强制 identity。镜像 gzip 之后我们再透传给客户端就会
     *    与实际字节不符, 而 sha256 流式校验、Range 续传、EDGE 落地三处都按原始字节算。
     *    只有 API JSON 才允许 gzip(体积小、整段解析, 不存在切片问题)。
     *  - 客户端的 If-None-Match 绝不当作对上游的条件头: 那会让上游替我们决定 304,
     *    而我们的缓存与它的 ETag 根本不是同一套(见类注释第 2 条)。只有 stale revalidate
     *    才带上一次**存下来的上游** ETag。
     *  - Authorization/Cookie 默认不转发: 转发用户的 GitHub token 给第三方镜像等于把
     *    凭据交给陌生人。自建源可以在配置里显式打开。
     *
     * @return list<string>
     */
    public function requestLines(GitHubRef $ref, array $opts = []): array
    {
        $method = strtoupper((string) ($opts['method'] ?? 'GET'));
        $api = ($opts['api'] ?? null) === true || $ref->scene === Scene::ApiJson;
        $client = $this->normalize((array) ($opts['client_headers'] ?? []));
        $allowToken = $this->cfg->bool('security.forward_client_token', false);

        $lines = [];
        $skip = self::REQ_STRIP;
        if ($allowToken) {
            $skip = array_values(array_diff($skip, ['authorization', 'cookie']));
        }
        foreach ($client as $name => $value) {
            if (in_array($name, $skip, true) || $value === '') {
                continue;
            }
            // 客户端自定义头只在 API 场景保留(带 Accept 之外的 GitHub 版本头有意义);
            // 字节流场景保留任何客户端头都只可能泄露用户环境。
            if (!$api && !in_array($name, ['accept', 'accept-language', 'priority'], true)) {
                continue;
            }
            $lines[] = self::restoreCase($name) . ': ' . self::sanitize($value);
        }

        $lines[] = 'User-Agent: ' . self::sanitize($this->userAgent());
        // 一律 identity, 连 API 场景也不 gzip: 本机没有解压(不设 CURLOPT_ENCODING), 若上游
        // 回了 gzip 而我们的白名单/长度对账按明文写, 就会出现"头说明白、体是压缩"的错位。
        // 让字节与头自始至终是同一份东西, 比省几十 KB 重要(zstd/brotli 透传在 v2 再谈)。
        $lines[] = 'Accept-Encoding: identity';
        $lines[] = 'Connection: keep-alive';

        // 客户端的 Range 一律逐字节原样转发, 不看 allowRange: "透传原则, 不许自创"。
        // allowRange=false 约束的是**我们自己**发起的 Range(探测、续传、EDGE 切片)以及
        // 是否向客户端注入 Accept-Ranges, 而不是把用户写好的请求头改掉 —— 后者会让
        // "上游到底支不支持"这个问题永远测不出来。
        $range = self::sanitize((string) ($opts['range'] ?? ''));
        if ($range !== '') {
            $lines[] = 'Range: ' . $range;
        }

        $etag = self::sanitize((string) ($opts['upstream_etag'] ?? ''));
        if ($etag !== '') {
            $lines[] = 'If-None-Match: ' . $etag;
        }
        $lm = self::sanitize((string) ($opts['upstream_last_modified'] ?? ''));
        if ($lm !== '' && $etag === '') {
            $lines[] = 'If-Modified-Since: ' . $lm;
        }
        if ($method === 'HEAD') {
            $lines[] = 'X-GhAccel-Head: 1';
        }

        return $lines;
    }

    private static function restoreCase(string $lower): string
    {
        return implode('-', array_map(
            static fn (string $p): string => $p === '' ? '' : strtoupper($p[0]) . substr($p, 1),
            explode('-', $lower)
        ));
    }

    /**
     * 发往 GitHub / 镜像的 User-Agent。
     *
     * app.user_agent 非空时按显式值原样使用(部署者可能要伪装成自家产品名); 为空时由
     * app.repo_url 与 app.contact 现组合。之所以不直接把 URL 抄进 user_agent 默认值:
     * 同一个地址写在两处必然漂移, 而漂移后的产物就是原先那句半截的
     * "GhAccel/1.0 (+https://github.com; contact=)" —— 看着像来源, 实际解析不到任何东西。
     * GitHub 对匿名 API 请求明确希望 UA 带可解析的出处, 版本号也取自 Bootstrap::VERSION,
     * 免得发版后 UA 里还写着旧版本。
     */
    private function userAgent(): string
    {
        $explicit = trim($this->cfg->str('app.user_agent', ''));
        if ($explicit !== '') {
            return $explicit;
        }

        $ua = 'GhAccel/' . Bootstrap::VERSION;
        $bits = [];
        $repo = trim($this->cfg->str('app.repo_url', ''));
        if ($repo !== '' && preg_match('#\Ahttps://[a-z0-9.\-]+(/[^\s;]*)?\z#i', $repo) === 1) {
            $bits[] = '+' . rtrim($repo, '/');
        }
        $contact = trim($this->cfg->str('app.contact', ''));
        if ($contact !== '') {
            $bits[] = 'contact=' . $contact;
        }
        if ($bits !== []) {
            $ua .= ' (' . implode('; ', $bits) . ')';
        }

        return $ua;
    }

    // ------------------------------------------------------------------
    // 响应方向
    // ------------------------------------------------------------------

    /**
     * 由上游响应头生成要发给客户端的头。返回 [小写头名 => 值], 键在 emit 时还原大小写。
     *
     * $opts 见方法内注释。绝不在此处做字节切片或伪造 206 —— 上游已经是 CDN,
     * 自己切片只会引入偏差与内存, 而"伪造的 206"会让客户端写出一份偏移错位的文件。
     */
    public function response(GitHubRef $ref, ?Source $src, int $status, array $upstream, array $opts = []): array
    {
        $up = $this->normalize($upstream);
        $multipart = str_contains(strtolower($up['content-type'] ?? ''), 'multipart/byteranges');
        $is206 = $status === 206;
        $is304 = $status === 304;
        $rangeRequested = (bool) ($opts['range_requested'] ?? false);
        // 实测能力优先于配置声称: 出厂源表的 caps 全是 false, 只有 Streamer 的实测能纠正它。
        $rangeSupported = (bool) ($opts['range_supported'] ?? $ref->allowRange);
        $corsPublic = (bool) ($opts['cors'] ?? ($this->cfg->str('app.exposure', 'private') === 'public'));
        $diag = (array) ($opts['diag'] ?? []);
        $diagVisible = (bool) ($opts['diag_visible'] ?? false);

        $keep = self::PASSTHROUGH;
        if ($ref->scene === Scene::ApiJson) {
            $keep = array_merge($keep, self::API_KEEP);
        }

        $out = [];
        foreach ($up as $name => $value) {
            if (!in_array($name, $keep, true) || $value === '') {
                continue;
            }
            if ($name === 'content-encoding' && str_contains($value, 'gzip')) {
                // curl 已经解压过(我们没设 ACCEPT_ENCODING: gzip 时上游不该回 gzip; 回了就是
                // 镜像无视 identity)。此时字节与 Content-Encoding 不再对应, 必须连长度一起丢。
                continue;
            }
            $out[$name] = self::sanitize($value);
        }

        if ($is304) {
            // 304 的响应体必须为空, 所以任何描述"体"的头都是错的。
            $out = array_intersect_key($out, array_flip(['etag', 'last-modified', 'cache-control']));
            if (!isset($out['cache-control'])) {
                // 上游不给 Cache-Control 时也必须带一个: 没有它, 共享缓存与浏览器会按
                // 各自默认策略处理这次"未变", 304 的可缓存性就成了不确定的事。
                $out['cache-control'] = $this->cacheControlFor($ref, $src, $opts);
            }
        } else {
            if (!isset($out['cache-control'])) {
                $out['cache-control'] = $this->cacheControlFor($ref, $src, $opts);
            }
            if ($is206 && !$multipart) {
                // 206 保留原文件的 Content-Type; 只有 multipart 时必须原样透传上游那个带
                // boundary 的 Content-Type, 改写它等于让客户端解析不出分片边界。
                if (isset($up['content-type']) && stripos($up['content-type'], 'multipart/') !== 0) {
                    $out['content-type'] = self::sanitize($up['content-type']);
                }
            }
            if ($rangeSupported) {
                if (!isset($out['accept-ranges'])) {
                    // 不注入 Accept-Ranges, aria2/IDM 根本不会发起并发分片 —— 这一条不影响
                    // 单次下载成败, 所以极容易漏, 但对国内用户体感差别是数量级的。
                    $out['accept-ranges'] = 'bytes';
                }
            } else {
                // 判定为不支持 Range 时, 连**上游自己声明的** Accept-Ranges 也要丢。
                // 实测 codeload 一边回 Accept-Ranges: bytes 一边对 bytes=0-64 返回 200 全量:
                // 留着那句谎话, aria2 就会开 16 路并发把同一个文件拉 16 遍。
                // 这是本网关唯一主动改写上游语义的地方, 因为它改的是"能力声明"而不是内容。
                unset($out['accept-ranges']);
            }
        }

        // 自造 ETag: 只在能标识"这份完整内容"时给。206 也带同一个 tag 是合法的
        // (RFC 9110: ETag 标识当前表示), 客户端拿它做 If-Range 才能安全续传。
        $ours = (string) ($opts['etag'] ?? '');
        if ($ours !== '') {
            $out['etag'] = $ours;
        }

        // Content-Length 与 Content-Range 冲突就丢长度; 上游 chunked 无长度也不补 ——
        // 补一个错的长度比不给长度破坏性大得多(客户端会按错误长度截断或挂住等剩余字节)。
        if ($is206 && isset($out['content-range'], $out['content-length'])) {
            $expect = self::lengthFromRange($out['content-range']);
            if ($expect === null || $expect !== (int) $out['content-length']) {
                unset($out['content-length']);
            }
        }
        if (isset($opts['content_length']) && (int) $opts['content_length'] > 0) {
            $out['content-length'] = (string) (int) $opts['content_length'];
        }
        if ($is304 || $status === 204) {
            unset($out['content-length'], $out['content-type'], $out['content-disposition']);
        }

        // 客户端要 Range、上游回 200 全量(实测归档就是这样): 如实透传 200 并标注不支持,
        // 让调用方与用户都能看见"分片没有生效"而不是以为分片成功了。
        if ($rangeRequested && $status === 200) {
            $out['x-ghaccel-range'] = 'unsupported';
        }
        if ($rangeRequested && $is206 && $rangeSupported === false) {
            $out['x-ghaccel-range'] = 'unexpected';
        }

        // Content-Disposition: 上游给的就是权威(资产名可能含空格与 Unicode, GitHub 已经
        // 按 RFC 5987 编码好了), 只有二进制场景且上游没给时才用 ref 里的下载名兜底。
        if (!$is304 && $ref->scene->isBinaryStream()) {
            if (isset($out['content-disposition'])) {
                $out['content-disposition'] = self::sanitize($out['content-disposition']);
            } else {
                $name = (string) ($opts['download_name'] ?? $ref->downloadName);
                if ($name !== '') {
                    $out['content-disposition'] = self::disposition($name);
                }
            }
        }

        if ($corsPublic) {
            foreach ($this->cors() as $k => $v) {
                $out[$k] = $v;
            }
        }

        // 诊断头只在 ?debug=1 且已登录管理员会话时才出。否则等于把整份镜像池、命中状态
        // 与决策结果公开给扫描器和竞品。
        if ($diagVisible && $diag !== []) {
            foreach ($diag as $key => $value) {
                $value = self::sanitize((string) $value);
                if ($value === '') {
                    continue;
                }
                $out['x-ghaccel-' . strtolower((string) $key)] = $value;
            }
        }
        $out['x-ghaccel-request-id'] = Http::requestId();

        ksort($out);

        return $out;
    }

    /** 真正发头。必须在任何 body 字节之前调用; 一旦调用过, 回退就不可能了。 */
    public function emit(int $status, array $headers): void
    {
        Http::status($status);
        foreach ($headers as $name => $value) {
            if ($value === '' || $value === null) {
                continue;
            }
            Http::header(self::restoreCase((string) $name), self::sanitize((string) $value), true);
        }
    }

    /**
     * 错误响应(429/413/503/404/416)的头。Range 请求也必须走这里而不是 HTML 错误页 ——
     * aria2 会把任何 200 的 HTML 当成一个分片写进文件, 产出一个静默损坏的产物。
     */
    public function errorHeaders(int $status, array $extra = []): array
    {
        $out = [
            'content-type'  => 'application/problem+json; charset=utf-8',
            'cache-control' => 'no-store',
            'x-ghaccel-request-id' => Http::requestId(),
        ];
        foreach ($extra as $k => $v) {
            if ($v === '' || $v === null) {
                continue;
            }
            $out[strtolower((string) $k)] = self::sanitize((string) $v);
        }
        if ($this->cfg->str('app.exposure', 'private') === 'public') {
            foreach ($this->cors() as $k => $v) {
                $out[$k] = $v;
            }
        }

        return $out;
    }

    /** 416: 已知总体积时本地即可判定, 不必再打下游。Content-Range 必须给 */
    public function rangeUnsatisfiable(int $total): array
    {
        return [
            'status'  => 416,
            'headers' => $this->errorHeaders(416, [
                'content-range' => 'bytes */' . max(0, $total),
                'accept-ranges' => 'bytes',
            ]),
        ];
    }

    /** CORS 三件套。Expose-Headers 少了 Content-Range 的话浏览器端的 JS 分片下载读不到区间。 */
    public function cors(): array
    {
        return [
            'access-control-allow-origin'  => '*',
            'access-control-allow-methods' => 'GET, HEAD, OPTIONS',
            'access-control-allow-headers' => 'Range, If-Range, If-None-Match, Accept, Accept-Encoding, User-Agent',
            'access-control-expose-headers' => implode(', ', [
                'Content-Range', 'Accept-Ranges', 'Content-Length', 'Content-Type', 'Content-Disposition',
                'ETag', 'Last-Modified', 'Cache-Control',
                'X-GhAccel-Request-Id', 'X-GhAccel-Mode', 'X-GhAccel-Source', 'X-GhAccel-Cache',
                'X-GhAccel-Range', 'X-GhAccel-Decided-By', 'X-RateLimit-Limit', 'X-RateLimit-Remaining',
            ]),
            'access-control-max-age' => '600',
        ];
    }

    /**
     * OPTIONS 预检: 直接 204 + CORS, **绝不进代理逻辑**。
     * 预检请求不带 Range, 也过不了 UrlGuard 的 method 检查, 更不该消耗一次上游往返与配额。
     */
    public function preflight(): array
    {
        $headers = $this->cors();
        $headers['content-length'] = '0';
        $headers['x-ghaccel-request-id'] = Http::requestId();

        return ['status' => 204, 'headers' => $headers];
    }

    /** Cache-Control 由 Policy 的 TTL 决定; API 场景一律 no-store(v1 不缓存 JSON)。 */
    public function cacheControlFor(GitHubRef $ref, ?Source $src, array $opts = []): string
    {
        if ($ref->scene === Scene::ApiJson || !$ref->cacheEligible()) {
            return 'no-store';
        }
        $mayCache = $src === null ? $ref->cacheEligible() : $this->policy->mayCache($ref, $src, max(1, $ref->sizeHint));
        if (!$mayCache) {
            return 'private, no-store';
        }
        $ttl = $this->policy->ttlFor($ref);
        if ($ttl['immutable']) {
            return 'public, max-age=' . max(1, $ttl['fresh']) . ', immutable';
        }

        return 'public, max-age=' . max(1, $ttl['fresh'])
            . ($ttl['stale'] > 0 ? ', stale-while-revalidate=' . $ttl['stale'] : '');
    }

    /**
     * Content-Disposition 的安全生成。
     *
     * 非 ASCII 文件名必须走 RFC 5987 的 filename*=UTF-8'' 形式: 只给 filename="中文.zip"
     * 在不同浏览器上会被按本地代码页解释成乱码。同时先剥 CR/LF 与路径分隔符 —— 这个值
     * 来自用户可控的 URL 尾段, 少剥一个 \r\n 就是一个响应头注入。
     */
    public static function disposition(string $name, string $kind = 'attachment'): string
    {
        $name = self::sanitize($name);
        $name = str_replace(['/', '\\', '"', "\x00"], '', $name);
        $name = trim($name, " \t.");
        if ($name === '' || $name === '.' || $name === '..') {
            $name = 'download';
        }
        if (strlen($name) > 200) {
            $name = substr($name, 0, 200);
        }

        $ascii = preg_replace('/[^\x20-\x7E]/', '', $name) ?? '';
        $ascii = trim(str_replace(['"', '\\'], '', $ascii), ' ');
        if ($ascii === '') {
            $ascii = 'download';
        }

        $out = $kind . '; filename="' . $ascii . '"';
        if ($ascii !== $name) {
            $out .= "; filename*=UTF-8''" . rawurlencode($name);
        }

        return $out;
    }

    /** Content-Range: bytes 0-99/12345 -> 100; 解析不出来返回 null(交调用方丢长度)。 */
    public static function lengthFromRange(string $contentRange): ?int
    {
        if (preg_match('#bytes\s+(\d+)-(\d+)/(\d+|\*)#i', $contentRange, $m) !== 1) {
            return null;
        }
        $start = (int) $m[1];
        $end = (int) $m[2];
        if ($end < $start) {
            return null;
        }
        $len = $end - $start + 1;
        if ($m[3] !== '*' && $len > (int) $m[3]) {
            return null;
        }

        return $len;
    }

    /** 从 Content-Range 解出总体积, "*" 时返回 0(未知)。 */
    public static function totalFromRange(string $contentRange): int
    {
        return preg_match('#bytes\s+\d+-\d+/(\d+)#i', $contentRange, $m) === 1 ? (int) $m[1] : 0;
    }
}
