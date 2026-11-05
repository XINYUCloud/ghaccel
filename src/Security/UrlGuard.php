<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 本项目的安全边界本体 —— "按用户给的 URL 去请求上游"这件事的全部校验:
 *             SSRF 判定链、逐跳复校、CURLOPT_RESOLVE 钉 IP。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Security;

use GhAccel\Config;
use GhAccel\Errors\GhpError;

/**
 * 判定链的顺序即防线, 任一步失败立即抛出, 绝不"降级放行"把原串交给 curl。
 *
 * 三条来自实测的原则, 改动前请先复现:
 *  1. 反斜杠前置拒绝。parse_url("https://evil.com\\@github.com") 得到 host=github.com,
 *     而 WHATWG 与部分 curl 版本把 '\' 当 '/', 于是它们看到的是 evil.com ——
 *     解析器分歧本身就是绕过, 与谁更"正确"无关。
 *  2. userinfo 一刀切。含 '@' 的 authority 一律拒, 这一条同时消灭 `\@`、`%40`、
 *     `user:pass@`、`#@` 整个分歧家族, 而本项目从不需要在 URL 里带凭据。
 *  3. v1 只做精确 host 集合。endswith/str_contains 会被 github.com.evil.com 与
 *     notgithub.com 双双绕过, 而 GitHub 侧域名有限可枚举, 后缀匹配没有收益只有风险。
 */
final class UrlGuard
{
    /** host 中一个都不允许出现的字符: 分隔、凭据、编码、空白与控制符。 */
    private const ILLEGAL_HOST_CHARS = "%:/@#?\"<> \t\r\n\\[]'";

    /** LDH + 至少一个点。这一条同时消灭非 ASCII 同形字、单标签、IPv6 字面量、以及
     *  2130706433 / 0x7f000001 / 0177.0.0.1 / 127.1 / 127 这类数字写法。 */
    private const LDH = '/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+$/';

    /** @var array<string,true> */
    private array $allowed = [];

    /** @var array<string,true> */
    private array $denied = [];

    private int $maxUrlLen;

    private int $maxHops;

    /** @var array<int,string> */
    private array $extraDeny;

    /** 自身 host 与面板前缀, 来自 app.base_origin + panel.path_prefix, 用于识别指回本机。 */
    private string $ownHost = '';

    private string $ownPath = '/';

    /** @var array<int,string> 自身入口前缀(相对 Location 也要能判出来) */
    private array $ownEntryPrefixes;

    public function __construct(private readonly Config $cfg)
    {
        foreach ((array) $cfg->arr('security.allowed_hosts') as $h) {
            $h = strtolower(trim((string) $h));
            if ($h !== '') {
                $this->allowed[$h] = true;
            }
        }
        foreach ((array) $cfg->arr('security.denied_hosts') as $h) {
            $h = strtolower(trim((string) $h));
            if ($h !== '') {
                $this->denied[$h] = true;
            }
        }

        $this->maxUrlLen = (int) $cfg->int('security.max_url_len', $cfg->int('routing.max_url_len', 4096));
        $this->maxHops = max(0, (int) $cfg->int('security.max_redirect_hops', 3));
        $this->extraDeny = array_values(array_filter(
            (array) $cfg->arr('security.extra_deny_cidrs'),
            static fn ($v): bool => is_string($v) && trim($v) !== ''
        ));

        $origin = trim((string) $cfg->str('app.base_origin'));
        if ($origin !== '') {
            $parts = parse_url($origin);
            if (is_array($parts) && isset($parts['host'])) {
                $this->ownHost = strtolower((string) $parts['host']);
                $p = trim((string) ($parts['path'] ?? ''), '/');
                // base_origin 只写到站点根时, 用面板前缀补上: 部署者常常只填站点根,
                // 而"自身前缀"要判的是面板与代理入口这两类路径, 少一层就把环漏了。
                $panel = trim((string) $cfg->str('panel.path_prefix', 'panel'), '/');
                $this->ownPath = $p !== '' ? '/' . $p : ($panel !== '' ? '/' . $panel : '');
            }
        }

        $prefix = trim((string) $cfg->str('panel.path_prefix', 'panel'), '/');
        $entries = ['gh', 'raw', 'release', 'latest', 'zip', 'tar', 'archive', 'api', 'gist'];
        // 绝对形式在 nginx 里长这样: /https://github.com/...; merge_slashes 折叠后是 /https:/...
        foreach (['https:/'] as $e) {
            $entries[] = rtrim($e, '/');
        }
        if ($prefix !== '') {
            array_unshift($entries, $prefix);
        }
        $this->ownEntryPrefixes = array_values(array_unique(array_filter($entries)));
    }

    /**
     * 校验一个绝对 URL 是否允许出站, 并返回钉好 IP 的 GuardResult。
     *
     * @throws GhpError 判定链上任一步失败
     */
    public function assertAllowed(string $absoluteUrl): GuardResult
    {
        $url = $this->sanitize($absoluteUrl);

        if ($url === '') {
            throw GhpError::make(GhpError::UNPARSEABLE, '空 URL');
        }
        if (strlen($url) > $this->maxUrlLen) {
            throw GhpError::make(GhpError::URL_TOO_LONG, sprintf('长度 %d 超过上限 %d', strlen($url), $this->maxUrlLen));
        }
        // 反斜杠: 见类注释第 1 条。
        if (str_contains($url, '\\')) {
            throw GhpError::make(GhpError::BACKSLASH_IN_URL, 'URL 含反斜杠');
        }

        $parts = parse_url($url);
        if (!is_array($parts)) {
            // 解析失败绝不回退成"原样交给 curl"。curl 的解析器与 PHP 的不同, 分歧即绕过。
            throw GhpError::make(GhpError::UNPARSEABLE, 'URL 无法解析');
        }
        if (!isset($parts['host']) || $parts['host'] === '') {
            throw GhpError::make(GhpError::UNPARSEABLE, 'URL 无 host');
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        if ($scheme !== 'https') {
            throw GhpError::make(GhpError::SCHEME_NOT_ALLOWED, $scheme === '' ? '缺少 scheme' : $scheme);
        }

        // userinfo: authority 段(第一个 / ? # 之前)含 '@' 即拒, 覆盖 parse_url 认出与认不出的
        // 两种情况; 路径里的 '@'(资产名常见)不受影响。
        $authority = $this->authorityOf($url);
        if (str_contains($authority, '@') || isset($parts['user']) || isset($parts['pass'])) {
            throw GhpError::make(GhpError::USERINFO_NOT_ALLOWED, 'URL 含凭据段');
        }

        $port = isset($parts['port']) ? (int) $parts['port'] : 443;
        if ($port !== 443 && $port !== 80) {
            throw GhpError::make(GhpError::PORT_NOT_ALLOWED, (string) $port);
        }

        $hostRaw = (string) $parts['host'];
        $host = strtolower($hostRaw);
        if ($hostRaw !== $host) {
            // 把 URL 里的 host 就地改成小写形式, 保证后续 RESOLVE 条目与 URL 逐字节一致。
            $url = $this->replaceAuthority($url, $host, $port);
        }

        if ($host === '' || strpbrk($host, self::ILLEGAL_HOST_CHARS) !== false) {
            throw GhpError::make(GhpError::ILLEGAL_HOST_CHARS, $host);
        }
        // 数字面量放在 LDH 之前判: 两道都拒得住, 但先判它能让 2130706433 / 127.1 /
        // 0177.0.0.1 落到 NUMERIC_HOST_LITERAL 这个语义正确的码上, 而不是含糊的
        // "host 含非法字符" —— 拒绝理由错了, 运维就查不动(诊断码也是给用户看的)。
        if (preg_match('/\A[0-9.]+\z/', $host) === 1) {
            throw GhpError::make(GhpError::NUMERIC_HOST_LITERAL, $host);
        }
        // 纯 LDH + 至少一个点: 一条规则同时消灭非 ASCII 同形字、单标签、IPv6 字面量,
        // 以及 0x7f000001 这类带字母的数字写法。
        if (preg_match(self::LDH, $host) !== 1) {
            throw GhpError::make(GhpError::ILLEGAL_HOST_CHARS, 'host 非纯 LDH 形态');
        }

        // denied 先于 allowed 生效: 即使有人误把通配或过宽的域加进 allowed 也挡得住。
        if (isset($this->denied[$host])) {
            throw GhpError::make(GhpError::HOST_NOT_ALLOWED, $host . ' 在明确拒绝名单中');
        }
        if (!isset($this->allowed[$host])) {
            throw GhpError::make(GhpError::HOST_NOT_ALLOWED, $host);
        }

        $ips = $this->resolveA($host);
        foreach ($ips as $ip) {
            // 多 IP 全部必须合格。"挑一个好的用"等于把 DNS 轮询变成绕过通道。
            if (!IpRange::isPubliclyRoutable($ip, $this->extraDeny)) {
                throw GhpError::make(GhpError::IP_DENIED, sprintf('%s 解析到受保护地址 %s', $host, $ip));
            }
        }

        $entries = [];
        foreach ($ips as $ip) {
            $entries[] = sprintf('%s:%d:%s', $host, $port, $ip);
        }

        return new GuardResult($url, $host, $ips[0] ?? '', $entries);
    }

    /**
     * 事后复核: curl 实际连接的地址必须落在本次解析出的集合里。
     *
     * 不一致意味着 DNS 重绑定或"校验用的解析器"与"连接用的解析器"不是同一个。
     * 这一条要连观测一起作废: 一次没锁住 IP 的交互, 它的耗时样本不属于这个源。
     */
    public function verifyPrimaryIp(GuardResult $r, string $primaryIp): void
    {
        $want = strtolower($primaryIp);
        foreach ($r->ips() as $ip) {
            if (hash_equals(strtolower($ip), $want)) {
                return;
            }
        }

        throw GhpError::make(GhpError::GUARD_MISMATCH, '实际连接地址与校验结果不一致');
    }

    /**
     * 逐跳复校: 把 Location 绝对化后回到判定链顶再跑同一整套。
     *
     * @return string 绝对化并规范化后的目标 URL
     * @throws GhpError 跳数超限 / 指回自身 / 判定链任一失败
     */
    public function assertRedirect(string $location, string $fromUrl, int $hop): string
    {
        return $this->assertRedirectResult($location, $fromUrl, $hop)->url;
    }

    /**
     * 同 assertRedirect, 但把 GuardResult 一起交出去。
     *
     * 存在的理由: Transport 拿到跳转目标后必须重新钉 IP, 若只拿到字符串就得再查一次 DNS,
     * 而"校验用的解析"与"连接用的解析"分成两次就是 TOCTOU。
     */
    public function assertRedirectResult(string $location, string $fromUrl, int $hop): GuardResult
    {
        if ($hop > $this->maxHops) {
            throw GhpError::make(GhpError::REDIRECT_TOO_MANY, sprintf('hop=%d limit=%d', $hop, $this->maxHops));
        }

        $absolute = $this->absolutize($location, $fromUrl);

        // 指回自身前缀: 自家网关被当成上游就是自喂环。github.com ->
        // objects.githubusercontent.com 是合法常见链路, 所以这里只判"是不是我自己的入口",
        // 不判"是不是 GitHub"。
        $own = $this->isOwnPrefix($absolute);
        if ($own !== '') {
            throw GhpError::make(GhpError::REDIRECT_LOOP, 'Location 指回本网关前缀 ' . $own);
        }

        return $this->assertAllowed($absolute);
    }

    /**
     * 该 URL 是否指向本网关自己的入口。返回命中的自身前缀, 未命中返回空串。
     *
     * 判定用精确 host 等值(小写)或入口前缀字面匹配, 绝不做"看起来像"的模糊匹配 ——
     * 判错方向的代价不对称: 误判成自身会让合法跳转失败(可发现、可修), 漏判会让请求
     * 绕回本机形成环并把网关变成开放代理(静默、危险)。
     *
     * 自身 host 取自 app.base_origin。没配它就只能认出相对形态, 跨站指向自己域名的环检测
     * 会退化 —— base_origin 本来也是 CSRF 基准的必要项, 所以这是同一条部署要求。
     */
    public function isOwnPrefix(string $url): string
    {
        $u = $this->sanitize($url);
        if ($u === '') {
            return '';
        }
        $parts = parse_url($u);
        if (!is_array($parts)) {
            return '';
        }

        $host = strtolower((string) ($parts['host'] ?? ''));
        $path = '/' . ltrim((string) ($parts['path'] ?? ''), '/');
        $isOwnHost = $this->ownHost !== '' && $host === $this->ownHost;
        // 只在"没有 host"时才有另一种形态: 站内相对引用。assertRedirect 传进来的已经是
        // 绝对化结果, 所以这一支主要服务于入口与面板的直接调用。
        $relativeShape = $host === '';

        if ($isOwnHost) {
            if ($this->ownPath !== '' && str_starts_with($path, $this->ownPath)) {
                return $this->ownHost . $this->ownPath;
            }

            return $this->ownHost;
        }

        if ($relativeShape) {
            foreach ($this->ownEntryPrefixes as $p) {
                if ($p !== '' && (str_starts_with($path, '/' . $p . '/') || $path === '/' . $p)) {
                    return '/' . $p;
                }
            }
        }

        return '';
    }

    /**
     * Location 绝对化。处理 //host/path、/path、相对引用、%2e%2e、自带 userinfo 与自带 query。
     *
     * 相对引用必须按 RFC3986 去掉点段: 点段留到后面会被 LDH/path 检查放过, 而 curl
     * 会自己折叠它, 于是"校验看到的"与"连接发出的"不是同一个 URL。
     * %2e%2e 只在点段判定这一步解码 —— 其余任何字节都不做解码, 因为 objects 签名参数
     * 含 %2B/%2F, 解码再编码就 403。
     */
    public function absolutize(string $location, string $fromUrl): string
    {
        $loc = $this->sanitize($location);
        if ($loc === '') {
            throw GhpError::make(GhpError::UNPARSEABLE, 'Location 为空');
        }

        $base = parse_url($this->sanitize($fromUrl));
        if (!is_array($base)) {
            throw GhpError::make(GhpError::UNPARSEABLE, '跳转基准 URL 无法解析');
        }
        $scheme = strtolower((string) ($base['scheme'] ?? 'https'));
        $baseAuth = $this->authorityOf($this->sanitize($fromUrl));

        // 注意模式里的 '#' 必须转义: 分隔符就是 '#', 不转义会让 PCRE 提前收尾,
        // preg_match 返回 false, 于是协议相对 Location 静默走进相对引用分支 —— 拼出
        // "https://github.com/codeload.github.com/..." 这种谁都不会报错的地址。
        if (preg_match('#\A//([^/?\#]*)#', $loc, $m) === 1) {
            // 协议相对: 继承基准 scheme。authority 里的 '@' 交给 assertAllowed 去拒。
            return $scheme . ':' . $loc;
        }

        if (preg_match('#\A[a-zA-Z][a-zA-Z0-9+.\-]*:#', $loc) === 1) {
            // 自带 scheme: 原样交回判定链, 非 https 会在那里被拒。
            return $loc;
        }

        if (str_starts_with($loc, '/')) {
            return $this->finish($scheme, $baseAuth, $this->collapseDotSegments($loc), $loc);
        }

        // 相对引用: 基于基准 URL 的目录解析。
        $basePath = (string) ($base['path'] ?? '/');
        $dir = str_contains($basePath, '/') ? substr($basePath, 0, (int) strrpos($basePath, '/')) . '/' : '/';
        $joined = $this->collapseDotSegments($dir . $loc);

        return $this->finish($scheme, $baseAuth, $joined, $loc);
    }

    /**
     * 点段归一。
     *
     * 先把 %2e / %2E 形态的点段还原成字面点再做折叠: 这两者在 URL 语义上等价, 而 curl
     * 与浏览器都会折叠它们。除此之外不解码任何内容。
     */
    private function collapseDotSegments(string $path): string
    {
        $decodedForDots = preg_replace('/%2e/i', '.', $path) ?? $path;
        if ($decodedForDots !== $path) {
            // 只在"点段形态"这一维度上承认解码结果, 其余字节保持原样。
            $path = $decodedForDots;
        }

        $out = [];
        $trailingSlash = str_ends_with($path, '/');
        foreach (explode('/', $path) as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                if ($out === []) {
                    throw GhpError::make(GhpError::PATH_TRAVERSAL, '点段逃逸出根路径');
                }
                array_pop($out);
                continue;
            }
            $out[] = $seg;
        }

        $res = '/' . implode('/', $out);

        return ($trailingSlash && !str_ends_with($res, '/')) ? $res . '/' : $res;
    }

    private function finish(string $scheme, string $authority, string $path, string $original): string
    {
        if ($authority === '') {
            throw GhpError::make(GhpError::UNPARSEABLE, '跳转缺少 authority: ' . substr($original, 0, 120));
        }

        return $scheme . '://' . $authority . $path;
    }

    /** 去掉控制字符(\x00-\x20 与 \x7F)。它们在解析器之间制造分歧, 且从不出现在合法 URL 里。 */
    private function sanitize(string $url): string
    {
        return preg_replace('/[\x00-\x20\x7F]/', '', $url) ?? $url;
    }

    /** scheme:// 之后、第一个 / ? # 之前的那段。 */
    private function authorityOf(string $url): string
    {
        $pos = strpos($url, '://');
        $rest = $pos === false ? $url : substr($url, $pos + 3);
        $end = strcspn($rest, '/?#');

        return substr($rest, 0, $end);
    }

    /** 只替换 authority 里的 host 大小写, 其余字节一律不动(不做整体重新组装)。 */
    private function replaceAuthority(string $url, string $host, int $port): string
    {
        $pos = strpos($url, '://');
        if ($pos === false) {
            return $url;
        }
        $authStart = $pos + 3;
        $authLen = strcspn(substr($url, $authStart), '/?#');
        $auth = substr($url, $authStart, $authLen);
        $newHost = $host;
        if ($port !== 443) {
            $newHost .= ':' . $port;
        }

        return substr($url, 0, $authStart) . $newHost . substr($url, $authStart + $authLen);
    }

    /**
     * 只解析 A 记录。
     *
     * 不做 AAAA 是设计而非偷懒: 出站锁 IPv4 之后, 6to4/Teredo/NAT64/v4-mapped 整条隧道
     * 绕过链就没有落地路径了(IpRange 里的 v6 判定是"写了但默认不调用"的第二层)。
     *
     * 用 gethostbynamel 而不是 curl 的解析: 判定必须先于连接发生, 且要拿到完整列表
     * 才能做"多 IP 全部必须合格"。
     *
     * @return array<int,string>
     */
    public function resolveA(string $host): array
    {
        $ips = gethostbynamel($host);
        if (!is_array($ips)) {
            $ips = [];
        }
        // 某些平台 gethostbynamel 只回一条, 用 dns_get_record 补齐, 保证"全部 IP 校验"
        // 覆盖的是这个域名的全部 A 记录而不是解析器随手给的那一个。
        if (function_exists('dns_get_record')) {
            $rr = @dns_get_record($host, DNS_A);
            if (is_array($rr)) {
                foreach ($rr as $r) {
                    if (isset($r['ip']) && is_string($r['ip'])) {
                        $ips[] = $r['ip'];
                    }
                }
            }
        }

        $ips = array_values(array_unique(array_filter(array_map(
            [IpRange::class, 'normalizeIp'],
            $ips
        ))));

        if ($ips === []) {
            throw GhpError::make(GhpError::UPSTREAM_FAILED, sprintf('%s 无可用 A 记录', $host));
        }

        // 只保留 v4, 与"锁 IPv4 出站"保持一致。
        $v4 = array_values(array_filter($ips, static fn (string $ip): bool => !str_contains($ip, ':')));
        if ($v4 === []) {
            // 有记录但全是 v6: 本部署不出站 v6, 放行就等于让 curl 自己再去解析一次。
            throw GhpError::make(GhpError::IP_DENIED, sprintf('%s 只有非 IPv4 记录', $host));
        }

        return $v4;
    }
}
