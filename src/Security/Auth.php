<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 管理面身份 —— selector/verifier 双段 Token、自管会话、CSRF/Origin/
 *             Sec-Fetch-Site 写请求校验、Token 签发与吊销。
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
 * 三处与"直觉做法"相反的选择, 都有实测理由:
 *
 *  1. 故意不用 bcrypt。本机实测 cost=11 单次 167ms, 而 verifier 本身是 80 个十六进制字符
 *     = 320bit 全熵, 慢哈希不增加破解成本, 反而让攻击者发 20 个错 Token 就占住 20 个
 *     worker —— 把认证变成免费的 CPU 反射攻击。这里用快哈希 + login 桶限流 + 失败加倍扣分。
 *  2. 不用 PHP 原生 session_start()。同一 session 的并发请求会被串行阻塞, 面板多开几个
 *     页签(轮询四个视图)就把自己卡死。
 *  3. Cookie 不设 Domain。host-only 是唯一能防止"以后加的某个子域"接管管理会话的写法,
 *     而 SameSite=Strict + HttpOnly + Path=面板前缀把可投递范围压到最小。
 *
 * 未登录的面板请求一律给 404 语义而不是 401/登录页: 不给扫描器"这里有个面板"的信号。
 */
final class Auth
{
    public const COOKIE = 'gha_sid';
    public const TOKEN_CHARS = 96;          // 48 字节 hex
    public const SELECTOR_CHARS = 16;       // 8 字节
    public const WRITE_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH'];

    private string $adminDir;

    private string $sessionDir;

    private string $repoRoot;

    private string $prefix;

    private ?string $secret = null;

    private ?RateLimiter $limiter = null;

    public function __construct(private readonly Config $cfg, string $root)
    {
        $this->repoRoot = rtrim($root, '/\\');
        $this->adminDir = $this->repoRoot . '/var/state/admin';
        $this->sessionDir = $this->repoRoot . '/var/sessions';
        $this->prefix = trim($cfg->str('panel.path_prefix', 'panel'), '/');
    }

    // ------------------------------------------------------------------
    // 登录与登出
    // ------------------------------------------------------------------

    /**
     * 读 POST 表单里的 Token。成功即建立会话并发 Cookie(302); 失败抛 GhpError。
     *
     * 调用方必须在返回后立即停止输出 —— 本方法不 exit, 因为在 CLI 自检与面板 SSR 里
     * "自己决定怎么收尾"比被硬截断好用。
     */
    public function handleLogin(): void
    {
        $ip = $this->clientIp();
        $rl = $this->limiter();
        $bucket = $rl->consume('login', $ip !== '' ? $ip : 'unknown-ip', 1.0);
        if (!$bucket['allowed']) {
            throw GhpError::make(GhpError::RATE_LIMITED, '登录尝试过于频繁', ['retry_after' => $bucket['retry_after']]);
        }

        $raw = trim((string) ($_POST['token'] ?? $_POST['gha_token'] ?? ''));
        $row = $raw === '' ? null : $this->verifyTokenRaw($raw);
        if ($row === null) {
            // 失败加倍扣桶: 让"批量试 Token"在几次之内就被拒, 而不必给每次验证加 167ms。
            $rl->consume('login', $ip !== '' ? $ip : 'unknown-ip', 2.0);
            Audit::log('anonymous', 'POST', '/' . $this->prefix . '/login', null, 'denied', $ip, $this->cfg);
            // 不区分"Token 不存在"与"verifier 不对": 两种情况给完全一样的话术。
            throw GhpError::make(GhpError::UNAUTHENTICATED, '凭据无效');
        }

        $selector = (string) $row['selector'];
        $sid = bin2hex(random_bytes(16));
        $this->writeSession($selector, $sid, $ip, (array) $row['scopes'], (string) $row['label']);
        $this->touchVerifier($selector);
        $cookieValue = $selector . '.' . $sid;
        // Cookie 与 302 的先后无所谓(都进同一份响应头), setCookie 自己判 headers_sent。
        $this->setCookie($cookieValue);
        // 同步超全局: header() 是单向的, 不设这一步的话"同一次请求里后续代码读不到自己刚
        // 发的 Cookie", 面板 SSR 会在登录后立刻把自己当未登录。
        $_COOKIE[self::COOKIE] = $cookieValue;

        Audit::log(Audit::actorFromSelector($selector), 'POST', '/' . $this->prefix . '/login', null, 'ok', $ip, $this->cfg);

        if (!headers_sent()) {
            http_response_code(302);
            header('Location: ' . $this->panelBase() . '/');
        }
    }

    /** 登出: 删会话文件 + 过期 Cookie。幂等, 未登录调用不报错。 */
    public function handleLogout(): void
    {
        $parts = $this->cookieParts();
        if ($parts !== null) {
            @unlink($this->sessionFile($parts[0]));
            unset($_COOKIE[self::COOKIE]);
        }
        $ip = $this->clientIp();
        if ($parts !== null) {
            Audit::log(Audit::actorFromSelector($parts[0]), 'POST', '/' . $this->prefix . '/logout', null, 'ok', $ip, $this->cfg);
        }
        if (!headers_sent()) {
            $this->clearCookie();
            http_response_code(302);
            header('Location: ' . $this->panelBase() . '/');
        }
    }

    /**
     * 当前会话。任何一项不符即视为无会话(返回 null), 不做"部分信任"。
     *
     * 绑定 IP 前缀而不是整 IP: 移动网络与校园网会中途换出口地址, 绑整 IP 的结果是
     * 面板每几分钟掉线一次, 运维最后只会把会话校验关掉 —— 安全项死于难用。
     */
    public function session(): ?array
    {
        $parts = $this->cookieParts();
        if ($parts === null) {
            return null;
        }
        [$selector, $sid] = $parts;

        $file = $this->sessionFile($selector);
        if (!is_readable($file)) {
            return null;
        }
        $s = json_decode((string) @file_get_contents($file), true);
        if (!is_array($s) || ($s['sid'] ?? '') !== $sid) {
            return null;
        }

        $now = time();
        $idle = (int) $this->cfg->int('panel.session_idle_s', 1800);
        $abs = (int) $this->cfg->int('panel.session_abs_s', 43200);
        $created = (int) ($s['created_at'] ?? 0);
        $seen = (int) ($s['last_seen_at'] ?? 0);
        if ($created === 0 || ($abs > 0 && $now - $created > $abs) || ($idle > 0 && $seen > 0 && $now - $seen > $idle)) {
            @unlink($file);

            return null;
        }

        if (!hash_equals((string) ($s['ip_prefix'] ?? ''), $this->ipPrefix())
            || !hash_equals((string) ($s['ua_hash'] ?? ''), $this->uaHash())) {
            // 地址前缀或 UA 变了: 宁可掉线也不续会话。这类变更在中途劫持里是必需前提。
            return null;
        }

        // 只在超过 5 秒时才回写: 面板 4 个视图并发轮询会把会话文件写成热点。
        if ($now - $seen > 5) {
            $s['last_seen_at'] = $now;
            Config::atomicWrite($file, (string) json_encode($s, JSON_UNESCAPED_SLASHES));
            @chmod($file, 0600);
        }

        return [
            'selector' => $selector,
            'actor' => Audit::actorFromSelector($selector),
            'label' => (string) ($s['label'] ?? ''),
            'scopes' => (array) ($s['scopes'] ?? []),
            'sid' => $sid,
            'created_at' => $created,
            'last_seen_at' => $now,
        ];
    }

    /**
     * 要求已认证。
     *
     * HTML 请求给 404(不给扫描器面板存在的信号, 登录页只由显式入口渲染),
     * API 请求给 401 —— 脚本客户端需要能区分"没带凭证"与"路径不存在", 否则排查
     * 配置错误时只能靠猜。若部署方要连 API 也伪装成不存在, 在入口把 UNAUTHENTICATED
     * 映射成 NOT_FOUND 即可(错误码语义已分开, 不必改这里)。
     */
    public function requireAuth(): array
    {
        if (!$this->cfg->bool('panel.enabled', true)) {
            throw GhpError::make(GhpError::NOT_FOUND);
        }
        $s = $this->session();
        if ($s !== null) {
            return $s;
        }

        if ($this->wantsHtml()) {
            throw GhpError::make(GhpError::NOT_FOUND, '面板未启用或未认证');
        }

        throw GhpError::make(GhpError::UNAUTHENTICATED);
    }

    /** 要求写作用域。未认证时先走 requireAuth 的 404/401 分流。 */
    public function requireWrite(string $method): void
    {
        $s = $this->requireAuth();
        $m = strtoupper($method);
        if (!in_array($m, self::WRITE_METHODS, true)) {
            throw GhpError::make(GhpError::UNSUPPORTED_METHOD, $m);
        }
        if (!in_array('write', (array) $s['scopes'], true)) {
            throw GhpError::make(GhpError::SCOPE_REQUIRED, '当前 Token 只读');
        }
    }

    /**
     * 写请求全链校验。任一失败立即抛出, 抛出前不产生任何副作用。
     *
     * 顺序即强度: 先协议(method)→ 再浏览器侧信号(Sec-Fetch-Site, 攻击者删不掉)→
     * 再 Origin 严格等值配置基准(绝不用 $_SERVER['HTTP_HOST']: Host 直通 $http_host 时
     * 可伪造, 用它当基准等于把同源判定交给攻击者)→ 再 HMAC Token → 再 Content-Type
     * (挡掉简单表单 CSRF)→ confirm 由调用方按操作危险度自判(CONFIRM_REQUIRED)。
     */
    public function verifyWriteRequest(string $method, string $path): void
    {
        $m = strtoupper($method);
        if (!in_array($m, self::WRITE_METHODS, true)) {
            throw GhpError::make(GhpError::UNSUPPORTED_METHOD, $m);
        }
        $this->requireWrite($m);

        $sfs = strtolower(trim((string) ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '')));
        if ($sfs !== '' && !in_array($sfs, ['same-origin', 'none'], true)) {
            throw GhpError::make(GhpError::CSRF_FAILED, 'Sec-Fetch-Site=' . $sfs);
        }

        $base = strtolower(rtrim(trim((string) $this->cfg->str('app.base_origin')), '/'));
        $origin = strtolower(rtrim(trim((string) ($_SERVER['HTTP_ORIGIN'] ?? '')), '/'));
        if ($origin !== '') {
            if ($base === '') {
                throw GhpError::make(GhpError::CSRF_FAILED, '未配置 app.base_origin, 无法建立同源基准');
            }
            if (!hash_equals($base, $origin)) {
                throw GhpError::make(GhpError::CSRF_FAILED, 'Origin 不匹配');
            }
        } elseif ($base !== '') {
            // 没有 Origin(同源 GET 形态的表单或非浏览器)时退到 Referer: 有就必须同源。
            $ref = strtolower(trim((string) ($_SERVER['HTTP_REFERER'] ?? '')));
            if ($ref !== '' && !str_starts_with($ref, $base)) {
                throw GhpError::make(GhpError::CSRF_FAILED, 'Referer 不匹配');
            }
        }

        $token = trim((string) ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? $_POST['_csrf'] ?? ''));
        $want = $this->csrfTokenFor($m, $path);
        if ($token === '' || !hash_equals($want, $token)) {
            throw GhpError::make(GhpError::CSRF_FAILED, 'X-CSRF-Token 校验未通过');
        }

        $ctype = strtolower(trim(explode(';', (string) ($_SERVER['CONTENT_TYPE'] ?? ''))[0]));
        if (!in_array($ctype, ['application/json', 'application/x-www-form-urlencoded'], true) && $ctype !== 'text/plain') {
            // text/plain 放行是因为"简单表单只能发这三种 Content-Type", 而简单表单发不出
            // JSON API 需要的结构; 反过来 multipart/form-data 是攻击者可控的, 拒。
            throw GhpError::make(GhpError::CSRF_FAILED, 'Content-Type 必须是 application/json 或表单');
        }
    }

    // ------------------------------------------------------------------
    // CSRF
    // ------------------------------------------------------------------

    /** 当前请求上下文下的 CSRF Token(面板 SSR 直接放 meta 里)。 */
    public function csrfToken(): string
    {
        $m = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $p = '/' . ltrim((string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/'), '/');

        return $this->csrfTokenFor($m, $p);
    }

    /**
     * 绑定到具体 method+path 的 Token。
     *
     * 为什么不用一个全局 CSRF Token: 绑定之后, 攻击者即使从别处拿到一个 Token,
     * 也无法用它去动另一个接口(比如把"改权重"的 Token 拿去删源), 而且 Token 泄漏的
     * 影响面从"整个面板"缩到"一个动作"。
     * 再叠上会话 sid 作为密钥派生的一部分: 跨会话重放也要先猜中 sid。
     */
    public function csrfTokenFor(string $method, string $path): string
    {
        $bind = $this->sessionSidForCsrf();
        $msg = strtoupper($method) . ':' . $path . ':' . $bind;

        return base64_encode(hash_hmac('sha256', $msg, $this->secret(), true));
    }

    /**
     * 面板 boot JSON 用: 一次把多个动作的 Token 算好。
     *
     * @param array<int,string> $actions 形如 ["POST:/panel/api/sources", "DELETE:/panel/api/breaker"]
     * @return array<string,string>
     */
    public function csrfMap(array $actions): array
    {
        $out = [];
        foreach ($actions as $a) {
            [$m, $p] = array_pad(explode(':', (string) $a, 2), 2, '/');
            $out[(string) $a] = $this->csrfTokenFor(strtoupper($m), $p);
        }

        return $out;
    }

    // ------------------------------------------------------------------
    // Token 管理
    // ------------------------------------------------------------------

    /**
     * 签发新 Token。
     *
     * @return array{raw:string, selector:string} raw 只在这里返回一次, 之后不可再取
     */
    public function issueToken(string $label, array $scopes): array
    {
        $raw = bin2hex(random_bytes(48));
        $selector = substr($raw, 0, self::SELECTOR_CHARS);
        $verifier = substr($raw, self::SELECTOR_CHARS);

        $clean = [];
        foreach ($scopes as $s) {
            $s = strtolower(trim((string) $s));
            if ($s !== '' && !in_array($s, $clean, true)) {
                $clean[] = $s;
            }
        }

        $this->mutateStore(function (array $store) use ($selector, $verifier, $label, $clean): array {
            $store[$selector] = [
                'hash' => hash('sha256', $verifier),
                'label' => substr(preg_replace('/[\x00-\x20\x7F]/', '', $label) ?? '', 0, 64),
                'scopes' => $clean,
                'created_at' => time(),
                'last_used_at' => 0,
            ];

            return $store;
        });

        return ['raw' => $raw, 'selector' => $selector];
    }

    /**
     * 按 selector 前缀吊销。
     *
     * 前缀至少 8 字符(32bit): 允许"复制粘贴被截了"这种误操作, 同时挡住"传 1 个字符
     * 把全部 Token 清光"这种一发入魂的破坏面。命中 0 个抛 NOT_FOUND。
     */
    public function revokeToken(string $selectorPrefix): void
    {
        $p = strtolower(trim($selectorPrefix));
        if (strlen($p) < 8) {
            throw GhpError::make(GhpError::NOT_FOUND, '吊销需要至少 8 位 selector 前缀');
        }

        $hit = 0;
        $this->mutateStore(function (array $store) use ($p, &$hit): array {
            foreach (array_keys($store) as $sel) {
                if (is_string($sel) && str_starts_with(strtolower($sel), $p)) {
                    unset($store[$sel]);
                    $hit++;
                    // 会话跟着作废: 只删 verifier 而留会话是最常见的"吊销了但还能用"事故。
                    $this->dropSession($sel);
                }
            }

            return $store;
        });

        if ($hit === 0) {
            throw GhpError::make(GhpError::NOT_FOUND, '没有匹配的 Token');
        }
    }

    /** 列表: 只暴露 selector 前 8 位与元数据, 永远不含 hash 或 verifier。 */
    public function listTokens(): array
    {
        $store = $this->readStore();
        $out = [];
        foreach ($store as $sel => $row) {
            if (!is_array($row)) {
                continue;
            }
            $out[] = [
                'selector_prefix' => substr((string) $sel, 0, 8),
                'label' => (string) ($row['label'] ?? ''),
                'scopes' => (array) ($row['scopes'] ?? []),
                'created_at' => (int) ($row['created_at'] ?? 0),
                'last_used_at' => (int) ($row['last_used_at'] ?? 0),
            ];
        }
        usort($out, static fn (array $a, array $b): int => $b['created_at'] <=> $a['created_at']);

        return $out;
    }

    /** 校验明文 Token。命中返回该条记录, 否则 null。 */
    public function verifyTokenRaw(string $raw): ?array
    {
        $raw = strtolower(trim($raw));
        if (strlen($raw) !== self::TOKEN_CHARS || preg_match('/\A[0-9a-f]+\z/', $raw) !== 1) {
            return null;
        }
        $selector = substr($raw, 0, self::SELECTOR_CHARS);
        $verifier = substr($raw, self::SELECTOR_CHARS);

        $store = $this->readStore();
        // 按 selector 键 O(1) 取值: 不遍历比较, 于是"哪个 selector 存在"既不进时间也进不了日志。
        $row = $store[$selector] ?? null;
        if (!is_array($row)) {
            // 不存在也要算一次哈希, 让两条分支的耗时差降到噪声级。
            hash('sha256', $verifier);

            return null;
        }
        if (!hash_equals((string) ($row['hash'] ?? ''), hash('sha256', $verifier))) {
            return null;
        }

        $row['selector'] = $selector;

        return $row;
    }

    /** 供 bin/token.php 与入口做自检: 校验并顺带建立会话。 */
    public function loginWithToken(string $raw): array
    {
        $row = $this->verifyTokenRaw($raw);
        if ($row === null) {
            throw GhpError::make(GhpError::UNAUTHENTICATED, '凭据无效');
        }
        $selector = (string) $row['selector'];
        $sid = bin2hex(random_bytes(16));
        $this->writeSession($selector, $sid, $this->clientIp(), (array) $row['scopes'], (string) $row['label']);

        return ['selector' => $selector, 'sid' => $sid, 'cookie' => $selector . '.' . $sid];
    }

    // ------------------------------------------------------------------
    // 内部
    // ------------------------------------------------------------------

    /** 会话文件名: 键用 sha256(selector), 免得目录列表本身泄露有哪些 Token 在用。 */
    public static function sessionFileName(string $selector): string
    {
        return 'sess_' . hash('sha256', strtolower(trim($selector))) . '.json';
    }

    /** 吊销时连带删会话。用实例的 sessionDir 而不是重拼路径: root 只有一处定义。 */
    private function dropSession(string $selector): void
    {
        @unlink($this->sessionFile($selector));
    }

    private function sessionFile(string $selector): string
    {
        return $this->sessionDir . '/' . self::sessionFileName($selector);
    }

    private function writeSession(string $selector, string $sid, string $ip, array $scopes, string $label): void
    {
        $this->ensureDir($this->sessionDir);
        $now = time();
        $row = [
            'sid' => $sid,
            'scopes' => $scopes,
            'label' => $label,
            'created_at' => $now,
            'last_seen_at' => $now,
            'ip_prefix' => $this->ipPrefix(),
            'ua_hash' => $this->uaHash(),
            'ip_hash' => Audit::ipHash($ip, (string) $this->cfg->str('limits.bucket_salt')),
        ];
        Config::atomicWrite($this->sessionFile($selector), (string) json_encode($row, JSON_UNESCAPED_SLASHES));
        @chmod($this->sessionFile($selector), 0600);
    }

    /** cookie 值 = selector.sid ; 拆不出两段就是没有会话。 */
    private function cookieParts(): ?array
    {
        $v = (string) ($_COOKIE[self::COOKIE] ?? '');
        if ($v === '' || substr_count($v, '.') !== 1) {
            return null;
        }
        [$sel, $sid] = explode('.', $v, 2);
        $sel = strtolower(trim($sel));
        if (preg_match('/\A[0-9a-f]{16}\z/', $sel) !== 1 || preg_match('/\A[0-9a-f]{32}\z/', $sid) !== 1) {
            return null;
        }

        return [$sel, $sid];
    }

    private function setCookie(string $value): void
    {
        if (headers_sent()) {
            return;
        }
        // Path 收成面板前缀: 数据面(/gh、/raw ...)根本不需要带管理会话 Cookie 过去,
        // 少带一次就少一次被日志/代理采集到的机会。
        $path = '/' . ($this->prefix !== '' ? $this->prefix : '');
        $cookie = self::COOKIE . '=' . $value
            . '; Path=' . $path
            . '; HttpOnly; SameSite=Strict'
            . ($this->isHttps() ? '; Secure' : '');
        // 故意不带 Domain(host-only)与 Max-Age(会话型 Cookie)。
        header('Set-Cookie: ' . $cookie);
    }

    private function clearCookie(): void
    {
        $path = '/' . ($this->prefix !== '' ? $this->prefix : '');
        header('Set-Cookie: ' . self::COOKIE . '=; Path=' . $path . '; Max-Age=0; HttpOnly; SameSite=Strict'
            . ($this->isHttps() ? '; Secure' : ''));
    }

    private function isHttps(): bool
    {
        $https = strtolower((string) ($_SERVER['HTTPS'] ?? ''));
        if (in_array($https, ['on', '1', 'true', 'yes'], true)) {
            return true;
        }
        // 只有"确实来自可信代理"的 X-Forwarded-Proto 才作数: 宝塔直通 $http_x_forwarded_proto
        // 时这个头可由客户端自填, 信它等于让客户端决定 Cookie 要不要带 Secure。
        if (!$this->cfg->bool('security.trust_proxy_headers', false)) {
            return false;
        }
        $remote = $this->remoteAddr();
        if ($remote === '' || !IpRange::inCidrs($remote, (array) $this->cfg->arr('security.trusted_proxies'))) {
            return false;
        }

        return strtolower(trim((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''))) === 'https';
    }

    /** 出口 IP: 可信代理链上取第一个不可信地址, 否则只认 REMOTE_ADDR。 */
    private function clientIp(): string
    {
        $remote = $this->remoteAddr();
        if (!$this->cfg->bool('security.trust_proxy_headers', false) || $remote === '') {
            return $remote;
        }
        if (!IpRange::inCidrs($remote, (array) $this->cfg->arr('security.trusted_proxies'))) {
            return $remote;
        }
        $xff = (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
        if ($xff === '') {
            return $remote;
        }
        $chain = array_reverse(array_map('trim', explode(',', $xff)));
        $trusted = (array) $this->cfg->arr('security.trusted_proxies');
        foreach ($chain as $hop) {
            $norm = IpRange::normalizeIp($hop);
            if ($norm === null) {
                continue;
            }
            if (!IpRange::inCidrs($norm, $trusted)) {
                return $norm;
            }
        }

        return $chain !== [] ? (IpRange::normalizeIp((string) end($chain)) ?? $remote) : $remote;
    }

    private function remoteAddr(): string
    {
        return IpRange::normalizeIp((string) ($_SERVER['REMOTE_ADDR'] ?? '')) ?? '';
    }

    private function ipPrefix(): string
    {
        return IpRange::sessionPrefix(
            $this->clientIp(),
            (int) $this->cfg->int('panel.bind_ip_prefix_v4', 24),
            (int) $this->cfg->int('panel.bind_ip_prefix_v6', 48)
        );
    }

    private function uaHash(): string
    {
        return substr(hash('sha256', (string) ($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 16);
    }

    /**
     * 这是浏览器要看的页面, 还是脚本要读的接口?
     *
     * 先按路径分段判(面板前缀之下、api 之外一律算页面), 再退回 Accept: 只看 Accept 会被
     * 扫描器与 curl 默认的那个通配 Accept 误导, 把面板 HTML 请求判成 API 从而回 401 ——
     * 那正好把"这里有个面板"告诉了对方。
     */
    private function wantsHtml(): bool
    {
        $accept = strtolower((string) ($_SERVER['HTTP_ACCEPT'] ?? ''));
        $path = '/' . ltrim((string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/'), '/');
        $inPanel = $this->prefix === ''
            || str_starts_with($path, '/' . $this->prefix . '/')
            || rtrim($path, '/') === '/' . $this->prefix;
        if ($inPanel) {
            // 面板之下只有显式的 /api/ 子树按接口对待, 其余给 404 语义。
            return !str_contains($path, '/api/');
        }

        if (str_contains($accept, 'application/json') || str_contains($path, '/api/')) {
            return false;
        }

        return $accept === '' || str_contains($accept, 'text/html');
    }

    private function panelBase(): string
    {
        $origin = rtrim((string) $this->cfg->str('app.base_origin'), '/');
        $prefix = $this->prefix !== '' ? '/' . $this->prefix : '';

        return $origin !== '' ? $origin . $prefix : ($prefix !== '' ? $prefix : '/');
    }

    private function sessionSidForCsrf(): string
    {
        $parts = $this->cookieParts();

        return $parts === null ? 'anon' : $parts[1];
    }

    /**
     * CSRF/HMAC 根密钥。
     *
     * 不落配置文件而落 var/state/admin/secret.key(0600 意图): 配置文件在宝塔里常被当作
     * 站点备份的一部分带走, 而随机密钥必须由部署者之外的东西生成。文件缺失就生成一把,
     * 生成失败直接抛 —— 用一把硬编码默认密钥的面板, 等于没有 CSRF。
     */
    private function secret(): string
    {
        if (is_string($this->secret) && $this->secret !== '') {
            return $this->secret;
        }
        $cfgSecret = trim((string) $this->cfg->str('panel.csrf_secret'));
        if (strlen($cfgSecret) >= 32) {
            return $this->secret = $cfgSecret;
        }

        $file = $this->adminDir . '/secret.key';
        $this->ensureDir($this->adminDir);
        if (is_readable($file)) {
            $s = trim((string) @file_get_contents($file));
            if (strlen($s) >= 32) {
                return $this->secret = $s;
            }
        }
        $s = bin2hex(random_bytes(32));
        if (@file_put_contents($file, $s . "\n") === false) {
            throw GhpError::make(GhpError::CSRF_FAILED, '无法写入 CSRF 根密钥, 管理面拒绝启动');
        }
        @chmod($file, 0600);

        return $this->secret = $s;
    }

    private function verifierFile(): string
    {
        return $this->adminDir . '/verifiers.json';
    }

    /** @return array<string,array> */
    private function readStore(): array
    {
        $file = $this->verifierFile();
        if (!is_readable($file)) {
            return [];
        }
        $store = json_decode((string) @file_get_contents($file), true);

        return is_array($store) ? $store : [];
    }

    /**
     * 读改写整个 verifier 库。
     *
     * 阻塞锁: 签发/吊销是分钟级的人工操作, 这里要的是"不丢改动", 不是"不等待"。
     * 与限流桶相反 —— 桶丢了无所谓, Token 库写坏了谁都进不来。
     */
    private function mutateStore(callable $mutator): void
    {
        $this->ensureDir($this->adminDir);
        $file = $this->verifierFile();
        $fh = @fopen($file, 'c+');
        if ($fh === false) {
            throw GhpError::make(GhpError::UPSTREAM_FAILED, '无法打开 Token 库');
        }
        if (!@flock($fh, LOCK_EX)) {
            fclose($fh);
            throw GhpError::make(GhpError::UPSTREAM_FAILED, 'Token 库被占用');
        }
        $size = fstat($fh);
        $raw = ($size !== false && $size['size'] > 0) ? (string) fread($fh, (int) min((int) $size['size'], 1048576)) : '';
        $store = $raw === '' ? [] : json_decode($raw, true);
        if (!is_array($store)) {
            $store = [];
        }

        $store = (array) $mutator($store);

        rewind($fh);
        ftruncate($fh, 0);
        fwrite($fh, (string) json_encode($store, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . "\n");
        fflush($fh);
        flock($fh, LOCK_UN);
        fclose($fh);
        @chmod($file, 0600);
    }

    private function touchVerifier(string $selector): void
    {
        try {
            $this->mutateStore(function (array $store) use ($selector): array {
                if (isset($store[$selector]) && is_array($store[$selector])) {
                    $store[$selector]['last_used_at'] = time();
                }

                return $store;
            });
        } catch (\Throwable) {
            // 记账失败不该让一次合法登录失败: 时间戳是锦上添花, 认证结果才是结论。
        }
    }

    private function limiter(): RateLimiter
    {
        return $this->limiter ??= new RateLimiter($this->cfg, $this->repoRoot);
    }

    private function ensureDir(string $dir): void
    {
        if (!is_dir($dir)) {
            @mkdir($dir, 0770, true);
        }
    }
}
