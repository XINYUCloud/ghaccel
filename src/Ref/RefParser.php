<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 把用户给的任意一种入口写法归一成 GitHubRef —— 三种等价形式、五种残缺写法、
 *             短别名、blob→raw 与 tree→contents 的位置限定改写、身份判定与拒绝规则。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Ref;

use GhAccel\Config;
use GhAccel\Enum\IdentityKind;
use GhAccel\Enum\Scene;
use GhAccel\Errors\GhpError;

/**
 * 判定顺序本身就是设计:
 *   1. 表面(首页/健康/面板/静态)先分出去, 代理面才进这里。
 *   2. 绝对形式优先于别名形式。绝对形式"只做 host 白名单 + 字节级原样重放", 不理解语义,
 *      因此它永远看得懂任何合法的 GitHub URL —— 这是消除歧义的关键: 复杂分支名、奇怪
 *      query、未来新增的路径形态, 都有一条不会失败的通路。
 *   3. 别名/结构化形式才做 ref 与 path 的切分, 也才有 AMBIGUOUS_REF 这种"看不懂就说看不懂"。
 *
 * 输入只信 $_SERVER['REQUEST_URI'] 的原始串(由调用方传入), 绝不对整段 urldecode:
 * objects 签名参数含 %2B/%2F, 解码再编码就 403 SignatureDoesNotMatch —— 这条是本文件
 * 一切"字节级"处理的唯一理由。
 */
final class RefParser
{
    /** 短别名 -> 段语法。config routing.alias 决定"哪些别名开着", 语法在这里固定。 */
    private const ALIAS_ORDER = ['gh', 'raw', 'release', 'latest', 'zip', 'tar', 'archive', 'api', 'gist'];

    /** 由网关消费、不向上游透传的查询键。 */
    private const CONTROL_KEYS = ['u', 'url', 'sha256', 'part', 'mode', 'debug', 'src', 'source', 'plain', 'name', 'as', 'nocache', 'raw'];

    /** 凭据类查询键: 丢弃且不进缓存, 绝不转发给上游(转发等于替用户把 token 送进镜像)。 */
    private const DENY_KEYS = ['access_token', 'token', 'client_secret', 'client_id', 'code', 'password', 'secret', 'bearer', 'private_token'];

    private UpstreamMap $map;

    /** @var array<string,true> 精确 host 白名单(小写) */
    private array $allowed = [];

    /** @var array<string,true> 已启用的别名 */
    private array $alias = [];

    private int $maxUrlLen;

    private int $maxQueryLen;

    private bool $enableAbsolute;

    private bool $enableGh;

    private bool $enableQuery;

    private bool $autoRefResolve;

    public function __construct(private readonly Config $cfg)
    {
        $this->map = new UpstreamMap($cfg);

        foreach ((array) $cfg->arr('security.allowed_hosts') as $h) {
            $h = strtolower(trim((string) $h));
            if ($h !== '') {
                $this->allowed[$h] = true;
            }
        }

        foreach ((array) $cfg->arr('routing.alias') as $k => $_v) {
            $k = strtolower(trim((string) $k));
            if ($k !== '') {
                $this->alias[$k] = true;
            }
        }
        // archive 与 gist 在代码里始终可用: 少一个别名就多一类静默 404, 而它们没有风险面。
        foreach (['archive', 'gist'] as $k) {
            $this->alias[$k] = true;
        }

        $this->maxUrlLen = (int) $cfg->int('routing.max_url_len', 4096);
        $this->maxQueryLen = (int) $cfg->int('routing.max_query_len', 2048);
        $this->enableAbsolute = $cfg->bool('routing.enable_absolute_form', true);
        $this->enableGh = $cfg->bool('routing.enable_gh_form', true);
        $this->enableQuery = $cfg->bool('routing.enable_query_form', true);
        $this->autoRefResolve = $cfg->bool('routing.autoref_resolve', false);
    }

    /**
     * 路由表面互斥判定。返回 home|health|panel|assets|proxy。
     *
     * 只看原始路径的第一段, 绝不由 URI 推文件路径 —— 那正是"var/cache 里的上传物
     * 被当成 PHP 执行"的入口。
     */
    public function surface(string $rawPath): string
    {
        $path = self::clean($rawPath);
        $seg = explode('/', ltrim($path, '/'));
        $first = strtolower((string) ($seg[0] ?? ''));

        if ($first === '') {
            return 'home';
        }

        $prefix = strtolower(trim((string) $this->cfg->str('panel.path_prefix', 'panel'), '/'));
        if ($prefix !== '' && $first === $prefix) {
            // 面板静态资源单独一个表面: 它的响应头(CSP/缓存)与面板 HTML 不同, 且永不进代理链。
            return (isset($seg[1]) && strtolower((string) $seg[1]) === 'assets') ? 'assets' : 'panel';
        }

        if ($first === 'assets' && isset($seg[1])) {
            return 'assets';
        }
        if (in_array($first, ['health', 'healthz', '_health'], true)) {
            return 'health';
        }

        return 'proxy';
    }

    /**
     * @param string $rawPath  REQUEST_URI 的 path 部分, 原始字节
     * @param string $rawQuery REQUEST_URI 的 query 部分(不含 '?'), 原始字节
     * @throws GhpError
     */
    public function parse(string $rawPath, string $rawQuery): GitHubRef
    {
        $this->assertMethod();

        $path = self::clean($rawPath);
        $query = ltrim(self::clean($rawQuery), '?');

        if (strlen($path) > $this->maxUrlLen) {
            throw GhpError::make(GhpError::URL_TOO_LONG, sprintf('path %d > %d', strlen($path), $this->maxUrlLen));
        }
        if (strlen($query) > $this->maxQueryLen) {
            throw GhpError::make(GhpError::URL_TOO_LONG, sprintf('query %d > %d', strlen($query), $this->maxQueryLen));
        }
        if (str_contains($path, '\\') || str_contains($query, '\\')) {
            throw GhpError::make(GhpError::BACKSLASH_IN_URL, '加速前缀后含反斜杠');
        }

        $warnings = [];
        // fragment 从不进上游; '?' 之后带 '#' 也一并剥掉。
        $hashAt = strpos($query, '#');
        if ($hashAt !== false) {
            $query = substr($query, 0, $hashAt);
            $warnings[] = 'fragment_stripped';
        }

        self::assertNoDotSegments($path);

        $pairs = self::splitQuery($query);
        $inner = self::pick($pairs, ['u', 'url']);
        $passthrough = self::filterQuery($pairs);
        $expectedSha = self::shaParam($pairs);
        if ($inner !== '' && $path !== '' && $path !== '/') {
            $warnings[] = 'query_u_ignored_path_used';
        }

        // 1) 绝对形式(路径里的完整 URL)。
        if ($this->enableAbsolute && $path !== '/' && $path !== '') {
            $ref = $this->parseAbsolute(ltrim($path, '/'), $passthrough, $expectedSha, $warnings);
            if ($ref !== null) {
                return $ref;
            }
        }

        // 2) 查询形式 ?u= —— 为穿透"会改写 // 的代理"而存在, 所以它的值是 percent 编码的,
        //    解码一次是正确且必要的(只解这一层, 内层 query 的 %2B/%2F 原样留在解出来的串里)。
        if ($this->enableQuery && $inner !== '') {
            $decoded = rawurldecode($inner);
            if (str_contains($decoded, '\\')) {
                throw GhpError::make(GhpError::BACKSLASH_IN_URL, 'u= 解码后含反斜杠');
            }
            self::assertNoDotSegments((string) (parse_url($decoded, PHP_URL_PATH) ?: ''));
            $withoutFragment = explode('#', $decoded, 2)[0];
            $ref = $this->parseAbsolute(self::stripLeadingSlash($withoutFragment), $passthrough, $expectedSha, $warnings, true);
            if ($ref === null) {
                throw GhpError::make(GhpError::UNPARSEABLE, 'u= 不是白名单内的完整 URL');
            }

            return $ref;
        }

        // 3) 别名 / 结构化形式。
        $ref = $this->parseAlias($path, $passthrough, $expectedSha, $warnings);
        if ($ref !== null) {
            return $ref;
        }

        throw GhpError::make(
            GhpError::UNPARSEABLE,
            '无法识别的写法',
            ['hint_forms' => ['/https://github.com/...', '/gh/{owner}/{repo}@{ref}/{path}', '?u=...', '/raw/ /release/ /latest/ /zip/ /tar/ /archive/ /api/ /gist/']]
        );
    }

    /** UpstreamMap 暴露给 Transport 复用(二次解析跳转、latest 兜底)。 */
    public function upstreamMap(): UpstreamMap
    {
        return $this->map;
    }

    // ------------------------------------------------------------------
    // 绝对形式
    // ------------------------------------------------------------------

    /**
     * `/https://github.com/o/r/blob/main/a.md` 及其四种残缺写法。
     *
     * "不解析语义"的确切含义: 看不懂不报错(交回调用方继续试别的形式), host 过了白名单就
     * 按字节重放路径与 query。唯一的两处改写是 blob→raw 与 tree→contents, 且都限定在
     * 第 3 段位置 —— 位置限定是必需的: `/tree/main/blob/x` 里 blob 出现在深处, 用全局
     * strpos 替换会把目录路径改写成错误的 raw 地址, 这是此类项目最常见的一类 bug。
     */
    private function parseAbsolute(
        string $tail,
        array $passthrough,
        string $expectedSha,
        array &$warnings,
        bool $fromQuery = false
    ): ?GitHubRef {
        $scheme = '';
        if (preg_match('#\A([a-zA-Z][a-zA-Z0-9+.\-]*):/{1,2}#', $tail, $m) === 1) {
            $scheme = strtolower($m[1]);
            $tail = substr($tail, strlen($m[0]));
        } elseif (preg_match('#\A/{2}#', $tail) === 1) {
            $tail = substr($tail, 2);
        }

        if ($scheme !== '' && $scheme !== 'https') {
            // 明确写了别的 scheme: 这是降级企图, 不能当"没写 scheme"继续试别名形式。
            throw GhpError::make(GhpError::SCHEME_NOT_ALLOWED, $scheme);
        }

        $hostEnd = strcspn($tail, '/?#');
        $authority = substr($tail, 0, $hostEnd);
        if ($authority === '') {
            return null;
        }
        if (str_contains($authority, '@')) {
            throw GhpError::make(GhpError::USERINFO_NOT_ALLOWED, '绝对形式的 authority 含凭据段');
        }
        if (str_contains($authority, '%')) {
            throw GhpError::make(GhpError::ILLEGAL_HOST_CHARS, 'host 不得含百分号编码');
        }

        // IPv6 字面量与中括号: 本项目出站锁 IPv4, 这类写法一律视为非法形态(与 UrlGuard
        // 的 LDH 规则同一口径), 不给"看起来能解析但两边理解不同"留余地。
        if (preg_match('/[\[\]]/', $authority) === 1 || substr_count($authority, ':') > 1) {
            throw GhpError::make(GhpError::ILLEGAL_HOST_CHARS, '不接受 IPv6 字面量');
        }

        $port = '';
        $host = $authority;
        $colon = strpos($authority, ':');
        if ($colon !== false) {
            $host = substr($authority, 0, $colon);
            $port = substr($authority, $colon + 1);
            if ($port !== '443') {
                throw GhpError::make(GhpError::PORT_NOT_ALLOWED, $port);
            }
            $port = ':' . $port;
        }

        $host = strtolower($host);
        // 数字形式的 host(十进制/八进制/十六进制整型、缩写点分)在不同解析器里落到不同
        // 地址, 显式拒一道, 与 UrlGuard 的 NUMERIC_HOST_LITERAL 双保险同构。
        if (preg_match('/\A[0-9.]+\z/', $host) === 1) {
            throw GhpError::make(GhpError::NUMERIC_HOST_LITERAL, $host);
        }
        // www.github.com 是人手打出来的常见形态, 归一到 github.com 后仍走精确白名单。
        if (str_starts_with($host, 'www.')) {
            $host = substr($host, 4);
            $warnings[] = 'www_stripped';
        }
        if (!isset($this->allowed[$host])) {
            // 带 scheme 的写法说明用户就是想直连某个域, 给明确错误而不是"看不懂"。
            if ($scheme !== '' || $fromQuery) {
                throw GhpError::make(GhpError::HOST_NOT_ALLOWED, $host);
            }

            return null;
        }

        $rest = substr($tail, $hostEnd);
        $cut = strcspn($rest, '?#');
        $pathPart = substr($rest, 0, $cut);
        // query 的起点是 rest 里第一个 '?', 而不是"rest 以 ? 开头": 带路径的 URL 里
        // rest 形如 "/x/a.bin?Expires=1&Signature=%2B", 早判会让签名参数整段丢失。
        $innerQuery = '';
        $qPos = strpos($rest, '?');
        if ($qPos !== false) {
            $tailQ = substr($rest, $qPos + 1);
            $hashPos = strpos($tailQ, '#');
            $innerQuery = $hashPos === false ? $tailQ : substr($tailQ, 0, $hashPos);
        }

        // 上游 URL 一律按字节重放: 不解码、不重新编码、不排序、不改大小写(除 host 与
        // owner/repo 的显式归一)。objects 签名参数含 %2B/%2F, 动一下就 403。
        $upstream = 'https://' . $host . $port . $pathPart;
        $forward = $innerQuery === '' ? [] : self::filterQuery(self::splitQuery($innerQuery));
        if ($innerQuery !== '') {
            $dropped = count(self::splitQuery($innerQuery)) - count($forward);
            if ($dropped > 0) {
                $warnings[] = 'query_keys_dropped';
            }
        }
        $all = $forward === [] ? $passthrough : array_merge($forward, $passthrough);
        if ($all !== []) {
            $upstream .= '?' . self::joinQuery($all);
        }

        $seg = array_values(array_filter(explode('/', ltrim($pathPart, '/')), static fn (string $s): bool => $s !== ''));
        $owner = strtolower((string) ($seg[0] ?? ''));
        $repo = strtolower((string) ($seg[1] ?? ''));
        $raw = $owner === '' ? '' : ($repo === '' ? $owner : $owner . '/' . $repo);

        // blob→raw 改写(位置限定)。改写后原始 github.com 的 HTML 形态不再可达, 这是
        // ghproxy 风格用户唯一真正想要的结果。ref 位置就是 seg[3]: 再往里都是 path, 不做
        // 任何"分支名可能含斜杠"的猜测 —— 那种猜测归结构化形式。
        if (count($seg) >= 4 && $host === UpstreamMap::HOST_MAIN && strtolower($seg[2]) === 'blob') {
            $ref = $seg[3];
            $p = implode('/', array_slice($seg, 4));
            $identity = GitHubRef::looksLikeSha($ref) ? IdentityKind::CommitSha : IdentityKind::RefName;
            $url = $this->map->rawUrl($owner, $repo, $ref, $p);
            if ($all !== []) {
                $url .= '?' . self::joinQuery($all);
            }

            return GitHubRef::make(
                Scene::Raw,
                $identity,
                $url,
                $owner,
                $repo,
                ['ref' => $ref, 'sha' => $identity === IdentityKind::CommitSha ? strtolower($ref) : '',
                    'path' => $p, 'download_name' => self::baseName($p), 'api_query' => $all,
                    'expected_sha256' => $expectedSha, 'warnings' => self::push($warnings, 'absolute_blob_rewritten')]
            );
        }

        // tree→contents: 目录只有 API 能列, 重放 github.com 会得到 HTML。
        if (count($seg) >= 4 && $host === UpstreamMap::HOST_MAIN && strtolower($seg[2]) === 'tree') {
            $ref = $seg[3];
            $p = implode('/', array_slice($seg, 4));
            $url = $this->map->contentsApiUrl($owner, $repo, $ref, $p);

            return GitHubRef::make(
                Scene::ApiJson,
                IdentityKind::MutableApi,
                $url,
                $owner,
                $repo,
                ['ref' => $ref, 'path' => $p, 'api_endpoint' => 'repos/' . $owner . '/' . $repo . '/contents' . ($p !== '' ? '/' . $p : ''),
                    'api_query' => $all, 'allow_range' => false, 'expected_sha256' => $expectedSha,
                    'warnings' => self::push($warnings, 'absolute_tree_rewritten')]
            );
        }

        [$scene, $identity, $allowRange, $needsResolve, $extra] = $this->classifyAbsolute($host, $seg, $pathPart, $warnings);
        if ($raw === '') {
            $warnings[] = 'owner_repo_unresolved';
        }

        return GitHubRef::make(
            $scene,
            $identity,
            $upstream,
            $extra['owner'] ?? $owner,
            $extra['repo'] ?? $repo,
            array_merge([
                'ref' => $extra['ref'] ?? '',
                'sha' => $extra['sha'] ?? '',
                'path' => $extra['path'] ?? ltrim($pathPart, '/'),
                'archive_fmt' => $extra['archive_fmt'] ?? '',
                // api_endpoint 只在 API 场景填: 它进缓存键, 给 raw 条目填上路径等于让同一资源
                // 的两种写法产生两个键, 白丢一次命中。
                'api_endpoint' => $scene === Scene::ApiJson ? ($extra['api_endpoint'] ?? ltrim($pathPart, '/')) : '',
                'asset_id' => $extra['asset_id'] ?? null,
                'asset_name' => $extra['asset_name'] ?? '',
                'download_name' => self::baseName($pathPart),
                'allow_range' => $allowRange,
                'needs_redirect_resolve' => $needsResolve,
                'api_query' => $all,
                'expected_sha256' => $expectedSha,
                'warnings' => self::push($warnings, $fromQuery ? 'absolute_from_query' : 'absolute_byte_replay'),
            ], $extra['opts'] ?? [])
        );
    }

    /**
     * 绝对形式的场景判定: 只按 host + 极少量路径关键字, 目的是给出正确的 allow_range 与
     * needs_redirect_resolve(这两个字段决定 Range 语义与是否要先跟一跳), 而不是"理解 URL"。
     *
     * @return array{0:Scene,1:IdentityKind,2:bool,3:bool,4:array}
     */
    private function classifyAbsolute(string $host, array $seg, string $pathPart, array &$warnings): array
    {
        $sha = '';
        foreach ($seg as $s) {
            if (GitHubRef::looksLikeSha($s)) {
                $sha = strtolower($s);
                break;
            }
        }

        if ($host === UpstreamMap::HOST_RAW || $host === UpstreamMap::HOST_GIST_RAW) {
            // raw host 的形态是 {o}/{r}/{ref}/{path}: ref 在第 3 段。
            $ref = $seg[2] ?? '';
            $path = implode('/', array_slice($seg, 3));

            return [
                $host === UpstreamMap::HOST_GIST_RAW ? Scene::GistRaw : Scene::Raw,
                $sha !== '' ? IdentityKind::CommitSha : IdentityKind::RefName,
                true,
                false,
                ['ref' => $ref, 'path' => $path, 'sha' => $sha, 'owner' => strtolower($seg[0] ?? ''), 'repo' => strtolower($seg[1] ?? ''), 'opts' => []],
            ];
        }

        if ($host === UpstreamMap::HOST_CODELOAD) {
            // codeload 实测对 Range: bytes=0-64 返回 200 全量 10.6MB, 所以一律 allow_range=false。
            // 它的形态是 {o}/{r}/{zip|tar.gz}/{ref...} —— ref 在后面, 且可能本身就是 40 位 sha。
            $fmt = strtolower($seg[2] ?? '') === 'zip' ? 'zip' : 'tar.gz';

            return [Scene::Archive, $sha !== '' ? IdentityKind::CommitSha : IdentityKind::RefName, false, false,
                ['ref' => implode('/', array_slice($seg, 3)), 'path' => '', 'archive_fmt' => $fmt, 'sha' => $sha,
                    'owner' => strtolower($seg[0] ?? ''), 'repo' => strtolower($seg[1] ?? ''), 'opts' => []]];
        }

        if ($host === UpstreamMap::HOST_API) {
            // API JSON 不按 Range 对待: 上游会重算 body, 切片语义不成立。
            return [Scene::ApiJson, IdentityKind::MutableApi, false, false,
                ['ref' => '', 'path' => '', 'api_endpoint' => ltrim($pathPart, '/'),
                    'owner' => strtolower($seg[1] ?? ''), 'repo' => strtolower($seg[2] ?? ''), 'opts' => []]];
        }

        if (UpstreamMap::isSignedAssetHost($host)) {
            // 一次性签名 URL: 绝不缓存、绝不回吐、绝不复用 Location。
            // 两个签名落点(objects 与 release-assets)都得认, 只认一个就是"换了域名就退化成
            // 普通 ref"的静默错误。
            $warnings[] = 'signed_url_not_cacheable';

            return [Scene::ReleaseAsset, IdentityKind::Ambiguous, true, false,
                ['ref' => '', 'path' => '', 'opts' => []]];
        }

        // github.com 与其馀白名单域: 按路径关键字给最保守的能力位。
        $joined = strtolower($pathPart);
        if (str_contains($joined, '/releases/download/')) {
            return [Scene::ReleaseAsset, IdentityKind::RefName, true, true,
                ['ref' => self::segAfter($seg, 'download') ?? '', 'path' => '', 'asset_name' => self::baseName($pathPart),
                    'owner' => strtolower($seg[0] ?? ''), 'repo' => strtolower($seg[1] ?? ''), 'opts' => []]];
        }
        if (str_contains($joined, '/releases/assets/')) {
            $id = (int) (self::segAfter($seg, 'assets') ?? 0);

            return [Scene::ReleaseAsset, $id > 0 ? IdentityKind::AssetId : IdentityKind::Ambiguous, true, true,
                ['path' => '', 'owner' => strtolower($seg[0] ?? ''), 'repo' => strtolower($seg[1] ?? ''),
                    'opts' => $id > 0 ? ['asset_id' => $id] : []]];
        }
        if (str_contains($joined, '/archive/')) {
            // ref 段带 .tar.gz/.zip 后缀, 所以 sha 判定必须在剥掉后缀之后做 —— 早判会把它
            // 认成普通段, 于是内容寻址的归档被当成可变 ref, 白丢一次 EDGE。
            $ref = self::refInArchivePath($seg) ?? '';
            $isSha = GitHubRef::looksLikeSha($ref);

            return [Scene::Archive, $isSha ? IdentityKind::CommitSha : IdentityKind::RefName, false, true,
                ['ref' => $ref, 'path' => '', 'archive_fmt' => UpstreamMap::fmtFromSuffix($joined) ?: 'tar.gz',
                    'sha' => $isSha ? strtolower($ref) : $sha, 'owner' => strtolower($seg[0] ?? ''), 'repo' => strtolower($seg[1] ?? ''), 'opts' => []]];
        }
        if (str_contains($joined, '/releases/latest') || str_contains($joined, '/releases/tag/')) {
            $warnings[] = 'latest_tag_unresolved_use_redirect';

            return [Scene::ReleaseAsset, IdentityKind::Ambiguous, true, true,
                ['ref' => self::segAfter($seg, 'tag') ?? '', 'path' => '', 'owner' => strtolower($seg[0] ?? ''), 'repo' => strtolower($seg[1] ?? ''), 'opts' => []]];
        }
        if ($host === UpstreamMap::HOST_GIST) {
            return [Scene::GistRaw, IdentityKind::RefName, true, true,
                ['ref' => '', 'path' => ltrim($pathPart, '/'), 'owner' => strtolower($seg[0] ?? ''), 'repo' => '', 'opts' => []]];
        }

        // 兜底: 原样重放, 让上游自己回答。假 200/HTML 由 Transport 的 wrong_content 判定处理。
        $warnings[] = 'absolute_shape_unrecognized';

        return [Scene::Raw, $sha !== '' ? IdentityKind::CommitSha : IdentityKind::RefName, true, true,
            ['ref' => '', 'path' => ltrim($pathPart, '/'), 'owner' => strtolower($seg[0] ?? ''), 'repo' => strtolower($seg[1] ?? ''), 'opts' => []]];
    }

    // ------------------------------------------------------------------
    // 别名 / 结构化形式
    // ------------------------------------------------------------------

    /** 短别名分发。每个别名一条正则, 语法固定; config 的 alias 表只决定"开不开"。 */
    private function parseAlias(string $path, array $passthrough, string $expectedSha, array &$warnings): ?GitHubRef
    {
        $trimmed = ltrim($path, '/');
        $first = strtolower((string) strtok($trimmed . '/', '/'));
        if ($first === '' || !isset($this->alias[$first])) {
            return null;
        }
        if ($first === 'gh' && !$this->enableGh) {
            return null;
        }

        $body = substr($trimmed, strlen($first));
        $body = ltrim($body, '/');

        return match ($first) {
            'gh'       => $this->aliasGh($body, $passthrough, $expectedSha, $warnings),
            'raw'      => $this->aliasRaw($body, $passthrough, $expectedSha, $warnings),
            'release'  => $this->aliasRelease($body, $passthrough, $expectedSha, $warnings),
            'latest'   => $this->aliasLatest($body, $passthrough, $expectedSha, $warnings),
            'zip', 'tar', 'archive' => $this->aliasArchive($first, $body, $passthrough, $expectedSha, $warnings),
            'api'      => $this->aliasApi($body, $passthrough, $expectedSha, $warnings),
            'gist'     => $this->aliasGist($body, $passthrough, $expectedSha, $warnings),
            default    => null,
        };
    }

    /**
     * /gh/{owner}/{repo}@{ref}/{path} —— 推荐给脚本与 Agent 的无歧义形式。
     *
     * '@' 定住了 ref 的起点但定不住终点(分支名可以含 '/'), 所以终点由 takeRef() 的
     * 语法限定: 只有 refs/heads/x、heads/x、pull/N/head、40 位 sha 这类"自己说明了自己
     * 长度"的写法能安全跨越 '/'。裸名一律取一段, 剩下的都算 path。
     */
    private function aliasGh(string $body, array $q, string $sha, array &$warnings): ?GitHubRef
    {
        if (preg_match('#\A([^/]+)/([^/@]+)@(.*)\z#s', $body, $m) === 1) {
            $tail = explode('/', $m[3]);
            $ref = $this->takeRef($tail, $warnings);
            $path = implode('/', $tail);

            return $this->buildRaw($m[1], $m[2], $ref, $path, $q, $sha, $warnings);
        }

        // 容错: 忘了 '@' 时退化成 /gh/{o}/{r}/{ref}/{path}, 与 raw 别名同构。
        if (substr_count($body, '/') >= 2) {
            return $this->aliasRaw($body, $q, $sha, $warnings);
        }

        throw GhpError::make(GhpError::UNPARSEABLE, 'gh 形式需要 {owner}/{repo}@{ref}[/{path}]');
    }

    /** /raw/{owner}/{repo}/{ref}/{path} —— 也接受 repo@ref 与 blob/tree 标记写法。 */
    private function aliasRaw(string $body, array $q, string $sha, array &$warnings): ?GitHubRef
    {
        $seg = array_values(array_filter(explode('/', $body), static fn (string $s): bool => $s !== ''));
        if (count($seg) < 3) {
            throw GhpError::make(GhpError::UNPARSEABLE, 'raw 形式需要 {owner}/{repo}/{ref}/{path}');
        }
        $owner = $seg[0];
        $repo = $seg[1];

        if (str_contains($repo, '@')) {
            [$repo, $head] = explode('@', $repo, 2);
            $tail = $head === '' ? array_slice($seg, 2) : array_merge([$head], array_slice($seg, 2));
        } elseif (strtolower($seg[2]) === 'blob' && count($seg) >= 4) {
            // 兼容 /raw/{o}/{r}/blob/{ref}/{path}: 别名占了第 0 段, 所以标记落在第 3 段。
            // 只认这一个位置, 不做全局 strpos —— /tree/main/blob/x 里的 blob 在深处,
            // 全局替换会把目录路径改写成错误的 raw 地址(此类项目最常见的一类 bug)。
            $tail = array_slice($seg, 3);
            $warnings[] = 'alias_blob_marker_consumed';
        } elseif (strtolower($seg[2]) === 'tree' && count($seg) >= 4) {
            // 目录形态: raw host 对目录回 404, 只有 contents API 能列。
            $t = array_slice($seg, 3);
            $ref = $this->takeRef($t, $warnings);

            return $this->buildContents($owner, $repo, $ref, implode('/', $t), $q, $sha, $warnings);
        } else {
            $tail = array_slice($seg, 2);
        }

        $ref = $this->takeRef($tail, $warnings);
        $path = implode('/', $tail);

        return $this->buildRaw($owner, $repo, $ref, $path, $q, $sha, $warnings);
    }

    /** /release/{owner}/{repo}/{tag}/{asset} */
    private function aliasRelease(string $body, array $q, string $sha, array &$warnings): ?GitHubRef
    {
        $seg = array_values(array_filter(explode('/', $body), static fn (string $s): bool => $s !== ''));
        if (count($seg) < 3) {
            throw GhpError::make(GhpError::UNPARSEABLE, 'release 形式需要 {owner}/{repo}/{tag}/{asset}');
        }
        $owner = $seg[0];
        $repo = $seg[1];
        $tail = array_slice($seg, 2);
        // tag 用语法限定切一段: tag 名极少含 '/', 而资产名可能含 '/'(scoped 包名)。
        $tag = $this->takeRef($tail, $warnings);
        $asset = implode('/', $tail);

        if ($asset === '') {
            throw GhpError::make(GhpError::UNPARSEABLE, 'release 形式缺少资产名');
        }

        $url = $this->map->releaseDownloadUrl(strtolower($owner), strtolower($repo), $tag, $asset);

        return GitHubRef::make(
            Scene::ReleaseAsset,
            IdentityKind::RefName,
            $url,
            $owner,
            $repo,
            ['ref' => $tag, 'asset_name' => $asset, 'download_name' => self::baseName($asset),
                'needs_redirect_resolve' => true, 'api_query' => $q, 'expected_sha256' => $sha,
                'warnings' => self::push($warnings, 'release_needs_internal_redirect_resolve')]
        );
    }

    /**
     * /latest/{owner}/{repo}[/{asset}] —— 免 API 路径。
     *
     * 上游给的是 releases/latest(302 到具体 tag), 所以这里只把"要跳一次"标出来;
     * 拿到 Location 后由调用方用 UpstreamMap::latestTagFromRedirect() 反解 tag, 再拼
     * releaseDownloadUrl()。API 只作兜底, 因为本机实测 api.github.com 直连与经镜像都是 403。
     */
    private function aliasLatest(string $body, array $q, string $sha, array &$warnings): ?GitHubRef
    {
        $seg = array_values(array_filter(explode('/', $body), static fn (string $s): bool => $s !== ''));
        if (count($seg) < 2) {
            throw GhpError::make(GhpError::UNPARSEABLE, 'latest 形式需要 {owner}/{repo}[/{asset}]');
        }
        $owner = strtolower($seg[0]);
        $repo = strtolower($seg[1]);
        $asset = implode('/', array_slice($seg, 2));
        $url = $this->map->releasesLatestUrl($owner, $repo);

        $warnings[] = $asset === '' ? 'latest_redirect_resolves_tag' : 'latest_tag_from_redirect_required';

        return GitHubRef::make(
            Scene::ReleaseAsset,
            $asset === '' ? IdentityKind::Ambiguous : IdentityKind::RefName,
            $url,
            $owner,
            $repo,
            ['asset_name' => $asset, 'download_name' => self::baseName($asset), 'needs_redirect_resolve' => true,
                'api_query' => $q, 'expected_sha256' => $sha, 'warnings' => $warnings]
        );
    }

    /**
     * /zip /tar /archive 三种别名。
     *
     * archive 一律 allow_range=false: 实测 codeload 对 Range: bytes=0-64 回 200 全量,
     * 注入 Accept-Ranges 或按 Range 切片服务都会产出损坏文件。
     */
    private function aliasArchive(string $alias, string $body, array $q, string $sha, array &$warnings): ?GitHubRef
    {
        $seg = array_values(array_filter(explode('/', $body), static fn (string $s): bool => $s !== ''));
        $hasAt = str_contains((string) ($seg[1] ?? ''), '@');
        if (count($seg) < 3 && !$hasAt) {
            throw GhpError::make(GhpError::UNPARSEABLE, $alias . ' 形式需要 {owner}/{repo}/{ref} 或 {owner}/{repo}@{ref}');
        }
        if (count($seg) < 2) {
            throw GhpError::make(GhpError::UNPARSEABLE, $alias . ' 形式缺少 owner/repo');
        }
        $owner = strtolower($seg[0]);
        $repo = strtolower($seg[1]);
        $tail = array_slice($seg, 2);

        // 同时支持 {o}/{r}/{ref} 与 {o}/{r}@{ref}。@ 形式不是语法糖: 分支名与 tag 名本身可以含
        // '/'(refs/tags/codeql/v2.12.0 这类真实存在), 用 '/' 分隔时无法与后续段区分, 只有 @ 能
        // 唯一确定 repo 与 ref 的边界。不认 @ 会把 "git@refs" 当成仓库名静默拼出错误 URL。
        if ($hasAt) {
            [$repo, $refHead] = explode('@', $repo, 2);
            if ($refHead !== '') {
                $tail = array_merge([$refHead], $tail);
            }
        }

        $fmt = match ($alias) {
            'zip' => 'zip',
            'tar' => 'tar.gz',
            default => UpstreamMap::fmtFromSuffix($body) !== '' ? UpstreamMap::fmtFromSuffix($body) : 'tar.gz',
        };

        // 文件名形态的 ref(refs/heads/main.tar.gz)把后缀吃掉再判身份。
        $lastIdx = count($tail) - 1;
        $suffix = UpstreamMap::fmtFromSuffix($tail[$lastIdx]);
        if ($suffix !== '') {
            $tail[$lastIdx] = substr($tail[$lastIdx], 0, 0 - strlen($suffix) - 1);
            $fmt = $suffix;
        }
        // 归档形式没有 path, 所以尾部所有段都属于 ref —— 交给 splitRef 判定歧义。
        $ref = implode('/', $tail);
        if ($ref === '') {
            throw GhpError::make(GhpError::UNPARSEABLE, '归档缺少 ref');
        }
        if (!GitHubRef::looksLikeSha($ref) && !preg_match('#\A(refs/|heads/|tags/|pull/\d)#i', $ref)) {
            $warnings[] = 'bare_ref_resolution_order';
        }

        [$refClean, $identity] = $this->splitRef($ref, $warnings);
        $url = $this->map->archiveUrl($owner, $repo, $refClean, $fmt);

        return GitHubRef::make(
            Scene::Archive,
            $identity,
            $url,
            $owner,
            $repo,
            ['ref' => $refClean, 'sha' => GitHubRef::looksLikeSha($refClean) ? strtolower($refClean) : '',
                'archive_fmt' => $fmt, 'download_name' => sprintf('%s-%s.%s', $repo, $refClean !== '' ? $refClean : 'archive', $fmt),
                // allow_range=false: 302 落地的是 codeload, 实测它对 Range 回 200 全量。
                // needs_redirect_resolve=true: archiveUrl 现在发的是 github.com/archive 形态,
                // 它必 302 到 codeload, 不先跟一跳就既拿不到真实体积也确认不了源有没有吞掉跳转。
                'allow_range' => false, 'needs_redirect_resolve' => true,
                'api_query' => $q, 'expected_sha256' => $sha,
                'warnings' => self::push($warnings, 'archive_range_unsupported')]
        );
    }

    /** /api/{endpoint} -> api.github.com */
    private function aliasApi(string $body, array $q, string $sha, array &$warnings): ?GitHubRef
    {
        $endpoint = trim($body, '/');
        if ($endpoint === '') {
            throw GhpError::make(GhpError::UNPARSEABLE, 'api 形式缺少 endpoint');
        }
        $url = $this->map->apiUrl($endpoint, self::joinQuery($q));
        $seg = explode('/', $endpoint);
        $owner = strtolower($seg[1] ?? '');
        $repo = strtolower($seg[2] ?? '');
        if (($seg[0] ?? '') !== 'repos') {
            $owner = '';
            $repo = '';
        }

        return GitHubRef::make(
            Scene::ApiJson,
            IdentityKind::MutableApi,
            $url,
            $owner,
            $repo,
            ['api_endpoint' => $endpoint, 'allow_range' => false, 'expected_sha256' => $sha,
                'warnings' => self::push($warnings, 'api_edge_cache_disabled_v1')]
        );
    }

    /** /gist/{owner}/{gistId}[/{revision}][/{path}] */
    private function aliasGist(string $body, array $q, string $sha, array &$warnings): ?GitHubRef
    {
        $seg = explode('/', $body);
        if (count($seg) < 2 || $seg[0] === '' || $seg[1] === '') {
            throw GhpError::make(GhpError::UNPARSEABLE, 'gist 形式需要 {owner}/{gistId}[/{path}]');
        }
        $owner = strtolower($seg[0]);
        $id = $seg[1];

        $rest = array_slice($seg, 2);
        $rev = '';
        // 只有 40 位十六进制才当 revision: gist id 本身也是十六进制但只有 20~32 位,
        // 长度是这里唯一可靠的区分依据。
        if (isset($rest[0]) && GitHubRef::looksLikeSha($rest[0])) {
            $rev = strtolower((string) array_shift($rest));
        }
        if (isset($rest[0]) && strtolower((string) $rest[0]) === 'raw') {
            array_shift($rest);
        }
        $path = implode('/', $rest);
        $url = $this->map->gistRawUrl($owner, $id, $path, $rev);

        return GitHubRef::make(
            Scene::GistRaw,
            $rev !== '' ? IdentityKind::GistRev : IdentityKind::RefName,
            $url,
            $owner,
            $id,
            ['ref' => $rev, 'path' => $path, 'sha' => $rev, 'download_name' => self::baseName($path),
                'api_query' => $q, 'expected_sha256' => $sha,
                'warnings' => self::push($warnings, 'gist_without_revision_mutable')]
        );
    }

    // ------------------------------------------------------------------
    // 构造块
    // ------------------------------------------------------------------

    /** raw 场景的统一出口: ref/path 判定 + blob 标记丢弃 + 身份判定都在这里。 */
    private function buildRaw(string $owner, string $repo, string $ref, string $path, array $q, string $sha, array &$warnings): GitHubRef
    {
        $owner = strtolower($owner);
        $repo = strtolower($repo);
        if ($owner === '' || $repo === '') {
            throw GhpError::make(GhpError::UNPARSEABLE, 'owner/repo 为空');
        }

        [$refClean, $identity] = $this->splitRef($ref, $warnings);
        if ($refClean === '') {
            throw GhpError::make(GhpError::UNPARSEABLE, '缺少 ref');
        }

        // 文件本身是 HTML 时 raw 也返回 HTML, 这里不做内容判断, 只保证 host 正确。
        $url = $this->map->rawUrl($owner, $repo, $refClean, $path);
        if ($q !== []) {
            $url .= '?' . self::joinQuery($q);
        }

        return GitHubRef::make(
            Scene::Raw,
            $identity,
            $url,
            $owner,
            $repo,
            ['ref' => $refClean, 'sha' => GitHubRef::looksLikeSha($refClean) ? strtolower($refClean) : '',
                'path' => $path, 'download_name' => self::baseName($path), 'api_query' => $q,
                'expected_sha256' => $sha, 'warnings' => $warnings]
        );
    }

    /** tree 形态 -> api contents(目录无法当 raw 取)。 */
    private function buildContents(string $owner, string $repo, string $ref, string $path, array $q, string $sha, array &$warnings): GitHubRef
    {
        $owner = strtolower($owner);
        $repo = strtolower($repo);
        $url = $this->map->contentsApiUrl($owner, $repo, $ref, $path);

        $warnings[] = 'tree_served_via_contents_api';

        return GitHubRef::make(
            Scene::ApiJson,
            IdentityKind::MutableApi,
            $url,
            $owner,
            $repo,
            ['ref' => $ref, 'path' => $path, 'api_endpoint' => 'repos/' . $owner . '/' . $repo . '/contents' . ($path !== '' ? '/' . $path : ''),
                'allow_range' => false, 'expected_sha256' => $sha, 'warnings' => $warnings]
        );
    }

    /**
     * ref 与 path 的四级判定(由稳到不稳):
     *   1. 40 位十六进制 -> CommitSha, 内容寻址, 可长 TTL 与 EDGE 直出。
     *   2. 全限定 refs/heads|refs/tags|heads|tags|pull -> RefName, 类型已定, 名字可含 '/'。
     *   3. 单段裸名 -> RefName(GitHub 自己按 branch 优先解析)。
     *   4. 多段裸名 -> Ambiguous: branch 与 tag 可同名, 而 GitHub 在 raw 与 archive 两条
     *      链路上的优先级并不一致。默认(autoref_resolve=false)抛 AMBIGUOUS_REF 让用户改写成
     *      refs/heads/xxx 或用绝对形式(那条不解析语义, 按字节重放一定成)。
     *
     * @return array{0:string,1:IdentityKind}
     */
    private function splitRef(string $ref, array &$warnings): array
    {
        $ref = trim($ref, '/');
        if ($ref === '') {
            return ['', IdentityKind::Ambiguous];
        }

        if (GitHubRef::looksLikeSha($ref)) {
            return [strtolower($ref), IdentityKind::CommitSha];
        }

        $lower = strtolower($ref);
        foreach (['refs/heads/', 'refs/tags/', 'refs/pull/', 'heads/', 'tags/'] as $q2) {
            if (str_starts_with($lower, $q2)) {
                return [$ref, IdentityKind::RefName];
            }
        }
        if (preg_match('#\Arefs/\A#', $ref) === 1) {
            return [$ref, IdentityKind::RefName];
        }
        if (preg_match('#\Apull/\d+#', $lower) === 1) {
            return [$ref, IdentityKind::RefName];
        }

        if (str_contains($ref, '/')) {
            if (!$this->autoRefResolve) {
                throw GhpError::make(GhpError::AMBIGUOUS_REF, $ref, ['ref' => $ref]);
            }
            // 开关打开时也不在这里调 API(RefParser 不发请求): 按 branch 优先接受并告警,
            // 让调用方决定是否用 matching-refs 预解析后重写。
            $warnings[] = 'ambiguous_ref_accepted_branch_first';

            return [$ref, IdentityKind::RefName];
        }

        return [$ref, IdentityKind::RefName];
    }

    /**
     * 从段数组头部切走 ref, 剩下的原样留在数组里(调用方 join 成 path)。
     *
     * 为什么不能"取一段就完事": 分支名可以含 '/', 而 tag 与 branch 可以同名, 所以 ref 的
     * 终点只有在"写法自己说明了长度"时才确定 —— refs/heads/x、heads/x、pull/N/head、
     * 40 位 sha 属于这一类。其余情况一律取一段并把剩下的当 path: 这与 GitHub raw host 的
     * 解析顺序一致, 也是唯一不查 API 就能对齐上游的做法。
     *
     * 需要"整段都是 ref"的场景(归档别名)不走这里, 它把整个尾部交给 splitRef() 判定歧义。
     */
    private function takeRef(array &$seg, array &$warnings): string
    {
        if ($seg === [] || $seg[0] === '') {
            return '';
        }

        if (GitHubRef::looksLikeSha($seg[0])) {
            return strtolower((string) array_shift($seg));
        }

        if (strtolower($seg[0]) === 'refs' && count($seg) >= 3) {
            $type = strtolower($seg[1]);
            $n = in_array($type, ['heads', 'tags', 'notes'], true) ? 3 : 0;
            if ($type === 'pull') {
                // refs/pull/N 之后可跟 head|merge, 带上才完整
                $n = isset($seg[3]) && in_array(strtolower($seg[3]), ['head', 'merge'], true) ? 4 : 3;
            }
            if ($n > 0) {
                $ref = implode('/', array_slice($seg, 0, $n));
                array_splice($seg, 0, $n);

                return $ref;
            }
        }

        if (count($seg) >= 2 && in_array(strtolower($seg[0]), ['heads', 'tags', 'notes'], true)) {
            $ref = $seg[0] . '/' . $seg[1];
            array_splice($seg, 0, 2);

            return $ref;
        }

        if (count($seg) >= 2 && strtolower($seg[0]) === 'pull' && preg_match('#\A\d+\z#', $seg[1]) === 1) {
            $n = isset($seg[2]) && in_array(strtolower($seg[2]), ['head', 'merge'], true) ? 3 : 2;
            $ref = implode('/', array_slice($seg, 0, $n));
            array_splice($seg, 0, $n);

            return $ref;
        }

        return (string) array_shift($seg);
    }

    // ------------------------------------------------------------------
    // 静态小工具
    // ------------------------------------------------------------------

    /**
     * 只允许 GET/HEAD 进代理解析。
     *
     * OPTIONS 必须在入口拦掉(它没有路径语义且 CORS 预检不该打到上游), 所以走到这里仍然
     * 抛 405 是有意为之: 谁忘了拦, 这里会挡住而不是把 OPTIONS 转发出去。
     */
    private function assertMethod(): void
    {
        $m = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? ''));
        if ($m !== '' && !in_array($m, ['GET', 'HEAD'], true)) {
            throw GhpError::make(GhpError::UNSUPPORTED_METHOD, $m);
        }
    }

    /** 剥控制字符。与 UrlGuard 同一套规则, 两边行为不能分叉。 */
    private static function clean(string $s): string
    {
        return preg_replace('/[\x00-\x20\x7F]/', '', $s) ?? '';
    }

    private static function stripLeadingSlash(string $s): string
    {
        return ltrim($s, '/');
    }

    /**
     * 路径段不得出现 '.' 或 '..'(含 %2e 形态)。
     *
     * 必须连 %2e 一起看: normPath 会逐段 decode, 于是 %2e%2e 与 .. 在缓存键上等价,
     * 只挡字面写法等于没挡。
     */
    private static function assertNoDotSegments(string $path): void
    {
        foreach (explode('/', $path) as $seg) {
            if ($seg === '' || $seg === '.' || $seg === '..') {
                if ($seg === '.' || $seg === '..') {
                    throw GhpError::make(GhpError::PATH_TRAVERSAL, $seg);
                }
                continue;
            }
            $dec = preg_replace('/%2e/i', '.', $seg) ?? $seg;
            if ($dec === '.' || $dec === '..') {
                throw GhpError::make(GhpError::PATH_TRAVERSAL, $seg);
            }
        }
    }

    /**
     * 按 '&' 与 '=' 字面切分, 一个字节都不解码。
     *
     * @return array<int,array{0:string,1:string}>
     */
    private static function splitQuery(string $query): array
    {
        if ($query === '') {
            return [];
        }
        $out = [];
        foreach (explode('&', $query) as $pair) {
            if ($pair === '') {
                continue;
            }
            $eq = strpos($pair, '=');
            if ($eq === false) {
                $out[] = [$pair, ''];
            } else {
                $out[] = [substr($pair, 0, $eq), substr($pair, $eq + 1)];
            }
        }

        return $out;
    }

    /** 原样拼回: 键与值都是进来的字节, 不重新编码。 */
    private static function joinQuery(array $pairs): string
    {
        $out = [];
        foreach ($pairs as $p) {
            $out[] = $p[1] === '' ? $p[0] : $p[0] . '=' . $p[1];
        }

        return implode('&', $out);
    }

    /** 丢弃控制键与凭据键, 其余原样透传。 */
    private static function filterQuery(array $pairs): array
    {
        $out = [];
        foreach ($pairs as [$k, $v]) {
            $low = strtolower(rawurldecode($k));
            if (in_array($low, self::CONTROL_KEYS, true) || in_array($low, self::DENY_KEYS, true)) {
                continue;
            }
            $out[] = [$k, $v];
        }

        return $out;
    }

    private static function pick(array $pairs, array $names): string
    {
        foreach ($pairs as [$k, $v]) {
            if (in_array(strtolower(rawurldecode($k)), $names, true) && $v !== '') {
                return $v;
            }
        }

        return '';
    }

    /** ?sha256= 必须是 64 位十六进制, 否则视为噪声丢弃(不能把乱码当校验值)。 */
    private static function shaParam(array $pairs): string
    {
        foreach ($pairs as [$k, $v]) {
            if (strtolower(rawurldecode($k)) === 'sha256') {
                $v = strtolower(trim($v));

                return preg_match('/\A[0-9a-f]{64}\z/', $v) === 1 ? $v : '';
            }
        }

        return '';
    }

    private static function baseName(string $path): string
    {
        $path = rtrim($path, '/');
        $pos = strrpos($path, '/');

        return $pos === false ? $path : substr($path, $pos + 1);
    }

    private static function push(array $warnings, string $w): array
    {
        if (!in_array($w, $warnings, true)) {
            $warnings[] = $w;
        }

        return $warnings;
    }

    /** 在段数组里找关键字后面那一段。 */
    private static function segAfter(array $seg, string $key): ?string
    {
        foreach ($seg as $i => $s) {
            if (strtolower($s) === $key && isset($seg[$i + 1])) {
                return $seg[$i + 1];
            }
        }

        return null;
    }

    /** /archive/refs/heads/main(.tar.gz) 里取出 ref。 */
    private static function refInArchivePath(array $seg): ?string
    {
        foreach ($seg as $i => $s) {
            if (strtolower($s) !== 'archive') {
                continue;
            }
            $tail = array_slice($seg, $i + 1);
            if ($tail === []) {
                return null;
            }
            $last = count($tail) - 1;
            $fmt = UpstreamMap::fmtFromSuffix($tail[$last]);
            if ($fmt !== '') {
                $tail[$last] = substr($tail[$last], 0, 0 - strlen($fmt) - 1);
            }

            return implode('/', $tail);
        }

        return null;
    }
}
