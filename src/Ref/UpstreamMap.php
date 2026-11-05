<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 四场景的"引用 -> 上游绝对 URL"重写规则表, 以及 releases/latest 的免 API
 *             取 tag 规则。RefParser 的内部拼装器, 也可被 Transport 二次解析跳转时复用。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Ref;

use GhAccel\Config;

/**
 * 规则表独立成文件的原因: 这些映射是"GitHub 当前的 URL 形态"的快照, 会随上游改版变化,
 * 集中一处便于对照上游复查, 而不是散落在解析器的分支里。
 *
 * 两条最贵的规则:
 *  1. Release 资产的真实落点是 objects.githubusercontent.com(带一次性签名)。白名单少了
 *     这个域, 全部 Release 下载直接失败 —— 这是此类项目最常见的功能性 bug, 所以
 *     requiredHosts() 把清单显式暴露给自检。
 *  2. 归档走 codeload 且实测无视 Range, 所以体积/断点续传语义必须按"不支持 Range"处理。
 */
final class UpstreamMap
{
    public const HOST_MAIN      = 'github.com';
    public const HOST_RAW       = 'raw.githubusercontent.com';
    public const HOST_API       = 'api.github.com';
    public const HOST_CODELOAD  = 'codeload.github.com';
    public const HOST_OBJECTS   = 'objects.githubusercontent.com';
    /**
     * Release 资产 302 的当前落点(实测 2026-11: jq 与 cli 两个仓库都跳这里, 而
     * objects.githubusercontent.com 仍在别的 blob 流程上, 所以两个都必须在白名单里)。
     */
    public const HOST_RELEASE_ASSETS = 'release-assets.githubusercontent.com';
    public const HOST_GIST      = 'gist.github.com';
    public const HOST_GIST_RAW  = 'gist.githubusercontent.com';

    /** 归档 fmt -> codeload 路径段。 */
    private const ARCHIVE_SEG = [
        'zip'    => 'zip',
        'tar.gz' => 'tar.gz',
        'tgz'    => 'tar.gz',
    ];

    public function __construct(private readonly Config $cfg)
    {
    }

    /**
     * 白名单里必须出现的域名。config 少配一条就有一整类场景静默失败, 自检必须能查出来。
     *
     * @return array<int,string>
     */
    public static function requiredHosts(): array
    {
        return [
            self::HOST_MAIN,
            self::HOST_RAW,
            self::HOST_API,
            self::HOST_CODELOAD,
            self::HOST_OBJECTS,
            self::HOST_RELEASE_ASSETS,
            self::HOST_GIST,
            self::HOST_GIST_RAW,
        ];
    }

    /**
     * 两个签名落点域名的共同特征: 一次性 SAS 参数, 时效以分钟计。
     *
     * 命中它们的引用一律不给缓存资格: 复用过期签名等于把"取不到字节"当成源的错,
     * 而回吐给用户更是让用户拿着一个必然 403 的地址去重试。
     */
    public static function isSignedAssetHost(string $host): bool
    {
        return $host === self::HOST_OBJECTS || $host === self::HOST_RELEASE_ASSETS;
    }

    /** 缺配置清单。返回空数组表示白名单完整。 */
    public function missingAllowedHosts(): array
    {
        $allowed = [];
        foreach ((array) $this->cfg->arr('security.allowed_hosts') as $h) {
            $allowed[strtolower(trim((string) $h))] = true;
        }

        return array_values(array_filter(
            self::requiredHosts(),
            static fn (string $h): bool => !isset($allowed[$h])
        ));
    }

    /** 单文件原始字节。 */
    public function rawUrl(string $owner, string $repo, string $ref, string $path): string
    {
        return sprintf(
            'https://%s/%s/%s/%s/%s',
            self::HOST_RAW,
            $owner,
            $repo,
            $this->rawRefSegment($ref),
            ltrim($path, '/')
        );
    }

    /**
     * 目录树 -> api contents。
     *
     * 只有 API 能列目录: raw.githubusercontent.com 对目录返回 404, 而 github.com 的 HTML
     * 页面不是数据源。ref 走 query 而不是路径, 因为分支名含 '/' 时路径形式会歧义。
     */
    public function contentsApiUrl(string $owner, string $repo, string $ref, string $path): string
    {
        $path = ltrim($path, '/');
        $url = sprintf('https://%s/repos/%s/%s/contents', self::HOST_API, $owner, $repo);
        if ($path !== '') {
            $url .= '/' . GitHubRef::normPath($path);
        }
        if ($ref !== '') {
            $url .= '?' . http_build_query(['ref' => $ref], '', '&', PHP_QUERY_RFC3986);
        }

        return $url;
    }

    /** Release 资产。真实落点是 objects 域, 所以必须内部解析 302。 */
    public function releaseDownloadUrl(string $owner, string $repo, string $tag, string $asset): string
    {
        return sprintf(
            'https://%s/%s/%s/releases/download/%s/%s',
            self::HOST_MAIN,
            $owner,
            $repo,
            $this->encodeSegment($tag),
            $this->encodeSegment($asset)
        );
    }

    /** 按数字 asset id 取资产: 比 (tag, 文件名) 稳, 同名重传不会拿到旧字节。 */
    public function releaseAssetByIdUrl(string $owner, string $repo, int $assetId): string
    {
        return sprintf('https://%s/%s/%s/releases/assets/%d', self::HOST_MAIN, $owner, $repo, $assetId);
    }

    /** releases/latest: 302 到具体 tag, 是本项目的免 API 路径。 */
    public function releasesLatestUrl(string $owner, string $repo): string
    {
        return sprintf('https://%s/%s/%s/releases/latest', self::HOST_MAIN, $owner, $repo);
    }

    /**
     * 归档。上游默认发 github.com/{o}/{r}/archive/{ref}.{fmt}, 由它 302 到 codeload。
     *
     * 曾经这里是直拼 codeload 的(省一跳), 实测证伪了: 公共镜像普遍**屏蔽 codeload 直链** ——
     * ghfast.top 对 `…/https://codeload.github.com/git/git/zip/…` 回 403, 而对
     * `…/https://github.com/git/git/archive/refs/tags/v2.40.0.zip` 回 200。直拼的后果是
     * "源明明活着、归档全部失败", 且失败长得很像资源不存在。
     * 多跟一跳 302 换来的是在所有镜像形态上一致可用, 这个代价可以接受。
     */
    public function archiveUrl(string $owner, string $repo, string $ref, string $fmt): string
    {
        $fmtL = strtolower($fmt) === 'tgz' ? 'tar.gz' : $fmt;
        // github.com 的 archive 形态是 ref 在前、fmt 在后, 与 codeload 相反。
        $refPart = GitHubRef::normalizeRef($ref);

        return sprintf(
            'https://%s/%s/%s/archive/%s.%s',
            self::HOST_MAIN,
            $owner,
            $repo,
            $refPart,
            $fmtL
        );
    }

    /** codeload 形态只在"用户本来就直给了 codeload URL"时用于比对, 见 ARCHIVE_SEG。 */
    public static function codeloadArchiveUrl(string $owner, string $repo, string $ref, string $fmt): string
    {
        $seg = self::ARCHIVE_SEG[strtolower($fmt)] ?? 'tar.gz';
        $refPart = GitHubRef::looksLikeSha($ref) ? strtolower($ref) : GitHubRef::normalizeRef($ref);

        return sprintf('https://%s/%s/%s/%s/%s', self::HOST_CODELOAD, $owner, $repo, $seg, $refPart);
    }

    /** API JSON。endpoint 不含前导斜杠, 逐段重编码但不改语义。 */
    public function apiUrl(string $endpoint, string $rawQuery = ''): string
    {
        $url = 'https://' . self::HOST_API . '/' . ltrim($endpoint, '/');
        if ($rawQuery !== '') {
            $url .= '?' . $rawQuery;
        }

        return $url;
    }

    /**
     * gist 原始文件。
     *
     * 真实形态是 {owner}/{id}/raw/{file} 与 {owner}/{id}/raw/{revision}/{file}: 'raw' 是
     * 固定段而不是可省的 ref 位, 拼成 raw/raw/ 会 404。带 revision 才是不可变的。
     *
     * 选 gist.githubusercontent.com 而不是 gist.github.com: 前者不经 HTML 渲染,
     * 换行与 BOM 不会被改写。
     */
    public function gistRawUrl(string $owner, string $gistId, string $path, string $revision = ''): string
    {
        return sprintf(
            'https://%s/%s/%s/raw/%s%s',
            self::HOST_GIST_RAW,
            $owner,
            $gistId,
            $revision !== '' ? $revision . '/' : '',
            ltrim($path, '/')
        );
    }

    /**
     * 从 releases/latest 的 302 Location 反解 tag。0 次 API 调用。
     *
     * 为什么必须是主路径而不是优化: 本机实测 api.github.com 直连与经镜像都回 403
     * (administrative rule), 依赖 API 的实现在这类网络上等于 releases/latest 完全不可用。
     *
     * 支持三种 Location 形态:
     *   https://github.com/o/r/releases/tag/v1.2.3
     *   /o/r/releases/tag/v1.2.3              (相对形态, 由 UrlGuard 绝对化后传进来)
     *   https://github.com/o/r/releases/expanded_assets/v1.2.3 (上游改版时的备用锚点)
     * tag 里含 '/' 时(GitHub 允许)取锚点之后的全部剩余路径, 不做段数假设。
     *
     * 结构性关键字大小写不敏感匹配, 但 tag 本体一个字节都不许改 —— tag 名大小写敏感,
     * 顺手 strtolower 会让 Release-v1 变成 404。
     *
     * @return string 解析不出返回空串, 由调用方决定回落到 API
     */
    public static function latestTagFromRedirect(string $location, string $owner = '', string $repo = ''): string
    {
        $loc = trim($location);
        if ($loc === '' || str_contains($loc, '\\')) {
            return '';
        }

        // host 复校: 这个函数的入参来自上游 302, 不检查就等于"任何一路都能告诉我们 tag"。
        // 相对形态(没有 host)由 UrlGuard 绝对化后传进来, 那时 host 已经过了白名单。
        $host = strtolower((string) (parse_url($loc, PHP_URL_HOST) ?: ''));
        if ($host !== '' && $host !== self::HOST_MAIN && !str_ends_with($host, '.' . self::HOST_MAIN)) {
            return '';
        }

        $path = (string) (parse_url($loc, PHP_URL_PATH) ?: '');
        if ($path === '' && str_starts_with($loc, '/')) {
            $path = $loc;
        }
        $path = trim($path, '/');
        if ($path === '') {
            return '';
        }

        $seg = explode('/', $path);
        $anchor = -1;
        foreach ($seg as $i => $s) {
            if ($i >= 2 && strcasecmp($s, 'tag') === 0) {
                $anchor = $i;
                break;
            }
        }
        if ($anchor < 3 || $anchor + 1 >= count($seg)) {
            return '';
        }
        if (strcasecmp($seg[$anchor - 1], 'releases') !== 0) {
            return '';
        }

        $segOwner = (string) ($seg[$anchor - 3] ?? '');
        $segRepo = (string) ($seg[$anchor - 2] ?? '');
        if ($owner !== '' && strcasecmp($segOwner, $owner) !== 0) {
            return '';
        }
        if ($repo !== '' && strcasecmp($segRepo, $repo) !== 0) {
            return '';
        }

        $tagSegs = array_slice($seg, $anchor + 1);
        if ($tagSegs === []) {
            return '';
        }
        $tag = implode('/', array_map(static fn (string $s): string => rawurldecode($s), $tagSegs));

        return ($tag === '' || strcasecmp($tag, 'latest') === 0) ? '' : $tag;
    }

    /** 兜底: 免 API 路径失败时才用。本机实测常被 403, 所以只作兜底而非主路径。 */
    public static function latestTagApiUrl(string $owner, string $repo): string
    {
        return sprintf('https://%s/repos/%s/%s/releases/latest', self::HOST_API, $owner, $repo);
    }

    /** 从 releases/latest 的 API JSON 里取 tag_name; 解析不出返回空串。 */
    public static function latestTagFromApiJson(mixed $decoded): string
    {
        if (is_array($decoded) && isset($decoded['tag_name']) && is_string($decoded['tag_name'])) {
            return $decoded['tag_name'];
        }

        return '';
    }

    /** host -> 场景默认归档 fmt, 供绝对形式(不解析语义)回填 archiveFmt。 */
    public static function fmtFromSuffix(string $path): string
    {
        $p = strtolower($path);
        if (str_ends_with($p, '.zip')) {
            return 'zip';
        }
        if (str_ends_with($p, '.tar.gz') || str_ends_with($p, '.tgz')) {
            return 'tar.gz';
        }

        return '';
    }

    /**
     * raw host 的 ref 段原样保留(含 refs/ 前缀)。
     *
     * 实测 raw.githubusercontent.com 对 {o}/{r}/master/README、/refs/heads/master/README、
     * /heads/master/README 三种写法都回 200, 所以"退化成裸名"没有收益只有损失: 全限定形态
     * 是唯一能表达"这是 branch 不是同名 tag"的写法, 剥掉 refs/ 前缀就把用户消的歧义又还回去了。
     */
    private function rawRefSegment(string $ref): string
    {
        return $ref;
    }

    /**
     * 单段编码: 逐段 rawurlencode 但保留字面 '/'。
     *
     * 保留 '/' 是因为 tag 与 asset 名都可能含斜杠, 而 GitHub 的 Location 里它们就是字面
     * 斜杠; 把 '/' 转成 %2F 会让 releases/download 404。反过来 '%' 必须转义, 否则
     * 名字里带 "100%" 的资产会被当成一个残缺转义序列。
     */
    private function encodeSegment(string $seg): string
    {
        return implode('/', array_map('rawurlencode', explode('/', $seg)));
    }
}
