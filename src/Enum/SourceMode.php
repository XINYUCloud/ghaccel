<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 加速源的拼接形态。国内公共镜像只有这几种真实存在的形式, 拼错就 404,
 *             所以必须显式建模而不是靠约定。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Enum;

enum SourceMode: string
{
    /** {base}/https://github.com/... 保留完整原始 URL, 经典 ghproxy 形态, 最常见 */
    case PrefixFull = 'prefix_full';

    /** {base}/github.com/owner/repo/... 去掉协议头, 与上一种拼错就 404 */
    case PrefixPath = 'prefix_path';

    /** 把 host 的 github.com 替换成镜像域名, 路径不变。对 Release 的 302 常不覆盖 */
    case HostReplace = 'host_replace';

    /** 用户自定义模板, 支持 {base} {url} {host} {path} 占位符, 给自建 Worker 用 */
    case Template = 'template';

    /**
     * 由目标 URL 生成该源上的加速地址。
     *
     * 这个方法是 REDIRECT 模式的全部依赖, 也是"键里绝不含镜像域名"之后仍能复现
     * 请求的唯一途径。template 形态必须校验占位符, 否则用户写错模板会把请求发去
     * 非 GitHub 域 —— 那会让本机变成开放代理。
     */
    public function buildUrl(string $base, string $absoluteUrl, string $fallbackHost = 'github.com'): string
    {
        $base = rtrim($base, '/');

        return match ($this) {
            self::PrefixFull  => $base . '/' . $absoluteUrl,
            self::PrefixPath  => $base . '/' . self::stripScheme($absoluteUrl),
            self::HostReplace => $base . '/' . self::stripSchemeStart($absoluteUrl, $fallbackHost),
            self::Template    => $base,
        };
    }

    /** 模板渲染, 只有 Template 形态调用。 */
    public static function renderTemplate(string $template, string $base, string $absoluteUrl): string
    {
        $host = parse_url($absoluteUrl, PHP_URL_HOST) ?: '';
        $path = (string) (parse_url($absoluteUrl, PHP_URL_PATH) ?: '');
        $query = (string) (parse_url($absoluteUrl, PHP_URL_QUERY) ?: '');
        if ($query !== '') {
            $path .= '?' . $query;
        }

        return strtr($template, [
            '{base}'  => rtrim($base, '/'),
            '{url}'   => $absoluteUrl,
            '{host}'  => $host,
            '{path}'  => $path,
        ]);
    }

    public static function stripScheme(string $url): string
    {
        return preg_replace('#^[a-zA-Z][a-zA-Z0-9+.-]*://#', '', $url) ?? $url;
    }

    private static function stripSchemeStart(string $url, string $fallbackHost): string
    {
        $rest = self::stripScheme($url);

        return str_starts_with($rest, $fallbackHost . '/')
            ? $rest
            : $fallbackHost . '/' . $rest;
    }
}
