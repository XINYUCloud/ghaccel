<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 一次上游交互的结果值对象, 是 Transport 交给 Execution 与观测层的唯一契约。
 *             失败分型(FailureKind)在这里判定, 不在调用方各写一遍。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Transport;

use GhAccel\Enum\FailureKind;
use GhAccel\Enum\Scene;

final class UpstreamResult
{
    public function __construct(
        public readonly FailureKind $failure,
        public readonly int $status = 0,
        /** 小写键的响应头 */
        public readonly array $headers = [],
        public readonly int $bytesReceived = 0,
        /** 首字节耗时与总耗时, 毫秒 */
        public readonly float $ttfbMs = 0.0,
        public readonly float $totalMs = 0.0,
        public readonly string $finalUrl = '',
        public readonly string $primaryIp = '',
        public readonly int $redirectHops = 0,
        public readonly int $curlErrno = 0,
        public readonly string $curlError = '',
        /** 是否已把字节写给客户端 —— 决定还能不能安全回退 */
        public readonly bool $committed = false,
        /** 实测到的能力, 回写 RuntimeStat.measuredCaps */
        public readonly array $observedCaps = [],
        /** 客户端可见的下载文件名兜底 */
        public readonly string $downloadName = '',
    ) {
    }

    public function ok(): bool
    {
        return !$this->failure->isFailure();
    }

    public function header(string $name): string
    {
        return (string) ($this->headers[strtolower($name)] ?? '');
    }

    /** 上游声明的总体积; chunked 无长度时为 0, 此时禁止分片与 EDGE 直出。 */
    public function contentLength(): int
    {
        $v = $this->header('content-length');

        return $v === '' ? 0 : max(0, (int) $v);
    }

    /** 从 Content-Range 里解出资源总体积, 用于 416 判定与分片对齐。 */
    public function totalSizeFromRange(): int
    {
        if (preg_match('#bytes\s+\d+-\d+/(\d+|\*)#i', $this->header('content-range'), $m)) {
            return $m[1] === '*' ? 0 : (int) $m[1];
        }

        return 0;
    }

    /**
     * 内容形态校验: 判定"假 200"。
     *
     * 公共镜像在限流或失效时会返回状态码好看的 HTML 错误页或验证码页。只统计 HTTP 状态码
     * 的话这类源的成功率会被算成 100%, 选路算法被彻底骗过 —— 这是本项目最容易漏掉的一点。
     */
    public static function looksLikeWrongContent(Scene $scene, string $headBytes, string $contentType): bool
    {
        if ($headBytes === '') {
            // 空响应: API 场景一定有问题, 其余场景可能只是 0 字节文件, 不能误判。
            return $scene === Scene::ApiJson;
        }

        $probe = ltrim($headBytes, "\xEF\xBB\xBF \t\r\n");
        $head = strtolower(substr($probe, 0, 512));
        $looksHtml = str_starts_with($head, '<!doctype html')
            || str_starts_with($head, '<html')
            || str_starts_with($head, '<head')
            || str_contains($head, '<html ');

        switch ($scene) {
            case Scene::ApiJson:
                if ($looksHtml) {
                    return true;
                }
                $json = json_decode($headBytes, true);

                return !is_array($json) && json_last_error() !== JSON_ERROR_NONE;

            case Scene::Archive:
                // ZIP 的 PK\x03\x04 / 空归档 PK\x05\x06, 或 gzip 的 1f 8b
                $isZip = str_starts_with($probe, "PK\x03\x04") || str_starts_with($probe, "PK\x05\x06");
                $isGz = str_starts_with($probe, "\x1f\x8b");

                return !($isZip || $isGz);

            case Scene::ReleaseAsset:
                // 二进制资产被回成 HTML 就是假 200; 但 text/* 类资产(如 .txt/.json 附件)合法。
                return $looksHtml && !in_array(self::baseType($contentType), ['text/plain', 'application/json'], true);

            case Scene::Raw:
            case Scene::GistRaw:
                // raw 场景源文件本身可能就是 HTML, 所以必须 Content-Type 也同意才判假 200。
                return $looksHtml && stripos($contentType, 'text/html') !== false;

            default:
                return false;
        }
    }

    private static function baseType(string $contentType): string
    {
        return strtolower(trim(explode(';', $contentType)[0]));
    }

    /**
     * curl easy 错误码 -> 失败分型。
     *
     * 这里刻意用字面整数而不是 CURLE_* 常量: PHP 的 curl 扩展只导出了部分常量, 实测
     * CURLE_PEER_FAILED_VERIFICATION / CURLE_SSL_ISSUER_ERROR / CURLE_HTTP2* 在本机构建里
     * 根本不存在, 引用未定义常量会直接 Fatal error。数值取自 libcurl 的 include/curl/curl.h。
     */
    private const SSL_ERRNOS = [35, 58, 59, 60, 77, 83];
    private const STALL_ERRNOS = [18, 56, 16, 17];

    public static function classifyCurl(int $errno, string $error): FailureKind
    {
        // 0 成功 / 1 协议不支持 / 3 URL 畸形 / 47 跳转过多 由调用方按各自语义处理
        if ($errno === 0) {
            return FailureKind::None;
        }
        if (in_array($errno, self::SSL_ERRNOS, true)) {
            return FailureKind::TlsVerify;
        }
        if (in_array($errno, self::STALL_ERRNOS, true)) {
            return FailureKind::Stall;
        }

        return match ($errno) {
            5, 6, 7        => FailureKind::Connect,          // RESOLVE_PROXY / RESOLVE_HOST / COULDNT_CONNECT
            28             => FailureKind::TimeoutTtfb,      // OPERATION_TIMEDOUT
            23             => FailureKind::Oversize,         // WRITE_ERROR: 本机主动截断, 不是源的错
            42             => FailureKind::ClientAbort,      // ABORTED_BY_CALLBACK
            1, 3           => FailureKind::GuardRejected,    // UNSUPPORTED_PROTOCOL / URL_MALFORMAT
            default        => FailureKind::Connect,
        };
    }
}
