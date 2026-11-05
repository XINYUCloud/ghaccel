<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: SSRF 判定链的产出值对象 —— 校验通过的 URL、host、钉住的 IP 与可直接喂给
 *             CURLOPT_RESOLVE 的条目, 一次生成, 让 Transport 不必二次解析。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Security;

/**
 * resolveEntries 的 host 拼写与 url 中逐字节一致是硬性约定: curl 按 "host:port" 字面匹配
 * RESOLVE 条目, 差一个大小写或一个尾点, 条目就静默失配, curl 重新自行解析 —— TOCTOU
 * 复活且日志里零告警。构造时做一次自检, 不一致直接抛, 把这个静默故障变成显式故障。
 */
final class GuardResult
{
    /**
     * @param string       $url            规范化后的绝对 URL(仅 https + 小写 host)
     * @param string       $host           URL 里逐字节的 host(已确认等于规范化 host)
     * @param string       $ip             选定的出站 IPv4
     * @param array<int,string> $resolveEntries 形如 ["github.com:443:1.2.3.4"]
     */
    public function __construct(
        public readonly string $url,
        public readonly string $host,
        public readonly string $ip,
        public readonly array $resolveEntries,
    ) {
        foreach ($this->resolveEntries as $entry) {
            $head = explode(':', (string) $entry, 2)[0];
            if (!hash_equals(strtolower($this->host), strtolower($head))) {
                throw new \InvalidArgumentException('CURLOPT_RESOLVE 条目与 URL 的 host 不一致, 拒绝构造');
            }
        }
    }

    /** 全部解析到的 IP(RESOLVE 条目里逐个出现), 供事后与 CURLINFO_PRIMARY_IP 比对。 */
    public function ips(): array
    {
        $out = [];
        foreach ($this->resolveEntries as $entry) {
            $seg = explode(':', (string) $entry, 3);
            if (count($seg) === 3 && $seg[2] !== '') {
                $out[] = $seg[2];
            }
        }

        return $out;
    }

    /** curl 的 CURLOPT_RESOLVE 接受 "HOST:PORT:IP" 字符串数组, 这里原样给出。 */
    public function resolveLines(): array
    {
        return array_values($this->resolveEntries);
    }

    public function port(): int
    {
        $p = (int) (parse_url($this->url, PHP_URL_PORT) ?: 443);

        return $p > 0 ? $p : 443;
    }
}
