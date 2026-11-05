<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: IP 字面量的规范化与"是否公网可路由"判定, 是 SSRF 判定链的最后一道地址关。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Security;

/**
 * 为什么不用 filter_var(..., FILTER_FLAG_NO_PRIV_RANGE|NO_RES_RANGE) 当防线:
 * 本机实测它放过了 2002:7f00:1::1(6to4→127.0.0.1)、2002:c0a8:1::1(6to4→192.168.0.1)、
 * 64:ff9b::7f00:1(NAT64→127.0.0.1) 三类 —— 隧道把内网地址藏在 v6 载荷里, 过滤器只看
 * 外层前缀。等于没有防护。所以这里自建段表 + 递归解封装。
 *
 * 所有判定一律 fail-closed: 非规范写法、解析不出、认不出的形态全部返回"不可路由"。
 * 宁可拒绝一个合法镜像, 也不能让 169.254.169.254 出去。
 */
final class IpRange
{
    /**
     * v4 拒绝段表。含 RFC1918/链路本地/环回/组播/保留段, 以及云厂商元数据端点。
     *
     * 100.100.100.200 必须单列: 它是阿里云元数据地址, 而 100.64/10 只覆盖
     * 100.64.0.0–100.127.255.255, 100.100 落在段表之外, 漏一条就是致命的。
     * 169.254/16 已覆盖 169.254.169.254 与 169.254.170.2(AWS ECS), 单列是为了让
     * 配置审查时一眼能看到这两处端点被显式考虑过。
     */
    private const DENY_V4 = [
        ['0.0.0.0', 8],
        ['10.0.0.0', 8],
        ['100.64.0.0', 10],      // CGNAT, 可路由到运营商内网
        ['127.0.0.0', 8],
        ['169.254.0.0', 16],     // 链路本地 + 云元数据
        ['172.16.0.0', 12],
        ['192.0.0.0', 24],       // IETF 协议分配
        ['192.0.2.0', 24],       // TEST-NET-1
        ['192.31.196.0', 24],    // AWS 全局加速地址池外的保留段
        ['192.88.99.32', 32],    // 6to4 relay anycast(旧任播, 现保留)
        ['192.168.0.0', 16],
        ['198.18.0.0', 15],      // 基准测试
        ['198.51.100.0', 24],    // TEST-NET-2
        ['203.0.113.0', 24],     // TEST-NET-3
        ['224.0.0.0', 4],        // 组播
        ['240.0.0.0', 4],        // 保留 + 255.255.255.255 广播
        ['100.100.100.200', 32], // 阿里云元数据
        ['169.254.170.2', 32],   // AWS ECS task metadata
    ];

    /**
     * v6 自身就要拒绝的前缀(纯 v6 语义的地址)。
     *
     * 隧道/映射前缀(2002::/16、2001::/32、64:ff9b::/96、::ffff:0:0/96)故意不在这里:
     * 它们整段拒会误伤合法公网 6to4, 而整段放行就是本次要修的绕过。判定交给
     * unencapsulated() 解封装回 v4。
     */
    private const DENY_V6 = [
        ['::1', 128],            // 环回
        ['::', 128],             // 未指定
        ['100::', 64],          // 丢弃前缀
        ['2001:db8::', 32],     // 文档
        ['3ffe::', 12],         // 旧 6bone
        ['5f00::', 8],          // SRv6 段路由
        ['fc00::', 7],          // ULA
        ['fe80::', 10],         // 链路本地
        ['ff00::', 8],          // 组播
    ];

    /** 必须解封装回 v4 才能判定的前缀 —— 内网地址最爱藏在这几段里。 */
    private const TUNNEL_PREFIXES = [
        '2002',         // 6to4
        '20010000',     // Teredo (2001::/32)
        '0064ff9b0000000000000000', // 64:ff9b::/96 NAT64 well-known
        '0064ff9b0001',             // 64:ff9b:1::/48 NAT64 本地使用
        '00000000000000000000ffff', // ::ffff:0:0/96 v4-mapped
    ];

    /**
     * 该 IP 是否允许作为出站目标。
     *
     * @param string $ip       点分十进制 v4 或小写规范 v6
     * @param array  $extraDeny 额外拒绝的 CIDR 列表(config security.extra_deny_cidrs)
     */
    public static function isPubliclyRoutable(string $ip, array $extraDeny = []): bool
    {
        $norm = self::normalizeIp($ip);
        if ($norm === null) {
            return false;
        }

        if (str_contains($norm, ':')) {
            return self::v6Public($norm, $extraDeny);
        }

        return self::v4Public(self::v4ToLong($norm), $extraDeny);
    }

    /**
     * 规范化并校验写法。返回 null 表示"这不是一个可安全判定的字面量"。
     *
     * v4 只收四段点分十进制且禁止前导零: 前导零是八进制歧义(0177.0.0.1), 段数不足是
     * 缩写歧义(127.1、127、2130706433), 这些写法在不同解析器里落到不同地址, 一律拒。
     * v6 要求 inet_pton→inet_ntop 往返与输入逐字符相同: 往返不等说明是非规范拼写
     * (前导零、0:0: 未压缩、大小写混合的映射段), 而 exactly 这类拼写最容易和
     * 解析器产生分歧。
     */
    public static function normalizeIp(string $ip): ?string
    {
        // 只 trim 空白, 不用 PHP 默认的 trim(): 默认字符表里含 NUL 与 \x0B, 会让
        // "127.0.0.1\0" 这种被截断过的头字段值看起来完全合法 —— 而我们后面拿到的字符串
        // 与传给解析器的字节必须一致, 所以控制字符一律拒而不是抹平。
        $ip = trim($ip, " \t\n\r");
        if ($ip === '' || str_contains($ip, '%') || str_contains($ip, '\\') || $ip !== preg_replace('/[\x00-\x20\x7F]/', '', $ip)) {
            return null;
        }

        if (str_contains($ip, ':')) {
            // IPv6 字面量可能带 zone id 或被中括号包裹, 两者都不是我们要放行的形态。
            $packed = @inet_pton($ip);
            if ($packed === false || strlen($packed) !== 16) {
                return null;
            }
            $canon = strtolower((string) inet_ntop($packed));
            // ::ffff:127.0.0.1 与 0:0:0:0:0:ffff:127.0.0.1 是同址的两种合法拼写,
            // 后者 ntop 会归一成前者; 只有 round-trip 相等才承认"作者 intent 明确"。
            if ($canon !== strtolower($ip)) {
                return null;
            }

            return $canon;
        }

        $parts = explode('.', $ip);
        if (count($parts) !== 4) {
            return null;
        }
        $octets = [];
        foreach ($parts as $p) {
            if ($p === '' || preg_match('/\A[0-9]{1,3}\z/', $p) !== 1) {
                return null;
            }
            // 前导零: "012" 与 "0" 长度不同却同值, 这是解析器分歧的经典来源。
            if ($p !== '0' && $p[0] === '0') {
                return null;
            }
            $v = (int) $p;
            if ($v > 255) {
                return null;
            }
            $octets[] = $v;
        }

        return implode('.', $octets);
    }

    /** 点分十进制 -> 无符号 32 位整数。非法输入返回 null。 */
    public static function v4ToLong(string $dotted): ?int
    {
        $packed = @inet_pton($dotted);
        if ($packed === false || strlen($packed) !== 4) {
            return null;
        }

        $u = unpack('Nv', $packed);

        return $u === false ? null : (int) $u['v'];
    }

    /** 单个 CIDR 命中判定, 供 trusted_cidrs 与 extra_deny_cidrs 使用。 */
    public static function matchesCidr(string $ip, string $cidr): bool
    {
        $seg = explode('/', trim($cidr), 2);
        $net = self::normalizeIp($seg[0]);
        if ($net === null) {
            return false;
        }
        $ipNorm = self::normalizeIp($ip);
        if ($ipNorm === null) {
            return false;
        }
        // v4 地址与 v6 CIDR(或反之)永不匹配: 不做隐式映射, 免得 ::ffff:10.0.0.0/104
        // 这类写法把 v4 私网"意外"匹配上一个 v6 白名单。
        if (str_contains($ipNorm, ':') !== str_contains($net, ':')) {
            return false;
        }
        $bits = isset($seg[1]) ? (int) $seg[1] : (str_contains($net, ':') ? 128 : 32);

        $a = @inet_pton($ipNorm);
        $b = @inet_pton($net);
        if ($a === false || $b === false) {
            return false;
        }
        $max = str_contains($ipNorm, ':') ? 128 : 32;
        $bits = max(0, min($max, $bits));
        $full = intdiv($bits, 8);
        if (substr($a, 0, $full) !== substr($b, 0, $full)) {
            return false;
        }
        $rem = $bits % 8;
        if ($rem === 0) {
            return true;
        }
        if (strlen($a) <= $full || strlen($b) <= $full) {
            return false;
        }
        $mask = (0xFF << (8 - $rem)) & 0xFF;

        return ((ord($a[$full]) & $mask) === (ord($b[$full]) & $mask));
    }

    /** 命中任一 CIDR 即为真。空列表恒为 false。 */
    public static function inCidrs(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $c) {
            if (is_string($c) && self::matchesCidr($ip, $c)) {
                return true;
            }
        }

        return false;
    }

    private static function v4Public(?int $n, array $extraDeny): bool
    {
        if ($n === null) {
            return false;
        }
        foreach (self::DENY_V4 as [$net, $bits]) {
            if (self::inV4Range($n, (string) $net, $bits)) {
                return false;
            }
        }
        foreach ($extraDeny as $c) {
            if (is_string($c) && ltrim($c) !== '' && !str_contains($c, ':') && self::matchesCidr(self::longToV4($n), $c)) {
                return false;
            }
        }

        return true;
    }

    private static function inV4Range(int $n, string $net, int $bits): bool
    {
        $base = self::v4ToLong($net);
        if ($base === null) {
            // 段表写错时按"拒绝"处理, 而不是跳过这条规则。
            return true;
        }
        $mask = $bits === 0 ? 0 : (~(0xFFFFFFFF >> $bits)) & 0xFFFFFFFF;

        return ($n & $mask) === ($base & $mask);
    }

    private static function longToV4(int $n): string
    {
        return implode('.', [(($n >> 24) & 0xFF), (($n >> 16) & 0xFF), (($n >> 8) & 0xFF), ($n & 0xFF)]);
    }

    /**
     * v6 判定: 先查纯 v6 段表, 再对隧道/映射前缀递归解封装回 v4 判定。
     *
     * 解封装是"命中隧道前缀就必须能抽出一个公网 v4"的正向要求: 抽出失败、抽出多个
     * 且任一不合格、或抽出的 v4 落在内网, 一律拒绝。宁可拒绝一个合法镜像,
     * 也不能让 127.0.0.1 借 6to4 的外衣出去。
     */
    private static function v6Public(string $norm, array $extraDeny): bool
    {
        $packed = @inet_pton($norm);
        if ($packed === false || strlen($packed) !== 16) {
            return false;
        }
        foreach (self::DENY_V6 as [$net, $bits]) {
            if (self::inV6Range($packed, (string) $net, $bits)) {
                return false;
            }
        }

        // v4-compatible (::/96) 已废弃且从不安全: 前 96 位为零意味着它想表达裸 v4,
        // 而双栈栈会把它当 v4 送出去。直接拒而不解封装, 免得留下解析器分歧面。
        if (substr($packed, 0, 12) === str_repeat("\x00", 12)) {
            return false;
        }

        $hex = bin2hex($packed);
        foreach (self::TUNNEL_PREFIXES as $p) {
            if (!str_starts_with($hex, $p)) {
                continue;
            }
            $inner = self::unencapsulated($hex);
            if ($inner === []) {
                return false; // 认得出是隧道却抽不出内层 v4: 非规范形态, 拒
            }
            foreach ($inner as $v4) {
                if (!self::v4Public($v4, [])) {
                    return false;
                }
            }
        }

        foreach ($extraDeny as $c) {
            if (is_string($c) && str_contains($c, ':') && self::matchesCidr($norm, $c)) {
                return false;
            }
        }

        return true;
    }

    /**
     * 从 v6 载荷里抽出所有可能被"藏"起来的 v4 地址(返回 uint32 形式)。
     *
     *  - 2002::/16   6to4   : 32..63 位是原始 IPv4
     *  - 2001::/32  Teredo  : 32..63 位是中继服务器 IPv4(明文), 80..111 位是客户端 IPv4(按位取反)
     *  - 64:ff9b::/96 与 64:ff9b:1::/48 NAT64 : 后 32 位是 v4 目的
     *  - ::ffff:0:0/96 v4-mapped : 后 32 位
     *
     * 一个都漏不得: 只要有一路没解封装, 攻击者就用它把 127.0.0.1 送进来。
     */
    private static function unencapsulated(string $hex): array
    {
        $out = [];

        // 6to4
        if (str_starts_with($hex, '2002')) {
            $out[] = self::hex32ToLong(substr($hex, 8, 8));
        }

        // Teredo
        if (str_starts_with($hex, '20010000')) {
            $out[] = self::hex32ToLong(substr($hex, 8, 8));                 // server, 明文
            $client = self::hex32ToLong(substr($hex, 20, 8));
            if ($client !== null) {
                $out[] = (~$client) & 0xFFFFFFFF;                            // client, 取反
            }
        }

        // NAT64 well-known /96: v4 在低 32 位。本地使用 /48: 中间 16 位是客户前缀,
        // v4 可能落在 64..95 或 96..127, 两个窗口都抽出来判, 任一内网即拒 —— 因为
        // 我们不知道部署方的映射器用的是哪种排布。
        if (str_starts_with($hex, '0064ff9b0000000000000000')) {
            $out[] = self::hex32ToLong(substr($hex, 24, 8));
        }
        if (str_starts_with(substr($hex, 0, 12), '0064ff9b0001')) {
            $out[] = self::hex32ToLong(substr($hex, 16, 8));
            $out[] = self::hex32ToLong(substr($hex, 24, 8));
        }

        // v4-mapped
        if (str_starts_with($hex, '00000000000000000000ffff')) {
            $out[] = self::hex32ToLong(substr($hex, 24, 8));
        }

        return array_values(array_filter($out, static fn (?int $v): bool => $v !== null));
    }

    private static function hex32ToLong(string $hex): ?int
    {
        if (strlen($hex) !== 8 || preg_match('/\A[0-9a-f]{8}\z/', $hex) !== 1) {
            return null;
        }

        return hexdec($hex) === false ? null : ((int) hexdec($hex)) & 0xFFFFFFFF;
    }

    private static function inV6Range(string $packed, string $net, int $bits): bool
    {
        $base = @inet_pton($net);
        if ($base === false || strlen($base) !== 16) {
            return true; // 表写错 -> 视为命中, fail-closed
        }
        $full = intdiv($bits, 8);
        if (substr($packed, 0, $full) !== substr($base, 0, $full)) {
            return false;
        }
        $rem = $bits % 8;
        if ($rem === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rem)) & 0xFF;

        return (ord($packed[$full]) & $mask) === (ord($base[$full]) & $mask);
    }

    /**
     * 会话绑定的地址前缀指纹: v4 取前 24 位, v6 取前 48 位。
     * 绑整 IP 会让移动网络换址就掉线, 绑前缀是可用性与风险的折中。
     */
    public static function sessionPrefix(string $ip, int $v4Bits = 24, int $v6Bits = 48): string
    {
        $norm = self::normalizeIp($ip);
        if ($norm === null) {
            return '';
        }
        $bits = str_contains($norm, ':') ? $v6Bits : $v4Bits;
        $packed = (string) inet_pton($norm);
        $full = intdiv($bits, 8);
        $rem = $bits % 8;
        $prefix = substr($packed, 0, $full);
        if ($rem !== 0 && strlen($packed) > $full) {
            $prefix .= chr(ord($packed[$full]) & ((0xFF << (8 - $rem)) & 0xFF));
        }

        return bin2hex($prefix);
    }
}
