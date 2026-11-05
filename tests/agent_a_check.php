<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: A 组(URL 引用解析层 + 安全边界层)的真实运行校验 —— SSRF 绕过用例必须全部
 *             被拒、三种入口形式与五种残缺写法必须解析成正确引用、限流/并发/管理面行为必须可验证。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

/**
 * 独立可跑: php tests/agent_a_check.php   (退出码 0 = 全通过)
 * 不引入断言框架: 本项目"零运行时依赖"的承诺包括测试脚本本身。
 *
 * 临时根目录 var/_agent_a_check/ 里放一份 config 覆盖层, 用来测"自身前缀/CSRF 基准"这类
 * 必须靠配置定义的行为 —— 不改仓库里的任何契约文件。
 */

$ROOT = dirname(__DIR__);
require $ROOT . '/src/Bootstrap.php';

use GhAccel\Bootstrap;
use GhAccel\Config;
use GhAccel\Enum\IdentityKind;
use GhAccel\Enum\Scene;
use GhAccel\Errors\GhpError;
use GhAccel\Ref\GitHubRef;
use GhAccel\Ref\RefParser;
use GhAccel\Ref\UpstreamMap;
use GhAccel\Security\Audit;
use GhAccel\Security\Auth;
use GhAccel\Security\GuardResult;
use GhAccel\Security\IpRange;
use GhAccel\Security\RateLimiter;
use GhAccel\Security\Slots;
use GhAccel\Security\UrlGuard;

Bootstrap::register();

$GLOBALS['__pass'] = 0;
$GLOBALS['__fail'] = 0;
$GLOBALS['__info'] = 0;
$GLOBALS['__fails'] = [];

function ok(bool $cond, string $name, string $extra = ''): void
{
    if ($cond) {
        $GLOBALS['__pass']++;
        printf("  [PASS] %s\n", $name);
    } else {
        $GLOBALS['__fail']++;
        $GLOBALS['__fails'][] = $name . ($extra === '' ? '' : ('   << ' . $extra));
        printf("  [FAIL] %s%s\n", $name, $extra === '' ? '' : ('   << ' . $extra));
    }
}

function eq(mixed $got, mixed $want, string $name): void
{
    ok($got === $want, $name, sprintf('got=%s want=%s', var_export($got, true), var_export($want, true)));
}

/** 断言抛的就是指定错误码: "反正拒了"不够, 拒绝理由错了运维就查不动。 */
function rejects(callable $fn, string $code, string $name): void
{
    try {
        $r = $fn();
        ok(false, $name, '没有抛出, 返回 ' . (is_object($r) ? $r::class : var_export($r, true)));
    } catch (GhpError $e) {
        ok($e->errorCode === $code, $name, '实际抛 ' . $e->errorCode . ' / 期望 ' . $code);
    } catch (\Throwable $e) {
        ok(false, $name, '抛了非 GhpError: ' . $e::class . ' ' . $e->getMessage());
    }
}

function section(string $t): void
{
    printf("\n== %s ==\n", $t);
}

function info(string $t): void
{
    $GLOBALS['__info']++;
    printf("  [INFO] %s\n", $t);
}

function rrmdir(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }
    foreach (scandir($dir) ?: [] as $f) {
        if ($f === '.' || $f === '..') {
            continue;
        }
        $p = $dir . '/' . $f;
        is_dir($p) ? rrmdir($p) : @unlink($p);
    }
    @rmdir($dir);
}

$TMP = $ROOT . '/var/_agent_a_check';
rrmdir($TMP);
foreach (['config', 'var/concurrency', 'var/sessions', 'var/state/admin', 'var/log', 'var/ratelimit'] as $d) {
    @mkdir($TMP . '/' . $d, 0770, true);
}
copy($ROOT . '/config/config.dist.php', $TMP . '/config/config.dist.php');

/** 往临时根写覆盖层: 只改这个临时文件, 仓库里的 config.dist.php 与契约文件都不动。 */
function overlay(array $data): void
{
    file_put_contents(
        dirname(__DIR__) . '/var/_agent_a_check/config/config.php',
        "<?php\nreturn " . var_export($data, true) . ";\n"
    );
}
overlay([]);

$exec = escapeshellarg(PHP_BINARY);
$cfg = Config::load($ROOT, true);
$guard = new UrlGuard($cfg);
$parser = new RefParser($cfg);

info('PHP ' . PHP_VERSION . ' / SAPI ' . PHP_SAPI . ' / curl ' . (function_exists('curl_version') ? curl_version()['version'] : 'none'));
ok(version_compare(PHP_VERSION, '8.1.0', '>='), '运行环境满足 PHP 8.1 下限');
foreach (['hash', 'curl', 'json'] as $e) {
    ok(extension_loaded($e), '扩展可用: ' . $e);
}

// ----------------------------------------------------------------------
section('1. IpRange: 位运算段表 + 隧道递归解封装');
// ----------------------------------------------------------------------
$denyV4 = ['127.0.0.1', '10.1.2.3', '172.16.9.9', '172.31.255.255', '192.168.0.1', '169.254.169.254',
    '169.254.170.2', '100.100.100.200', '100.64.0.1', '0.0.0.0', '224.0.0.5', '240.0.0.1',
    '255.255.255.255', '198.18.0.1', '192.0.2.1', '192.0.0.1', '127.10.10.10', '192.88.99.32', '192.31.196.1'];
foreach ($denyV4 as $ip) {
    ok(!IpRange::isPubliclyRoutable($ip), 'v4 拒绝 ' . $ip);
}
foreach (['20.205.243.166', '185.199.108.133', '8.8.8.8', '140.82.112.3', '13.225.0.1'] as $ip) {
    ok(IpRange::isPubliclyRoutable($ip), 'v4 放行 ' . $ip);
}

// filter_var 实测放过的三类隧道, 这里必须全拒 —— 同时把"过滤器确实放过"这件事本身断言下来
foreach (['2002:7f00:1::1' => '6to4 -> 127.0.0.1', '2002:c0a8:1::1' => '6to4 -> 192.168.0.1', '64:ff9b::7f00:1' => 'NAT64 -> 127.0.0.1'] as $ip => $why) {
    ok(!IpRange::isPubliclyRoutable($ip), 'v6 解封装拒绝 ' . $ip . ' (' . $why . ')');
    ok(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false,
        '对照: filter_var 确实放过 ' . $ip . ' —— 段表不可省');
}
$mk = static fn (string $hex): string => (string) inet_ntop(hex2bin($hex));
// 布局: 2001::/32 | server IPv4(明文, 字节4-7) | 端口(字节8-9) | 客户端 IPv4 取反(字节10-13) | flags
$teredoInternal = $mk('200100004136e3780000' . '80fffffe' . '0000'); // 内层 127.0.0.1
$teredoPublic = $mk('200100004136e3780000' . 'f7f7f7f7' . '0000');   // 内层 8.8.8.8
ok(!IpRange::isPubliclyRoutable($teredoInternal), 'v6 解封装拒绝 Teredo ' . $teredoInternal);
ok(IpRange::isPubliclyRoutable($teredoPublic), 'v6 Teredo 内层公网不误伤 ' . $teredoPublic);
ok(!IpRange::isPubliclyRoutable('::ffff:169.254.169.254'), 'v6 mapped 拒绝 ::ffff:169.254.169.254');
ok(!IpRange::isPubliclyRoutable('::ffff:127.0.0.1'), 'v6 mapped 拒绝 ::ffff:127.0.0.1');
ok(!IpRange::isPubliclyRoutable('64:ff9b:1::7f00:1'), 'v6 NAT64 本地前缀拒绝 64:ff9b:1::7f00:1');
ok(!IpRange::isPubliclyRoutable($mk('0000000000000000000000007f000001')), 'v6 v4-compatible(::/96) 直接拒');
ok(!IpRange::isPubliclyRoutable('::1'), 'v6 拒绝 ::1');
ok(!IpRange::isPubliclyRoutable('::'), 'v6 拒绝 ::');
ok(!IpRange::isPubliclyRoutable('fe80::1'), 'v6 拒绝 fe80::1');
ok(!IpRange::isPubliclyRoutable('fc00::1'), 'v6 拒绝 fd00::/8 ULA');
ok(!IpRange::isPubliclyRoutable('ff02::1'), 'v6 拒绝 ff00::/8');
ok(!IpRange::isPubliclyRoutable('2001:db8::1'), 'v6 拒绝文档段');
ok(IpRange::isPubliclyRoutable('2002:8888:8888::1'), 'v6 合法 6to4 不误伤(内层 136.136.136.136)');
ok(IpRange::isPubliclyRoutable('2606:4700:1::1111'), 'v6 合法公网不误伤 Cloudflare');

foreach (['0177.0.0.1', '127.1', '127', '2130706433', '0x7f000001', '999.1.1.1', '127.0.0.1.', '127.0.0.1:80', '010.0.0.1', '256.0.0.1', '1.2.3.4.5', '127.0.0.1' . chr(0), '1.2.3' . chr(0x1B) . '.4'] as $bad) {
    eq(IpRange::normalizeIp($bad), null, 'normalizeIp 拒非规范写法 ' . bin2hex($bad));
}
// 首尾空白来自 X-Forwarded-For 一类的逗号列表, 必须容忍; 内嵌控制字符一律拒
eq(IpRange::normalizeIp(' 127.0.0.1 '), '127.0.0.1', 'normalizeIp 容忍首尾空白(XFF 列表带空格)');
eq(IpRange::normalizeIp('127.0.0.1' . chr(9)), '127.0.0.1', 'normalizeIp 容忍尾部制表符');
eq(IpRange::normalizeIp('127.0.0.1'), '127.0.0.1', 'normalizeIp 收规范 v4');
eq(IpRange::normalizeIp('2002:7F00:1::1'), '2002:7f00:1::1', 'normalizeIp 收规范 v6 并转小写');
eq(IpRange::normalizeIp('0:0:0:0:0:ffff:127.0.0.1'), null, 'normalizeIp 拒未压缩的 v4-mapped(往返不等)');
ok(IpRange::matchesCidr('10.0.0.5', '10.0.0.0/8'), 'CIDR /8 命中');
ok(!IpRange::matchesCidr('11.0.0.5', '10.0.0.0/8'), 'CIDR /8 不命中');
ok(IpRange::matchesCidr('192.168.1.7', '192.168.0.0/16'), 'CIDR /16 命中');
ok(IpRange::matchesCidr('100.64.1.2', '100.64.0.0/10'), 'CIDR /10 命中');
ok(!IpRange::matchesCidr('10.0.0.1', '2002:7f00:1::1'), 'v4 与 v6 不跨族匹配');
ok(IpRange::inCidrs('192.168.7.7', ['10.0.0.0/8', '192.168.0.0/16']), 'inCidrs 列表命中');
ok(!IpRange::isPubliclyRoutable('8.8.8.8', ['8.8.8.0/24']), 'extra_deny_cidrs 生效');
eq(IpRange::sessionPrefix('203.0.113.9'), IpRange::sessionPrefix('203.0.113.77'), 'v4 会话前缀绑 24 位');
ok(IpRange::sessionPrefix('203.0.113.9') !== IpRange::sessionPrefix('198.51.100.9'), '换 /24 前缀就变');
ok(IpRange::sessionPrefix('2606:4700:1::1111') !== IpRange::sessionPrefix('2606:4701:1::1111'), 'v6 会话前缀绑 48 位');

// ----------------------------------------------------------------------
section('2. UrlGuard: SSRF 判定链(以下每一条都必须被拒)');
// ----------------------------------------------------------------------
$ssrf = [
    'https://evil.com\\@github.com' => GhpError::BACKSLASH_IN_URL,
    'https://evil.com\\@github.com/x' => GhpError::BACKSLASH_IN_URL,
    'https://github.com@evil.com' => GhpError::USERINFO_NOT_ALLOWED,
    'https://github.com.evil.com/' => GhpError::HOST_NOT_ALLOWED,
    'https://notgithub.com/' => GhpError::HOST_NOT_ALLOWED,
    'https://2130706433/' => GhpError::NUMERIC_HOST_LITERAL,
    'https://0x7f000001/' => GhpError::ILLEGAL_HOST_CHARS,
    'https://127.1/' => GhpError::NUMERIC_HOST_LITERAL,
    'https://127/' => GhpError::NUMERIC_HOST_LITERAL,
    'https://0177.0.0.1/' => GhpError::NUMERIC_HOST_LITERAL,
    'https://[::ffff:169.254.169.254]/' => GhpError::ILLEGAL_HOST_CHARS,
    'https://::ffff:169.254.169.254/' => GhpError::UNPARSEABLE,
    'https://2002:7f00:1::1/' => GhpError::PORT_NOT_ALLOWED,
    'https://64:ff9b::7f00:1/' => GhpError::PORT_NOT_ALLOWED,
    'http://github.com/' => GhpError::SCHEME_NOT_ALLOWED,
    'file:///etc/passwd' => GhpError::UNPARSEABLE,
    'gopher://github.com:1121/' => GhpError::SCHEME_NOT_ALLOWED,
    'https://:@github.com/' => GhpError::USERINFO_NOT_ALLOWED,
    'https://user:pass@github.com/' => GhpError::USERINFO_NOT_ALLOWED,
    'https://github.com%2fevil.com/' => GhpError::ILLEGAL_HOST_CHARS,
    'https://github.com:8080/o/r' => GhpError::PORT_NOT_ALLOWED,
    'https://private-user-images.githubusercontent.com/x' => GhpError::HOST_NOT_ALLOWED,
    'https://gıthub.com/' => GhpError::ILLEGAL_HOST_CHARS,
    'https://github/' => GhpError::ILLEGAL_HOST_CHARS,
    // 尾点 FQDN 被 LDH 拒: 它会和 URL 里的分隔点混淆, 且 RESOLVE 条目按字面匹配必然失配
    'https://github.com./x' => GhpError::ILLEGAL_HOST_CHARS,
    'https://169.254.169.254/' => GhpError::NUMERIC_HOST_LITERAL,
    'https://100.100.100.200/' => GhpError::NUMERIC_HOST_LITERAL,
    'not a url at all' => GhpError::UNPARSEABLE,
    'https://' => GhpError::UNPARSEABLE,
    'https://github.com/' . str_repeat('a', 5000) => GhpError::URL_TOO_LONG,
];
foreach ($ssrf as $u => $code) {
    rejects(static fn () => $guard->assertAllowed((string) $u), (string) $code, '拒绝 ' . substr((string) $u, 0, 44) . ' -> ' . $code);
}
rejects(static function () use ($guard) {
    // 长度上限必须先于解析: 超长串留在内存里再抛 UNPARSEABLE 也是拒绝, 但会白烧一次解析
    $guard->assertAllowed("https://github.com/\x00" . str_repeat('a', 5000));
}, GhpError::URL_TOO_LONG, '含控制字符的超长串仍然被长度上限挡住');

$gr = $guard->assertAllowed('https://raw.githubusercontent.com/octocat/Hello-World/master/README');
ok($gr instanceof GuardResult, '合法 raw URL 通过');
eq($gr->host, 'raw.githubusercontent.com', 'GuardResult.host');
eq($gr->url, 'https://raw.githubusercontent.com/octocat/Hello-World/master/README', '合法 URL 逐字节不动');
ok(IpRange::normalizeIp($gr->ip) === $gr->ip, 'GuardResult.ip 是规范化 v4: ' . $gr->ip);
ok($gr->ips() !== [], 'RESOLVE 覆盖了全部 A 记录而不是随手挑一条');
foreach ($gr->resolveLines() as $line) {
    ok(str_starts_with($line, $gr->host . ':' . $gr->port() . ':'), 'RESOLVE 条目 host 与 URL 逐字节一致: ' . $line);
}
$grUp = $guard->assertAllowed('https://GitHub.COM/octocat/Hello-World');
ok(str_contains($grUp->url, '://github.com/'), 'host 大小写先归一再拼 RESOLVE');
foreach ($grUp->resolveLines() as $line) {
    ok(str_starts_with($line, 'github.com:'), '归一后的 RESOLVE 条目: ' . $line);
}
rejects(static fn () => $guard->verifyPrimaryIp($gr, '127.0.0.1'), GhpError::GUARD_MISMATCH, '事后 primary_ip 不符必须显式故障');
$guard->verifyPrimaryIp($gr, $gr->ip);
ok(true, 'primary_ip 相符时不误报');

// ----------------------------------------------------------------------
section('3. UrlGuard: 逐跳复校 / 指回自身前缀');
// ----------------------------------------------------------------------
eq($guard->assertRedirect('https://objects.githubusercontent.com/x/a.bin?sig=abc%2Bdef%2Fghi', 'https://github.com/o/r/releases/download/v1/tool.zip', 1),
    'https://objects.githubusercontent.com/x/a.bin?sig=abc%2Bdef%2Fghi',
    '合法链路 github.com -> objects 域放行且 %2B/%2F 未被二次编码');
eq($guard->assertRedirect('/octocat/Hello-World/releases/download/v1/tool.zip', 'https://github.com/octocat/Hello-World/releases/latest', 1),
    'https://github.com/octocat/Hello-World/releases/download/v1/tool.zip', '相对 Location 绝对化');
eq($guard->assertRedirect('//codeload.github.com/o/r/tar.gz/main', 'https://github.com/o/r/archive/main.tar.gz', 1),
    'https://codeload.github.com/o/r/tar.gz/main', '协议相对 Location 继承基准 scheme');
eq($guard->assertRedirect('blob/x/../y.bin', 'https://raw.githubusercontent.com/o/r/main/dir/a.bin', 2),
    'https://raw.githubusercontent.com/o/r/main/dir/blob/y.bin', '相对引用点段按 RFC3986 归一(只消掉 x 这一段)');
eq($guard->assertRedirect('../y.bin', 'https://raw.githubusercontent.com/o/r/main/dir/a.bin', 2),
    'https://raw.githubusercontent.com/o/r/main/y.bin', '上一级点段确实退一层');
eq($guard->assertRedirect('%2e%2e/y.bin', 'https://raw.githubusercontent.com/o/r/main/dir/a.bin', 2),
    'https://raw.githubusercontent.com/o/r/main/y.bin', 'Location 里的 %2e%2e 也参与点段归一');
rejects(static fn () => $guard->assertRedirect('/x', 'https://github.com/o/r', 99), GhpError::REDIRECT_TOO_MANY, '跳数超限 -> REDIRECT_TOO_MANY');
rejects(static fn () => $guard->assertRedirect('https://evil.com\\@github.com/x', 'https://github.com/o/r', 1), GhpError::BACKSLASH_IN_URL, '跳转同样复校反斜杠');
rejects(static fn () => $guard->assertRedirect('http://github.com/x', 'https://github.com/o/r', 1), GhpError::SCHEME_NOT_ALLOWED, '跳转不许降级到 http');
rejects(static fn () => $guard->assertRedirect('https://github.com@evil.com/x', 'https://github.com/o/r', 1), GhpError::USERINFO_NOT_ALLOWED, 'Location 自带 userinfo');
rejects(static fn () => $guard->assertRedirect('https://evil.com/x', 'https://github.com/o/r', 1), GhpError::HOST_NOT_ALLOWED, 'Location 指向非白名单域');
rejects(static fn () => $guard->assertRedirect('', 'https://github.com/o/r', 1), GhpError::UNPARSEABLE, '空 Location');

// 自身前缀: 需要 app.base_origin, 走临时根的 config.php 覆盖层
overlay(['app' => ['base_origin' => 'https://accel.example.com'], 'panel' => ['path_prefix' => 'ctl-7f3a']]);
$cfgOwn = Config::load($TMP, true);
$own = new UrlGuard($cfgOwn);
eq($own->isOwnPrefix('https://accel.example.com/ctl-7f3a/api'), 'accel.example.com/ctl-7f3a', '识别自身 host + 面板前缀');
eq($own->isOwnPrefix('https://accel.example.com/anything'), 'accel.example.com', '自身 host 的任意路径都算自身');
eq($own->isOwnPrefix('/gh/o/r@main/a.md'), '/gh', '相对形态按入口前缀识别');
eq($own->isOwnPrefix('/https://github.com/o/r'), '/https:', '绝对形式入口也是自身前缀');
eq($own->isOwnPrefix('https://github.com/o/r'), '', 'GitHub 上游不误判成自身');
eq($own->isOwnPrefix('https://accel.example.com.evil.com/x'), '', '伪装成自身 host 的域不误判(仍会被白名单拒)');
rejects(static fn () => $own->assertRedirect('https://accel.example.com/ctl-7f3a/login', 'https://github.com/o/r/releases/latest', 1),
    GhpError::REDIRECT_LOOP, '指回自身面板 -> REDIRECT_LOOP');
eq($own->isOwnPrefix('https://accel.example.com/ctl-7f3a'), 'accel.example.com/ctl-7f3a', '面板根路径本身也算自身前缀');
rejects(static fn () => $own->assertRedirect('https://accel.example.com/gh/o/r@main/a.md', 'https://api.github.com/repos/o/r', 2),
    GhpError::REDIRECT_LOOP, '指回自身代理入口 -> REDIRECT_LOOP');
eq($own->assertRedirect('/api/repos/octocat/Hello-World', 'https://api.github.com/repositories/1', 1),
    'https://api.github.com/api/repos/octocat/Hello-World', 'GitHub 自己的相对 api 路径落在来源主机根上, 不误判成环');
rejects(static fn () => $own->assertRedirect('/x', 'https://accel.example.com/ctl-7f3a', 99),
    GhpError::REDIRECT_TOO_MANY, '跳数上限优先于自身前缀判定');
$guard = new UrlGuard($cfg);

// ----------------------------------------------------------------------
section('4. RefParser: 表面互斥与三种入口形式');
// ----------------------------------------------------------------------
foreach (['/', '/health', '/panel', '/panel/assets/panel.css', '/https://github.com/x', '/gh/o/r@main/a', '/raw/o/r/m/a'] as $p) {
    info('surface(' . str_pad($p, 26) . ') = ' . $parser->surface($p));
}
eq($parser->surface('/'), 'home', 'surface 首页');
eq($parser->surface(''), 'home', 'surface 空路径');
eq($parser->surface('/health'), 'health', 'surface 健康');
eq($parser->surface('/panel'), 'panel', 'surface 面板');
eq($parser->surface('/panel/assets/panel.css'), 'assets', 'surface 面板静态');
eq($parser->surface('/https://github.com/x'), 'proxy', 'surface 代理(绝对形式)');
eq($parser->surface('/gh/o/r@main/a'), 'proxy', 'surface 代理(别名形式)');

$wantRaw = 'https://raw.githubusercontent.com/octocat/hello-world/master/README.md';
$entries = [
    '/https://github.com/octocat/Hello-World/blob/master/README.md',
    '/gh/octocat/Hello-World@master/README.md',
    '/raw/octocat/Hello-World/master/README.md',
    '/raw/octocat/Hello-World/blob/master/README.md',
    '/raw/octocat/Hello-World@master/README.md',
];
foreach ($entries as $e) {
    $r = $parser->parse($e, '');
    eq($r->upstreamUrl, $wantRaw, '不同写法收敛到同一上游: ' . $e);
    eq($r->scene, Scene::Raw, $e . ' -> scene=raw');
    eq($r->identityKind, IdentityKind::RefName, $e . ' -> identity=ref_name');
    eq($r->upstreamHost, 'raw.githubusercontent.com', $e . ' -> upstreamHost 已填好');
}
eq($parser->parse($entries[0], '')->canonical(), $parser->parse($entries[1], '')->canonical(), '绝对形式与 gh 形式缓存键一致');
eq($parser->parse($entries[1], '')->canonical(), $parser->parse($entries[2], '')->canonical(), 'gh 与 raw 别名缓存键一致');

// 五种残缺写法
foreach ([
    '/https:/github.com/o/r/blob/main/a.md',
    '//github.com/o/r/blob/main/a.md',
    '/HTTPS://github.com/o/r/blob/main/a.md',
    '/https://www.github.com/o/r/blob/main/a.md',
    '/HTTPS://WWW.GitHub.COM/o/r/blob/main/a.md',
] as $s) {
    $r = $parser->parse($s, '');
    eq($r->upstreamUrl, 'https://raw.githubusercontent.com/o/r/main/a.md', '残缺写法归一: ' . $s);
    eq($r->owner, 'o', $s . ' -> owner 小写');
    eq($r->repo, 'r', $s . ' -> repo 小写');
    eq($r->path, 'a.md', $s . ' -> path 保留');
}
$r = $parser->parse('/gh/OctoCat/Hello-World@Main/Dir/ReadMe.MD', '');
eq($r->upstreamUrl, 'https://raw.githubusercontent.com/octocat/hello-world/Main/Dir/ReadMe.MD', 'owner/repo 小写而 ref/path 保留大小写');
eq($r->ref, 'Main', 'ref 保留原大小写');
eq($r->path, 'Dir/ReadMe.MD', 'path 保留原大小写与层级');

// ?u= 形式: 穿透任何改写 // 的代理, 且内层 query 一个字节都不动
$inner = 'https://objects.githubusercontent.com/x/a.bin?Expires=1700000000&Signature=abc%2Bdef%2Fghi&key-id=1';
$r = $parser->parse('/anything', 'u=' . rawurlencode($inner) . '&sha256=' . str_repeat('a', 64));
eq($r->upstreamUrl, $inner, '?u= 的 %2B/%2F 原样保留(解码再编码就 403 SignatureDoesNotMatch)');
eq($r->expectedSha256, str_repeat('a', 64), '?u= 形式带出 ?sha256=');
eq($r->upstreamHost, 'objects.githubusercontent.com', '?u= 形式的 upstreamHost');
eq($r->identityKind, IdentityKind::Ambiguous, '签名 URL 不给缓存资格');
ok(in_array('signed_url_not_cacheable', $r->warnings, true), '签名 URL 不可缓存必须留告警');
rejects(static fn () => $parser->parse('/p', 'u=' . rawurlencode('http://github.com/x')), GhpError::SCHEME_NOT_ALLOWED, '?u= 里的 http 被拒');
rejects(static fn () => $parser->parse('/p', 'u=' . rawurlencode('https://evil.com/x')), GhpError::HOST_NOT_ALLOWED, '?u= 里的非白名单域被拒');
rejects(static fn () => $parser->parse('/p', 'u=' . rawurlencode('https://github.com\\@evil.com/x')), GhpError::BACKSLASH_IN_URL, '?u= 解码后的反斜杠被拒');

// blob→raw 的位置限定(深处 blob 不许动)
$r = $parser->parse('/https://github.com/o/r/tree/main/blob/x', '');
eq($r->upstreamUrl, 'https://api.github.com/repos/o/r/contents/blob/x?ref=main', 'tree 走 contents, 深处 blob 未被误改写');
eq($r->scene, Scene::ApiJson, 'tree -> api_json');
ok(!str_contains($r->upstreamUrl, 'raw.githubusercontent'), '没有把 /tree/main/blob/x 改成 raw');
eq($parser->parse('/raw/o/r/blob/main/a.md', '')->upstreamUrl, 'https://raw.githubusercontent.com/o/r/main/a.md', '别名里的 blob 标记只吃一次');
eq($parser->parse('/https://github.com/o/r/blob/main/blob/blob.md', '')->upstreamUrl, 'https://raw.githubusercontent.com/o/r/main/blob/blob.md', 'path 里同名的 blob 段不受影响');

// 归档: allowRange=false(302 落地的 codeload 实测无视 Range 回全量), 且必须先跟一跳才拿得到真实体积。
// 上游默认发 github.com/.../archive/... 而不是直拼 codeload —— 实测公共镜像普遍屏蔽 codeload 直链
// (ghfast.top 对 …/https://codeload.github.com/… 回 403, 对 …/https://github.com/…/archive/… 回 200)。
foreach (['/zip/o/r/main', '/tar/o/r/main', '/archive/o/r/main.tar.gz', '/archive/o/r/refs/heads/main.zip'] as $a) {
    $r = $parser->parse($a, '');
    eq($r->scene, Scene::Archive, $a . ' -> archive');
    eq($r->allowRange, false, $a . ' allowRange=false');
    eq($r->needsRedirectResolve, true, $a . ' archive 形态必 302, 标记需跟跳');
}
eq($parser->parse('/archive/o/r/refs/heads/main.tar.gz', '')->upstreamUrl, 'https://github.com/o/r/archive/refs/heads/main.tar.gz', '归档走 github.com/archive');
eq($parser->parse('/archive/o/r/main.zip', '')->upstreamUrl, 'https://github.com/o/r/archive/main.zip', '归档 zip 走 github.com/archive');
eq($parser->parse('/tar/o/r/refs/heads/feat/x', '')->upstreamUrl, 'https://github.com/o/r/archive/refs/heads/feat/x.tar.gz', '含斜杠的全限定分支归档');
$sha = '7fd1a60b01f91b314f59955a4e4d4e80d8edf11d';
eq($parser->parse('/tar/o/r/' . $sha, '')->upstreamUrl, 'https://github.com/o/r/archive/' . $sha . '.tar.gz', '40 位 sha 直接当 ref');
eq($parser->parse('/tar/o/r/' . $sha, '')->identityKind, IdentityKind::CommitSha, 'sha 归档身份 = commit_sha');
// @ 分隔形式: ref 本身可以含 '/', 只有 @ 能唯一确定 repo 与 ref 的边界。
eq($parser->parse('/zip/o/r@refs/tags/v1.2.3', '')->upstreamUrl, 'https://github.com/o/r/archive/refs/tags/v1.2.3.zip', '@ 形式的归档重写');
eq($parser->parse('/tar/o/r@refs/tags/v1.2.3', '')->owner, 'o', '@ 形式 owner 不被污染');
eq($parser->parse('/tar/o/r@refs/tags/v1.2.3', '')->repo, 'r', '@ 形式 repo 不含 @ 与 ref 残片');
eq($parser->parse('/https://github.com/o/r/archive/' . $sha . '.zip', '')->identityKind, IdentityKind::CommitSha, '绝对形式 sha 归档身份 = commit_sha');
ok($parser->parse('/https://github.com/o/r/archive/refs/heads/main.tar.gz', '')->needsRedirectResolve, '绝对形式归档按字面重放并标记需跟一跳');
ok($parser->parse('/https://codeload.github.com/o/r/tar.gz/main', '')->allowRange === false, '绝对形式 codeload 也标 allowRange=false');

// Release / API / gist
$r = $parser->parse('/release/o/r/v1.2.3/tool-1.0.zip', '');
eq($r->upstreamUrl, 'https://github.com/o/r/releases/download/v1.2.3/tool-1.0.zip', 'release 资产上游形态');
eq($r->needsRedirectResolve, true, 'release 必须内部解析 302');
eq($r->identityKind, IdentityKind::RefName, '按 (tag, 文件名) 的身份只是 ref_name(同名重传会变 asset_id)');
eq($r->downloadName, 'tool-1.0.zip', 'downloadName 兜底');
$r = $parser->parse('/https://github.com/o/r/releases/assets/12345678', '');
eq($r->identityKind, IdentityKind::AssetId, '数字 asset id -> asset_id');
eq($r->assetId, 12345678, 'assetId 填入引用');
eq($parser->parse('/api/repos/o/r/releases/latest', '')->identityKind, IdentityKind::MutableApi, 'api -> mutable_api');
eq($parser->parse('/api/repos/o/r', 'per_page=100')->upstreamUrl, 'https://api.github.com/repos/o/r?per_page=100', 'api query 透传');
eq($parser->parse('/api/rate_limit', '')->allowRange, false, 'api 不按 Range 对待');
eq($parser->parse('/gist/octocat/1a2b3c4d5e6f7g8h9i0j/file.sh', '')->upstreamUrl, 'https://gist.githubusercontent.com/octocat/1a2b3c4d5e6f7g8h9i0j/raw/file.sh', 'gist raw 形态');
eq($parser->parse('/gist/octocat/1a2b/' . $sha . '/file.sh', '')->identityKind, IdentityKind::GistRev, '带 revision 的 gist -> gist_rev');

// releases/latest 免 API 解 tag(本机 api 实测常被 403, 免 API 是必须而非优化)
eq(UpstreamMap::latestTagFromRedirect('https://github.com/jqlang/jq/releases/tag/jq-1.8.2'), 'jq-1.8.2', 'latestTagFromRedirect(实测上游真实 Location, 免 API 取 tag)');
foreach ([
    'https://github.com/O/R/releases/tag/v1.2.3' => 'v1.2.3',
    '/o/r/releases/tag/feat%2Fv1' => 'feat/v1',
    'https://github.com/o/r/releases/expanded_assets/v1' => '',
    'https://github.com/o/r/releases/latest' => '',
    'https://evil.example/o/r/releases/tag/x' => '',
    'https://github.com/o/r' => '',
    'https://github.com/o/r/releases/tag/v1.0/builds/12' => 'v1.0/builds/12',
] as $loc => $tag) {
    eq(UpstreamMap::latestTagFromRedirect((string) $loc, 'o', 'r'), (string) $tag, 'latestTagFromRedirect(' . $loc . ')');
}
eq(UpstreamMap::latestTagFromRedirect('https://github.com/O/R/releases/tag/Release-v1'), 'Release-v1', 'tag 大小写不被破坏');
eq(UpstreamMap::latestTagApiUrl('o', 'r'), 'https://api.github.com/repos/o/r/releases/latest', 'API 兜底端点');
eq($parser->parse('/latest/o/r/tool.zip', '')->needsRedirectResolve, true, 'latest 标记需要跟一跳取 tag');
eq($parser->parse('/latest/o/r/tool.zip', '')->upstreamUrl, 'https://github.com/o/r/releases/latest', 'latest 上游指向 302 端点');
ok($parser->parse('/latest/o/r', '')->cacheEligible() === false, '拿不到 tag 的 latest 不给缓存资格');

// query 白名单: plain 与凭据键丢弃, 其余原样
$r = $parser->parse('/gh/o/r@main/a.md', 'plain=1&access_token=SECRET&foo=bar');
ok(!str_contains($r->upstreamUrl, 'plain=1'), '丢弃 ?plain=1');
ok(!str_contains($r->upstreamUrl, 'SECRET'), '丢弃 access_token 且不进上游');
ok(str_contains($r->upstreamUrl, 'foo=bar'), '其余 query 原样透传');
$r = $parser->parse('/https://github.com/o/r/releases/download/v1/t.zip', 'x=a%2Bb');
ok(str_contains($r->upstreamUrl, 'x=a%2Bb'), '绝对形式外层 query 不被解码');

// 入参与方法拒绝
rejects(static fn () => $parser->parse('/https://github.com/o/r/blob/main/a.md', str_repeat('k=v&', 600)), GhpError::URL_TOO_LONG, 'query 超长拒绝');
rejects(static fn () => $parser->parse('/https://github.com/' . str_repeat('a', 5000), ''), GhpError::URL_TOO_LONG, 'path 超长拒绝');
rejects(static fn () => $parser->parse('/gh/o/r@main/../etc/passwd', ''), GhpError::PATH_TRAVERSAL, '路径段 .. 拒绝');
rejects(static fn () => $parser->parse('/gh/o/r@main/%2e%2e/x', ''), GhpError::PATH_TRAVERSAL, '点段的 %2e 形态同样拒绝');
rejects(static fn () => $parser->parse('/https://user@github.com/o/r', ''), GhpError::USERINFO_NOT_ALLOWED, '绝对形式 userinfo 拒绝');
rejects(static fn () => $parser->parse('/https://github.com\\@evil.com/o/r', ''), GhpError::BACKSLASH_IN_URL, '入口层也拒反斜杠');
rejects(static fn () => $parser->parse('/https://evil.com/o/r', ''), GhpError::HOST_NOT_ALLOWED, '非白名单 host 拒绝');
rejects(static fn () => $parser->parse('/nonsense/thing', ''), GhpError::UNPARSEABLE, '看不懂的写法拒绝而不是猜');
$_SERVER['REQUEST_METHOD'] = 'POST';
rejects(static fn () => $parser->parse('/gh/o/r@main/a.md', ''), GhpError::UNSUPPORTED_METHOD, 'POST 拒绝');
$_SERVER['REQUEST_METHOD'] = 'OPTIONS';
rejects(static fn () => $parser->parse('/gh/o/r@main/a.md', ''), GhpError::UNSUPPORTED_METHOD, '入口忘了拦 OPTIONS 时这里兜底');
unset($_SERVER['REQUEST_METHOD']);

// ref 歧义: 归档形式没有 path, 整段都是 ref -> 多段裸名无法区分 branch/tag
rejects(static fn () => $parser->parse('/tar/o/r/feat/x', ''), GhpError::AMBIGUOUS_REF, '多段裸 ref -> AMBIGUOUS_REF');
eq($parser->parse('/tar/o/r/refs/heads/feat/x', '')->ref, 'refs/heads/feat/x', '全限定 ref 允许含斜杠');
overlay(['routing' => ['autoref_resolve' => true]]);
$r = (new RefParser(Config::load($TMP, true)))->parse('/tar/o/r/feat/x', '');
eq($r->identityKind, IdentityKind::RefName, 'autoref_resolve=true 时按 branch 优先接受');
ok(in_array('ambiguous_ref_accepted_branch_first', $r->warnings, true), '歧义放行必须留 warning(否则运维以为结果是精确的)');
overlay([]);
Config::load($TMP, true);

// ----------------------------------------------------------------------
section('5. RateLimiter: 回填 / 拒绝 / 争用降级');
// ----------------------------------------------------------------------
$rl = new RateLimiter($cfg, $TMP);
$b = $rl->consume('ip', '203.0.113.7', 100.0);
eq([$b['allowed'], $b['limit'], (int) $b['remaining'], $b['contended']], [true, 120.0, 20, false], '首次消费: cap120 扣 100 余 20');
$b = $rl->consume('ip', '203.0.113.7', 25.0);
eq([$b['allowed'], $b['contended']], [false, false], '余量不足 -> 拒绝且非争用');
ok($b['retry_after'] >= 1, 'retry_after 给了可执行等待值: ' . $b['retry_after'] . 's');
eq($rl->consume('ip', '203.0.113.7', 999.0)['allowed'], false, '单次成本超 cap 直接拒(不让它等到天荒地老)');
eq($rl->consume('panel', '203.0.113.7', 1.0)['limit'], 10.0, 'panel 桶与 ip 桶独立(数据面/管理面分开)');
eq($rl->consume('ipday', '203.0.113.7', 1.0)['limit'], 16384.0, 'ipday 字节配额桶存在且很宽');
eq($rl->consume('login', '203.0.113.7', 1.0)['limit'], 5.0, 'login 桶存在');
eq($rl->consume('suspect_ua', '203.0.113.7', 1.0)['limit'], 3.0, 'suspect_ua 桶存在');
eq($rl->consume('未配置的作用域', '203.0.113.7', 1.0)['allowed'], true, '未知 scope 用兜底参数而不是崩溃');

$bucketFile = null;
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($TMP . '/var/ratelimit', FilesystemIterator::SKIP_DOTS)) as $f) {
    if ($f->isFile() && str_ends_with($f->getFilename(), '.json')) {
        $c = json_decode((string) file_get_contents($f->getPathname()), true);
        if (is_array($c) && ($c['scope'] ?? '') === 'ip') {
            $bucketFile = $f->getPathname();
        }
    }
}
ok(is_string($bucketFile), '桶文件按 hash 派生 + 两级目录分片');
ok(!str_contains((string) $bucketFile, '203.0.113'), '文件名不含明文 IP');
ok(!str_contains(basename((string) $bucketFile), ':'), '文件名本身不含冒号(IPv6 键在 Windows 直接炸)');
ok(!preg_match('/[<>:"|?*]/', basename((string) $bucketFile)), '文件名是 Windows 安全字符集');
ok(substr_count((string) $bucketFile, DIRECTORY_SEPARATOR) >= 6, '两级分片目录: ' . str_replace($TMP, '', (string) $bucketFile));

// 回填公式 refill = min(cap, tokens + rate*(now-updated))
file_put_contents((string) $bucketFile, json_encode(['tokens' => 0.0, 'updated' => microtime(true) - 3.0, 'scope' => 'ip']));
eq($rl->consume('ip', '203.0.113.7', 59.0)['allowed'], true, '3s x rate20 = 回填 60 -> 59 可满足');
file_put_contents((string) $bucketFile, json_encode(['tokens' => 0.0, 'updated' => microtime(true) - 3.0, 'scope' => 'ip']));
$b = $rl->consume('ip', '203.0.113.7', 61.0);
eq($b['allowed'], false, '回填 60 时 61 不满足');
ok($b['remaining'] >= 58.0 && $b['remaining'] <= 61.0, '拒绝时 remaining 反映回填后的真实余量: ' . $b['remaining']);
file_put_contents((string) $bucketFile, json_encode(['tokens' => 9999.0, 'updated' => microtime(true) - 86400.0, 'scope' => 'ip']));
eq($rl->consume('ip', '203.0.113.7', 121.0)['allowed'], false, '空闲一夜不攒出超过 cap 的配额(clamp 生效)');
file_put_contents((string) $bucketFile, json_encode(['tokens' => 10.0, 'updated' => microtime(true) + 3600, 'scope' => 'ip']));
eq($rl->consume('ip', '203.0.113.7', 11.0)['allowed'], false, '时钟回拨(未来 updated)不把扣费变成回填');
file_put_contents((string) $bucketFile, '{"tokens": 这不是合法 JSON');
$b = $rl->consume('ip', '203.0.113.7', 1.0);
eq([$b['allowed'], $b['remaining'] > 110], [true, true], '桶文件损坏 -> 重建满桶并放行');

// 争用降级: 另一个 fd 占住排他锁时必须"放行 + contended", 绝不阻塞等锁
file_put_contents((string) $bucketFile, json_encode(['tokens' => 0.0, 'updated' => microtime(true), 'scope' => 'ip']));
$held = fopen((string) $bucketFile, 'c+');
ok(is_resource($held) && flock($held, LOCK_EX | LOCK_NB), '测试侧先占住桶锁');
$t0 = microtime(true);
$b = $rl->consume('ip', '203.0.113.7', 1.0);
$dt = microtime(true) - $t0;
eq([$b['allowed'], $b['contended']], [true, true], '抢不到锁 -> 降级放行并标记 contended');
ok($dt < 0.2, '降级不阻塞等锁: ' . round($dt * 1000, 1) . 'ms');
flock($held, LOCK_UN);
fclose($held);

@mkdir($TMP . '/blocker', 0770, true);
file_put_contents($TMP . '/blocker/plain', 'x');
$b = (new RateLimiter($cfg, $TMP . '/blocker/plain'))->consume('ip', '198.51.100.9', 1.0);
eq($b['allowed'], true, '桶目录建不出来时放行(限流坏了不能拖垮请求)');
eq($rl->peek('ipday', '从未用过的键')['known'], false, 'peek 未知桶返回未知情而非崩溃');
ok($rl->peek('ip', '203.0.113.7')['known'] === true, 'peek 已知桶读得到');
ok($rl->prune(-1) >= 0, 'prune 可调用');

// ----------------------------------------------------------------------
section('6. Slots: lock-slot 并发');
// ----------------------------------------------------------------------
$s1 = new Slots($TMP, 3);
$s2 = new Slots($TMP, 3);
$s3 = new Slots($TMP, 3);
eq($s1->acquire(), 0, '第 1 个槽');
eq($s2->acquire(), 1, '第 2 个槽(不同实例 -> 不同 fd, 真互斥)');
eq($s1->acquire(), 0, '同实例重复 acquire 不重复占用(可重入)');
$s4 = new Slots($TMP, 3);
eq($s4->acquire(), 2, '第 3 个槽');
eq((new Slots($TMP, 3))->acquire(), null, '并发已满 -> null(调用方回 503)');
eq($s3->used(), 3, 'used() 观测到 3');
eq($s1->count(), 3, 'count() 报告容量');
$s2->release();
$s2->release();
eq($s2->acquire(), 1, '释放后重新拿到同一个槽号');
$s2->release();
$s1->release();
$s4->release();
eq($s3->used(), 0, '全部释放后 used()=0');
eq($s1->held(), false, 'held() 反映自身状态');
ok(is_file($TMP . '/var/concurrency/slot_00'), '槽文件命名 slot_NN: ' . basename($TMP . '/var/concurrency/slot_00'));

// 真并发: 6 个子进程各占槽 2s, 槽数 2 -> 成功数不得超过 2 且至少 1
$helper = $TMP . '/slot_child.php';
file_put_contents($helper, "<?php\nrequire \$argv[2] . '/src/Bootstrap.php';\n\\GhAccel\\Bootstrap::register();\n\\GhAccel\\Bootstrap::autoload('');\n\$s = new \\GhAccel\\Security\\Slots(\$argv[1], (int) \$argv[3]);\necho \$s->acquire() === null ? 'X' : 'G';\nusleep((int) \$argv[4]);\n");
$outDir = $TMP . '/slot_out';
@mkdir($outDir, 0770, true);
$procs = [];
for ($i = 0; $i < 6; $i++) {
    $cmd = sprintf('%s %s %s %s %d %d', $exec, escapeshellarg($helper), escapeshellarg($TMP), escapeshellarg($ROOT), 2, 2000000);
    $p = proc_open($cmd, [1 => ['file', $outDir . '/' . $i . '.txt', 'w'], 2 => ['file', $outDir . '/' . $i . '.err', 'w']], $pipes);
    if (is_resource($p)) {
        $procs[] = $p;
    }
}
foreach ($procs as $p) {
    proc_close($p);
}
$got = 0;
for ($i = 0; $i < 6; $i++) {
    $got += substr_count((string) @file_get_contents($outDir . '/' . $i . '.txt'), 'G');
}
info('并发结果: ' . $got . '/6 个进程拿到槽(容量 2)');
ok($got <= 2, '并发数绝不超过槽容量(拿到 ' . $got . ' 个)');
ok($got >= 1, '至少一个进程拿到槽');
$orphan = new Slots($TMP, 2);
eq($orphan->acquire(), 0, '子进程全部退出后槽自动回收(崩溃/超时不漂移)');
$orphan->release();

// ----------------------------------------------------------------------
section('7. Auth: selector/verifier、会话绑定与写请求校验');
// ----------------------------------------------------------------------
$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
$_SERVER['HTTPS'] = 'on';
$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 panel-test';
$_SERVER['HTTP_ACCEPT'] = 'text/html';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/ctl-7f3a';
$_SERVER['HTTP_ORIGIN'] = 'https://accel.example.com';
$_SERVER['CONTENT_TYPE'] = 'application/json';
unset($_SERVER['HTTP_SEC_FETCH_SITE'], $_SERVER['HTTP_X_CSRF_TOKEN'], $_SERVER['HTTP_REFERER'], $_SERVER['HTTP_HOST']);
$_COOKIE = [];
$_POST = [];

overlay(['app' => ['base_origin' => 'https://accel.example.com'], 'panel' => ['path_prefix' => 'ctl-7f3a']]);
$cfgOwn = Config::load($TMP, true);
$auth = new Auth($cfgOwn, $TMP);

$issued = $auth->issueToken('ops-laptop', ['read', 'write']);
eq(strlen($issued['raw']), 96, 'raw token = 48 字节 hex');
eq(strlen($issued['selector']), 16, 'selector = 前 8 字节 = 16 字符');
eq(substr($issued['raw'], 0, 16), $issued['selector'], 'selector 就是 raw 的前 16 字符');
eq(strlen(substr($issued['raw'], 16)), 80, 'verifier = 剩余 80 字符');

$storeRaw = (string) file_get_contents($TMP . '/var/state/admin/verifiers.json');
ok(!str_contains($storeRaw, $issued['raw']), '库里没有明文 Token');
ok(!str_contains($storeRaw, substr($issued['raw'], 16)), '库里没有 verifier 明文');
ok(str_contains($storeRaw, hash('sha256', substr($issued['raw'], 16))), '库里只有 sha256(verifier)');

$row = $auth->verifyTokenRaw($issued['raw']);
ok(is_array($row) && in_array('write', (array) $row['scopes'], true), '正确 Token 校验通过并带出 scopes');
$flip = substr($issued['raw'], 0, 95) . (substr($issued['raw'], 95, 1) === 'a' ? 'b' : 'a');
eq($auth->verifyTokenRaw($flip), null, 'verifier 差一个字符即失败');
eq($auth->verifyTokenRaw(bin2hex(random_bytes(48))), null, '全新随机 Token( selector 不存在)失败');
eq($auth->verifyTokenRaw($issued['selector'] . str_repeat('0', 80)), null, 'selector 存在但 verifier 不对 -> 失败');
eq($auth->verifyTokenRaw('short'), null, '长度不对的 Token 失败');
eq($auth->verifyTokenRaw(str_repeat('g', 96)), null, '非 hex 的 Token 失败');

$login = $auth->loginWithToken($issued['raw']);
$_COOKIE[Auth::COOKIE] = $login['cookie'];
$s = $auth->session();
ok(is_array($s), '登录后 session() 有值');
eq($s['scopes'] ?? null, ['read', 'write'], 'session 带出 scopes');
eq($s['selector'] ?? null, $issued['selector'], 'session 记录 selector');
eq($s['actor'] ?? null, substr($issued['selector'], 0, 8), 'actor 是派生值而不是 Token');
eq($auth->requireAuth()['selector'] ?? null, $issued['selector'], 'requireAuth 命中会话');
$auth->requireWrite('POST');
ok(true, '有 write 作用域时 requireWrite 通过');
$_SERVER['HTTP_X_CSRF_TOKEN'] = $auth->csrfTokenFor('POST', '/ctl-7f3a/api/sources');
rejects(static fn () => $auth->requireWrite('GET'), GhpError::UNSUPPORTED_METHOD, 'GET 不是写方法');
$auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources');
ok(true, '同源 + Origin 相符 + Content-Type json + 会话 sid 绑定 -> 通过');
$_SERVER['HTTP_X_CSRF_TOKEN'] = $auth->csrfTokenFor('POST', '/ctl-7f3a/api/sources');
$auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources');
ok(true, '带正确的 X-CSRF-Token 通过');
$_SERVER['HTTP_X_CSRF_TOKEN'] = $auth->csrfTokenFor('POST', '/ctl-7f3a/api/breaker');
rejects(static fn () => $auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources'), GhpError::CSRF_FAILED, 'Token 绑到别的动作 -> 拒');
$_SERVER['HTTP_X_CSRF_TOKEN'] = $auth->csrfTokenFor('GET', '/ctl-7f3a/api/sources');
rejects(static fn () => $auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources'), GhpError::CSRF_FAILED, 'Token 绑到别的 method -> 拒');
$_SERVER['HTTP_X_CSRF_TOKEN'] = 'aaaa';
rejects(static fn () => $auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources'), GhpError::CSRF_FAILED, 'Token 被伪造 -> 拒');
$_SERVER['HTTP_X_CSRF_TOKEN'] = $auth->csrfTokenFor('POST', '/ctl-7f3a/api/sources');
$_COOKIE = [];
rejects(static fn () => $auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources'), GhpError::NOT_FOUND, '无会话的 HTML 语境写请求 -> 404 语义');
$_COOKIE[Auth::COOKIE] = $login['cookie'];
$_SERVER['HTTP_SEC_FETCH_SITE'] = 'cross-site';
rejects(static fn () => $auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources'), GhpError::CSRF_FAILED, 'Sec-Fetch-Site=cross-site -> 拒');
$_SERVER['HTTP_SEC_FETCH_SITE'] = 'same-origin';
$auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources');
ok(true, 'Sec-Fetch-Site=same-origin 通过');
$_SERVER['HTTP_SEC_FETCH_SITE'] = 'none';
$auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources');
ok(true, 'Sec-Fetch-Site=none 允许(靠 Origin 与 Token 兜住)');
unset($_SERVER['HTTP_SEC_FETCH_SITE']);
$_SERVER['HTTP_ORIGIN'] = 'https://evil.example.com';
rejects(static fn () => $auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources'), GhpError::CSRF_FAILED, 'Origin 不同源 -> 拒');
$_SERVER['HTTP_ORIGIN'] = 'https://accel.example.com:8443';
rejects(static fn () => $auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources'), GhpError::CSRF_FAILED, 'Origin 带别的端口 -> 拒');
$_SERVER['HTTP_ORIGIN'] = 'https://ACCEL.example.com';
$auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources');
ok(true, 'Origin 仅大小写差异可接受(scheme+host 语义)');
$_SERVER['HTTP_ORIGIN'] = 'https://accel.example.com';
// Host 伪造不影响基准: 基准只来自配置
$_SERVER['HTTP_HOST'] = 'evil.example.com';
$_SERVER['HTTP_ORIGIN'] = 'https://evil.example.com';
rejects(static fn () => $auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources'), GhpError::CSRF_FAILED, 'Host 伪造 + Origin 跟着伪造 -> 仍拒');
unset($_SERVER['HTTP_HOST']);
$_SERVER['HTTP_ORIGIN'] = 'https://accel.example.com';
unset($_SERVER['HTTP_ORIGIN']);
$_SERVER['HTTP_REFERER'] = 'https://evil.example.com/page';
rejects(static fn () => $auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources'), GhpError::CSRF_FAILED, '无 Origin 时 Referer 不同源 -> 拒');
$_SERVER['HTTP_REFERER'] = 'https://accel.example.com/ctl-7f3a';
$auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources');
ok(true, '无 Origin 但 Referer 同源 -> 通过');
unset($_SERVER['HTTP_REFERER']);
$_SERVER['HTTP_ORIGIN'] = 'https://accel.example.com';
$_SERVER['CONTENT_TYPE'] = 'text/html';
rejects(static fn () => $auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources'), GhpError::CSRF_FAILED, 'Content-Type 不是 json/表单 -> 拒');
$_SERVER['CONTENT_TYPE'] = 'multipart/form-data';
rejects(static fn () => $auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources'), GhpError::CSRF_FAILED, 'multipart 也拒(攻击者可控)');
$_SERVER['CONTENT_TYPE'] = 'application/json';
$_SERVER['REQUEST_METHOD'] = 'GET';
eq($auth->csrfToken(), $auth->csrfTokenFor('GET', '/ctl-7f3a'), 'csrfToken() 取当前请求上下文');
$_SERVER['REQUEST_METHOD'] = 'POST';
eq($auth->csrfToken(), $auth->csrfTokenFor('POST', '/ctl-7f3a'), 'csrfToken() 绑当前 method+path');
$map = $auth->csrfMap(['POST:/ctl-7f3a/api/sources', 'DELETE:/ctl-7f3a/api/sources']);
eq(count($map), 2, 'csrfMap 一次算好面板需要的多个动作');
ok($map['POST:/ctl-7f3a/api/sources'] !== $map['DELETE:/ctl-7f3a/api/sources'], '不同动作的 Token 不同');
unset($_SERVER['REQUEST_METHOD']);

// 会话绑定与 TTL
$_COOKIE[Auth::COOKIE] = $login['selector'] . '.' . str_repeat('0', 32);
eq($auth->session(), null, 'sid 被换掉 -> 会话失效');
$_COOKIE[Auth::COOKIE] = $login['cookie'];
$_SERVER['REMOTE_ADDR'] = '198.51.100.44';
eq($auth->session(), null, '换 /24 出口地址 -> 会话失效');
$_SERVER['REMOTE_ADDR'] = '203.0.113.200';
ok(is_array($auth->session()), '同一 /24 内换地址不掉线(绑前缀而非整 IP)');
$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
$_SERVER['HTTP_USER_AGENT'] = 'curl/8.0 other-agent';
eq($auth->session(), null, 'UA 变化 -> 会话失效');
$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 panel-test';
$sessFile = $TMP . '/var/sessions/' . Auth::sessionFileName($issued['selector']);
ok(basename($sessFile) === 'sess_' . hash('sha256', $issued['selector']) . '.json', '会话文件名 = sess_<sha256(selector)>');
ok(!str_contains(basename($sessFile), $issued['raw']), '会话文件名不含 Token');
$j = json_decode((string) file_get_contents($sessFile), true);
$j['last_seen_at'] = time() - 4000;
Config::atomicWrite($sessFile, (string) json_encode($j));
eq($auth->session(), null, '超过 idle TTL -> 失效(会话文件顺手删除)');
$_COOKIE[Auth::COOKIE] = $auth->loginWithToken($issued['raw'])['cookie'];
$j = json_decode((string) file_get_contents($sessFile), true);
$j['last_seen_at'] = time();
$j['created_at'] = time() - 100000;
Config::atomicWrite($sessFile, (string) json_encode($j));
eq($auth->session(), null, '超过 abs TTL -> 就算一直活跃也要重登');
$re = $auth->loginWithToken($issued['raw']);
$_COOKIE[Auth::COOKIE] = $re['cookie'];
ok(is_array($auth->session()), '重登后恢复');

// 未登录的分流
$_COOKIE = [];
$_SERVER['HTTP_ACCEPT'] = 'text/html';
$_SERVER['REQUEST_URI'] = '/ctl-7f3a';
rejects(static fn () => $auth->requireAuth(), GhpError::NOT_FOUND, '未登录 HTML 请求 -> 404(不给"这里有个面板"的信号)');
$_SERVER['HTTP_ACCEPT'] = 'application/json';
$_SERVER['REQUEST_URI'] = '/ctl-7f3a/api/summary';
rejects(static fn () => $auth->requireAuth(), GhpError::UNAUTHENTICATED, '未登录 API 请求 -> 401(脚本要能区分没带凭证与不存在)');
$_SERVER['HTTP_ACCEPT'] = '*/*';
rejects(static fn () => $auth->requireAuth(), GhpError::UNAUTHENTICATED, '无 Accept 但路径在 /api/ 下 -> 401');
$_SERVER['REQUEST_URI'] = '/ctl-7f3a/overview';
rejects(static fn () => $auth->requireAuth(), GhpError::NOT_FOUND, '面板页无 Accept -> 404');

// 只读 Token
$_SERVER['HTTP_ACCEPT'] = 'application/json';
$readOnly = $auth->issueToken('ci-readonly', ['read']);
$_COOKIE[Auth::COOKIE] = $auth->loginWithToken($readOnly['raw'])['cookie'];
$_SERVER['HTTP_X_CSRF_TOKEN'] = $auth->csrfTokenFor('POST', '/ctl-7f3a/api/sources');
rejects(static fn () => $auth->verifyWriteRequest('POST', '/ctl-7f3a/api/sources'), GhpError::SCOPE_REQUIRED, '无 write 作用域 -> SCOPE_REQUIRED');
rejects(static fn () => $auth->requireWrite('DELETE'), GhpError::SCOPE_REQUIRED, 'requireWrite 同样挡住只读 Token');

// 登录入口: 话术不区分、限流生效
$_COOKIE = [];
$_SERVER['REQUEST_URI'] = '/ctl-7f3a/login';
$_SERVER['REMOTE_ADDR'] = '198.51.100.9';
$_POST = ['token' => $issued['raw']];
$auth->handleLogin();
ok(is_array($auth->session()), 'handleLogin 成功即建立会话');
$_POST = ['token' => str_repeat('1', 96)];
$msgA = '';
try {
    $auth->handleLogin();
} catch (GhpError $e) {
    $msgA = $e->errorCode . '|' . $e->getMessage();
}
$_POST = ['token' => $issued['selector'] . str_repeat('0', 80)];
$msgB = '';
try {
    $auth->handleLogin();
} catch (GhpError $e) {
    $msgB = $e->errorCode . '|' . $e->getMessage();
}
eq($msgB, $msgA, '不区分"selector 不存在"与"verifier 不对"(错误话术逐字符相同)');
$codes = [];
$limited = false;
for ($i = 0; $i < 30; $i++) {
    $_POST = ['token' => bin2hex(random_bytes(48))];
    try {
        $auth->handleLogin();
    } catch (GhpError $e) {
        $codes[$e->errorCode] = ($codes[$e->errorCode] ?? 0) + 1;
        if ($e->errorCode === GhpError::RATE_LIMITED) {
            $limited = true;
            break;
        }
    }
}
ok($limited, '连发错 Token 被 login 桶挡住: 快哈希 + 限流替代 bcrypt(实测 cost11 单次 167ms)');
info('登录尝试分布: ' . json_encode($codes));
$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
$_POST = ['token' => $issued['raw']];
$auth->handleLogin();
ok(is_array($auth->session()), '别的 IP 不受该桶影响(NAT 连坐问题靠分键)');
$_POST = [];
$auth->handleLogout();
$_COOKIE = [];
eq($auth->session(), null, 'handleLogout 后会话不可用');

// 吊销
$sel = $issued['selector'];
$_COOKIE[Auth::COOKIE] = $auth->loginWithToken($issued['raw'])['cookie'];
rejects(static fn () => $auth->revokeToken('abc'), GhpError::NOT_FOUND, '前缀太短不许吊销(防一发清光)');
$auth->revokeToken(substr($sel, 0, 12));
eq($auth->verifyTokenRaw($issued['raw']), null, '吊销后 Token 失效');
$_COOKIE[Auth::COOKIE] = $auth->loginWithToken($readOnly['raw'])['cookie'];
$auth->revokeToken(substr($readOnly['selector'], 0, 8));
eq($auth->session(), null, '吊销连带作废会话(不是"吊销了但还能用")');
rejects(static fn () => $auth->revokeToken('ffffffff'), GhpError::NOT_FOUND, '吊销不存在的 Token -> 404');
$auth->issueToken('list-me', ['read']);
$list = $auth->listTokens();
ok($list !== [], 'listTokens 返回条目');
foreach ($list as $t) {
    ok(!array_key_exists('hash', $t) && !array_key_exists('verifier', $t), '列表不含哈希/verifier: ' . $t['label']);
    eq(strlen((string) $t['selector_prefix']), 8, '列表只给 selector 前 8 位');
}

// ----------------------------------------------------------------------
section('8. Audit: 只落最小必要字段');
// ----------------------------------------------------------------------
$secretBody = ['url' => 'https://github.com/o/r', 'note' => 'SECURE-TOKEN-XYZ-DO-NOT-LOG', 'confirm' => true];
Audit::log('deadbeef', 'POST', '/ctl-7f3a/api/sources', $secretBody, 'ok', '203.0.113.9', $cfgOwn);
$file = $TMP . '/var/log/audit.ndjson';
ok(is_file($file), '审计文件写在配置指定的 logging.dir 下');
$lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$last = is_array($lines) && $lines !== [] ? (string) end($lines) : '';
$rowA = json_decode($last, true);
ok(is_array($rowA), '审计行是合法 JSON(NDJSON 一行一条)');
foreach (['ts', 'actor', 'ip_hash', 'method', 'path', 'body_sha256', 'result'] as $k) {
    ok(is_array($rowA) && array_key_exists($k, $rowA), '字段存在: ' . $k);
}
ok(!str_contains($last, 'SECURE-TOKEN-XYZ-DO-NOT-LOG'), 'body 明文绝不落审计');
ok(!str_contains($last, '203.0.113.9'), '明文 IP 绝不落审计');
ok(!str_contains($last, 'github.com/o/r'), '请求里的源 URL 也不落明文');
eq($rowA['actor'] ?? '', 'deadbeef', 'actor 是派生值');
eq($rowA['body_sha256'] ?? '', Audit::bodySha256($secretBody), 'body 只留 sha256');
eq(Audit::bodySha256(['b' => 2, 'a' => 1]), Audit::bodySha256(['a' => 1, 'b' => 2]), '键序不同的同一 body 得到同一摘要');
eq($rowA['result'] ?? '', 'ok', 'result 落盘');
eq(Audit::actorFromSelector($sel), substr($sel, 0, 8), 'actorFromSelector 取前 8 位');
ok(Audit::ipHash('203.0.113.9', 's') === Audit::ipHash('203.0.113.9', 's'), 'ip_hash 稳定可关联');
ok(Audit::ipHash('203.0.113.9', 's') !== Audit::ipHash('203.0.113.9', 't'), '换 salt 即历史作废');
ok(Audit::tail(5, $cfgOwn) !== [], 'tail 读得到(路径只由配置拼出)');
eq(Audit::log('beef', 'POST', '/x', [], 'ok', '203.0.113.9', $cfgOwn), true, '空 body 也能记');

// ----------------------------------------------------------------------
section('9. 契约与自检');
// ----------------------------------------------------------------------
eq(UpstreamMap::requiredHosts(), array_values(array_unique(UpstreamMap::requiredHosts())), 'requiredHosts 无重复');
$missing = (new UpstreamMap($cfg))->missingAllowedHosts();
if ($missing !== []) {
    info('!! 出厂白名单缺口(要主 agent 补进 config/config.dist.php 的 security.allowed_hosts): ' . implode(',', $missing));
}
// 2026-11 实测: Release 资产的 302 落点已从 objects 迁到 release-assets(jq 与 cli 两个仓库都验过)。
// 曾经出厂白名单缺它, 于是每一次 Release 下载都在第二跳被自己的 host_not_allowed 挡掉 ——
// 症状是"源全绿但下载全 403", 极难归因。缺口已补, 这条改为锁死"不得再缺"。
eq($missing, [], '出厂白名单覆盖全部必需上游域(Release 落点不缺)');
ok(in_array('objects.githubusercontent.com', UpstreamMap::requiredHosts(), true), 'objects 域仍在必需清单里(别的 blob 流程还用)');
ok(UpstreamMap::isSignedAssetHost('release-assets.githubusercontent.com') && UpstreamMap::isSignedAssetHost('objects.githubusercontent.com'), '两个签名落点都按不可缓存处理');
overlay(['security' => ['allowed_hosts' => array_values(array_unique(array_merge(
    (array) $cfg->arr('security.allowed_hosts'), ['release-assets.githubusercontent.com']
)))]]);
$cfgFixed = Config::load($TMP, true);
$fixed = new UrlGuard($cfgFixed);
$sas = 'https://release-assets.githubusercontent.com/github-production-release-asset/5101141/e7a8?sp=r&sv=2018-11-09&sig=cWfa%2FwWxxq8%3D';
$grSas = $fixed->assertAllowed($sas);
eq($grSas->host, 'release-assets.githubusercontent.com', '补上白名单后 Release 真实落点过守卫');
ok(str_contains($grSas->url, 'sig=cWfa%2FwWxxq8%3D'), 'SAS 的 %2F/%3D 逐字节保留(二次编码就 SignatureDoesNotMatch)');
ok(str_starts_with((string) $grSas->resolveLines()[0], 'release-assets.githubusercontent.com:443:'), '落点域名的 RESOLVE 条目 host 逐字节一致');
$refSas = (new RefParser($cfgFixed))->parse('/' . $sas, '');
eq($refSas->identityKind, IdentityKind::Ambiguous, '签名落点引用不给缓存资格');
eq($refSas->scene, Scene::ReleaseAsset, '签名落点识别为 release_asset');
overlay(['security' => ['allowed_hosts' => ['github.com']]]);
$broken = Config::load($TMP, true);
ok(count((new UpstreamMap($broken))->missingAllowedHosts()) > 1, '白名单被砍时自检成批报出来(而不是只报第一个)');
overlay([]);
Config::load($ROOT, true);
$guard = new UrlGuard($cfg);

foreach ([
    [RefParser::class, ['surface', 'parse']],
    [UrlGuard::class, ['assertAllowed', 'assertRedirect', 'isOwnPrefix']],
    [RateLimiter::class, ['consume']],
    [Slots::class, ['acquire', 'release', 'used']],
    [Auth::class, ['handleLogin', 'handleLogout', 'session', 'requireAuth', 'requireWrite', 'verifyWriteRequest', 'csrfToken', 'issueToken', 'revokeToken', 'listTokens']],
] as [$cls, $methods]) {
    foreach ($methods as $m) {
        ok(method_exists($cls, $m), basename($cls) . '::' . $m . '()');
    }
}
foreach (['url', 'host', 'ip', 'resolveEntries'] as $p) {
    ok((new ReflectionProperty(GuardResult::class, $p))->isReadOnly(), 'GuardResult 属性 readonly: ' . $p);
}
foreach (['isPubliclyRoutable', 'normalizeIp'] as $m) {
    ok(method_exists(IpRange::class, $m), 'IpRange::' . $m . '()');
}
$b = (new RateLimiter($cfg, $TMP))->consume('ip', '203.0.113.120', 1.0);
foreach (['allowed', 'retry_after', 'limit', 'remaining', 'contended'] as $k) {
    ok(array_key_exists($k, $b), 'consume 返回键: ' . $k);
}
$ref = $parser->parse('/https://github.com/octocat/Hello-World/blob/master/README.md', '');
ok($ref instanceof GitHubRef && $ref->upstreamUrl !== '' && $ref->upstreamHost !== '', '产出是已填好 upstream 的完整 GitHubRef(调用方无需二次组装)');
eq($parser->parse('/gh/o/r@main/a.md', '')::class, GitHubRef::class, '三种形式都返回同一契约类型');

printf(
    "\n================ 结果: 通过 %d, 失败 %d, 信息 %d ================\n",
    $GLOBALS['__pass'],
    $GLOBALS['__fail'],
    $GLOBALS['__info']
);
if ($GLOBALS['__fail'] > 0) {
    echo "失败项:\n";
    foreach ($GLOBALS['__fails'] ?? [] as $f) {
        echo ' - ' . $f . "\n";
    }
}
rrmdir($TMP);
exit($GLOBALS['__fail'] === 0 ? 0 : 1);
