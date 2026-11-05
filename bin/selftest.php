<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: CLI 自检聚合器 + 部署体检 + takedown 落地。它不重写任何测试断言, 只把
 *             tests/ 下已存在的脚本聚合起来跑, 再对"这个实例到底挡不挡得住 SSRF"做一次
 *             端到端判定, 最后提供一个把 owner/repo 写进下架清单的子命令。
 *
 *   php bin/selftest.php                       # 聚合测试 + 部署体检(默认不联网)
 *   php bin/selftest.php --probe               # 额外对出厂源逐个探活(联网, 建议配 CA bundle)
 *   php bin/selftest.php takedown --repo=owner/repo   # 把仓库写进 var/state/blocklist.json
 *
 * 退出码: 0 = 全部通过; 1 = 任一硬失败(测试失败 / selfCheck 有 critical / 端到端判定不符)。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg') {
    // 内置服务器与 php-cgi 都不该把这套聚合跑在请求路径上 —— 它会 fork 子进程跑测试。
    http_response_code(404);
    echo "bin/selftest.php 只能从命令行运行 (php bin/selftest.php)\n";

    return;
}

$ROOT = dirname(__DIR__);

if (PHP_VERSION_ID < 80100) {
    fwrite(STDERR, sprintf("需要 PHP >= 8.1, 当前 %s\n", PHP_VERSION));
    exit(1);
}

require $ROOT . '/src/Bootstrap.php';
GhAccel\Bootstrap::register();

use GhAccel\Bootstrap;
use GhAccel\Config;
use GhAccel\Enum\Scene;
use GhAccel\Errors\GhpError;
use GhAccel\Ref\RefParser;
use GhAccel\Security\UrlGuard;

// 子进程里的联网用例一律关掉: 自检默认必须能在没有外网、没有 CA bundle 的机器上跑完。
putenv('GHA_OFFLINE=1');
$_ENV['GHA_OFFLINE'] = '1';

$args = array_slice($argv ?? [], 1);
$mode = 'check';
$probe = false;
$repoArg = '';
foreach ($args as $a) {
    if ($a === '--probe') {
        $probe = true;
    } elseif ($a === 'takedown') {
        $mode = 'takedown';
    } elseif (str_starts_with((string) $a, '--repo=')) {
        $repoArg = substr((string) $a, 7);
        $mode = 'takedown';
    } elseif ($a === '--help' || $a === '-h') {
        st_usage();
        exit(0);
    }
}

$exit = 0;

if ($mode === 'takedown') {
    $exit = st_takedown($ROOT, $repoArg);
    exit($exit);
}

// ======================================================================
// 1) 聚合已有测试
// ======================================================================
st_head('1) 聚合测试 (tests/*.php)');

$tests = [
    'tests/agent_a_check.php' => 'A 组: URL 解析 + 安全边界',
    'tests/agent_b_check.php' => 'B 组: 选路算法 + 缓存 + 状态存储',
    'tests/agent_c1_check.php' => 'C1 组: 传输层 + 端到端',
    'tests/agent_c2_check.php' => 'C2 组: 面板 + 令牌 + 压实 (由另一路交付)',
];

foreach ($tests as $rel => $label) {
    $file = $ROOT . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
    if (!is_readable($file)) {
        // 缺失只跳过并注明: C2 等文件由并行交付的同事负责, 现在不存在不代表本实例坏了。
        printf("  SKIP  %-24s 未找到 %s (由并行交付负责, 暂不计入)\n", $label, $rel);

        continue;
    }

    $out = [];
    $code = 0;
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($file) . ' 2>&1';
    @exec($cmd, $out, $code);

    $pass = 0;
    $fail = 0;
    foreach ($out as $line) {
        if (preg_match('/\[(PASS|ok)\b/i', $line) === 1) {
            $pass++;
        }
        if (preg_match('/\bFAIL\]/i', $line) === 1) {
            $fail++;
        }
    }

    // 退出码才是权威: 有的脚本(如 C1 组 fatal)根本跑不出 PASS/FAIL 行。
    $hardFail = $code !== 0;
    if ($hardFail || $fail > 0) {
        $exit = 1;
    }

    $status = $hardFail ? "FAIL(exit={$code})" : ($fail > 0 ? "FAIL({$fail})" : 'ok');
    printf("  %-14s %-24s pass=%-4d fail=%-3d %s\n", $status, $label, $pass, $fail, $rel);

    if ($hardFail || $fail > 0) {
        // 只回显末尾几行, 定位失败原因靠原始脚本输出, 这里不翻译不美化。
        $tailLines = $out === [] ? ['(无输出)'] : array_slice($out, -4);
        foreach ($tailLines as $t) {
            printf('        | %s%s', trim((string) $t), PHP_EOL);
        }
    }
}

// ======================================================================
// 2) 部署体检: Bootstrap::selfCheck
// ======================================================================
st_head('2) 部署体检 Bootstrap::selfCheck()');

$check = Bootstrap::selfCheck($ROOT);
if ($check['critical'] !== []) {
    $exit = 1;
    foreach ($check['critical'] as $k => $v) {
        printf("  CRIT  %-22s %s\n", $k, $v);
    }
} else {
    echo "  ok    无 critical 项 (可安全启动; 半死实例比直接拒服更坏)\n";
}
foreach ($check['warnings'] as $k => $v) {
    printf("  WARN  %-22s %s\n", $k, $v);
}
if ($check['warnings'] === []) {
    echo "  (无告警)\n";
}
$info = $check['info'];
printf(
    "  info  php=%s sapi=%s curl=%s cainfo=%s var_free=%s MB\n",
    (string) ($info['php_version'] ?? ''),
    (string) ($info['sapi'] ?? ''),
    (string) ($info['curl_version'] ?? ''),
    ($info['curl_cainfo'] ?? '') === '' ? '(未设, --probe 需 -d curl.cainfo=...)' : (string) $info['curl_cainfo'],
    isset($info['var_free_bytes']) ? number_format(((int) $info['var_free_bytes']) / 1048576, 1) : '?'
);
// ca_bundle / opcache 是本机便携 PHP 的常态告警, 不判失败, 但 --probe 前必须知道。
if (isset($check['warnings']['ca_bundle'])) {
    echo "  note  联网探活请这样跑: php -d curl.cainfo='<ca-bundle.crt>' bin/selftest.php --probe\n";
}

// ======================================================================
// 3) 端到端判定: 入口解析 + SSRF 必须全部拒绝
// ======================================================================
st_head('3) 端到端判定 (RefParser + UrlGuard)');

$cfg = null;
try {
    $cfg = Config::load($ROOT, true);
} catch (\Throwable $e) {
    $exit = 1;
    printf("  FAIL  配置装载失败: %s\n", $e->getMessage());
}

if ($cfg !== null) {
    try {
        $parser = new RefParser($cfg);
        $guard = new UrlGuard($cfg);
    } catch (\Throwable $e) {
        $exit = 1;
        $parser = null;
        $guard = null;
        printf("  FAIL  RefParser/UrlGuard 构造失败: %s\n", $e->getMessage());
    }

    if ($parser !== null && $guard !== null) {
        // 3.1 三种等价入口形式必须解析成同一个引用(owner=cli repo=cli ref=main path=README.md)。
        $forms = [
            '绝对形式 /https://' => [
                '/https://github.com/cli/cli/blob/main/README.md',
                '',
            ],
            '结构化 /gh/{o}/{r}@{ref}/{path}' => [
                '/gh/cli/cli@refs/heads/main/README.md',
                '',
            ],
            '查询 ?u=' => [
                '/',
                'u=https%3A%2F%2Fgithub.com%2Fcli%2Fcli%2Fblob%2Fmain%2FREADME.md',
            ],
        ];
        foreach ($forms as $name => [$p, $q]) {
            try {
                $ref = $parser->parse($p, $q);
                $good = $ref->owner === 'cli'
                    && $ref->repo === 'cli'
                    && $ref->path === 'README.md'
                    && $ref->scene === Scene::Raw;      // blob 已改写成 raw
                st_mark($good, sprintf('入口形式: %s', $name), sprintf(
                    'scene=%s host=%s ref=%s path=%s',
                    $ref->scene->value,
                    $ref->upstreamHost,
                    $ref->ref,
                    $ref->path
                ));
                if (!$good) {
                    $exit = 1;
                }
            } catch (\Throwable $e) {
                st_mark(false, sprintf('入口形式: %s', $name), get_class($e) . ': ' . $e->getMessage());
                $exit = 1;
            }
        }

        // 3.2 blob -> raw 改写: 上游必须是 raw host 且串里不再有 /blob/。
        try {
            $ref = $parser->parse('/https://github.com/cli/cli/blob/main/README.md', '');
            $good = $ref->upstreamHost === 'raw.githubusercontent.com'
                && str_contains($ref->upstreamUrl, '/blob/') === false;
            st_mark($good, 'blob → raw 改写', $ref->upstreamUrl);
            if (!$good) {
                $exit = 1;
            }
        } catch (\Throwable $e) {
            st_mark(false, 'blob → raw 改写', get_class($e) . ': ' . $e->getMessage());
            $exit = 1;
        }

        // 3.3 归档 allowRange=false: codeload 实测对 Range 回 200 全量, 不能注入 Accept-Ranges。
        try {
            $ref = $parser->parse('/zip/cli/cli/refs/heads/main', '');
            $good = $ref->scene === Scene::Archive && $ref->allowRange === false;
            st_mark($good, '归档 allowRange=false', sprintf(
                'scene=%s allowRange=%s host=%s',
                $ref->scene->value,
                $ref->allowRange ? 'true' : 'false',
                $ref->upstreamHost
            ));
            if (!$good) {
                $exit = 1;
            }
        } catch (\Throwable $e) {
            st_mark(false, '归档 allowRange=false', get_class($e) . ': ' . $e->getMessage());
            $exit = 1;
        }

        // 3.4 一整组 SSRF 用例必须全部被拒 —— 这是本项目最该自证的东西。
        //     判定用 UrlGuard::assertAllowed(与传输层出站前跑的是同一条链)。
        $ssrf = [
            'https://evil.com\\@github.com'                    => '反斜杠解析分歧',
            'https://github.com@evil.com'                      => 'userinfo 一刀切',
            'https://github.com.evil.com/'                     => '后缀匹配绕过',
            'https://notgithub.com/'                           => '看起来像但不是',
            'https://2130706433/'                              => '十进制整型 IP',
            'https://127.1/'                                   => '缩写点分 IP',
            'https://[::ffff:169.254.169.254]/'                => 'v4-mapped 元数据',
            'https://2002:7f00:1::1/'                          => '6to4 → 127.0.0.1',
            'https://64:ff9b::7f00:1/'                         => 'NAT64 → 127.0.0.1',
            'http://github.com/'                               => '降级到 http',
            'file:///etc/passwd'                                => '非 http 协议',
            'https://private-user-images.githubusercontent.com/x' => '明确拒绝的私有域',
        ];
        echo "\n  SSRF 判定链 (逐条都必须被拒):\n";
        foreach ($ssrf as $url => $why) {
            try {
                $guard->assertAllowed((string) $url);
                // 没抛异常 = 放行 = 这是最严重的失败。
                st_mark(false, sprintf('SSRF %-46s', $url), "!! 被放行了: {$why}");
                $exit = 1;
            } catch (GhpError $e) {
                st_mark(true, sprintf('SSRF %-46s', $url), sprintf('拒绝 code=%s (%s)', $e->errorCode, $why));
            } catch (\Throwable $e) {
                // 抛了但不是 GhpError: 仍然拦住了出站, 但拒绝语义不对(诊断码会误导运维)。
                st_mark(true, sprintf('SSRF %-46s', $url), sprintf('异常拦截 %s: %s', get_class($e), $why));
            }
        }
    }
}

// ======================================================================
// 4) 可选探活 (默认关闭)
// ======================================================================
if ($probe) {
    st_head('4) 源探活 (--probe, 联网)');
    st_probe($ROOT);
} else {
    st_head('4) 源探活');
    echo "  SKIP  默认不联网。加 --probe 才对 config/sources.dist.php 的源各发一次 1.5s 超时探活。\n";
}

st_head('结论');
printf("  %s\n", $exit === 0 ? 'PASS — 部署体检与端到端判定全部符合预期。' : 'FAIL — 见上文 CRIT/FAIL, 退出码 1。');
exit($exit);

// ----------------------------------------------------------------------
// 辅助函数
// ----------------------------------------------------------------------

function st_usage(): void
{
    $self = 'bin/selftest.php';
    echo <<<TXT
GhAccel 自检聚合器

用法:
  php {$self}                          聚合测试 + 部署体检 + 端到端判定(默认不联网)
  php {$self} --probe                  额外对出厂源逐个探活(联网)
  php {$self} takedown --repo=owner/repo
                                       把该仓库写进 var/state/blocklist.json (见输出中的"接入"说明)

联网探活若报 unable to get local issuer certificate, 请带 CA:
  php -d curl.cainfo='<ca-bundle.crt>' {$self} --probe

TXT;
}

function st_head(string $t): void
{
    echo PHP_EOL . '== ' . $t . ' ==' . PHP_EOL;
}

function st_mark(bool $ok, string $name, string $extra = ''): void
{
    printf("  %s  %s%s\n", $ok ? 'ok  ' : 'FAIL', $name, $extra === '' ? '' : ('   -> ' . $extra));
}

/**
 * takedown: 落地 var/state/blocklist.json。
 *
 * 诚实边界: 当前代码里没有任何 owner/repo 级拒绝点(只有 host 级 security.denied_hosts)。
 * 本命令只保证"把清单写成一个原子可读的文件", 不代表下架已经生效 —— 生效需要接入点, 见返回文本。
 */
function st_takedown(string $root, string $repoArg): int
{
    $repoArg = trim($repoArg);
    if ($repoArg === '' || substr_count($repoArg, '/') !== 1) {
        fwrite(STDERR, "用法: php bin/selftest.php takedown --repo=owner/repo\n");

        return 1;
    }
    [$owner, $repo] = explode('/', $repoArg, 2);
    $owner = strtolower(trim($owner));
    $repo = strtolower(trim($repo));
    if ($owner === '' || $repo === ''
        || preg_match('/\A[a-z0-9._-]+\z/', $owner) !== 1
        || preg_match('/\A[a-z0-9._-]+(\.git)?\z/', $repo) !== 1) {
        fwrite(STDERR, sprintf("非法 owner/repo: %s\n", $repoArg));

        return 1;
    }

    $file = $root . '/var/state/blocklist.json';
    $store = is_readable($file) ? (array) json_decode((string) @file_get_contents($file), true) : [];
    if (!isset($store['repos']) || !is_array($store['repos'])) {
        $store['repos'] = [];
    }

    $exists = false;
    foreach ($store['repos'] as $row) {
        if (is_array($row) && ($row['owner'] ?? '') === $owner && ($row['repo'] ?? '') === $repo) {
            $exists = true;
            break;
        }
    }
    if (!$exists) {
        $store['repos'][] = [
            'owner'     => $owner,
            'repo'      => $repo,
            'added_at'  => date('c'),
            'reason'    => 'takedown',
        ];
    }
    $store['schema'] = 1;
    $store['updated_at'] = date('c');

    $json = json_encode($store, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    if ($json === false || !Config::atomicWrite($file, $json)) {
        fwrite(STDERR, "写入失败: {$file} (检查 var/state 是否可写)\n");

        return 1;
    }

    st_head('takedown — 已落地清单文件');
    printf("  文件: %s\n", $file);
    printf("  动作: %s %s/%s (当前清单共 %d 条)\n", $exists ? '已存在(未重复追加)' : '已加入', $owner, $repo, count($store['repos']));
    echo "\n  !! 重要: 该清单目前【尚未生效】。代码里没有 owner/repo 级拒绝点,\n";
    echo "     本命令只保证文件写好。要让下架真正挡住请求, 至少需要接入以下 2 处:\n";
    echo "       1) 入口拒绝点 —— public/index.php 在 RefParser::parse() 之后、\n";
    echo "          Dispatcher::serve() 之前读 var/state/blocklist.json, 命中 owner/repo\n";
    echo "          即抛 GhpError(建议新增专用码, 语义上可先借用 404 not_found 对外);\n";
    echo "          或等价地放在 Dispatcher::serve() 顶部做纵深。\n";
    echo "       2) 缓存历史清理 —— Cache\\Key 是 canonical() 的 sha256, 无法按 owner/repo\n";
    echo "          反查已落地条目; 需新增 (owner|repo)->keys 反向索引, 否则下架只挡新请求、\n";
    echo "          旧缓存仍在 EDGE 直出。\n";
    echo "     详见 SECURITY.md「被投诉/被要求下架时怎么处置」一节。\n";

    return 0;
}

/**
 * 出厂源探活: 对每个 enabled 源的 base_url 发一次 1.5s 超时的 GET, 只判可达性不判内容。
 * 纯信息展示, 不改变 selftest 退出码(探活失败不代表本实例坏, 只代表那条第三方镜像今天不可用)。
 */
function st_probe(string $root): void
{
    if (!function_exists('curl_init')) {
        echo "  无法探活: 缺少 curl 扩展。\n";

        return;
    }
    $srcFile = $root . '/config/sources.dist.php';
    if (!is_readable($srcFile)) {
        echo "  未找到 config/sources.dist.php。\n";

        return;
    }
    $data = include $srcFile;
    $sources = is_array($data) && isset($data['sources']) && is_array($data['sources']) ? $data['sources'] : [];
    // SourceRepo 会把 defaults 浅合并进每条源(同名字段整条替换)。enabled 也来自 defaults,
    // 所以这里要按同一口径判启用, 否则出厂默认启用的公共源会被误标成"停用"。
    $defaultEnabled = (bool) (is_array($data) && isset($data['defaults']['enabled']) ? $data['defaults']['enabled'] : false);
    if ($sources === []) {
        echo "  源表为空。\n";

        return;
    }

    printf("  %-18s %-8s %-6s %s\n", 'ID', '启用', '结果', '说明');
    foreach ($sources as $s) {
        $id = substr(str_pad((string) ($s['id'] ?? '?'), 18), 0, 18);
        $enabled = (bool) ($s['enabled'] ?? $defaultEnabled);
        $base = rtrim((string) ($s['base_url'] ?? ''), '/');
        if (!$enabled || $base === '') {
            printf("  %-18s %-8s %-6s %s\n", $id, '-', 'SKIP', $enabled ? '无 base_url' : '出厂停用(示例源)');

            continue;
        }
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $base);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, 1500);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, 1500);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_NOSIGNAL, 1);
        curl_setopt($ch, CURLOPT_IPRESOLVE, defined('CURL_IPRESOLVE_V4') ? CURL_IPRESOLVE_V4 : 1);
        $ok = @curl_exec($ch);
        $errno = (int) curl_errno($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = (string) curl_error($ch);
        curl_close($ch);

        if ($errno !== 0) {
            $res = 'FAIL';
            $note = substr($err, 0, 60);
            if (str_contains($err, 'certificate') || $errno === 60 || $errno === 77 || $errno === 35) {
                $note .= ' (缺 CA? 用 -d curl.cainfo= 再跑)';
            }
        } elseif ($ok === false) {
            $res = 'FAIL';
            $note = '无响应';
        } else {
            $res = $code > 0 ? 'UP' : 'FAIL';
            $note = 'HTTP ' . $code;
        }
        printf("  %-18s %-8s %-6s %s\n", $id, 'yes', $res, $note);
    }
    echo "\n  note  出厂源可用性随时变化, 探活结论仅供选路参考, 不承诺任何第三方镜像(见 README 诚实的局限)。\n";
}
