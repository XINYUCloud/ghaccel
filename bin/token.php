<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 管理令牌的 CLI 签发/列出/吊销。直接复用 Security\Auth 的同一套实现,
 *             不另写一份 Token 逻辑 —— 两份 Token 存储迟早会漂移出"哪个才对"的事故。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 * @see       https://github.com/  完整版权与许可信息见仓库根目录 LICENSE
 */

declare(strict_types=1);

if (PHP_VERSION_ID < 80100) {
    fwrite(STDERR, 'GhAccel 需要 PHP >= 8.1, 当前 ' . PHP_VERSION . "\n");
    exit(1);
}

$ROOT = dirname(__DIR__);
require $ROOT . '/src/Bootstrap.php';
require $ROOT . '/src/Config.php';
require $ROOT . '/src/Http.php';
GhAccel\Bootstrap::register();

use GhAccel\Config;
use GhAccel\Errors\GhpError;
use GhAccel\Security\Auth;

/**
 * argv 解析成 --k=v 与位置参数。
 *
 * @return array{0:list<string>,1:array<string,string>}
 */
function cliParse(array $argv): array
{
    $pos = [];
    $opt = [];
    foreach (array_slice($argv, 1) as $a) {
        if (is_string($a) && str_starts_with($a, '--')) {
            $body = substr($a, 2);
            if (str_contains($body, '=')) {
                [$k, $v] = explode('=', $body, 2);
                $opt[strtolower(trim($k))] = trim($v);
            } else {
                $opt[strtolower(trim($body))] = '1';
            }
            continue;
        }
        $pos[] = (string) $a;
    }

    return [$pos, $opt];
}

function cliOut(string $s): void
{
    fwrite(STDOUT, $s . "\n");
}

function cliErr(string $s): void
{
    fwrite(STDERR, $s . "\n");
}

function usage(): void
{
    cliOut(<<<TXT
用法: php bin/token.php <子命令> [选项]

  issue  --label="办公机" [--scope=read,write]   签发新令牌(明文只打印一次)
  list                                          列出令牌(只显示 selector 前 8 位与元数据)
  revoke --selector=<前缀>                       按 selector 前缀吊销(至少 8 位)
  help

说明:
  * 服务端只存 sha256(verifier) 摘要。明文丢了无法找回, 只能重签并吊销旧的。
  * --scope=read 签出的令牌只能看面板, 任何写接口(POST/PUT/DELETE)都会被 403 拒绝。
  * 吊销会连带作废该令牌的会话, 只删 verifier 而留会话是"吊销了但还能用"的常见事故。
TXT);
}

[$pos, $opt] = cliParse($argv);
$cmd = strtolower((string) ($pos[0] ?? ''));

$cfg = Config::load($ROOT);
$auth = new Auth($cfg, $ROOT);

try {
    switch ($cmd) {
        case 'issue':
            $label = $opt['label'] ?? '';
            if ($label === '') {
                // 没标签的令牌在 list 里根本认不出是哪个, 事后追责等于猜。
                $label = 'cli-' . date('Ymd-His');
                cliErr('提示: 未给 --label, 已自动使用 ' . $label);
            }
            $scopeRaw = $opt['scope'] ?? 'read,write';
            $scopes = array_values(array_filter(array_map(
                static fn (string $s): string => strtolower(trim($s)),
                explode(',', $scopeRaw)
            ), static fn (string $s): bool => $s !== ''));
            foreach ($scopes as $s) {
                if (!in_array($s, ['read', 'write'], true)) {
                    throw GhpError::make('invalid_argument', "未知 scope: {$s}");
                }
            }
            if ($scopes === []) {
                $scopes = ['read', 'write'];
            }

            $r = $auth->issueToken($label, $scopes);
            cliOut('已签发令牌');
            cliOut('  label           : ' . $label);
            cliOut('  scope           : ' . implode(',', $scopes));
            cliOut('  selector 前 8 位 : ' . substr((string) $r['selector'], 0, 8) . '  (吊销时用)');
            cliOut('  明文 token       : ' . (string) $r['raw']);
            cliOut('');
            cliOut('!! 只保存 sha256 摘要, 这条明文不会再次出现, 丢了无法找回, 只能重签 !!');
            cliOut('!! 现在把它复制进密码管理器, 不要贴进聊天工具或提交进仓库 !!');
            exit(0);

        case 'list':
            $rows = $auth->listTokens();
            if ($rows === []) {
                cliOut('尚无令牌。用 php bin/token.php issue 签发第一个。');
                exit(0);
            }
            cliOut(str_pad('selector前8', 14) . str_pad('scope', 12) . str_pad('签发', 22) . str_pad('最后使用', 22) . 'label');
            foreach ($rows as $r) {
                $scopes = array_map('strval', (array) ($r['scopes'] ?? []));
                cliOut(str_pad((string) $r['selector_prefix'], 14)
                    . str_pad(implode(',', $scopes), 12)
                    . str_pad($r['created_at'] > 0 ? date('Y-m-d H:i:s', (int) $r['created_at']) : '-', 22)
                    . str_pad($r['last_used_at'] > 0 ? date('Y-m-d H:i:s', (int) $r['last_used_at']) : '从未', 22)
                    . (string) $r['label']);
            }
            cliOut('');
            cliOut('共 ' . count($rows) . ' 枚; 明文不可回读, 只显示摘要元数据。');
            exit(0);

        case 'revoke':
            $sel = (string) ($opt['selector'] ?? ($pos[1] ?? ''));
            if (strlen($sel) < 8) {
                // 下限 8 位(32bit): 容忍复制被截断, 同时挡住"传 1 个字符清光所有令牌"。
                throw GhpError::make('invalid_argument', '--selector 需要至少 8 位前缀');
            }
            $before = count($auth->listTokens());
            $auth->revokeToken($sel);
            $after = count($auth->listTokens());
            cliOut("已吊销 selector 前缀 {$sel} 命中的令牌; 数量 {$before} -> {$after}");
            cliOut('使用该令牌的会话已同时作废。');
            exit(0);

        case '':
        case 'help':
        case '-h':
        case '--help':
            usage();
            exit($cmd === '' ? 1 : 0);

        default:
            cliErr('未知子命令: ' . $cmd);
            usage();
            exit(1);
    }
} catch (GhpError $e) {
    cliErr('失败: ' . $e->getMessage());
    exit(1);
} catch (\Throwable $t) {
    // Token 库写坏时只给一句话: 堆栈里带绝对路径, 而这类输出常被贴进 issue 与群聊。
    cliErr('失败: ' . get_class($t) . ' ' . $t->getMessage());
    exit(1);
}
