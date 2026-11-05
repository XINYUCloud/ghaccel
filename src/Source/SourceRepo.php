<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 加速源清单的装载、校验与面板侧变更持久化。静态配置与运行时状态严格分离,
 *             所以这里只产出 Source, 不碰 RuntimeStat。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Source;

use GhAccel\Config;
use GhAccel\Enum\Scene;
use GhAccel\Enum\SourceMode;
use GhAccel\Enum\Trust;

/**
 * 源仓库。三级来源按后者胜合并:
 *   config/sources.dist.php -> config/sources.php -> var/state/sources.overlay.json
 *
 * overlay 单独走 JSON 而不是回写 PHP 文件: 面板由 www 用户跑, 而配置文件目录按部署规范
 * 属主要求 www 只读, 能写配置文件等于把"面板被拿下"升级成"任意代码执行"。
 */
final class SourceRepo
{
    /** id 只允许 slug: 它直接作为状态与统计的键, 含 / 或 .. 会污染所有按 id 拼路径的地方 */
    private const ID_PATTERN = '#\A[a-z0-9][a-z0-9._-]{1,62}\z#';

    private array $sources = [];
    private array $warnings = [];
    private bool $loaded = false;

    public function __construct(private readonly Config $cfg, private readonly string $root)
    {
    }

    /** @return list<Source> */
    public function all(): array
    {
        $this->load();

        return array_values($this->sources);
    }

    public function get(string $id): ?Source
    {
        $this->load();

        return $this->sources[$id] ?? null;
    }

    /** 装载期发现的配置问题, 面板与 /health 必须显示而不是静默丢掉一个源。 */
    public function warnings(): array
    {
        $this->load();

        return $this->warnings;
    }

    /** @return array<string, Source> 以 id 索引, 供选路与面板直接查。 */
    public function indexed(): array
    {
        $this->load();

        return $this->sources;
    }

    /**
     * 新增或编辑一个源。$def 用与 sources.dist.php 相同的字段名。
     * 变更只落 overlay, 因此重启与配置回滚都不会丢, 也不会踩到部署者的配置文件。
     */
    public function upsert(array $def): Source
    {
        $id = strtolower(trim((string) ($def['id'] ?? '')));
        if ($id === '' || !preg_match(self::ID_PATTERN, $id)) {
            throw new \InvalidArgumentException('源 id 必须是 2-63 位的 slug(小写字母/数字/._-)');
        }
        $baseUrl = rtrim(trim((string) ($def['base_url'] ?? '')), '/');
        if ($baseUrl === '' || !str_starts_with(strtolower($baseUrl), 'https://')) {
            throw new \InvalidArgumentException('base_url 必须是完整的 https 地址');
        }
        if (SourceMode::tryFrom((string) ($def['mode'] ?? '')) === null) {
            throw new \InvalidArgumentException('mode 必须是 prefix_full/prefix_path/host_replace/template 之一');
        }

        $overlay = $this->readOverlay();
        $patch = $overlay['sources'][$id] ?? [];
        $merged = array_merge($patch, $this->onlyKnownKeys($def));
        $merged['id'] = $id;
        $overlay['sources'][$id] = $merged;
        // 删除留的是 tombstone(removed[$id]=true), load() 会据此跳过该 id。重建同名源时
        // 必须把它摘掉, 否则"删掉一个源之后这个 id 就永久废了" —— 而且写入侧一切正常,
        // 只有读回来是空, 表现成 upsert 末尾那句含义完全不对的"已写入但校验未通过"。
        unset($overlay['removed'][$id]);
        $overlay['updated_at'] = time();
        $this->writeOverlay($overlay);
        $this->loaded = false;

        $src = $this->get($id);
        if ($src === null) {
            $w = $this->warnings[$id] ?? null;
            throw new \InvalidArgumentException(
                '源已写入但未能加载: '
                . ($w === null ? '字段不完整或形态非法(检查 base_url/mode/scenes/hosts)'
                               : (is_array($w) ? (string) ($w['message'] ?? 'unknown') : (string) $w))
            );
        }

        return $src;
    }

    public function toggle(string $id, bool $on): void
    {
        $this->patchOverlay($id, ['enabled' => $on]);
    }

    public function setPriority(string $id, int $p): void
    {
        $this->patchOverlay($id, ['priority' => max(1, min(100, $p))]);
    }

    /** 整体替换某个源的出厂定义(面板"编辑"用), 保留历史其他 patch。 */
    public function remove(string $id): void
    {
        $this->load();
        $overlay = $this->readOverlay();
        unset($overlay['sources'][$id], $overlay['disabled'][$id]);
        $overlay['removed'][$id] = true;
        $overlay['updated_at'] = time();
        $this->writeOverlay($overlay);
        $this->loaded = false;
    }

    private function patchOverlay(string $id, array $patch): void
    {
        $this->load();
        $overlay = $this->readOverlay();
        if (!isset($this->sources[$id]) && !isset($overlay['sources'][$id])) {
            throw new \InvalidArgumentException("未知源 id: {$id}");
        }
        $overlay['sources'][$id] = array_merge($overlay['sources'][$id] ?? [], $patch);
        $overlay['updated_at'] = time();
        $this->writeOverlay($overlay);
        $this->loaded = false;
    }

    private function onlyKnownKeys(array $def): array
    {
        $allow = [
            'id', 'base_url', 'mode', 'url_template', 'scenes', 'hosts', 'trust', 'priority',
            'enabled', 'connect_timeout_ms', 'ttfb_budget_ms', 'stall_timeout_ms',
            'max_size_bytes', 'blocked_ext', 'min_interval_ms', 'max_concurrent',
            'hourly_bytes_soft_cap', 'region', 'owner_note', 'caps',
        ];

        return array_intersect_key($def, array_flip($allow));
    }

    private function load(): void
    {
        if ($this->loaded) {
            return;
        }
        $this->loaded = true;
        $this->sources = [];
        $this->warnings = [];

        $defs = [];
        $defaults = [];
        foreach ($this->files() as $file) {
            if (!is_readable($file)) {
                continue;
            }
            $data = include $file;
            if (!is_array($data)) {
                $this->warnings[] = ['id' => basename($file), 'message' => '配置文件未返回数组'];
                continue;
            }
            $defaults = array_merge($defaults, (array) ($data['defaults'] ?? []));
            foreach ((array) ($data['sources'] ?? []) as $def) {
                if (is_array($def) && isset($def['id'])) {
                    // 后者浅覆盖前者: 同一个 id 在 dist 与本地表里出现时, 本地表整条替换,
                    // 不做深合并 —— 深合并会让"本地只想改 priority"意外继承 dist 的错误 hosts。
                    $defs[strtolower((string) $def['id'])] = array_merge($defs[strtolower((string) $def['id'])] ?? [], $def);
                }
            }
        }

        $overlay = $this->readOverlay();
        foreach ((array) ($overlay['sources'] ?? []) as $id => $patch) {
            $defs[(string) $id] = array_merge((array) ($defs[(string) $id] ?? []), (array) $patch, ['id' => (string) $id]);
        }

        foreach ($defs as $id => $def) {
            if (isset($overlay['removed'][$id])) {
                continue;
            }
            $def = array_merge($defaults, $def, ['id' => $id]);
            $source = $this->build($def);
            if ($source !== null) {
                // 停用的源仍然保留在索引里: 面板要显示它并允许一键开启, 选路靠 enabled 剔除;
                // 一旦这里 continue, 面板就再也找不到它了。
                $this->sources[$id] = $source;
            }
        }
    }

    /** @return list<string> */
    private function files(): array
    {
        return [
            $this->root . '/config/sources.dist.php',
            $this->root . '/config/sources.php',
        ];
    }

    private function build(array $def): ?Source
    {
        $id = strtolower(trim((string) ($def['id'] ?? '')));
        if ($id === '' || !preg_match(self::ID_PATTERN, $id)) {
            $this->warnings[$id === '' ? '(missing id)' : $id] = 'id 不合法, 已跳过该源';

            return null;
        }

        $baseUrl = rtrim(trim((string) ($def['base_url'] ?? '')), '/');
        $mode = SourceMode::tryFrom((string) ($def['mode'] ?? 'prefix_full')) ?? SourceMode::PrefixFull;
        if ($baseUrl === '' || !preg_match('#\Ahttps://[a-z0-9.\-]+(:\d{2,5})?\z#i', $baseUrl)) {
            // base_url 只允许协议+域名(+端口): 带路径的 base 会让三种拼接形态的语义漂移,
            // 带 http:// 的 base 会让本机明文出站。
            $this->warnings[$id] = "base_url 不合法({$baseUrl}), 必须是 https://host[:port] 且不含路径";

            return null;
        }
        if ($mode === SourceMode::Template && !str_contains((string) ($def['url_template'] ?? ''), '{url}')) {
            // 模板里没有 {url} 意味着所有请求都打到同一个固定地址 —— 那是配置错误,
            // 更糟的情况是把本机变成面向任意地址的开放代理。
            $this->warnings[$id] = 'template 形态的 url_template 必须包含 {url} 占位符';

            return null;
        }

        $hosts = (array) ($def['hosts'] ?? []);
        if ($hosts === []) {
            $this->warnings[$id] = 'hosts 为空, 该源不可能命中任何上游域名, 已跳过';

            return null;
        }
        if ((array) ($def['scenes'] ?? []) === []) {
            $this->warnings[$id] = 'scenes 为空, 已跳过';

            return null;
        }
        if (Trust::tryFrom((string) ($def['trust'] ?? '')) === null) {
            $def['trust'] = 'unknown';
            $this->warnings[$id] = 'trust 取值未知, 已按 unknown 处理';
        }
        foreach ((array) ($def['scenes'] ?? []) as $s) {
            if (Scene::tryFrom(is_string($s) ? $s : '') === null) {
                $this->warnings[$id] = "未知场景 {$s}, 该位不会参与能力掩码";
            }
        }

        $source = Source::fromArray($def);

        // 能力位一律以"未实测"为起点: 配置里写 true 也只当作声称。measuredCaps 为空时
        // 选路按 NotYetProbed 处理(可逐级放宽), 一旦被探测证伪则硬性剔除。
        return $source;
    }

    private function overlayFile(): string
    {
        return $this->root . '/var/state/sources.overlay.json';
    }

    private function readOverlay(): array
    {
        $file = $this->overlayFile();
        if (!is_readable($file)) {
            return ['sources' => [], 'removed' => []];
        }
        $data = json_decode((string) @file_get_contents($file), true);

        return is_array($data) ? ['sources' => (array) ($data['sources'] ?? []), 'removed' => (array) ($data['removed'] ?? [])] : ['sources' => [], 'removed' => []];
    }

    private function writeOverlay(array $overlay): void
    {
        $overlay['schema'] = 1;
        ksort($overlay['sources']);
        if (!Config::atomicWrite($this->overlayFile(), json_encode($overlay, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT))) {
            throw new \RuntimeException('无法写入源覆盖层, 检查 var/state 是否可写');
        }
    }
}
