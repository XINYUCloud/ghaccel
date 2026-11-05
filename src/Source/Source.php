<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 加速源的静态配置实体。静态属性与运行时观测严格分离(运行时在 RuntimeStat,
 *             由状态存储重建), 这样配置可以进 git 共享、状态可以独立压实而互不污染。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Source;

use GhAccel\Enum\Scene;
use GhAccel\Enum\SourceMode;
use GhAccel\Enum\Trust;

/**
 * 一个可用的加速线路。
 *
 * 两个字段值得单独说明, 它们是这类项目最常踩的坑:
 *  - followsRedirectInternally: 源是内部跟完 302 直接吐字节, 还是把 302 原样回吐给客户端。
 *    后者对 Release 等于完全不加速, 所以 Release 场景必须在 L0 直接剔除。必须由探测实测,
 *    不能信配置里写的。
 *  - rangeVerified: 同理, codeload 实测会对 Range 返回 200 全量。声称支持与实测支持是两回事。
 */
final class Source
{
    public function __construct(
        /** 稳定的 slug, 作为状态存储的键; 改了等于历史清零 */
        public readonly string $id,
        public readonly string $baseUrl,
        public readonly SourceMode $mode,
        /** 仅 Template 形态使用 */
        public readonly string $urlTemplate = '',
        /** Scene 位掩码 OR 的结果 */
        public readonly int $sceneBits = 0,
        /** 该源覆盖哪些 GitHub 上游域名, 精确 host 小写集合 */
        public readonly array $hosts = [],
        public readonly Trust $trust = Trust::Unknown,
        /** 人工先验 1-100, 只作为打分的一个小因子, 不参与硬排序 */
        public readonly int $priority = 50,
        public readonly bool $enabled = true,
        /** 毫秒 */
        public readonly int $connectTimeoutMs = 1500,
        public readonly int $ttfbBudgetMs = 3000,
        public readonly int $stallTimeoutMs = 25000,
        /** 单请求体积上限, 0 表示沿用全局上限 */
        public readonly int $maxSizeBytes = 0,
        /** 该源明确屏蔽的扩展名, 小写不含点 */
        public readonly array $blockedExt = [],
        /** 最小请求间隔毫秒, 公益镜像会被打IP限流 */
        public readonly int $minIntervalMs = 0,
        public readonly int $maxConcurrent = 4,
        /** 软性小时字节帽, 超了打折不熔断 */
        public readonly int $hourlyBytesSoftCap = 0,
        public readonly string $region = 'unknown',
        /** 面板展示的来源与免责说明 */
        public readonly string $ownerNote = '',
        /** 探测得到的能力位, 见 caps() */
        public readonly array $caps = [],
    ) {
    }

    public static function fromArray(array $a): self
    {
        $scenes = 0;
        foreach ((array) ($a['scenes'] ?? []) as $s) {
            $scene = Scene::tryFrom(is_string($s) ? $s : '');
            if ($scene !== null) {
                $scenes |= $scene->bit();
            }
        }

        $hosts = [];
        foreach ((array) ($a['hosts'] ?? []) as $h) {
            $hosts[strtolower(trim((string) $h))] = true;
        }

        $blocked = [];
        foreach ((array) ($a['blocked_ext'] ?? []) as $e) {
            $blocked[strtolower(ltrim((string) $e, '.'))] = true;
        }

        return new self(
            id: (string) $a['id'],
            baseUrl: rtrim((string) $a['base_url'], '/'),
            mode: SourceMode::tryFrom((string) ($a['mode'] ?? 'prefix_full')) ?? SourceMode::PrefixFull,
            urlTemplate: (string) ($a['url_template'] ?? ''),
            sceneBits: $scenes,
            hosts: $hosts,
            trust: Trust::tryFrom((string) ($a['trust'] ?? 'unknown')) ?? Trust::Unknown,
            priority: max(1, min(100, (int) ($a['priority'] ?? 50))),
            enabled: (bool) ($a['enabled'] ?? true),
            connectTimeoutMs: (int) ($a['connect_timeout_ms'] ?? 1500),
            ttfbBudgetMs: (int) ($a['ttfb_budget_ms'] ?? 3000),
            stallTimeoutMs: (int) ($a['stall_timeout_ms'] ?? 25000),
            maxSizeBytes: (int) ($a['max_size_bytes'] ?? 0),
            blockedExt: $blocked,
            minIntervalMs: (int) ($a['min_interval_ms'] ?? 0),
            maxConcurrent: (int) ($a['max_concurrent'] ?? 4),
            hourlyBytesSoftCap: (int) ($a['hourly_bytes_soft_cap'] ?? 0),
            region: (string) ($a['region'] ?? 'unknown'),
            ownerNote: (string) ($a['owner_note'] ?? ''),
            caps: (array) ($a['caps'] ?? []),
        );
    }

    /**
     * 还原成 fromArray()/sources.dist.php 接受的字段数组。
     *
     * 存在的理由: 面板的"编辑源"是 PATCH 语义(只提交改动的几个字段), 而 upsert 会先把传入
     * 的 def 当完整定义校验一遍。没有这个方法, 局部编辑必然因为缺 base_url/mode 而被拒,
     * 表现成 500 —— 调用方必须先拿现有源展开成完整 def, 再覆盖要改的那几项。
     */
    public function definition(): array
    {
        $scenes = [];
        foreach (Scene::cases() as $s) {
            if ($s->bit() !== 0 && ($this->sceneBits & $s->bit()) === $s->bit()) {
                $scenes[] = $s->value;
            }
        }

        return [
            'id'                  => $this->id,
            'base_url'            => $this->baseUrl,
            'mode'                => $this->mode->value,
            'url_template'        => $this->urlTemplate,
            'scenes'              => $scenes,
            'hosts'               => array_keys($this->hosts),
            'trust'               => $this->trust->value,
            'priority'            => $this->priority,
            'enabled'             => $this->enabled,
            'connect_timeout_ms'  => $this->connectTimeoutMs,
            'ttfb_budget_ms'      => $this->ttfbBudgetMs,
            'stall_timeout_ms'    => $this->stallTimeoutMs,
            'max_size_bytes'      => $this->maxSizeBytes,
            'blocked_ext'         => array_keys($this->blockedExt),
            'min_interval_ms'     => $this->minIntervalMs,
            'max_concurrent'      => $this->maxConcurrent,
            'hourly_bytes_soft_cap' => $this->hourlyBytesSoftCap,
            'region'              => $this->region,
            'owner_note'          => $this->ownerNote,
            'caps'                => $this->caps,
        ];
    }

    public function supports(Scene $scene): bool
    {
        $bit = $scene->bit();

        return $bit !== 0 && ($this->sceneBits & $bit) === $bit;
    }

    public function coversHost(string $host): bool
    {
        return isset($this->hosts[strtolower($host)]);
    }

    /** 扩展名黑名单命中判定, 输入不含点。 */
    public function blocksExt(string $ext): bool
    {
        return $ext !== '' && isset($this->blockedExt[strtolower($ext)]);
    }

    /** 能力位读取, 默认全部为未知(false)。未知不等于支持, 在 L0 里按不满足处理。 */
    public function cap(string $name): bool
    {
        return (bool) ($this->caps[$name] ?? false);
    }

    /**
     * 该源上的加速地址。REDIRECT 模式与 Template 渲染都走这里。
     *
     * 前置约束: $absoluteUrl 的 host 必须已经过 Security/UrlGuard 的精确白名单校验。
     * Template 形态若用户写的模板把 {url} 之外的域名硬编码进去, 本机就会变成开放代理,
     * 所以模板渲染后还要再跑一次同一套校验, 不允许只校验入参。
     */
    public function accelerate(string $absoluteUrl): string
    {
        if ($this->mode === SourceMode::Template) {
            return SourceMode::renderTemplate($this->urlTemplate, $this->baseUrl, $absoluteUrl);
        }

        return $this->mode->buildUrl($this->baseUrl, $absoluteUrl);
    }
}
