<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 一次引用的投递决策与执行。EDGE / REDIRECT / FAILOVER 的自动选择、时间预算、
 *             逐候选回退、观测与统计回写、分片子接口、错误渲染都在这里。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Execution;

use GhAccel\Cache\Entry;
use GhAccel\Cache\Key;
use GhAccel\Cache\Policy;
use GhAccel\Cache\Store;
use GhAccel\Config;
use GhAccel\Enum\ExecMode;
use GhAccel\Enum\FailureKind;
use GhAccel\Enum\Scene;
use GhAccel\Errors\GhpError;
use GhAccel\Http;
use GhAccel\Ref\GitHubRef;
use GhAccel\Routing\Breaker;
use GhAccel\Routing\Candidate;
use GhAccel\Routing\Latency;
use GhAccel\Routing\Plan;
use GhAccel\Routing\Selector;
use GhAccel\Routing\Success;
use GhAccel\Security\UrlGuard;
use GhAccel\Source\RuntimeStat;
use GhAccel\Source\Source;
use GhAccel\Source\SourceRepo;
use GhAccel\Store\Observatory;
use GhAccel\Store\Snapshot;
use GhAccel\Transport\Headers;
use GhAccel\Transport\Streamer;
use GhAccel\Transport\UpstreamResult;

/**
 * 薄入口只需要按这个顺序用本类(见 flush()/renderError() 的注释):
 * OPTIONS -> surface 分发 -> 限流/并发槽 -> RefParser::parse -> serve() -> catch GhpError -> renderError()
 * -> flushObservations()
 *
 * 一条贯穿全类的规则: **本机从不把上游的 302 转给客户端**。要么我们把它跟完(Streamer),
 * 要么我们把 302 指向镜像源(Redirect 模式), 要么回结构化错误。把 GitHub 的 Location 透出去
 * 等于让国内客户端自己跳回跨洋直连, 加速当场失效, 还顺带泄露了上游真实域名。
 */
final class Dispatcher
{
    /** Streamer 交回的最后一次探测/流式细节, 只服务诊断与记账, 不参与决策。 */
    private array $lastDetail = [];

    private array $attempts = [];

    private ?Plan $plan = null;

    /** @var array<string,RuntimeStat> */
    private array $stats = [];

    private bool $statsLoaded = false;

    /** @var array<string,mixed> */
    private array $deps;

    public function __construct(
        private readonly Config $cfg,
        private readonly string $root,
        array $deps = []
    ) {
        // 依赖全部可注入(CLI 自检与面板要换实现), 缺省时按配置懒建。键名见各 x() 方法。
        $this->deps = $deps;
    }

    // ------------------------------------------------------------------
    // 主入口
    // ------------------------------------------------------------------

    /**
     * OPTIONS 预检: 直接 204 + CORS, 绝不进代理逻辑。
     *
     * 预检没有 Range、没有目标 URL, 而 RefParser/UrlGuard 都会把 OPTIONS 判成非法 method ——
     * 让它进链路的结局是"浏览器全部失败, 命令行全部正常", 极难从报错里定位。
     */
    public function preflight(): void
    {
        $pack = $this->headers()->preflight();
        $this->headers()->emit($pack['status'], $pack['headers']);
    }

    /**
     * @param array<string,mixed> $ctx 见 normalizeCtx() 的键表
     * @return array<string,mixed> 投递结果摘要(mode/status/source/bytes/attempts/decision/...)
     * @throws GhpError 只有"一个字节都还没发给客户端"的失败才抛: 那时入口才还能换状态码渲染
     */
    public function serve(GitHubRef $ref, array $ctx = []): array
    {
        $ctx = $this->normalizeCtx($ctx);
        $now = microtime(true);
        $this->plan = null;
        $this->attempts = [];
        $this->lastDetail = [];

        // 0) 分片子接口: 只对已完整落在 EDGE 的条目开放, 未命中一律 409。
        //    实测 codeload 无视 Range, 未缓存时"分 16 片"就是向源拉 16 份完整文件 ——
        //    既打穿自家带宽, 也让镜像把我们当滥用封掉。
        if ($ctx['split'] !== null) {
            return $this->serveSplit($ref, $ctx, $now);
        }

        // 1) EDGE: 命中且新鲜 -> 直出, 零上游往返。无条件优先于任何模式。
        $entry = $ctx['cache'] && $ref->cacheEligible() ? $this->store()->lookup($ref) : null;
        if ($entry !== null && $entry->isFresh($now)) {
            $served = $this->serveEdge($ref, $entry, $ctx, $now, 'hit');
            if ($served !== null) {
                return $served;
            }
            // null = 这条缓存满足不了本次请求(例如 Range 落在 partial 条目之外), 落网络。
        }

        // 2) 选路。ranked 为空绝不静默直连 github.com: 那是"配置坏了"而不是"没源了",
        //    必须让运维在面板看到每个源被剔除的原因码。
        $plan = $this->buildPlan($ref, $ctx, $now);
        if (!$plan->hasCandidates()) {
            throw GhpError::make(GhpError::NO_ELIGIBLE_SOURCE, '所有源都被硬约束筛掉', [
                'excluded'   => array_map(static fn (array $e): array => [
                    'id' => (string) ($e['id'] ?? ''),
                    'code' => (string) ($e['code'] ?? ''),
                ], (array) $plan->excluded),
                'relaxed'    => $plan->relaxedFlags,
                'cold_start' => $plan->coldStart,
                'total'      => $plan->totalSources,
            ]);
        }

        // 3) stale 条目的条件请求(第三层协商): 用**存下来的上游** ETag 问一次, 304 就只刷
        //    新鲜度不重写文件。客户端的 If-None-Match 永远不参与这一步。
        if ($entry !== null && $entry->isServeableStale($now) && $ctx['range'] === '' && $entry->upstreamEtag !== '') {
            $rv = $this->revalidate($ref, $entry, $ctx, $plan, $now);
            if ($rv !== null) {
                return $rv;
            }
        }

        // 4) 模式
        $mode = $this->chooseMode($ref, $ctx, $plan, $entry, $now);
        if ($mode === ExecMode::Redirect) {
            return $this->serveRedirect($ref, $ctx, $plan, $now);
        }

        return $this->serveFailover($ref, $ctx, $plan, $now);
    }

    /**
     * @return array<string,mixed>
     */
    private function normalizeCtx(array $ctx): array
    {
        $out = $ctx + [
            'method'        => Http::method(),
            'range'         => '',
            'if_none_match' => '',
            'if_modified_since' => '',
            'client_headers' => [],
            'client_ip'     => '',
            'is_agent'      => false,
            'want_json'     => false,
            'size_hint'     => 0,
            'out'           => null,
            'max_bytes'     => 0,
            'deadline_ms'   => 0.0,
            'mode'          => null,
            'split'         => null,
            'cache'         => true,
            'diag_visible'  => false,
            'progress'      => null,
            'stream'        => false,
        ];
        $out['method'] = strtoupper((string) $out['method']);
        if (!in_array($out['method'], ['GET', 'HEAD'], true)) {
            $out['method'] = 'GET';
        }
        $out['range'] = self::str($out['range']);
        $out['range_requested'] = $out['range'] !== '';
        $out['size_hint'] = max(0, (int) ($out['size_hint'] ?: 0));
        $out['diag_visible'] = (bool) $out['diag_visible'];

        return $out;
    }

    // ------------------------------------------------------------------
    // 模式选择
    // ------------------------------------------------------------------

    public function chooseMode(GitHubRef $ref, array $ctx, Plan $plan, ?Entry $entry, float $now): ExecMode
    {
        $forced = is_string($ctx['mode'] ?? null) ? strtolower((string) $ctx['mode']) : '';
        if ($forced !== '') {
            // Hedge 在 v1 是"接口先占位、运行时明确拒绝": 阻碍是响应头固化与部署侧缓冲链,
            // 而不是并发语义。宁可可解释地失败, 也不静默降级成别的模式。
            if ($forced === ExecMode::Hedge->value) {
                throw GhpError::make(GhpError::MODE_UNSUPPORTED, 'hedge', ['requested' => 'hedge']);
            }
            if ($forced === ExecMode::Edge->value) {
                if ($entry !== null && $entry->isFresh($now)) {
                    return ExecMode::Edge;
                }
                return ExecMode::Failover; // 强行 edge 但没命中: 老实走网络而不是回 503
            }
            if ($forced === ExecMode::Redirect->value) {
                return ExecMode::Redirect;
            }
            if ($forced === ExecMode::Failover->value) {
                return ExecMode::Failover;
            }
            throw GhpError::make(GhpError::MODE_UNSUPPORTED, $forced, ['requested' => $forced]);
        }

        if ($entry !== null && $entry->isFresh($now) && $ref->cacheEligible()) {
            return ExecMode::Edge;
        }

        $min = $this->cfg->int('algo.mode.redirect_min_bytes', 52428800);
        $hint = max((int) $ctx['size_hint'], $ref->sizeHint);
        if ($min > 0 && $hint >= $min && !$this->mustStream($ctx, $ref)) {
            return ExecMode::Redirect;
        }

        return ExecMode::Failover;
    }

    /**
     * 什么情况下"绝不能 302"。
     *
     *  - 带 Range: 跨 host 的重定向里各下载器对"是否保留 Range"行为不一致, 赌这个就是赌
     *    用户拿到错位的文件; 分片请求一律由本机流式镜像。
     *  - API JSON: 脚本要的是响应体本身, 302 到一个镜像地址对不跟随重定向的客户端毫无意义。
     *  - 显式 ?mode=failover / 面板"直连测速"。
     */
    private function mustStream(array $ctx, GitHubRef $ref): bool
    {
        return $ctx['range'] !== '' || $ref->scene === Scene::ApiJson || (bool) $ctx['stream'];
    }

    // ------------------------------------------------------------------
    // EDGE
    // ------------------------------------------------------------------

    /**
     * 缓存直出。恒定内存: 由 Cache\Store::sliceToOutput() 的 fseek+分块读服务, 包括 Range。
     * 返回 null 表示这条缓存无法满足本次请求(交回主流程走网络)。
     */
    private function serveEdge(GitHubRef $ref, Entry $entry, array $ctx, float $now, string $cacheTag): ?array
    {
        $total = (int) $entry->bytes;
        if ($total < 0) {
            return null;
        }
        $etag = $entry->etag !== '' ? $entry->etag : $this->policy()->etagFor($entry->key, 'full');

        // 第一层协商: 客户端 If-None-Match 只对**我们自造的** ETag 作数。
        if ($ctx['if_none_match'] !== '' && self::etagMatches($ctx['if_none_match'], $etag)) {
            $this->headers()->emit(304, [
                'etag'                   => $etag,
                'last-modified'          => $entry->lastModified,
                'cache-control'          => $this->edgeCacheControl($entry, $now),
                'x-ghaccel-request-id'   => Http::requestId(),
            ] + $this->corsIfPublic());
            $this->store()->noteHit($entry);
            $this->recordLocal('edge304', $ref, $ctx, 0, $cacheTag);

            return $this->summary(ExecMode::Edge, 304, $entry->sourceId, 0, 0.0, $cacheTag, $entry, false);
        }

        $slice = $this->resolveSlice($ctx['range'], $total, $entry);
        if ($slice[0] === 'fallback') {
            return null; // Range 只有完整条目能切; partial 条目交给网络, 绝不自造 206
        }
        if ($slice[0] === 'range_error') {
            // 越界: 本地回 416 + Content-Range。这是"由本机判"的唯一合法情形, 因为总体积
            // 是我们自己存着的, 打下游也只会拿到同一个答案。
            $this->emit416($total);
            $this->recordLocal('range416', $ref, $ctx, 0, 'hit');

            return $this->summary(ExecMode::Edge, 416, $entry->sourceId, 0, 0.0, 'hit', $entry, true);
        }
        [, $start, $end, $isPartial] = $slice;

        if ($ctx['method'] === 'HEAD') {
            $headers = $this->edgeHeaders($ref, $entry, $etag, $total, $start, $end, $isPartial, $now, $cacheTag);
            $this->headers()->emit(200, $headers);
            $this->store()->noteHit($entry);

            return $this->summary(ExecMode::Edge, 200, $entry->sourceId, 0, 0.0, $cacheTag, $entry, false);
        }

        $out = is_resource($ctx['out']) ? $ctx['out'] : Http::out();
        $this->headers()->emit($isPartial ? 206 : 200, $this->edgeHeaders($ref, $entry, $etag, $total, $start, $end, $isPartial, $now, $cacheTag));
        Http::noBuffering();
        $want = $end - $start + 1;
        $written = $this->store()->sliceToOutput($entry, $out, $start, $end);
        if ($written !== $want) {
            // 短写只可能是客户端断开。断开不该记进源成功率, 也不该再改状态码(头已固化)。
            $this->recordLocal('client_abort', $ref, $ctx, $written, $cacheTag);

            return $this->summary(ExecMode::Edge, $isPartial ? 206 : 200, $entry->sourceId, $written, 0.0, 'aborted', $entry, true);
        }
        Http::flush();
        $this->store()->noteHit($entry);
        $this->recordLocal('edge', $ref, $ctx, $written, $cacheTag);

        return $this->summary(ExecMode::Edge, $isPartial ? 206 : 200, $entry->sourceId, $written, 0.0, $cacheTag, $entry, true);
    }

    /**
     * 把客户端 Range 换算成完整条目的闭区间切片。
     *
     * @return array{0:string,1?:int,2?:int,3?:bool} ['slice',start,end,isPartial]
     *                                               | ['range_error',total] | ['fallback']
     */
    private function resolveSlice(string $range, int $total, Entry $entry): array
    {
        if ($range === '') {
            return ['slice', 0, max(0, $total - 1), false];
        }
        if (trim($entry->rangeSpec) !== '' && !Key::isFull($entry->rangeSpec)) {
            return ['fallback'];
        }
        $single = Key::parseSingle($range);
        if ($single === null) {
            // 多段 Range: 由本机拼 multipart 就是"自创 206", 明确不做,
            // 交回网络让上游自己决定(上游会连 boundary 一起给, 我们只镜像)。
            return ['fallback'];
        }
        $start = (int) $single[0];
        $end = (int) $single[1];
        if ($start < 0) {
            // 后缀式 bytes=-n: Key::parseSingle 用 [-1, -n] 表示, 换算成绝对区间要有总体积。
            $start = max(0, $total - abs($end));
            $end = max(0, $total - 1);
        } elseif ($end < 0 || $end >= $total) {
            $end = max(0, $total - 1);
        }
        if ($start >= $total) {
            return ['range_error', $total];
        }

        return ['slice', $start, $end, true];
    }

    private function edgeHeaders(GitHubRef $ref, Entry $entry, string $etag, int $total, int $start, int $end, bool $isPartial, float $now, string $cacheTag): array
    {
        $h = [
            'content-type'   => $entry->contentType !== '' ? $entry->contentType : 'application/octet-stream',
            'content-length' => (string) ($isPartial ? ($end - $start + 1) : $total),
            'accept-ranges'  => 'bytes',
            'etag'           => $etag,
            'cache-control'  => $this->edgeCacheControl($entry, $now),
            'x-ghaccel-request-id' => Http::requestId(),
            'x-ghaccel-cache' => $cacheTag,
        ];
        if ($entry->lastModified !== '') {
            $h['last-modified'] = $entry->lastModified;
        }
        if ($isPartial) {
            $h['content-range'] = sprintf('bytes %d-%d/%d', $start, $end, $total);
        }
        if ($ref->scene->isBinaryStream()) {
            $name = $ref->downloadName !== '' ? $ref->downloadName : basename($ref->path);
            if ($name !== '') {
                $h['content-disposition'] = Headers::disposition($name);
            }
        }
        $h += $this->corsIfPublic();

        return $h;
    }

    private function edgeCacheControl(Entry $entry, float $now): string
    {
        $left = (int) max(1.0, $entry->freshUntil - $now);

        return $entry->isImmutable()
            ? 'public, max-age=' . $left . ', immutable'
            : 'public, max-age=' . $left . ($entry->staleUntil > $entry->freshUntil
                ? ', stale-while-revalidate=' . (int) max(1, $entry->staleUntil - $entry->freshUntil)
                : '');
    }

    /**
     * stale 条目的上游校验。返回 null 表示"没谈成", 主流程继续按网络路径取。
     */
    private function revalidate(GitHubRef $ref, Entry $entry, array $ctx, Plan $plan, float $now): ?array
    {
        $cand = $plan->top();
        if ($cand === null) {
            return null;
        }
        $opts = $ctx;
        $opts['cache'] = false;      // 304 不该顺手开一个 .part; 真有新内容时下面这条路径会重开
        $opts['budget_ms'] = max(700.0, $this->cfg->float('budgets.ttfb_budget_ms', 3000.0));
        $opts['upstream_etag'] = $entry->upstreamEtag;
        $opts['upstream_last_modified'] = $entry->upstreamLastModified;

        $detail = null;
        $res = $this->doFetch($cand->source, $ref, $opts, $detail);
        $this->lastDetail = is_array($detail) ? $detail : [];
        $this->recordOutcome($cand, $res, $ref, $ctx);

        if ($res->status === 304 && !$res->committed) {
            // 上游确认内容未变: 只推时间戳, 不重写文件(B 组契约: Entry::revalidated 不动字节)。
            $ttl = $this->policy()->ttlFor($ref);
            $fresh = $entry->revalidated($now, $ttl['fresh'], $ttl['stale']);
            $served = $this->serveEdge($ref, $fresh, $ctx, $now, 'stale-revalidated');

            return $served ?? $this->summary(ExecMode::Edge, 304, $cand->id(), 0, $res->ttfbMs, 'revalidated', $fresh, false);
        }

        if ($res->committed) {
            // 上游给了新内容并且已经流出去(头也发了), 这里只能记账不能重渲染。
            if (!$res->ok()) {
                return $this->summary(ExecMode::Failover, $res->status, $cand->id(), $res->bytesReceived, $res->ttfbMs, 'miss', null, true);
            }

            return $this->summary(ExecMode::Failover, $res->status, $cand->id(), $res->bytesReceived, $res->ttfbMs, 'revalidated-fetch', $this->entryOf($detail), true);
        }

        return null;
    }

    // ------------------------------------------------------------------
    // REDIRECT
    // ------------------------------------------------------------------

    /**
     * 302 到最优镜像源的地址(不是 GitHub 上游)。
     *
     * 三重收益: 本机 0 带宽、不泄露上游域名、并且真的在加速。反过来 302 到 github.com
     * 会让客户端自己跳回跨洋直连, 加速彻底失败 —— 所以这里必须先过一遍 UrlGuard 再交给
     * Source::accelerate(), 保证被改写的那一段仍然只是白名单内的 GitHub 地址。
     */
    private function serveRedirect(GitHubRef $ref, array $ctx, Plan $plan, float $now): array
    {
        $cand = $plan->top();
        if ($cand === null) {
            throw GhpError::make(GhpError::NO_ELIGIBLE_SOURCE, '无候选');
        }
        $inner = $this->guard()->assertAllowed($ref->upstreamUrl);
        $target = $cand->source->accelerate($inner->url);
        // 包装后的地址必须还能解析成同一个内层 URL: Template 形态最容易出现"把域名硬编码进
        // 模板"的配置错误, 那会让本机变成开放代理, 所以这里复校一次内层而不是外层。
        $innerOfTarget = $this->innerOf($target);
        if ($innerOfTarget !== '' && strtolower($innerOfTarget) !== strtolower($inner->url)) {
            throw GhpError::make(GhpError::HOST_NOT_ALLOWED, '模板改写后的内层地址与解析结果不一致');
        }

        $headers = [
            'location'        => $target,
            'cache-control'   => 'no-store',
            'content-length'  => '0',
            'x-ghaccel-request-id' => Http::requestId(),
            'x-ghaccel-mode'  => ExecMode::Redirect->value,
        ];
        if ($ctx['diag_visible']) {
            $headers['x-ghaccel-source'] = $cand->id();
            $headers['x-ghaccel-cache'] = 'miss';
        } else {
            unset($headers['x-ghaccel-mode']);
        }
        $headers += $this->corsIfPublic();
        $this->headers()->emit(302, $headers);

        // 没有与源交互, 所以不能记 outcome(记了就是把一次"没打过的请求"算成该源的成功)。
        $this->recordLocal('redirect', $ref, $ctx, 0, 'miss');

        return $this->summary(ExecMode::Redirect, 302, $cand->id(), 0, 0.0, 'miss', null, false, [
            'target' => $ctx['diag_visible'] ? $target : '',
        ]);
    }

    /** 从镜像包装地址里取出内层 GitHub URL; 取不出来(纯 host 替换形态)返回空串。 */
    private function innerOf(string $url): string
    {
        $pos = stripos($url, 'https://', 8);
        if ($pos === false) {
            return '';
        }

        return substr($url, $pos);
    }

    // ------------------------------------------------------------------
    // FAILOVER
    // ------------------------------------------------------------------

    private function serveFailover(GitHubRef $ref, array $ctx, Plan $plan, float $now): array
    {
        $failover = $this->failover();
        $ranked = array_slice($plan->ranked, 0, max(1, $this->cfg->int('algo.mode.top_k', 4)));

        $res = $failover->run(
            $ranked,
            ['deadline_ms' => $ctx['deadline_ms']],
            function (Candidate $c, float $budgetMs, int $index) use ($ref, $ctx, $plan): UpstreamResult {
                $opts = $ctx;
                $opts['budget_ms'] = $budgetMs;
                $opts['diag'] = [
                    'mode'   => ExecMode::Failover->value,
                    'source' => $c->id(),
                    'cache'  => 'miss',
                ];
                $opts['diag_visible'] = $ctx['diag_visible'];
                $detail = null;
                $r = $this->doFetch($c->source, $ref, $opts, $detail);
                $this->lastDetail = is_array($detail) ? $detail : [];

                return $r;
            },
            function (Candidate $c, UpstreamResult $r, float $budgetMs) use ($ref, $ctx): void {
                // 预算与实际模式随这次交互一起记账, 面板才能回答"这个源是在多少毫秒预算下
                // 被判死的", 否则冷却时长与超时率就成了无法对账的数字。
                $this->recordOutcome($c, $r, $ref, array_merge($ctx, [
                    'budget_ms' => $budgetMs,
                    'mode'      => ExecMode::Failover->value,
                ]));
            }
        );

        $this->attempts = $res['attempts'];
        /** @var UpstreamResult|null $last */
        $last = $res['result'];
        $cand = $res['candidate'];
        if ($last === null || $cand === null) {
            throw GhpError::make(GhpError::UPSTREAM_FAILED, '所有候选均未执行', [
                'stop' => (string) $res['stop'],
                'plan' => array_map(static fn (Candidate $c): string => $c->id(), $ranked),
            ]);
        }

        $summary = $this->summary(
            ExecMode::Failover,
            $last->status,
            $cand->id(),
            $last->bytesReceived,
            $last->ttfbMs,
            $last->ok() ? 'miss' : 'error',
            $this->entryOf($this->lastDetail),
            $last->committed
        );
        $summary['stop'] = (string) $res['stop'];
        $summary['failure'] = $last->failure->value;
        $summary['attempts'] = $this->attempts;

        if ($last->ok()) {
            return $summary;
        }
        if ($last->committed) {
            // 已经发过字节: 无法再改状态码, 只能带着不完整的结果返回。入口必须原样收尾。
            return $summary;
        }

        throw $this->errorFor($last, $cand, $ref, $res);
    }

    /** 上游结局 -> 对外错误码。每一条都要给 Agent 一个"下一步该做什么"的判断依据。 */
    private function errorFor(UpstreamResult $res, Candidate $cand, GitHubRef $ref, array $run): GhpError
    {
        $ctx = [
            'source'   => $cand->id(),
            'status'   => $res->status,
            'failure'  => $res->failure->value,
            'hops'     => $res->redirectHops,
            'attempts' => $this->attempts,
            'stop'     => (string) ($run['stop'] ?? ''),
        ];
        $detail = (string) $res->curlError;

        return match ($res->failure) {
            FailureKind::RateLimited   => GhpError::make(GhpError::UPSTREAM_RATE_LIMITED, $detail, $ctx + ['retry_after' => $this->retryAfterOf($res)]),
            FailureKind::Oversize      => GhpError::make(GhpError::OVERSIZE, $detail, $ctx + ['limit_bytes' => $this->cfg->int('limits.per_request_bytes', 0)]),
            FailureKind::Integrity     => GhpError::make(GhpError::INTEGRITY_MISMATCH, $detail, $ctx + ['expected' => substr($ref->expectedSha256, 0, 12)]),
            FailureKind::WrongContent  => GhpError::make(GhpError::WRONG_CONTENT, $detail, $ctx),
            FailureKind::TlsVerify     => GhpError::make(GhpError::TLS_VERIFY_FAILED, $detail, $ctx),
            FailureKind::GuardRejected => GhpError::make(GhpError::HOST_NOT_ALLOWED, $detail, $ctx),
            FailureKind::TimeoutTtfb   => GhpError::make(GhpError::UPSTREAM_TIMEOUT, $detail, $ctx),
            FailureKind::Blocked       => GhpError::make(GhpError::UPSTREAM_FAILED, '源拒绝该类资源: ' . $detail, $ctx),
            FailureKind::Http4xx       => $res->status === 404 || $res->status === 410
                ? GhpError::make(GhpError::UPSTREAM_NOT_FOUND, '上游 ' . $res->status, $ctx)
                : GhpError::make(GhpError::UPSTREAM_FAILED, $detail, $ctx),
            default => GhpError::make(GhpError::UPSTREAM_FAILED, $detail, $ctx),
        };
    }

    /** 429 的 Retry-After: 优先信上游的 Retry-After / X-RateLimit-Reset, 否则给一个保守值。 */
    private function retryAfterOf(UpstreamResult $res): int
    {
        $ra = (int) $res->header('retry-after');
        if ($ra > 0) {
            return min(3600, $ra);
        }
        $reset = (int) $res->header('x-ratelimit-reset');
        if ($reset > time()) {
            return min(3600, $reset - time());
        }

        return 30;
    }

    // ------------------------------------------------------------------
    // 分片子接口 ?part=i&of=n
    // ------------------------------------------------------------------

    public function serveSplit(GitHubRef $ref, array $ctx, float $now): array
    {
        [$part, $of] = (array) $ctx['split'];
        $maxOf = max(1, $this->cfg->int('algo.mode.split_max_of', 16));
        if ($of < 1 || $of > $maxOf || $part < 0 || $part >= $of) {
            throw GhpError::make(GhpError::UNPARSEABLE, '分片参数不合法', ['part' => $part, 'of' => $of, 'max_of' => $maxOf]);
        }

        $entry = $ctx['cache'] && $ref->cacheEligible() ? $this->store()->lookup($ref) : null;
        if ($entry === null || !$entry->isFresh($now) || !Key::isFull($entry->rangeSpec)) {
            // 未完整缓存就分片 = 把同一个文件向源拉 N 次。宁可回 409 让脚本先取一次整份。
            throw GhpError::make(GhpError::SPLIT_REQUIRES_CACHED, '该引用尚无完整缓存', [
                'part' => $part,
                'of' => $of,
                'next_action' => ['kind' => 'fetch_full_first', 'url_hint' => '去掉 part/of 取一次整份'],
            ]);
        }

        $total = (int) $entry->bytes;
        $start = intdiv($total * $part, $of);
        $end = $part === $of - 1 ? $total - 1 : intdiv($total * ($part + 1), $of) - 1;
        if ($start > $end || $start >= $total) {
            $this->emit416($total);

            return $this->summary(ExecMode::Split, 416, $entry->sourceId, 0, 0.0, 'hit', $entry, true);
        }

        $etag = $entry->etag !== '' ? $entry->etag : $this->policy()->etagFor($entry->key, 'full');
        $headers = $this->edgeHeaders($ref, $entry, $etag, $total, $start, $end, true, $now, 'hit');
        $headers['x-ghaccel-split'] = sprintf('%d/%d', $part, $of);
        $this->headers()->emit(206, $headers);
        Http::noBuffering();

        $out = is_resource($ctx['out']) ? $ctx['out'] : Http::out();
        $written = $this->store()->sliceToOutput($entry, $out, $start, $end);
        if ($written === $end - $start + 1) {
            Http::flush();
            $this->store()->noteHit($entry);
            $this->recordLocal('split', $ref, $ctx, $written, 'hit');
        } else {
            $this->recordLocal('client_abort', $ref, $ctx, $written, 'hit');
        }

        return $this->summary(ExecMode::Split, 206, $entry->sourceId, $written, 0.0, 'hit', $entry, true, [
            'split' => [$part, $of, $start, $end, $total],
        ]);
    }

    /**
     * 从原始 query 里取 part/of。入口用它, 因为 RefParser 把 part 归为控制键并从上游
     * query 里丢掉了 —— 也就是说这个信息只能在这里、只能从原始串拿到。
     *
     * @return array{0:int,1:int}|null
     */
    public static function parseSplit(string $rawQuery, Config $cfg): ?array
    {
        $part = null;
        $of = null;
        foreach (explode('&', $rawQuery) as $pair) {
            if ($pair === '' || !str_contains($pair, '=')) {
                continue;
            }
            [$k, $v] = explode('=', $pair, 2);
            $k = strtolower(rawurldecode($k));
            if ($k === 'part') {
                $part = (int) rawurldecode($v);
            } elseif ($k === 'of') {
                $of = (int) rawurldecode($v);
            }
        }
        if ($part === null) {
            return null;
        }
        if ($of === null || $of <= 0) {
            $of = max(1, $cfg->int('algo.mode.split_default_of', 8));
        }

        return [max(0, $part), $of];
    }

    // ------------------------------------------------------------------
    // 观测与统计回写
    // ------------------------------------------------------------------

    /**
     * 顺序是 B 组定的, 不要重排:
     *   Success::record -> Latency::update(有 ttfb/thr 才调) -> Breaker::recordOutcome(带场景键)
     *   -> Breaker::evaluate -> measuredCaps 回写 -> Observatory::record。
     *
     * measuredCaps 不回写的话, 出厂源表(caps 全 false)永远只能靠放宽档跑, 选路的 L0
     * 硬约束就形同虚设。flush() 由请求末尾统一调一次, 这里只进缓冲。
     */
    public function recordOutcome(Candidate $cand, UpstreamResult $res, GitHubRef $ref, array $ctx): void
    {
        $id = $cand->id();
        $stat = $this->stat($id);
        $now = microtime(true);
        $kind = $res->failure;

        $bodySecs = max(0.0, ($res->totalMs - $res->ttfbMs) / 1000.0);
        $thr = $res->bytesReceived > 0 && $bodySecs > 0.05 ? $res->bytesReceived / $bodySecs : 0.0;

        $stat = Success::record($stat, $kind, $this->cfg);
        if ($res->ttfbMs > 0.0 || $thr > 0.0) {
            $stat = Latency::update($stat, $res->ttfbMs, $thr, $now, $this->cfg);
        }
        $stat = Breaker::recordOutcome($stat, $kind, $res->ttfbMs, $now, $this->cfg, $ref->scene->configKey());
        $stat = Breaker::evaluate($stat, $now, $this->cfg);

        // 实测能力回写: 只收布尔位(Compactor 重放时逐位 (bool) 化, 别把体积之类塞进来)。
        foreach ((array) $res->observedCaps as $cap => $val) {
            if (is_bool($val)) {
                $stat->measuredCaps[(string) $cap] = $val;
            }
        }
        $stat->lastHttpStatus = $res->status;
        $stat->lastError = substr(str_replace(["\r", "\n"], '', (string) $res->curlError), 0, 160);

        $this->stats[$id] = $stat;

        $this->observatory()->record([
            'source'      => $id,
            'kind'        => $kind->value,
            'ttfb_ms'     => round($res->ttfbMs, 1),
            'thr_bps'     => round($thr, 1),
            'bytes'       => $res->bytesReceived,
            'observed_at' => $now,
            'scene'       => $ref->scene->configKey(),
            'caps'        => array_map(static fn ($v): bool => (bool) $v, (array) $res->observedCaps),
            'type'        => 'outcome',
            // 以下不进算法, 只供面板与事后对账。IP 与完整 ref 一律不落盘。
            'status'      => $res->status,
            'hops'        => $res->redirectHops,
            'committed'   => $res->committed,
            'budget_ms'   => (int) round((float) ($ctx['budget_ms'] ?? 0)),
            'mode'        => (string) ($ctx['mode'] ?? ExecMode::Failover->value),
            'ref'         => substr(Key::of($ref), 0, 16),
            'req'         => Http::requestId(),
        ]);
    }

    /**
     * 没有与上游交互的事件(EDGE 命中、302 直出、分片、客户端断开)记这里。
     *
     * source 传空串是**故意的**: Compactor 对空 source 的整行直接 continue, 于是这类记录
     * 既给了面板命中率与带宽的数字, 又不会被算成某个源的一次"成功"。
     */
    private function recordLocal(string $what, GitHubRef $ref, array $ctx, int $bytes, string $cacheTag): void
    {
        $this->observatory()->record([
            'source'  => '',
            'kind'    => $what === 'client_abort' ? FailureKind::ClientAbort->value : FailureKind::None->value,
            'type'    => $what,
            'bytes'   => max(0, $bytes),
            'scene'   => $ref->scene->configKey(),
            'caps'    => [],
            'ttfb_ms' => 0.0,
            'thr_bps' => 0.0,
            'cache'   => $cacheTag,
            'ref'     => substr(Key::of($ref), 0, 16),
            'req'     => Http::requestId(),
        ]);
    }

    /** 请求末尾一次: 落观测(1 次追加) + 概率触发压实。必须在响应发完之后调用。 */
    public function flushObservations(): void
    {
        $obs = $this->observatory();
        $obs->flush();
        $obs->maybeCompact();
    }

    /** @return array<string,mixed> 面板与 ?debug=1 用的决策快照 */
    public function decision(): array
    {
        return [
            'plan'      => $this->plan?->toArray() ?? [],
            'attempts'  => $this->attempts,
            'stats'     => array_map(
                static fn (RuntimeStat $s): array => [
                    'breaker' => $s->breaker->value,
                    'samples' => $s->sampleCount,
                    'caps'    => $s->measuredCaps,
                ],
                $this->stats
            ),
        ];
    }

    // ------------------------------------------------------------------
    // 错误渲染(入口的 catch 分支)
    // ------------------------------------------------------------------

    /**
     * 三态渲染: Agent 要 problem+json、浏览器要 HTML、健康检查/纯文本场景要 text。
     *
     * Range 请求无论走哪一态都必须是 problem+json 并带上正确的状态码 —— 给一个 200 的
     * HTML 错误页, 并发下载器就会把它当一个分片写进文件, 产出一个静默损坏的产物。
     */
    public function renderError(GhpError $e, array $ctx = []): void
    {
        $status = $e->status();
        $extra = ['retry-after' => $e->retryAfter()];
        if ($status === 503 && $e->retryAfter() === null) {
            // 并发满/无源这类 503 没有上游信号可依, 给一个保守的重试建议,
            // 否则 Agent 会立刻紧密循环, 把 503 变成 DDoS。
            $extra['retry-after'] = 5;
        }
        $headers = $this->headers()->errorHeaders($status, $extra);

        $wantJson = (bool) ($ctx['want_json'] ?? true) || (bool) ($ctx['is_agent'] ?? false)
            || (string) ($ctx['range'] ?? '') !== '';

        if ($wantJson) {
            Http::problem($e->toProblem(Http::requestId()), $headers);

            return;
        }
        if (($ctx['render'] ?? 'html') === 'text') {
            Http::text(sprintf('%s: %s (request_id=%s)', $e->title(), $e->hint(), Http::requestId()), $status);

            return;
        }
        Http::html(
            '<!doctype html><meta charset="utf-8"><title>' . htmlspecialchars($e->title(), ENT_QUOTES) . '</title>'
            . '<h1>' . htmlspecialchars($e->title(), ENT_QUOTES) . '</h1><p>'
            . htmlspecialchars($e->hint(), ENT_QUOTES) . '</p><p>request_id=' . Http::requestId() . '</p>',
            $status,
            $headers
        );
    }

    // ------------------------------------------------------------------
    // 内部
    // ------------------------------------------------------------------

    private function buildPlan(GitHubRef $ref, array $ctx, float $now): Plan
    {
        $sources = $this->sourceList();
        if (!$this->statsLoaded) {
            $this->stats = $this->snapshot()->statsMap();
            $this->statsLoaded = true;
        }
        $this->plan = $this->selector()->plan($sources, $this->stats, $ref, [
            'size_hint'       => max((int) $ctx['size_hint'], $ref->sizeHint),
            // 归档一类 allowRange=false 的引用, 传输层会主动忽略客户端的 Range(见 Streamer)。
            // 若这里仍按 range_requested=true 去过滤, L0 会以"源不支持 Range"剔掉几乎全部源,
            // 只剩一个候选; 它一挂就整条链无路可走, 症状是"发 Range 反而比不发更容易失败"。
            'range_requested' => (bool) $ctx['range_requested'] && $ref->allowRange,
            'needs_redirect'  => $ref->needsRedirectResolve,
            'is_agent'        => (bool) $ctx['is_agent'],
            'now'             => $now,
        ]);

        return $this->plan;
    }

    /**
     * 一次上游交互。
     *
     * deps['fetch'] 是自检与面板探活的注入点: Streamer 是 final(应当如此, 它持有传输状态),
     * 所以测试接缝只能做成可调用依赖而不是子类。真实路径永远走 Streamer。
     */
    private function doFetch(Source $src, GitHubRef $ref, array $opts, ?array &$detail): UpstreamResult
    {
        if (isset($this->deps['fetch']) && is_callable($this->deps['fetch'])) {
            $detail = null;
            $r = ($this->deps['fetch'])($src, $ref, $opts, $detail);

            return $r instanceof UpstreamResult ? $r : new UpstreamResult(FailureKind::Connect);
        }
        $detail = null;

        return $this->streamer()->fetch($src, $ref, $opts, $detail);
    }

    private function stat(string $id): RuntimeStat
    {
        if (!isset($this->stats[$id])) {
            $this->stats[$id] = new RuntimeStat();
        }

        return $this->stats[$id];
    }

    private function entryOf($detail): ?Entry
    {
        if (!is_array($detail)) {
            return null;
        }
        $e = $detail['entry'] ?? null;

        return $e instanceof Entry ? $e : null;
    }

    private function emit416(int $total): void
    {
        $pack = $this->headers()->rangeUnsatisfiable($total);
        $pack['headers']['content-length'] = '0';
        $this->headers()->emit($pack['status'], $pack['headers']);
    }

    /** @return array<string,string> */
    private function corsIfPublic(): array
    {
        // 面板同源时不注入 CORS: 公开代理需要它(下载器与网页按钮跨源取文件),
        // 而自用部署注入 * 只是给扫描器多一个可用的响应特征。
        return $this->cfg->str('app.exposure', 'private') === 'public' ? $this->headers()->cors() : [];
    }

    /** ETag 比较: 支持弱标记 W/"..." 与多值 If-None-Match 与 '*'。 */
    public static function etagMatches(string $ifNoneMatch, string $etag): bool
    {
        $want = strtolower(trim($etag));
        foreach (explode(',', $ifNoneMatch) as $one) {
            $one = strtolower(trim($one));
            if ($one === '' ) {
                continue;
            }
            if ($one === '*') {
                return true;
            }
            if (str_starts_with($one, 'w/')) {
                $one = trim(substr($one, 2));
            }
            if ($one === $want || trim($one, '"') === trim($want, '"')) {
                return true;
            }
        }

        return false;
    }

    private function summary(
        ExecMode $mode,
        int $status,
        string $source,
        int $bytes,
        float $ttfbMs,
        string $cacheTag,
        ?Entry $entry = null,
        bool $committed = false,
        array $extra = []
    ): array {
        return $extra + [
            'mode'       => $mode->value,
            'status'     => $status,
            'source'     => $source,
            'bytes'      => $bytes,
            'ttfb_ms'    => round($ttfbMs, 1),
            'cache'      => $cacheTag,
            'committed'  => $committed,
            'entry'      => $entry,
            'attempts'   => $this->attempts,
            'decision'   => $this->plan?->toArray() ?? [],
            'sha256'     => (string) ($this->lastDetail['sha256'] ?? ''),
            'integrity_ok' => (bool) ($this->lastDetail['integrity_ok'] ?? true),
            'caps'       => (array) ($this->lastDetail['caps'] ?? []),
            'total_size' => (int) ($this->lastDetail['total_size'] ?? 0),
        ];
    }

    // ------------------------------------------------------------------
    // 懒建依赖(键名即注入点: 面板与自检按这些键换实现)
    // ------------------------------------------------------------------

    private function dep(string $key, \Closure $make): object
    {
        if (!isset($this->deps[$key])) {
            $this->deps[$key] = $make();
        }

        return $this->deps[$key];
    }

    public function guard(): UrlGuard
    {
        /** @var UrlGuard $g */
        $g = $this->dep('guard', fn (): UrlGuard => new UrlGuard($this->cfg));

        return $g;
    }

    public function policy(): Policy
    {
        /** @var Policy $p */
        $p = $this->dep('policy', fn (): Policy => new Policy($this->cfg));

        return $p;
    }

    public function store(): Store
    {
        /** @var Store $s */
        $s = $this->dep('store', fn (): Store => new Store($this->root, $this->cfg, $this->policy()));

        return $s;
    }

    public function headers(): Headers
    {
        /** @var Headers $h */
        $h = $this->dep('headers', fn (): Headers => new Headers($this->cfg, $this->policy()));

        return $h;
    }

    /**
     * 源列表。
     *
     * deps['sources_list'] 是显式注入的 list<Source>: 自检与"一键探活"这类临时源草稿
     * 不该通过 SourceRepo::upsert() 落进生产 overlay(那会把一次测速变成永久配置)。
     *
     * @return list<\GhAccel\Source\Source>
     */
    private function sourceList(): array
    {
        if (isset($this->deps['sources_list']) && is_array($this->deps['sources_list'])) {
            return array_values($this->deps['sources_list']);
        }

        return $this->sources()->all();
    }

    public function sources(): SourceRepo
    {
        /** @var SourceRepo $r */
        $r = $this->dep('sources', fn (): SourceRepo => new SourceRepo($this->cfg, $this->root));

        return $r;
    }

    public function snapshot(): Snapshot
    {
        /** @var Snapshot $s */
        $s = $this->dep('snapshot', fn (): Snapshot => new Snapshot($this->root, $this->cfg));

        return $s;
    }

    public function selector(): Selector
    {
        /** @var Selector $s */
        $s = $this->dep('selector', fn (): Selector => new Selector($this->cfg));

        return $s;
    }

    public function observatory(): Observatory
    {
        /** @var Observatory $o */
        $o = $this->dep('observatory', fn (): Observatory => new Observatory($this->root, $this->cfg));

        return $o;
    }

    public function streamer(): Streamer
    {
        /** @var Streamer $s */
        $s = $this->dep('streamer', fn (): Streamer => new Streamer(
            $this->cfg,
            $this->guard(),
            $this->headers(),
            $this->policy(),
            $this->store()
        ));

        return $s;
    }

    public function failover(): Failover
    {
        /** @var Failover $f */
        $f = $this->dep('failover', fn (): Failover => new Failover($this->cfg));

        return $f;
    }

    private static function str(mixed $v): string
    {
        return is_scalar($v) ? trim((string) $v) : '';
    }
}
