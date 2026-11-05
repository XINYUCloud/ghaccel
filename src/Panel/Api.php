<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 面板 JSON 接口。读接口给四个视图供数据, 写接口做源 CRUD、熔断复位、
 *             缓存清理、配置覆盖与令牌管理。所有写路径先过 Auth 的 CSRF 链再动状态。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 * @see       https://github.com/  完整版权与许可信息见仓库根目录 LICENSE
 */

declare(strict_types=1);

namespace GhAccel\Panel;

use GhAccel\Bootstrap;
use GhAccel\Cache\Policy;
use GhAccel\Config;
use GhAccel\Enum\BreakerState;
use GhAccel\Enum\Scene;
use GhAccel\Enum\SourceMode;
use GhAccel\Enum\Trust;
use GhAccel\Errors\GhpError;
use GhAccel\Execution\Dispatcher;
use GhAccel\Http;
use GhAccel\Ref\RefParser;
use GhAccel\Routing\Success;
use GhAccel\Security\Audit;
use GhAccel\Security\Auth;
use GhAccel\Security\RateLimiter;
use GhAccel\Source\RuntimeStat;
use GhAccel\Source\Source;
use GhAccel\Store\Compactor;
use GhAccel\Store\Observatory;
use GhAccel\Store\Snapshot;

/**
 * 四条不可让步的规则, 每条都对应一类真实事故:
 *
 *  1. 未认证 = 404, 不是 401。Auth::requireAuth() 对 API 走 401 分支(脚本需要区分
 *     "没带凭证"与"路径不存在"), 但面板暴露在公网时 401 本身就是"这里有面板"的信号,
 *     所以在本层把 UNAUTHENTICATED 映射成 NOT_FOUND —— 错误码语义在 Auth 里已经分开,
 *     不需要改那个文件。
 *  2. 写接口一律 verifyWriteRequest() → requireWrite() → 危险操作再要求 body confirm,
 *     且 confirm 检查发生在任何状态变更之前。
 *  3. 本层轮询走 panel 桶而不是 ip 桶: 一个页签四个视图每秒一发, 混进数据面桶会让
 *     管理员自己被数据面的限流参数管着, 反过来也会把正常用户的额度吃光。
 *  4. 任何字段出网前都过 scrub(): 剥控制字符 + 截断 + 去绝对路径。RuntimeStat::$lastError
 *     已经截过 200 字符, 但那是 curl 原文, 里面可能出现服务器路径与上游最终地址。
 */
final class Api
{
    /** 可拼接示例用的内层地址: 只为展示形态, 绝不进任何请求。 */
    private const SAMPLE_URL = 'https://raw.githubusercontent.com/octocat/Hello-World/master/README';

    /** 实测能力位的唯一键名, 与 Selector 的三个常量一致。 */
    private const CAPS = ['range', 'follows_redirect_internally', 'json_api_ok'];

    /**
     * CSRF 绑定用"路由模板"而不是具体路径。
     *
     * 为什么: Auth::csrfMap() 只能在前端已知动作集合里预生成 Token, 而 /mirrors/{id} 的
     * id 是动态的(面板新增源之后没有再取 Token 的通道)。绑模板仍然保住 Auth 注释里的
     * 原意 —— "改权重的 Token 拿去删源"用不了, 因为动作形态就是 Token 的一部分。
     */
    private const TEMPLATES = [
        'mirrors' => '/mirrors',
        'mirror' => '/mirrors/{id}',
        'mirror_action' => '/mirrors/{id}/action',
        'cache_purge' => '/cache/purge',
        'config' => '/config',
        'tokens' => '/tokens',
        'token' => '/tokens/{prefix}',
    ];

    /** 面板可改的顶层配置段, 必须与 Config::filterOverlay 的白名单一致(见 configOverlayKeys)。 */
    private const CONFIG_SECTIONS = ['algo', 'cache', 'limits', 'budgets', 'panel', 'logging', 'routing'];

    /**
     * panel 段里不许从面板改的键。
     *
     * enabled/public_exposed/path_prefix 是"进门之后才能碰"的东西: 一次误操作把
     * public_exposed 关掉就会把管理员自己锁在外面, 而锁在外面时面板正是唯一的解锁手段。
     * 这类引导开关一律只在配置文件里改。
     */
    private const PANEL_DENY = ['enabled', 'public_exposed', 'path_prefix', 'csrf_secret', 'session_idle_s', 'session_abs_s'];

    private string $prefix;

    private string $base;

    private Dispatcher $disp;

    /**
     * 入口已经跑过的环境自检结果。
     *
     * 必须复用而不是在面板里重跑一次: Http::noBuffering() 会把 zlib.output_compression
     * 用 ini_set 写成字符串 "Off", 而 (bool)"Off" 在 PHP 里是 true(只有 '' 和 '0' 为假,
     * 布尔型 ini 项的 On/Off 解析只发生在读 php.ini 时)。于是 noBuffering 之后再跑自检,
     * 面板就会报一条根本不存在的"zlib 未关闭"严重项 —— 运维第一眼看到的却是致命告警。
     * @see tests/agent_c2_check.php 的同名断言
     */
    private ?array $selfCheck = null;

    public function __construct(
        private readonly Config $cfg,
        private readonly Auth $auth,
        private readonly string $root
    ) {
        $this->prefix = trim($cfg->str('panel.path_prefix', 'panel'), '/');
        $this->base = '/' . $this->prefix;
        $this->disp = new Dispatcher($cfg, $root);
    }

    /** 由 panel.php 把入口的自检结果传进来, 让概览显示的是同一份判定。 */
    public function useSelfCheck(array $check): void
    {
        $this->selfCheck = $check;
    }

    /** 静态资源文件名 -> 绝对路径。固定映射表, 绝不 readfile(路径来自 URL)。 */
    public static function assets(): array
    {
        return [
            'panel.css' => 'public/panel/assets/panel.css',
            'api.js'    => 'public/panel/assets/api.js',
            'chart.js'  => 'public/panel/assets/chart.js',
            'views.js'  => 'public/panel/assets/views.js',
            'panel.js'  => 'public/panel/assets/panel.js',
        ];
    }

    // ------------------------------------------------------------------
    // 入口
    // ------------------------------------------------------------------

    /**
     * @param string $method 已大写的请求方法
     * @param string $path   完整请求路径(含面板前缀), 同时是 CSRF 的绑定输入
     */
    public function handle(string $method, string $path): void
    {
        Http::noBuffering();
        $rid = Http::requestId();
        $this->apiHeaders();

        try {
            $this->throttle();
            // 读接口同样先要会话: Auth 对 API 路径给 401, 本层统一伪装成 404(见类注释第 1 条)。
            // 少了这一道, 面板的四个读接口就是公开的数据面侦察口。
            $this->auth->requireAuth();
            $rel = $this->relative($path);
            $data = $this->dispatch(strtoupper($method), $rel, $path);
            $this->send($this->envelope($data, $rid), 200);
        } catch (GhpError $e) {
            // 限流单独走 problem+json: Agent 与前端都按 RFC7807 读 Retry-After,
            // 而 429 混在 {ok:false} 信封里会让"面板被自己限流"看起来像接口坏了。
            if ($e->errorCode === GhpError::RATE_LIMITED) {
                $this->sendProblem($e, $rid);

                return;
            }
            $this->send($this->errorEnvelope($e, $rid), $this->mapStatus($e));
        } catch (\Throwable $t) {
            error_log('[GhAccel panel] ' . get_class($t) . ': ' . $t->getMessage() . ' req=' . $rid);
            $e = GhpError::make('internal_error', '面板接口内部错误, 见服务端日志', ['request_id' => $rid]);
            $this->send($this->errorEnvelope($e, $rid), 500);
        }
    }

    /** 面板 SSR 用的初始数据: 与 GET 接口同一套构造函数, 免得两套渲染口径漂移。 */
    public function initialData(string $view): array
    {
        $out = ['view' => $view];
        $out['summary'] = $this->summary();
        $out['mirrors'] = $this->mirrors();
        // 决策视图必须 SSR: 它渲染的 ref / 源域名 / 错误消息全是攻击者可控字符串,
        // 服务端转义是第一道, 前端 textContent 只是第二道。
        $out['decisions'] = $this->decisions(12);
        // 缓存视图要扫目录(水位 + 分场景), 只在真的要显示它时才扫。
        $out['cache'] = $view === 'cache' ? $this->cacheView() : null;

        return $out;
    }

    // ------------------------------------------------------------------
    // 路由
    // ------------------------------------------------------------------

    /**
     * @param array<int,string> $rel 去掉 /{prefix}/api 之后的段
     * @param string $path 完整路径(用于 CSRF 绑定)
     */
    private function dispatch(string $method, array $rel, string $path): array
    {
        $n = count($rel);
        $s0 = $rel[0] ?? '';

        if ($n === 1) {
            if ($s0 === 'summary' && $method === 'GET') {
                return $this->ok($this->summary());
            }
            if ($s0 === 'mirrors' && $method === 'GET') {
                return $this->ok($this->mirrors());
            }
            if ($s0 === 'mirrors' && $method === 'POST') {
                return $this->ok($this->createMirror($path));
            }
            if ($s0 === 'decisions' && $method === 'GET') {
                return $this->ok($this->decisions(max(1, min(100, $this->intQuery('limit', 20)))));
            }
            if ($s0 === 'cache' && $method === 'GET') {
                return $this->ok($this->cacheView());
            }
            if ($s0 === 'config' && $method === 'GET') {
                return $this->ok($this->configView());
            }
            if ($s0 === 'config' && $method === 'PUT') {
                return $this->ok($this->writeConfig($path));
            }
            if ($s0 === 'tokens' && $method === 'GET') {
                return $this->ok($this->tokens());
            }
            if ($s0 === 'tokens' && $method === 'POST') {
                return $this->ok($this->issueToken($path));
            }
            if ($s0 === 'me' && $method === 'GET') {
                return $this->ok($this->me());
            }
        }

        if ($n === 2 && $s0 === 'mirrors' && $method === 'GET') {
            return $this->ok($this->mirrorDetail($rel[1]));
        }
        if ($n === 2 && $s0 === 'cache' && $rel[1] === 'purge' && $method === 'POST') {
            return $this->ok($this->purge($path));
        }
        if ($n === 3 && $s0 === 'mirrors' && $rel[2] === 'action') {
            if ($method !== 'POST') {
                throw GhpError::make(GhpError::UNSUPPORTED_METHOD, $method);
            }

            return $this->ok($this->mirrorAction($rel[1], $path));
        }
        if ($n === 2 && $s0 === 'mirrors' && in_array($method, ['PUT', 'DELETE'], true)) {
            return $method === 'PUT'
                ? $this->ok($this->editMirror($rel[1], $path))
                : $this->ok($this->deleteMirror($rel[1], $path));
        }
        if ($n === 2 && $s0 === 'tokens' && $method === 'DELETE') {
            return $this->ok($this->revokeToken($rel[1], $path));
        }

        throw GhpError::make(GhpError::NOT_FOUND, '接口不存在');
    }

    private function relative(string $path): array
    {
        $rel = $path;
        if ($this->base !== '' && str_starts_with($path, $this->base)) {
            $rel = substr($path, strlen($this->base));
        }
        if (!str_starts_with($rel, '/api')) {
            throw GhpError::make(GhpError::NOT_FOUND, '接口不存在');
        }
        $seg = array_values(array_filter(explode('/', substr($rel, 4)), static fn (string $s): bool => $s !== ''));

        // 段本身也是输入: 只允许安全字符, 其余一律 404, 不给"存在但非法"留可分辨的信号。
        foreach ($seg as $s) {
            if (preg_match('#\A[a-z0-9._@:-]{1,80}\z#i', $s) !== 1) {
                throw GhpError::make(GhpError::NOT_FOUND, '接口不存在');
            }
        }

        return $seg === [] ? [''] : $seg;
    }

    // ------------------------------------------------------------------
    // 读接口
    // ------------------------------------------------------------------

    /** @return array<string,mixed> */
    public function summary(): array
    {
        $window = max(30, $this->cfg->int('panel.stats_window_s', 300));
        $rows = $this->journalRows(4000);
        $agg = $this->aggregate($rows, $window);
        $snap = $this->snapshotRaw();
        $stats = $this->statsMap();
        $sources = $this->disp->sources()->all();

        $open = 0;
        $half = 0;
        $samples = 0;
        foreach ($stats as $st) {
            $samples += $st->sampleCount;
            if ($st->breaker === BreakerState::Open) {
                $open++;
            } elseif ($st->breaker === BreakerState::HalfOpen) {
                $half++;
            }
        }

        $check = $this->selfCheck ?? Bootstrap::selfCheck($this->root);
        $minRank = max(1, $this->cfg->int('algo.explore.min_sample_for_rank', 30));
        $enabled = 0;
        foreach ($sources as $s) {
            if ($s->enabled) {
                $enabled++;
            }
        }

        // 运维第一眼要看的是"这套东西到底装对没有", 所以自检原样透出, 不摘要不美化。
        $selfcheck = [
            'critical' => $this->stringifyMap($check['critical']),
            'warnings' => $this->stringifyMap($check['warnings']),
            'info' => $this->stringifyMap($check['info']),
        ];

        return [
            'qps' => round($agg['requests'] / $window, 3),
            'requests_in_window' => $agg['requests'],
            'window_s' => $window,
            'hit_rate' => $agg['requests'] > 0 ? round($agg['hits'] / $agg['requests'], 4) : null,
            'p95_ttfb_ms' => $agg['ttfb'] === [] ? null : round(Compactor::percentile($agg['ttfb'], 0.95), 1),
            'p50_ttfb_ms' => $agg['ttfb'] === [] ? null : round(Compactor::percentile($agg['ttfb'], 0.50), 1),
            'samples_for_latency' => count($agg['ttfb']),
            'bytes_total' => $agg['bytes'],
            'bytes_saved_window' => $agg['saved'],
            // 节省带宽只能按窗口算: 观测日志按 access_days 轮转, 跨轮转的累计值不可信,
            // 报一个没有依据的"累计节省"比报窗口值更糟。
            'breakers_open' => $open,
            'breakers_half_open' => $half,
            'sources_total' => count($sources),
            'sources_enabled' => $enabled,
            'fail_last_window' => $agg['failures'],
            'cold_start' => [
                'global_samples' => $samples,
                'min_sample_for_rank' => $minRank,
                'cold' => $samples < $minRank,
                'note' => $samples < $minRank
                    ? '样本不足, 打分实质由 config/sources.dist.php 的人工先验主导; 这是冷启动的正常状态, 不是算法坏了'
                    : '样本已足够, 实测因子主导排序',
            ],
            'disk_free_bytes' => $agg['disk_free'],
            'cache_used_bytes' => $agg['used'],
            'cache_max_bytes' => $agg['max'],
            'cache_ratio' => $agg['ratio'],
            'snapshot_version' => $this->snapshotVersion(),
            'compacted_at' => (float) ($snap['meta']['compacted_at'] ?? 0.0),
            'journal_rows' => count($rows),
            'selfcheck' => $selfcheck,
            'series' => $this->seriesOf($rows, $window),
            'warnings' => $this->operationalWarnings(),
        ];
    }

    /** @return array<string,mixed> */
    public function mirrors(): array
    {
        $stats = $this->statsMap();
        $pending = $this->pendingProbes();
        $now = microtime(true);
        $rows = [];
        foreach ($this->disp->sources()->all() as $src) {
            $rows[] = $this->mirrorRow($src, $stats[$src->id] ?? new RuntimeStat(), $pending, $now, false);
        }
        // 榜单排序: 启用的在前、熔断的顶到上面、再按分数粗排。运维第一眼要看见的是坏的那个。
        // 三项都是降序, 所以比较键整体取反方(把 b 的键放左边比)。
        usort($rows, static function (array $a, array $b): int {
            $key = static fn (array $r): array => [
                $r['enabled'] ? 1 : 0, (int) $r['breaker_rank'], round((float) $r['score_hint'], 6),
            ];

            return $key($b) <=> $key($a);
        });

        return [
            'rows' => $rows,
            'warnings' => $this->stringifyMap($this->disp->sources()->warnings()),
            'caps_known' => self::CAPS,
            'pending_probes' => array_keys($pending),
            'snapshot_version' => $this->snapshotVersion(),
        ];
    }

    /** @return array<string,mixed> */
    public function mirrorDetail(string $id): array
    {
        $src = $this->disp->sources()->get($id);
        if ($src === null) {
            throw GhpError::make(GhpError::NOT_FOUND, '未知源');
        }
        $stats = $this->statsMap();
        $pending = $this->pendingProbes();
        $now = microtime(true);
        $hist = [];
        foreach ($this->journalRows(3000) as $r) {
            if ((string) ($r['source'] ?? '') !== $id) {
                continue;
            }
            $hist[] = [
                'observed_at' => round((float) ($r['observed_at'] ?? 0.0), 3),
                'type' => $this->scrub((string) ($r['type'] ?? 'outcome'), 40),
                'kind' => $this->scrub((string) ($r['kind'] ?? ''), 40),
                'scene' => $this->scrub((string) ($r['scene'] ?? ''), 30),
                'status' => (int) ($r['status'] ?? 0),
                'ttfb_ms' => round((float) ($r['ttfb_ms'] ?? 0.0), 1),
                'thr_bps' => round((float) ($r['thr_bps'] ?? 0.0), 1),
                'bytes' => (int) ($r['bytes'] ?? 0),
                'budget_ms' => (int) ($r['budget_ms'] ?? 0),
                'hops' => (int) ($r['hops'] ?? 0),
                'mode' => $this->scrub((string) ($r['mode'] ?? ''), 30),
                'caps' => $this->boolMap($r['caps'] ?? []),
            ];
            if (count($hist) >= 50) {
                break;
            }
        }

        return [
            'row' => $this->mirrorRow($src, $stats[$id] ?? new RuntimeStat(), $pending, $now, true),
            'history' => array_reverse($hist),
            'snapshot_version' => $this->snapshotVersion(),
        ];
    }

    /**
     * 决策追踪。
     *
     * 数据来源两条, 口径分开标注, 绝不混成一个数字:
     *  - plan: 由 Selector 用当前源表 + 当前快照**重放**一次纯内存选路(零网络、零上游),
     *    输出与 Dispatcher::decision()['plan'] 完全同构, 所以 breakdown 相加 == score
     *    这条不变式在这里同样成立。
     *  - attempts: 真实请求的逐次结果只能从观测流回读, 因为只有请求进程才有 attempts。
     *
     * @return array<string,mixed>
     */
    public function decisions(int $limit): array
    {
        $refArg = Http::queryStr('ref');
        if ($refArg === '') {
            $refArg = Http::queryStr('u');
        }
        $refArg = substr($refArg, 0, 2048);
        $usedDefault = $refArg === '';
        if ($usedDefault) {
            // 默认样例走 gh 形式: 它不含 //, 不会因为 merge_slashes 之类的部署差异解析失败。
            $refArg = '/gh/cli/cli@refs/heads/main/README.md';
        }

        $parser = new RefParser($this->cfg);
        $parseError = '';
        try {
            $ref = $parser->parse($refArg, '');
        } catch (GhpError $e) {
            $parseError = $this->scrub($e->safeMessage() . ' [' . $e->errorCode . ']', 160);
            $ref = null;
        }

        $planArr = [];
        $excludedReadable = [];
        if ($ref !== null) {
            $stats = $this->statsMap();
            $now = microtime(true);
            $plan = $this->disp->selector()->plan($this->disp->sources()->all(), $stats, $ref, [
                'size_hint' => $ref->sizeHint,
                'range_requested' => false,
                'needs_redirect' => $ref->needsRedirectResolve,
                'is_agent' => false,
                'now' => $now,
            ]);
            $planArr = $plan->toArray();
            foreach ((array) $planArr['excluded'] as $e) {
                $code = (string) ($e['code'] ?? '');
                $excludedReadable[] = [
                    'id' => $this->scrub((string) ($e['id'] ?? ''), 80),
                    'code' => $code,
                    'code_label' => $this->rejectLabel($code),
                    // detail 来自 RejectCode 的固定文案表, 不含外部输入, 但走一遍同一把尺子。
                    'detail' => $this->scrub((string) ($e['detail'] ?? ''), 160),
                    'retry_after_s' => isset($e['retry_after_s']) ? (float) $e['retry_after_s'] : null,
                    'breaker' => $this->scrub((string) ($e['breaker'] ?? ''), 20),
                ];
            }
            // 逐项把"权重 × 归一值 = 贡献"补成前端可直接渲染的行, 并带上求和校验。
            $planArr['ranked'] = $this->decorateRanked((array) ($planArr['ranked'] ?? []));
        }

        return [
            'ref_input' => $this->scrub($refArg, 120),
            'ref_default' => $usedDefault,
            'ref_display' => $ref === null ? '' : $this->scrub($ref->display(), 120),
            'ref_digest' => $ref === null ? '' : substr(hash('sha256', $ref->canonical()), 0, 16),
            'scene' => $ref?->scene?->value ?? '',
            'identity_kind' => $ref?->identityKind?->value ?? '',
            'upstream_host' => $ref === null ? '' : $this->hostPair((string) $ref->upstreamHost),
            'parse_error' => $parseError,
            'decision' => [
                'plan' => $planArr,
                'attempts' => $this->recentAttempts($limit),
                'stats' => $this->decisionStats(),
            ],
            'excluded' => $excludedReadable,
            'relaxed_flags' => (array) ($planArr['relaxed_flags'] ?? []),
            'cold_start' => (bool) ($planArr['cold_start'] ?? false),
            'score_gap' => (float) ($planArr['score_gap'] ?? 1.0),
            'elapsed_ms' => (float) ($planArr['elapsed_ms'] ?? 0.0),
            'snapshot_version' => $this->snapshotVersion(),
            'note' => 'plan 为当前状态下的纯内存重放(零上游请求); attempts 来自观测流回读, 属真实历史',
        ];
    }

    /** @return array<string,mixed> */
    public function cacheView(): array
    {
        $store = $this->disp->store();
        $wm = $store->watermark();
        $usage = $this->readJson($store->cacheDir() . '/.usage.json');
        $scan = $this->sceneScan($store->cacheDir());
        $rows = $this->journalRows(3000);
        $agg = $this->aggregate($rows, max(30, $this->cfg->int('panel.stats_window_s', 300)));

        return [
            'watermark' => [
                'used' => (int) $wm['used'],
                'max' => (int) $wm['max'],
                'ratio' => round((float) $wm['ratio'], 5),
                'soft' => (float) $wm['soft'],
                'hard' => (float) $this->cfg->float('cache.hard_watermark', 0.85),
                'stop' => (float) $this->cfg->float('cache.stop_watermark', 0.95),
                'soft_bytes' => (int) round((float) $wm['soft'] * (int) $wm['max']),
                'hard_bytes' => (int) round((float) $this->cfg->float('cache.hard_watermark', 0.85) * (int) $wm['max']),
                'stop_bytes' => (int) round((float) $this->cfg->float('cache.stop_watermark', 0.95) * (int) $wm['max']),
                'disk_free' => (int) $wm['disk_free'],
                'entries' => (int) $wm['entries'],
                'partial_bytes' => (int) $wm['partial'],
                'stop_writing' => (bool) $wm['stop'],
                'scanned_at' => round((float) $wm['at'], 3),
            ],
            'usage' => [
                'total_evicted' => (int) ($usage['total_evicted'] ?? 0),
                'total_hits' => (int) ($usage['total_hits'] ?? 0),
                'freed_last' => (int) ($usage['freed_last'] ?? 0),
                'expired_entries_purged' => (int) ($usage['expired_entries_purged'] ?? 0),
                'written_at' => round((float) ($usage['written_at'] ?? 0.0), 3),
            ],
            'partial_files' => $scan['partial_files'],
            'quarantine_files' => $scan['quarantine_files'],
            'by_scene' => $scan['scenes'],
            'scanned_meta' => $scan['scanned'],
            'scan_truncated' => $scan['truncated'],
            'hit_rate_window' => $agg['requests'] > 0 ? round($agg['hits'] / $agg['requests'], 4) : null,
            'bytes_saved_window' => $agg['saved'],
            'ttl_by_scene' => $this->cfg->arr('cache.ttl', []),
            'enabled' => $this->cfg->bool('cache.enabled', true),
            'snapshot_version' => $this->snapshotVersion(),
        ];
    }

    /** @return array<string,mixed> */
    public function configView(): array
    {
        $overlay = $this->readJson($this->root . '/var/state/overlay.json');
        $sections = [];
        foreach ($this->configOverlayKeys() as $k) {
            $v = $this->cfg->get($k, null);
            $sections[$k] = is_array($v) ? $this->redact($v) : $v;
        }

        return [
            'sections' => $sections,
            'overlay' => $this->redact($overlay),
            'editable_top' => $this->configOverlayKeys(),
            'panel_denied' => self::PANEL_DENY,
            'poll_ms' => $this->cfg->arr('panel.poll_ms', []),
            'base_origin_configured' => trim((string) $this->cfg->str('app.base_origin')) !== '',
            'snapshot_version' => $this->snapshotVersion(),
        ];
    }

    /** @return array<string,mixed> */
    public function tokens(): array
    {
        return [
            'rows' => $this->auth->listTokens(),
            'note' => '只存 sha256(verifier) 摘要; 明文只在签发那一刻出现一次, 丢了只能重签',
            'snapshot_version' => $this->snapshotVersion(),
        ];
    }

    /**
     * 当前会话 + 同机活跃会话摘要。
     *
     * 为什么连别的会话一起给: 管理员发现"异地会话"的唯一办法是看见一个不属于他的
     * IP 前缀。这里只给 ip_prefix / ua 摘要 / 时间, 既不给明文 IP 也不给可重放的 sid。
     *
     * @return array<string,mixed>
     */
    public function me(): array
    {
        $s = $this->auth->requireAuth();
        $ua = (string) Http::headerLine('user-agent');

        return [
            'selector_prefix' => substr((string) $s['selector'], 0, 8),
            'label' => $this->scrub((string) $s['label'], 64),
            'scopes' => (array) $s['scopes'],
            'created_at' => (int) $s['created_at'],
            'last_seen_at' => (int) $s['last_seen_at'],
            'ua_summary' => $this->uaSummary($ua),
            'ip_hash' => Audit::ipHash(Http::clientIp(), $this->cfg->str('limits.bucket_salt')),
            'can_write' => in_array('write', (array) $s['scopes'], true),
            'peers' => $this->peerSessions((string) $s['sid']),
            'session_idle_s' => $this->cfg->int('panel.session_idle_s', 1800),
            'session_abs_s' => $this->cfg->int('panel.session_abs_s', 43200),
            'snapshot_version' => $this->snapshotVersion(),
        ];
    }

    // ------------------------------------------------------------------
    // 写接口
    // ------------------------------------------------------------------

    /**
     * 写接口的统一前置。
     *
     * 顺序是定的: verifyWriteRequest(协议 + Sec-Fetch-Site + Origin + CSRF Token +
     * Content-Type, 内部已含 requireWrite) 再 requireWrite(作用域复核)。
     * 两道都在任何副作用之前 —— 抛出去的时候状态还是原样。
     */
    private function guardWrite(string $method, string $path): array
    {
        // CSRF Token 绑的是动作模板, 所以校验前先把具体 id 归一成模板;
        // 审计里记的仍是具体路径 —— 两边各有各的用途, 不能互相凑。
        $this->auth->verifyWriteRequest($method, self::csrfPathFor($path));
        $this->auth->requireWrite($method);

        return $this->body();
    }

    private function requireConfirm(array $body, string $what): void
    {
        if (($body['confirm'] ?? null) !== true) {
            throw GhpError::make(GhpError::CONFIRM_REQUIRED, $what . ' 需要显式确认(confirm:true)');
        }
    }

    private function createMirror(string $path): array
    {
        $body = $this->guardWrite('POST', $path);
        $def = $this->normalizeMirrorBody($body, true);
        $repo = $this->disp->sources();
        if ($repo->get((string) $def['id']) !== null) {
            throw GhpError::make('invalid_argument', '该 id 已存在; 编辑请用 PUT');
        }
        $src = $repo->upsert($def);
        Audit::log($this->actor(), 'POST', $path, $this->auditBody($body), 'ok', Http::clientIp(), $this->cfg);

        return ['row' => $this->mirrorRow($src, new RuntimeStat(), $this->pendingProbes(), microtime(true), false),
                   'repo_warnings' => $this->stringifyMap($repo->warnings())];
    }

    private function editMirror(string $id, string $path): array
    {
        $body = $this->guardWrite('PUT', $path);
        $repo = $this->disp->sources();
        $old = $repo->get($id);
        if ($old === null) {
            throw GhpError::make(GhpError::NOT_FOUND, '未知源');
        }
        $def = $this->normalizeMirrorBody($body, false);
        // PATCH 语义: 只提交改动字段时, 其余字段必须从现有源补全。upsert 是先把传入的 def
        // 当**完整定义**校验一遍再落 overlay 的, 所以直接把半份 def 交给它必然报"缺 base_url",
        // 而且那道 InvalidArgumentException 会被兜底成 500 —— 一次正常的编辑伪装成服务故障。
        $def = array_merge($old->definition(), $def);
        $def['id'] = $id;
        $src = $repo->upsert($def);
        Audit::log($this->actor(), 'PUT', $path, $this->auditBody($body), 'ok', Http::clientIp(), $this->cfg);

        return ['row' => $this->mirrorRow($src, $this->statsMap()[$id] ?? new RuntimeStat(), $this->pendingProbes(), microtime(true), false),
                   'repo_warnings' => $this->stringifyMap($repo->warnings())];
    }

    private function deleteMirror(string $id, string $path): array
    {
        $body = $this->guardWrite('DELETE', $path);
        $this->requireConfirm($body, '删除源 ' . $this->scrub($id, 64));
        $repo = $this->disp->sources();
        if ($repo->get($id) === null) {
            throw GhpError::make(GhpError::NOT_FOUND, '未知源');
        }
        $repo->remove($id);
        // 删除之后把待探活标记也清掉, 否则 cron 会一直探一个已经不存在的源。
        $this->dropPendingProbe($id);
        Audit::log($this->actor(), 'DELETE', $path, $this->auditBody($body), 'ok', Http::clientIp(), $this->cfg);

        return ['removed' => $id, 'remaining' => count($repo->all())];
    }

    /**
     * 源动作: enable | disable | priority | probe | reset_breaker。
     *
     * probe 与 reset_breaker 都只往观测流写**控制事件**, 面板进程绝不发上游请求:
     * 面板与代理共用同一个 PHP 进程池, 一次 3 秒的同步探活就占住一个 worker,
     * 两个页签点几下就能把并发槽打满。实测由 bin/compact.php 或下一次真实请求完成。
     */
    private function mirrorAction(string $id, string $path): array
    {
        $body = $this->guardWrite('POST', $path);
        $repo = $this->disp->sources();
        $src = $repo->get($id);
        if ($src === null) {
            throw GhpError::make(GhpError::NOT_FOUND, '未知源');
        }
        $action = strtolower(trim((string) ($body['action'] ?? '')));
        $extra = [];

        switch ($action) {
            case 'enable':
                $repo->toggle($id, true);
                break;

            case 'disable':
                $repo->toggle($id, false);
                break;

            case 'priority':
                $p = (int) ($body['priority'] ?? -1);
                if ($p < 1 || $p > 100) {
                    throw GhpError::make('invalid_argument', 'priority 需在 1-100');
                }
                $repo->setPriority($id, $p);
                break;

            case 'probe':
                $this->queueProbe($id);
                break;

            case 'reset_breaker':
                $this->requireConfirm($body, '手动复位熔断');
                $extra = ['compaction' => $this->resetBreaker($id)];
                break;

            default:
                throw GhpError::make('invalid_argument', '未知 action: ' . $this->scrub($action, 40));
        }

        Audit::log($this->actor(), 'POST', $path, ['action' => $action, 'id' => $id], 'ok', Http::clientIp(), $this->cfg);

        // 动作之后重新取一次 Source: $src 是改动前那份不可变配置, 拿它渲染会返回一个
        // "点击成功但榜单没变"的行, 而运维只会认为按钮坏了。
        $row = $this->mirrorRow(
            $repo->get($id) ?? $src,
            $this->statsMap()[$id] ?? new RuntimeStat(),
            $this->pendingProbes(),
            microtime(true),
            false
        );

        return ['action' => $action, 'row' => $row] + $extra;
    }

    /**
     * 熔断复位: 写控制事件 + 立刻压实一次, 让面板刷新就能看到状态变了。
     *
     * 压实用 LOCK_NB: 已有单写者在跑就立刻返回 locked=true, 面板据此如实报告
     * "复位已入队, 待下一次压实生效", 而不是显示一个还没变化的旧状态。
     */
    private function resetBreaker(string $id): array
    {
        $obs = $this->disp->observatory();
        $obs->record([
            'source' => $id,
            'type' => 'breaker_reset',
            'kind' => 'none',
            'scene' => '',
            'caps' => [],
            'observed_at' => microtime(true),
            'actor' => $this->actor(),
        ]);
        $obs->flush();
        $r = (new Compactor($this->root, $this->cfg))->run(true);
        unset($r['freed']);

        return $r;
    }

    /**
     * 待探活标记。
     *
     * 控制事件里的 source 字段必须留空 —— Compactor 对非 breaker_reset 的行会走
     * Success::record(), 带 source 的"探活请求"会被当成一次真实成功样本污染 EWMA。
     * 真正的探活结果只在探测确实跑完之后作为 outcome/caps 观测写入。
     */
    private function queueProbe(string $id): void
    {
        $obs = $this->disp->observatory();
        $obs->record([
            'source' => '',
            'type' => 'probe_request',
            'target' => $id,
            'scene' => '',
            'kind' => 'none',
            'ttfb_ms' => 0.0,
            'thr_bps' => 0.0,
            'bytes' => 0,
            'caps' => [],
            'observed_at' => microtime(true),
            'actor' => $this->actor(),
        ]);
        $obs->flush();

        $file = $this->probeFile();
        $data = $this->readJson($file);
        $pending = (array) ($data['pending'] ?? []);
        $pending[$id] = ['requested_at' => round(microtime(true), 3), 'actor' => $this->actor()];
        Config::atomicWrite($file, (string) json_encode([
            'pending' => $pending,
            'updated_at' => time(),
        ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
    }

    private function dropPendingProbe(string $id): void
    {
        $file = $this->probeFile();
        $data = $this->readJson($file);
        $pending = (array) ($data['pending'] ?? []);
        if (isset($pending[$id])) {
            unset($pending[$id]);
            Config::atomicWrite($file, (string) json_encode([
                'pending' => $pending,
                'updated_at' => time(),
            ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
        }
    }

    private function purge(string $path): array
    {
        $body = $this->guardWrite('POST', $path);
        $this->requireConfirm($body, '清理缓存');
        $scope = strtolower(trim((string) ($body['scope'] ?? '')));
        $target = isset($body['target']) ? substr((string) $body['target'], 0, 512) : null;
        $store = $this->disp->store();

        $count = match ($scope) {
            'all', 'expired', 'partial', 'scene', 'source', 'ref', 'key' => $store->purge($scope, $target),
            'prefix' => $this->purgePrefix($store, (string) $target),
            default => throw GhpError::make('invalid_argument', '未知 scope: ' . $this->scrub($scope, 40)),
        };

        Audit::log($this->actor(), 'POST', $path, ['scope' => $scope, 'target_sha' => substr(hash('sha256', (string) $target), 0, 12), 'confirm' => true], 'ok', Http::clientIp(), $this->cfg);

        return ['scope' => $scope, 'removed' => $count, 'watermark' => $store->watermark()['used']];
    }

    private function writeConfig(string $path): array
    {
        $body = $this->guardWrite('PUT', $path);
        $this->requireConfirm($body, '修改在线配置');
        $patch = $body['patch'] ?? $body;
        if (!is_array($patch)) {
            throw GhpError::make('invalid_argument', 'patch 必须是对象');
        }

        $allowed = $this->configOverlayKeys();
        $clean = [];
        foreach ($patch as $k => $v) {
            $k = (string) $k;
            if (!in_array($k, $allowed, true)) {
                throw GhpError::make('invalid_argument', '顶层键 ' . $this->scrub($k, 32) . ' 不在面板可改白名单内');
            }
            if (!is_array($v)) {
                throw GhpError::make('invalid_argument', $this->scrub($k, 32) . ' 段必须是对象');
            }
            if ($k === 'panel') {
                foreach (self::PANEL_DENY as $deny) {
                    if (array_key_exists($deny, $v)) {
                        throw GhpError::make('invalid_argument', 'panel.' . $deny . ' 只能在配置文件中修改');
                    }
                }
            }
            if ($this->containsSecret($v)) {
                throw GhpError::make('invalid_argument', $this->scrub($k, 32) . ' 段内含密钥类键, 面板不接受');
            }
            $clean[$k] = $v;
        }
        if ($clean === []) {
            throw GhpError::make('invalid_argument', '没有可写入的键');
        }

        $this->cfg->persistOverlay($clean);
        Audit::log($this->actor(), 'PUT', $path, $this->auditBody($clean), 'ok', Http::clientIp(), $this->cfg);

        return ['applied' => array_keys($clean), 'sections' => $this->configView()['sections']];
    }

    private function issueToken(string $path): array
    {
        $body = $this->guardWrite('POST', $path);
        $label = $this->scrub((string) ($body['label'] ?? '面板签发'), 64);
        $raw = $this->auth->issueToken($label, (array) ($body['scope'] ?? ['read']));

        Audit::log($this->actor(), 'POST', $path, ['label' => $label, 'scope' => (array) ($body['scope'] ?? ['read'])], 'ok', Http::clientIp(), $this->cfg);

        return [
            'selector_prefix' => substr((string) $raw['selector'], 0, 8),
            'raw_token' => $raw['raw'],
            'label' => $label,
            'once_only' => true,
            'note' => '只存 sha256 摘要, 丢失无法找回, 只能重签并吊销旧的',
        ];
    }

    private function revokeToken(string $prefix, string $path): array
    {
        $body = $this->guardWrite('DELETE', $path);
        $this->requireConfirm($body, '吊销令牌');
        $this->auth->revokeToken($prefix);
        Audit::log($this->actor(), 'DELETE', $path, ['prefix' => substr($prefix, 0, 16), 'confirm' => true], 'ok', Http::clientIp(), $this->cfg);

        return ['revoked_prefix' => substr($prefix, 0, 8), 'remaining' => count($this->auth->listTokens())];
    }

    // ------------------------------------------------------------------
    // 行构造
    // ------------------------------------------------------------------

    /** @return array<string,mixed> */
    private function mirrorRow(Source $s, RuntimeStat $st, array $pending, float $now, bool $full): array
    {
        $cooldown = max(0.0, $st->cooldownUntil - $now);
        $capsCfg = $this->boolMap($s->caps);
        $capsMeas = $this->boolMap($st->measuredCaps);
        $z = max(0.0, $this->cfg->float('algo.wilson_z', 1.0));

        $row = [
            'id' => $s->id,
            'enabled' => $s->enabled,
            'priority' => $s->priority,
            'mode' => $s->mode->value,
            'mode_label' => $this->modeLabel($s->mode),
            'base_host' => $this->hostPair((string) (parse_url($s->baseUrl, PHP_URL_HOST) ?: '')),
            'example' => $this->scrub($s->accelerate(self::SAMPLE_URL), 160),
            'scenes' => Scene::bitsToScenes($s->sceneBits),
            'hosts' => array_map(fn (string $h): string => $this->scrub($h, 80), array_keys((array) $s->hosts)),
            'trust' => $s->trust->value,
            'trust_label' => $s->trust->label(),
            'region' => $this->scrub($s->region, 40),
            'owner_note' => $this->scrub($s->ownerNote, 120),
            'breaker' => $st->breaker->value,
            'breaker_label' => $st->breaker->label(),
            // 排序用的粗档: 面板榜单把"熔断中"顶到前面, 运维第一眼就该看到坏的那个。
            'breaker_rank' => $st->breaker === BreakerState::Open ? 2 : ($st->breaker === BreakerState::HalfOpen ? 1 : 0),
            'cooldown_left_s' => round($cooldown, 1),
            'cooldown_until' => round($st->cooldownUntil, 3),
            'trip_count' => $st->tripCount,
            'consec_hard_fail' => $st->consecHardFail,
            'consec_probe_ok' => $st->consecProbeOk,
            'sample_count' => $st->sampleCount,
            'successes' => $st->successes,
            'failures_hard' => $st->failures,
            'wilson_lower' => round(Success::wilsonLowerBound($st->successes, $st->sampleCount, $z), 4),
            'hard_fail_rate' => round(Success::hardFailRate($st), 4),
            'ttfb_ewma_ms' => round($st->ttfbEwmaMs, 1),
            'ttfb_p85_ms' => round($st->ttfbP85Ms, 1),
            'conservative_ttfb_ms' => round($st->conservativeTtfbMs(), 1),
            'thr_bps' => round($st->throughputBps(), 1),
            'thr_p10_bps' => round($st->thrP10Bps, 1),
            'hour_bytes' => $st->hourBytes,
            'hour_requests' => $st->hourRequests,
            'last_request_at' => round($st->lastRequestAt, 3),
            'last_probe_at' => round($st->lastProbeAt, 3),
            'min_interval_ms' => $s->minIntervalMs,
            'polite_left_ms' => $s->minIntervalMs > 0 && $st->lastRequestAt > 0.0
                ? max(0, (int) round($s->minIntervalMs - ($now - $st->lastRequestAt) * 1000.0))
                : 0,
            'caps_config' => $capsCfg,
            'caps_measured' => $capsMeas,
            // 三态而不是布尔: 未实测既不是"支持"也不是"不支持", 选路对它的处理也不同。
            'caps_state' => $this->capsState($capsCfg, $capsMeas),
            'fail_breakdown' => $this->intMap($st->failBreakdown),
            'last_failure_kind' => $this->scrub($st->lastFailureKind, 40),
            'last_http_status' => $st->lastHttpStatus,
            'last_error' => $this->scrub($st->lastError, 120),
            'wrong_content_streak' => $st->wrongContentStreak,
            'cold_start' => $st->coldStart || $st->sampleCount < max(1, $this->cfg->int('algo.explore.min_sample_for_rank', 30)),
            'score_hint' => round(Success::rateForScoring($st, $this->cfg, $z) * 0.34
                + (0.85 + 0.3 * ($s->priority / 100.0)) / 2 * 0.20, 4),
            'pending_probe' => isset($pending[$s->id]),
            'stat_updated_at' => round($st->updatedAt, 3),
        ];
        if ($full) {
            $row['timeouts'] = [
                'connect_timeout_ms' => $s->connectTimeoutMs,
                'ttfb_budget_ms' => $s->ttfbBudgetMs,
                'stall_timeout_ms' => $s->stallTimeoutMs,
                'max_size_bytes' => $s->maxSizeBytes,
                'max_concurrent' => $s->maxConcurrent,
                'hourly_bytes_soft_cap' => $s->hourlyBytesSoftCap,
                'blocked_ext' => array_map(fn (string $e): string => $this->scrub($e, 20), array_keys((array) $s->blockedExt)),
                'url_template' => $s->urlTemplate !== '' ? $this->scrub($s->urlTemplate, 160) : '',
            ];
        }

        return $row;
    }

    /** @return array<string,string> 三态: measured_true / measured_false / claimed / unknown */
    private function capsState(array $cfg, array $meas): array
    {
        $out = [];
        foreach (self::CAPS as $c) {
            if (array_key_exists($c, $meas)) {
                $out[$c] = $meas[$c] ? 'measured_true' : 'measured_false';
            } else {
                $out[$c] = !empty($cfg[$c]) ? 'claimed_unverified' : 'unknown';
            }
        }

        return $out;
    }

    /**
     * 给 ranked 每一行补上"权重 × 归一值 = 贡献 + 求和"的可视化字段。
     *
     * 判据用 Selector 写进 breakdown['sum_check'] 的那份**未取整**分数: Plan::toArray() 会把
     * score 四舍五入到 4 位, 拿取整后的值去比 6 位精度的贡献和, 每一行都会显示"不一致" ——
     * 那正是这个视图存在的意义(能对账)被自己搞坏。显示仍然给两个数, 让运维看见取整前后的差。
     */
    private function decorateRanked(array $ranked): array
    {
        foreach ($ranked as $i => $row) {
            $items = [];
            $sum = 0.0;
            foreach ((array) ($row['breakdown'] ?? []) as $k => $v) {
                if (!is_array($v) || !isset($v['weight'], $v['value'])) {
                    continue;
                }
                $w = (float) $v['weight'];
                $val = (float) $v['value'];
                $contrib = (float) ($v['contrib'] ?? $w * $val);
                $sum += $contrib;
                $items[$k] = [
                    'label' => $this->factorLabel($k),
                    'weight' => $w,
                    'value' => $val,
                    'contrib' => round($contrib, 6),
                    // 让面板上相加就等于总分: 贡献按展示精度先定下来, 求和才有意义。
                    'bar' => $w > 0 ? round(min(1.0, $val), 4) : 0.0,
                ];
            }
            $exact = (float) (($row['breakdown'] ?? [])['sum_check'] ?? ($row['score'] ?? 0.0));
            $ranked[$i]['factors'] = $items;
            $ranked[$i]['contrib_sum'] = round($sum, 6);
            $ranked[$i]['score_exact'] = round($exact, 8);
            $ranked[$i]['sum_matches_score'] = abs($sum - $exact) < 1e-9;
            $ranked[$i]['id'] = $this->scrub((string) ($row['id'] ?? ''), 80);
            $ranked[$i]['relaxed'] = array_map(fn ($r): string => $this->rejectLabel((string) $r), (array) ($row['relaxed'] ?? []));
        }

        return $ranked;
    }

    /** @return array<int,array<string,mixed>> 按 req id 归组的逐次结果 */
    private function recentAttempts(int $limit): array
    {
        $groups = [];
        foreach ($this->journalRows(4000) as $r) {
            $rid = (string) ($r['req'] ?? '');
            if ($rid === '') {
                continue;
            }
            $g = $groups[$rid] ?? ['req' => $rid, 'rows' => [], 'at' => 0.0, 'ref' => ''];
            $g['at'] = max($g['at'], (float) ($r['observed_at'] ?? 0.0));
            $g['ref'] = (string) ($r['ref'] ?? $g['ref']);
            $g['rows'][] = [
                'source' => $this->scrub((string) ($r['source'] ?? ''), 80),
                'type' => $this->scrub((string) ($r['type'] ?? ''), 30),
                'kind' => $this->scrub((string) ($r['kind'] ?? ''), 30),
                'status' => (int) ($r['status'] ?? 0),
                'ttfb_ms' => round((float) ($r['ttfb_ms'] ?? 0.0), 1),
                'bytes' => (int) ($r['bytes'] ?? 0),
                'cache' => $this->scrub((string) ($r['cache'] ?? ''), 24),
                'mode' => $this->scrub((string) ($r['mode'] ?? ''), 20),
                'budget_ms' => (int) ($r['budget_ms'] ?? 0),
                'hops' => (int) ($r['hops'] ?? 0),
                'committed' => (bool) ($r['committed'] ?? false),
                'scene' => $this->scrub((string) ($r['scene'] ?? ''), 20),
            ];
            $groups[$rid] = $g;
        }
        usort($groups, static fn (array $a, array $b): int => $b['at'] <=> $a['at']);

        $out = [];
        foreach (array_slice($groups, 0, max(1, $limit)) as $g) {
            $kinds = array_values(array_filter(array_map(static fn (array $r): string => $r['kind'], $g['rows']), static fn (string $k): bool => $k !== 'none' && $k !== ''));
            $out[] = [
                'req' => substr((string) $g['req'], 0, 40),
                'at' => round((float) $g['at'], 3),
                // ref 在观测流里只存 16 位摘要(logging.ref_display=hash), 面板原样显示,
                // 明文 owner/repo 不进磁盘也不出面板 —— 这是隐私义务那条。
                'ref_digest' => substr((string) $g['ref'], 0, 16),
                'events' => $g['rows'],
                'outcome' => $kinds === [] ? 'ok' : implode(',', array_slice(array_unique($kinds), 0, 4)),
            ];
        }

        return $out;
    }

    /** @return array<string,mixed> 与 Dispatcher::decision()['stats'] 同构 */
    private function decisionStats(): array
    {
        $out = [];
        foreach ($this->statsMap() as $id => $s) {
            $out[$id] = [
                'breaker' => $s->breaker->value,
                'samples' => $s->sampleCount,
                'caps' => $this->boolMap($s->measuredCaps),
            ];
        }

        return $out;
    }

    // ------------------------------------------------------------------
    // 观测流回读
    // ------------------------------------------------------------------

    /**
     * 只读当日观测日志的**尾部**。
     *
     * 不做全量重放: 那是压实器的活。面板每 5-15 秒轮询一次, 一次读满一个几十 MB 的
     * 日志文件会把面板变成磁盘 IO 的最大消费者, 而它要的只是最近几百行的窗口指标。
     *
     * @return list<array<string,mixed>>
     */
    private function journalRows(int $maxRows): array
    {
        $obs = new Observatory($this->root, $this->cfg);
        $file = $obs->journalFile();
        if (!is_readable($file)) {
            return [];
        }
        $size = (int) (@filesize($file) ?: 0);
        if ($size === 0) {
            return [];
        }
        $maxBytes = max(65536, $this->cfg->int('panel.journal_tail_bytes', 512 * 1024));
        $start = max(0, $size - $maxBytes);
        $fh = @fopen($file, 'rb');
        if ($fh === false) {
            return [];
        }
        if ($start > 0) {
            fseek($fh, $start);
        }
        $buf = '';
        while (!feof($fh)) {
            $chunk = fread($fh, 65536);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $buf .= $chunk;
        }
        fclose($fh);

        $lines = explode("\n", $buf);
        if ($start > 0) {
            // 从中间切开的第一行是半条 JSON, 丢。
            array_shift($lines);
        }
        $lines = array_reverse(array_values(array_filter($lines, static fn (string $l): bool => trim($l) !== '')));

        $rows = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] !== '{') {
                continue;
            }
            $obj = json_decode($line, true);
            if (!is_array($obj)) {
                continue;
            }
            $inner = isset($obj['obs']) && is_array($obj['obs']) ? array_reverse(array_values($obj['obs'])) : [$obj];
            foreach ($inner as $one) {
                if (is_array($one)) {
                    $rows[] = $one;
                    if (count($rows) >= $maxRows) {
                        return $rows;
                    }
                }
            }
        }

        return $rows;
    }

    /** @return array<string,mixed> */
    private function aggregate(array $rows, int $window): array
    {
        $cutoff = microtime(true) - $window;
        $reqs = [];
        $hits = [];
        $bytes = 0;
        $saved = 0;
        $failures = 0;
        $ttfb = [];
        $scene = [];

        foreach ($rows as $r) {
            $at = (float) ($r['logged_at'] ?? $r['observed_at'] ?? 0.0);
            if ($at < $cutoff) {
                continue;
            }
            $rid = (string) ($r['req'] ?? '');
            if ($rid !== '') {
                $reqs[$rid] = true;
                $tag = (string) ($r['cache'] ?? '');
                if ($tag !== '' && $tag !== 'miss' && $tag !== 'error') {
                    $hits[$rid] = true;
                    $saved += max(0, (int) ($r['bytes'] ?? 0));
                }
            }
            $kind = (string) ($r['kind'] ?? '');
            if ($kind !== '' && $kind !== 'none') {
                $failures++;
            }
            $bytes += max(0, (int) ($r['bytes'] ?? 0));
            $t = (float) ($r['ttfb_ms'] ?? 0.0);
            if ($t > 0.0) {
                $ttfb[] = $t;
            }
            $sc = (string) ($r['scene'] ?? '');
            if ($sc !== '') {
                $scene[$sc] = ($scene[$sc] ?? 0) + 1;
            }
        }

        $wm = $this->safeWatermark();

        return [
            'requests' => count($reqs),
            'hits' => count($hits),
            'bytes' => $bytes,
            'saved' => $saved,
            'failures' => $failures,
            'ttfb' => $ttfb,
            'scenes' => $scene,
            'used' => (int) $wm['used'],
            'max' => (int) $wm['max'],
            'ratio' => round((float) $wm['ratio'], 5),
            'disk_free' => (int) $wm['disk_free'],
        ];
    }

    /** 时间序列: 按窗口分桶的请求数/命中数/失败数, 图表只吃这个。 */
    private function seriesOf(array $rows, int $window): array
    {
        $now = microtime(true);
        $buckets = 30;
        $width = max(1.0, $window / $buckets);
        $req = array_fill(0, $buckets, 0);
        $hit = array_fill(0, $buckets, 0);
        $fail = array_fill(0, $buckets, 0);
        $lat = array_fill(0, $buckets, []);
        $seenReq = [];

        foreach ($rows as $r) {
            $at = (float) ($r['logged_at'] ?? $r['observed_at'] ?? 0.0);
            $age = $now - $at;
            if ($age < 0 || $age > $window) {
                continue;
            }
            $idx = $buckets - 1 - (int) min($buckets - 1, floor($age / $width));
            $rid = (string) ($r['req'] ?? '');
            if ($rid !== '' && !isset($seenReq[$rid])) {
                $seenReq[$rid] = true;
                $req[$idx]++;
            }
            $tag = (string) ($r['cache'] ?? '');
            if ($tag !== '' && $tag !== 'miss' && $tag !== 'error') {
                $hit[$idx]++;
            }
            $kind = (string) ($r['kind'] ?? '');
            if ($kind !== '' && $kind !== 'none') {
                $fail[$idx]++;
            }
            $t = (float) ($r['ttfb_ms'] ?? 0.0);
            if ($t > 0.0) {
                $lat[$idx][] = $t;
            }
        }

        $p95 = [];
        foreach ($lat as $i => $vals) {
            $p95[$i] = $vals === [] ? null : round(Compactor::percentile($vals, 0.95), 1);
        }

        return [
            'bucket_s' => round($width, 2),
            'points' => $buckets,
            'requests' => $req,
            'hits' => $hit,
            'failures' => $fail,
            'p95_ttfb' => $p95,
            'saved_bytes' => $hit,
        ];
    }

    /** 有界扫描缓存目录: 分场景条目数/字节 + .part 与隔离区计数。 */
    private function sceneScan(string $cacheDir): array
    {
        $maxMeta = max(50, $this->cfg->int('panel.cache_scan_max_meta', 400));
        $deadline = microtime(true) + 0.25;
        $scenes = [];
        $scanned = 0;
        $truncated = false;

        $d1 = @scandir($cacheDir) ?: [];
        foreach ($d1 as $a) {
            if (!is_string($a) || !preg_match('#\A[0-9a-f]{2}\z#', $a)) {
                continue;
            }
            $dirA = $cacheDir . '/' . $a;
            foreach ((array) @scandir($dirA) ?: [] as $b) {
                if (!is_string($b) || !preg_match('#\A[0-9a-f]{3}\z#', $b)) {
                    continue;
                }
                $leaf = $dirA . '/' . $b;
                foreach ((array) @scandir($leaf) ?: [] as $f) {
                    if (!is_string($f) || !str_ends_with($f, '.meta.json')) {
                        continue;
                    }
                    if ($scanned >= $maxMeta || microtime(true) > $deadline) {
                        $truncated = true;
                        break 3;
                    }
                    $head = $this->readJson($leaf . '/' . $f);
                    $scanned++;
                    $sc = (string) ($head['scene'] ?? 'unknown');
                    $row = $scenes[$sc] ?? ['scene' => $sc, 'entries' => 0, 'bytes' => 0, 'fresh' => 0];
                    $row['entries']++;
                    $row['bytes'] += max(0, (int) ($head['bytes'] ?? 0));
                    if ((float) ($head['fresh_until'] ?? 0.0) > microtime(true)) {
                        $row['fresh']++;
                    }
                    $scenes[$sc] = $row;
                }
            }
        }

        return [
            'scenes' => array_values($scenes),
            'partial_files' => $this->countFiles($cacheDir . '/_partial', '.part'),
            'quarantine_files' => $this->countFiles($cacheDir . '/_quarantine', ''),
            'scanned' => $scanned,
            'truncated' => $truncated,
        ];
    }

    private function countFiles(string $dir, string $suffix): int
    {
        if (!is_dir($dir)) {
            return 0;
        }
        $n = 0;
        foreach ((array) @scandir($dir) ?: [] as $f) {
            if (is_string($f) && $f !== '.' && $f !== '..' && is_file($dir . '/' . $f)
                && ($suffix === '' || str_ends_with($f, $suffix))) {
                $n++;
            }
        }

        return $n;
    }

    /** prefix 档清理: Store 没有按前缀删的公开入口, 只能自己找出键再逐个走 purge('ref')。 */
    private function purgePrefix(\GhAccel\Cache\Store $store, string $prefix): int
    {
        $p = strtolower(trim($prefix));
        if (preg_match('#\A[0-9a-f]{4,64}\z#', $p) !== 1) {
            throw GhpError::make('invalid_argument', 'prefix 需为 4-64 位十六进制缓存键前缀');
        }
        $dir = $store->cacheDir();
        $keys = [];
        foreach ((array) @scandir($dir . '/' . substr($p, 0, 2)) ?: [] as $b) {
            if (!is_string($b) || !preg_match('#\A[0-9a-f]{3}\z#', $b)) {
                continue;
            }
            foreach ((array) @scandir($dir . '/' . substr($p, 0, 2) . '/' . $b) ?: [] as $f) {
                if (!is_string($f)) {
                    continue;
                }
                $base = basename($f);
                foreach (['.bin', '.meta.json', '.entry'] as $suf) {
                    if (str_ends_with($base, $suf)) {
                        $k = substr($base, 0, -strlen($suf));
                        if (preg_match('#\A[0-9a-f]{64}\z#', $k) === 1 && str_starts_with($k, $p)) {
                            $keys[$k] = true;
                        }
                        break;
                    }
                }
            }
        }
        $n = 0;
        foreach (array_keys($keys) as $k) {
            // 上限防呆: 一个短前缀能匹到成千上万条, 一次点击不该把库扫穿。
            if ($n >= 500) {
                break;
            }
            $store->purge('ref', (string) $k);
            $n++;
        }

        return $n;
    }

    // ------------------------------------------------------------------
    // 小工具
    // ------------------------------------------------------------------

    private function statsMap(): array
    {
        return $this->disp->snapshot()->statsMap();
    }

    private function snapshotRaw(): array
    {
        return $this->disp->snapshot()->raw();
    }

    private function snapshotVersion(): string
    {
        return $this->disp->snapshot()->version();
    }

    private function pendingProbes(): array
    {
        $d = $this->readJson($this->probeFile());

        return (array) ($d['pending'] ?? []);
    }

    private function probeFile(): string
    {
        return $this->root . '/var/state/probes.json';
    }

    /**
     * 概览里的磁盘数字来自 .usage.json, 不现场扫目录。
     *
     * 概览是 5 秒一轮的, 而 Store::watermark() 在新实例上必然触发一次全目录扫描 ——
     * 缓存里堆几万个条目时, 面板自己就成了磁盘 IO 的最大消费者, 反过来把数据面拖慢。
     * usage 文件由每次落地/淘汰/压实维护, 口径与实时扫描一致, 只是可能旧几秒。
     */
    private function usageSnapshot(): array
    {
        $u = $this->readJson($this->disp->store()->cacheDir() . '/.usage.json');
        $max = max(1, $this->cfg->int('cache.max_bytes', 10737418240));
        $used = isset($u['used']) ? (int) $u['used'] : -1;

        return [
            'used' => max(0, $used),
            'used_known' => $used >= 0,
            'max' => (int) ($u['max'] ?? $max),
            'ratio' => isset($u['ratio']) ? (float) $u['ratio'] : ($used > 0 ? min(1.0, $used / $max) : 0.0),
            'disk_free' => (int) ($u['disk_free'] ?? -1),
            'entries' => (int) ($u['entries'] ?? 0),
            'written_at' => round((float) ($u['written_at'] ?? $u['at'] ?? 0.0), 3),
        ];
    }

    private function safeWatermark(): array
    {
        try {
            return $this->usageSnapshot();
        } catch (\Throwable) {
            return ['used' => 0, 'max' => 0, 'ratio' => 0.0, 'disk_free' => -1];
        }
    }

    private function readJson(string $file): array
    {
        if (!is_readable($file)) {
            return [];
        }
        $d = json_decode((string) @file_get_contents($file), true);

        return is_array($d) ? $d : [];
    }

    private function intQuery(string $k, int $default): int
    {
        $v = Http::queryStr($k);

        return $v === '' || !is_numeric($v) ? $default : (int) $v;
    }

    private function actor(): string
    {
        $s = $this->auth->session();

        return $s === null ? 'anon' : Audit::actorFromSelector((string) $s['selector']);
    }

    /** 审计不落 body 明文(Audit 自己只取 sha256), 这里只多剥一层明显不该进摘要的字段。 */
    private function auditBody(array $body): array
    {
        unset($body['raw_token'], $body['token'], $body['_csrf']);

        return $body;
    }

    private function body(): array
    {
        $cap = Http::capture($this->cfg);
        $raw = (string) ($cap['raw_post'] ?? '');
        if ($raw !== '' && (str_starts_with(trim($raw), '{') || str_starts_with(trim($raw), '['))) {
            $d = json_decode($raw, true);
            if (!is_array($d)) {
                throw GhpError::make('invalid_argument', '请求体不是合法 JSON');
            }

            return $d;
        }
        if ($raw !== '') {
            // 表单编码的 body: $_POST 已由 PHP 填好, 但 confirm 得从 "true" 转成布尔。
            $d = $_POST;
            if (isset($d['confirm']) && is_string($d['confirm'])) {
                $d['confirm'] = in_array(strtolower($d['confirm']), ['1', 'true', 'yes', 'on'], true);
            }

            return is_array($d) ? $d : [];
        }

        return $_POST === [] ? [] : (array) $_POST;
    }

    /**
     * 源字段白名单。
     *
     * 只认 SourceRepo 认识的那几个键, 而且 base_url/scenes/hosts/trust/mode 在这里先做
     * 一次形态校验: 让 upsert 去猜会抛 InvalidArgumentException, 但那句话里带着用户自己的
     * 输入, 面板拿到就是一段攻击者可控文案。
     */
    private function normalizeMirrorBody(array $body, bool $isNew): array
    {
        $def = [];
        $id = strtolower(trim((string) ($body['id'] ?? '')));
        if ($id !== '') {
            if (preg_match('#\A[a-z0-9][a-z0-9._-]{1,62}\z#', $id) !== 1) {
                throw GhpError::make('invalid_argument', '源 id 需为 2-63 位 slug');
            }
            $def['id'] = $id;
        } elseif ($isNew) {
            throw GhpError::make('invalid_argument', '缺少 id');
        }

        if (isset($body['base_url'])) {
            $u = rtrim(trim((string) $body['base_url']), '/');
            if (preg_match('#\Ahttps://[a-z0-9.\-]{1,253}(:\d{2,5})?\z#i', $u) !== 1) {
                throw GhpError::make('invalid_argument', 'base_url 必须是 https://host[:端口] 且不含路径');
            }
            $def['base_url'] = $u;
        } elseif ($isNew) {
            throw GhpError::make('invalid_argument', '缺少 base_url');
        }

        if (isset($body['mode'])) {
            $m = strtolower(trim((string) $body['mode']));
            if (SourceMode::tryFrom($m) === null) {
                $names = implode('/', array_map(static fn (SourceMode $x): string => $x->value, SourceMode::cases()));
                throw GhpError::make('invalid_argument', 'mode 需为 ' . $names);
            }
            $def['mode'] = $m;
        } elseif ($isNew) {
            throw GhpError::make('invalid_argument', '缺少 mode');
        }

        foreach (['url_template', 'region', 'owner_note'] as $k) {
            if (isset($body[$k])) {
                $def[$k] = $this->scrub((string) $body[$k], $k === 'owner_note' ? 200 : 500);
            }
        }
        if (isset($body['trust'])) {
            $t = strtolower(trim((string) $body['trust']));
            if (Trust::tryFrom($t) === null) {
                throw GhpError::make('invalid_argument', 'trust 取值非法');
            }
            $def['trust'] = $t;
        }
        if (isset($body['enabled'])) {
            $def['enabled'] = (bool) $body['enabled'];
        }
        if (array_key_exists('priority', $body)) {
            $p = (int) $body['priority'];
            if ($p < 1 || $p > 100) {
                throw GhpError::make('invalid_argument', 'priority 需 1-100');
            }
            $def['priority'] = $p;
        }
        if (isset($body['scenes'])) {
            $scenes = [];
            foreach ((array) $body['scenes'] as $s) {
                $s = strtolower(trim((string) $s));
                if (Scene::tryFrom($s) === null) {
                    throw GhpError::make('invalid_argument', '未知场景 ' . $this->scrub($s, 30));
                }
                $scenes[$s] = true;
            }
            if ($scenes === [] && $isNew) {
                throw GhpError::make('invalid_argument', 'scenes 不能为空');
            }
            $def['scenes'] = array_keys($scenes);
        }
        if (isset($body['hosts'])) {
            $hosts = [];
            foreach ((array) $body['hosts'] as $h) {
                $h = strtolower(trim((string) $h));
                if (preg_match('#\A[a-z0-9.\-]{1,253}\z#', $h) !== 1) {
                    throw GhpError::make('invalid_argument', '非法 host: ' . $this->scrub($h, 60));
                }
                $hosts[$h] = true;
            }
            if ($hosts === [] && $isNew) {
                throw GhpError::make('invalid_argument', 'hosts 不能为空');
            }
            $def['hosts'] = array_keys($hosts);
        } elseif ($isNew) {
            // 新建时**根本不填 hosts** 也必须当场拒绝: 一个不覆盖任何上游域名的源永远不可能
            // 被 L0 选中, 留着它只是在源池里挂一个"已启用但永远不会被用"的假条目。
            // 漏掉这一支的话错误会一路掉进 SourceRepo::upsert 抛 InvalidArgumentException,
            // 再被兜底成 500 内部错误 —— 表单问题伪装成服务故障, 是最难排查的一类。
            throw GhpError::make('invalid_argument', '缺少 hosts: 新源至少要声明它覆盖哪些上游域名');
        }
        if (isset($body['blocked_ext'])) {
            $ext = [];
            foreach ((array) $body['blocked_ext'] as $e) {
                $e = strtolower(ltrim(trim((string) $e), '.'));
                if (preg_match('#\A[a-z0-9]{1,12}\z#', $e) === 1) {
                    $ext[$e] = true;
                }
            }
            $def['blocked_ext'] = array_keys($ext);
        }
        foreach (['connect_timeout_ms', 'ttfb_budget_ms', 'stall_timeout_ms', 'max_size_bytes',
                     'min_interval_ms', 'max_concurrent', 'hourly_bytes_soft_cap'] as $k) {
            if (array_key_exists($k, $body)) {
                $def[$k] = max(0, (int) $body[$k]);
            }
        }
        // 能力位不接受面板手填: 配置里写 true 也只是"声称", 而手填 true 的实际后果是让
        // 选路误以为源支持 Range/内部跳随, 用户拿到坏文件。只由探测与实测改写。
        if (isset($body['caps']) && is_array($body['caps'])) {
            $caps = [];
            foreach (self::CAPS as $c) {
                if (array_key_exists($c, $body['caps'])) {
                    $caps[$c] = (bool) $body['caps'][$c];
                }
            }
            if ($caps !== []) {
                $def['caps'] = $caps;
            }
        }

        return $def;
    }

    /** 顶层可改段。与 Config::filterOverlay 同一份名单: 优先反射取, 拿不到退回本地表。 */
    private function configOverlayKeys(): array
    {
        static $cached = null;
        if (is_array($cached)) {
            return $cached;
        }
        try {
            $m = new \ReflectionMethod(Config::class, 'filterOverlay');
            $src = (string) $m->getFileName();
            if ($src !== '' && is_readable($src)) {
                $code = (string) file_get_contents($src);
                if (preg_match('#\$allow\s*=\s*\[([^\]]*)\]#', $code, $mm) === 1) {
                    $list = array_values(array_filter(array_map(
                        static fn (string $x): string => trim($x, " \t\n\r\0\x0B'\""),
                        explode(',', $mm[1])
                    ), static fn (string $x): bool => $x !== ''));
                    if ($list !== []) {
                        return $cached = $list;
                    }
                }
            }
        } catch (\Throwable) {
            // 反射失败(例如配置类被改写成 trait)就用本地表, 面板不能因为取白名单失败而挂掉。
        }

        return $cached = self::CONFIG_SECTIONS;
    }

    private function containsSecret(array $v): bool
    {
        foreach ($v as $k => $sub) {
            $low = strtolower((string) $k);
            foreach (['secret', 'token', 'password', 'salt', 'key'] as $needle) {
                if (str_contains($low, $needle)) {
                    return true;
                }
            }
            if (is_array($sub) && $this->containsSecret($sub)) {
                return true;
            }
        }

        return false;
    }

    /** 递归脱敏: 配置里凡命中密钥类键名的值一律换成 ***(长度), 面板只该看见"有没有配"。 */
    private function redact(array $data): array
    {
        $out = [];
        foreach ($data as $k => $v) {
            $low = strtolower((string) $k);
            $secret = false;
            foreach (['secret', 'token', 'password', 'salt'] as $needle) {
                if (str_contains($low, $needle)) {
                    $secret = true;
                    break;
                }
            }
            if ($secret) {
                $out[$k] = is_scalar($v) ? '***(' . strlen((string) $v) . ')' : '***';
                continue;
            }
            $out[$k] = is_array($v) ? $this->redact($v) : (is_scalar($v) ? $v : gettype($v));
        }

        return $out;
    }

    private function peerSessions(string $mySid): array
    {
        $dir = $this->root . '/var/sessions';
        if (!is_dir($dir)) {
            return [];
        }
        $out = [];
        foreach ((array) @scandir($dir) ?: [] as $f) {
            if (!is_string($f) || !str_starts_with($f, 'sess_') || !str_ends_with($f, '.json')) {
                continue;
            }
            $d = $this->readJson($dir . '/' . $f);
            if ($d === []) {
                continue;
            }
            $out[] = [
                'self' => hash_equals((string) ($d['sid'] ?? ''), $mySid),
                'label' => $this->scrub((string) ($d['label'] ?? ''), 64),
                'ip_prefix' => $this->scrub((string) ($d['ip_prefix'] ?? ''), 60),
                'ua_digest' => substr((string) ($d['ua_hash'] ?? ''), 0, 8),
                'ip_hash' => substr((string) ($d['ip_hash'] ?? ''), 0, 16),
                'created_at' => (int) ($d['created_at'] ?? 0),
                'last_seen_at' => (int) ($d['last_seen_at'] ?? 0),
                'scopes' => array_map(fn ($x): string => $this->scrub((string) $x, 20), (array) ($d['scopes'] ?? [])),
            ];
        }
        usort($out, static fn (array $a, array $b): int => $b['last_seen_at'] <=> $a['last_seen_at']);

        return $out;
    }

    /** UA 摘要: 前 24 字符可见 + 长度 + 全串哈希前 8 位, 足够认出自己的浏览器又不够伪造。 */
    private function uaSummary(string $ua): string
    {
        if ($ua === '') {
            return '(空)';
        }

        return $this->scrub($ua, 24) . '… len=' . strlen($ua) . ' #' . substr(hash('sha256', $ua), 0, 8);
    }

    /**
     * IDN host 双列显示。
     *
     * 同形字域名(西里尔 а 冒充拉丁 a)在纯文本里看不出来, 而面板是管理员唯一会逐条
     * 读源域名的地方。punycode 列把欺骗变成可见的差异, 原文列保留可读性。
     *
     * @return array{display:string,punycode:string,idn:bool}
     */
    private function hostPair(string $host): array
    {
        $host = $this->scrub($host, 120);
        $puny = $host;
        if ($host !== '' && function_exists('idn_to_ascii') && defined('INTL_IDNA_VARIANT_UTS46')) {
            $r = @idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if (is_string($r) && $r !== '') {
                $puny = $r;
            }
        }

        return [
            'display' => $host,
            'punycode' => $puny,
            'idn' => $puny !== $host,
        ];
    }

    private function modeLabel(SourceMode $m): string
    {
        return match ($m) {
            SourceMode::PrefixFull => '前缀 + 完整原始 URL',
            SourceMode::PrefixPath => '前缀 + 去协议路径',
            SourceMode::HostReplace => '域名替换',
            SourceMode::Template => '自定义模板',
        };
    }

    private function factorLabel(string $k): string
    {
        return match ($k) {
            'p' => '成功率(Wilson 下界)',
            'c' => '预测耗时',
            'w' => '人工先验',
            'b' => '礼貌/负载',
            'u' => 'UCB 探索余量',
            default => $k,
        };
    }

    private function rejectLabel(string $code): string
    {
        foreach (\GhAccel\Enum\RejectCode::cases() as $c) {
            if ($c->value === $code) {
                return $c->detail();
            }
        }

        return $this->scrub($code, 60);
    }

    private function boolMap(mixed $v): array
    {
        $out = [];
        foreach ((array) $v as $k => $b) {
            $out[(string) $k] = (bool) $b;
        }

        return $out;
    }

    private function intMap(mixed $v): array
    {
        $out = [];
        foreach ((array) $v as $k => $n) {
            if (is_numeric($n)) {
                $out[(string) $k] = (int) $n;
            }
        }

        return $out;
    }

    /** 自检表里的 value 可能是 bool/int/数组, JSON 里要能原样显示, 但字符串要走脱敏。 */
    private function stringifyMap(array $m): array
    {
        $out = [];
        foreach ($m as $k => $v) {
            $k = (string) $k;
            if (is_bool($v) || is_int($v) || is_float($v)) {
                $out[$k] = $v;
            } elseif (is_array($v)) {
                $out[$k] = $this->stringifyMap($v);
            } else {
                $out[$k] = $this->scrub((string) $v, 240);
            }
        }

        return $out;
    }

    /**
     * 统一脱敏。
     *
     * 顺序: 剥控制字符 -> 抹绝对路径 -> 截断。截断放最后是因为"先截再抹"会把
     * 半个路径留在结果里, 而那正好是最像真路径的一段。
     */
    private function scrub(?string $s, int $max = 120): string
    {
        $s = (string) $s;
        if ($s === '') {
            return '';
        }
        $s = preg_replace('/[\x00-\x1F\x7F]/u', ' ', $s) ?? '';
        $s = preg_replace('#[A-Za-z]:[\\\\/][^\s\'",;)\]}]*#', '[path]', $s) ?? $s;
        $s = preg_replace('#(?:^|[\s\'",;(\\[])/(?:var|usr|etc|home|root|tmp|opt|proc|mnt|srv|data)/[^\s\'",;)\]}]*#', ' [path]', $s) ?? $s;
        $s = preg_replace('/\s{2,}/u', ' ', $s) ?? $s;
        $s = trim($s);
        if (mb_strlen($s) > $max) {
            $s = mb_substr($s, 0, $max) . '…';
        }

        return $s;
    }

    private function operationalWarnings(): array
    {
        $w = [];
        if (trim((string) $this->cfg->str('app.base_origin')) === '') {
            $w[] = 'app.base_origin 未配置: 浏览器带 Origin 的写请求会被 CSRF 同源校验拒绝(命令行不带 Origin 不受影响)。在配置文件中写死站点 origin 是 CSRF 链成立的前提。';
        }
        if (!$this->cfg->bool('panel.public_exposed', false)) {
            $w[] = 'panel.public_exposed=false: 面板只对回环/limits.trusted_cidrs 内的来源可达。公网部署需同时改这一项与前缀。';
        }
        if ($this->snapshotVersion() === '') {
            $w[] = '尚无状态快照: 所有源都按冷启动处理。跑一次 bin/compact.php --once 或等一次真实请求。';
        }
        $free = @disk_free_space($this->root . '/var');
        if (is_int($free) || is_float($free)) {
            if ((int) $free < max(0, $this->cfg->int('cache.min_free_bytes', 0))) {
                $w[] = 'var 所在磁盘余量已低于 cache.min_free_bytes: 缓存停写, 只服务命中。';
            }
        }

        return $w;
    }

    // ------------------------------------------------------------------
    // 输出
    // ------------------------------------------------------------------

    private function ok(array $data): array
    {
        return ['data' => $data];
    }

    private function envelope(array $data, string $rid): array
    {
        return [
            'ok' => true,
            'data' => $data['data'] ?? $data,
            'meta' => [
                'generated_at' => round(microtime(true), 3),
                'snapshot_version' => $this->snapshotVersion(),
                'request_id' => $rid,
                'panel_prefix' => $this->base,
                'poll_ms' => $this->cfg->arr('panel.poll_ms', []),
            ],
        ];
    }

    private function errorEnvelope(GhpError $e, string $rid): array
    {
        $code = $e->errorCode;
        // GhpError 的 message 是 "code: detail" 拼出来的, 面板信封里 code 已经单独有字段,
        // 再让 detail 带一遍前缀只会把内部码名暴露成界面文案。
        $raw = $e->getMessage();
        $prefix = $code . ': ';
        if (str_starts_with($raw, $prefix)) {
            $raw = substr($raw, strlen($prefix));
        }
        $msg = $this->scrub($raw, 200);
        if ($code === GhpError::UNAUTHENTICATED) {
            $code = GhpError::NOT_FOUND;
            $msg = '不存在';
        }

        return [
            'ok' => false,
            'error' => [
                'code' => $code,
                'message' => $msg === '' ? $e->title() : $msg,
                'request_id' => $rid,
            ],
            'meta' => ['generated_at' => round(microtime(true), 3), 'snapshot_version' => $this->snapshotVersion()],
        ];
    }

    private function mapStatus(GhpError $e): int
    {
        if ($e->errorCode === GhpError::UNAUTHENTICATED) {
            return 404;
        }
        if ($e->errorCode === 'invalid_argument') {
            return 422;
        }
        if (!GhpError::exists($e->errorCode)) {
            return 500;
        }

        return $e->status();
    }

    private function send(array $payload, int $status): void
    {
        Http::json($payload, $status, ['Cache-Control' => 'no-store']);
    }

    private function sendProblem(GhpError $e, string $rid): void
    {
        $problem = $e->toProblem($rid);
        Http::problem($problem, [
            'Retry-After' => $e->retryAfter() ?? 5,
            'X-RateLimit-Limit' => (string) round((float) ($e->context['limit'] ?? 0)),
            'X-RateLimit-Remaining' => '0',
        ]);
    }

    private function apiHeaders(): void
    {
        Http::header('Cache-Control', 'no-store');
        Http::header('X-Content-Type-Options', 'nosniff');
        Http::header('X-Frame-Options', 'DENY');
        Http::header('Referrer-Policy', 'no-referrer');
        Http::header('Cross-Origin-Resource-Policy', 'same-origin');
        Http::header('Content-Security-Policy', "default-src 'none'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'");
    }

    private function throttle(): void
    {
        if (!$this->cfg->bool('panel.enabled', true)) {
            throw GhpError::make(GhpError::NOT_FOUND, '面板未启用');
        }
        // 先认证再限流的反面选择: 未登录的洪水也得先把 panel 桶打掉, 所以限流在认证之前。
        $rl = new RateLimiter($this->cfg, $this->root);
        $r = $rl->consume('panel', Http::clientIp() !== '' ? Http::clientIp() : 'unknown', 1.0);
        if (!$r['allowed']) {
            throw GhpError::make(GhpError::RATE_LIMITED, '面板轮询超限', [
                'retry_after' => $r['retry_after'],
                'scope' => 'panel',
                'limit' => $r['limit'],
            ]);
        }
    }

    /** 动作模板表: 前端按 "方法:模板路径" 查 CSRF Token。 */
    public function csrfActionList(): array
    {
        return [
            'POST:' . $this->base . self::TEMPLATES['mirrors'],
            'PUT:' . $this->base . self::TEMPLATES['mirror'],
            'DELETE:' . $this->base . self::TEMPLATES['mirror'],
            'POST:' . $this->base . self::TEMPLATES['mirror_action'],
            'POST:' . $this->base . self::TEMPLATES['cache_purge'],
            'PUT:' . $this->base . self::TEMPLATES['config'],
            'POST:' . $this->base . self::TEMPLATES['tokens'],
            'DELETE:' . $this->base . self::TEMPLATES['token'],
        ];
    }

    /**
     * 具体请求路径 -> CSRF 绑定的模板路径。
     *
     * 把 id / prefix 换成占位符是**有意的**: 前端拿到的 Token 只在该动作形态下有效,
     * 换接口或换方法都对不上; 而如果把每个具体 id 也绑进去, boot JSON 要为每一行源
     * 预生成几个 Token —— 一堆条目却换不来任何额外安全性。
     */
    public static function csrfPathFor(string $fullPath): string
    {
        // CSRF Token 绑的是"面板前缀 + 动作模板"(见 csrfActionList 用 $this->base 拼键),
        // 而打进来的是完整请求路径, 中间多一段 /api。不归一就会三方各算各的:
        // boot 里是 /panel/mirrors、浏览器查 /api/mirrors、服务端验 /panel/api/mirrors,
        // 结果是面板的每一个写请求都 403 —— fail-closed, 但面板等于没有写操作。
        $normalized = (string) preg_replace('#\A(/[a-z0-9._-]+)/api(?=/|\z)#i', '$1', $fullPath, 1);

        $p = (string) preg_replace('#/mirrors/([a-z0-9._@:-]{1,80})/action\z#i', self::TEMPLATES['mirror_action'], $normalized);
        $p = (string) preg_replace('#/mirrors/[a-z0-9._@:-]{1,80}\z#i', self::TEMPLATES['mirror'], $p);
        $p = (string) preg_replace('#/tokens/[a-z0-9._:@-]{1,80}\z#i', self::TEMPLATES['token'], $p);

        return $p === '' ? $fullPath : $p;
    }
}
