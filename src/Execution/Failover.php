<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 按 ranked 顺序执行候选并决定"还能不能换下一个源"。时间预算与三条
 *             必须立刻中止链路的规则都集中在这一处, 免得散落到调用方各写一遍。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Execution;

use GhAccel\Config;
use GhAccel\Enum\FailureKind;
use GhAccel\Http;
use GhAccel\Routing\Candidate;
use GhAccel\Transport\UpstreamResult;

/**
 * 中止链路的两条规则各对应一类真实事故, 都不允许"顺手加个重试":
 *
 *  1. `mustStopFailover()`: 429 / integrity / guard / oversize。把限速信号当成"换个源
 *     接着刷"的结局是很快全源同时被封 —— 而 GitHub 对 api.github.com 的管理规则拦截
 *     (实测 403 Request forbidden by administrative rule) 属于同一族信号, 镜像也不代理 API,
 *     换源连"也许能成"的可能性都没有, 只是在消耗对面的封禁额度。
 *  2. 404/410: 换源不会让不存在的文件存在, 纯粹浪费配额, 还会把一个坏链接的失败记满全池。
 *  3. 已经 committed(有字节发给客户端)必须停: 响应头与已发字节都固化了, 再换源就是
 *     在一个 206 后面追加另一个源的内容, 产物必然损坏。这条优先于以上两条。
 */
final class Failover
{
    public function __construct(private readonly Config $cfg)
    {
    }

    /**
     * @param list<Candidate> $ranked
     * @param callable(Candidate, float, int): UpstreamResult $attempt  执行一个候选, 交回结果
     * @param callable(Candidate, UpstreamResult, float): void|null $onOutcome 逐候选回写统计与观测
     * @param array<string,mixed> $ctx
     * @return array{result:UpstreamResult|null,candidate:Candidate|null,attempts:list<array>,stop:string,elapsed_ms:float}
     */
    public function run(array $ranked, array $ctx, callable $attempt, ?callable $onOutcome = null): array
    {
        $t0 = microtime(true);
        $total = $this->totalBudgetMs($ctx);
        $reserve = max(0, $this->cfg->int('budgets.failover_min_reserve_ms', 250));
        $n = count($ranked);

        $out = ['result' => null, 'candidate' => null, 'attempts' => [], 'stop' => '', 'elapsed_ms' => 0.0];

        foreach ($ranked as $index => $cand) {
            $left = $n - $index;                       // 含当前这一个
            $remaining = $total - ((microtime(true) - $t0) * 1000.0);
            $budget = self::budgetFor($cand->predictedMs, $remaining, $left, $reserve);
            if ($budget <= 0.0) {
                // 预算不够再跑一个"至少能判出连不上"的候选: 把剩下的重试机会交还给客户端,
                // 比让它在第 3 个源上吊死 12 秒体验好, 也不会把 fpm worker 全占住。
                $out['stop'] = 'budget_exhausted';
                break;
            }

            try {
                $res = $attempt($cand, $budget, $index);
            } catch (\Throwable $e) {
                // 意外异常也要变成一次可记账的失败, 否则整条链的观测会整段消失,
                // 而观测是选路唯一的实测来源。已发头时按 committed 处理(不允许再换源)。
                $res = new UpstreamResult(
                    FailureKind::Connect,
                    0,
                    [],
                    0,
                    0.0,
                    0.0,
                    '',
                    '',
                    0,
                    0,
                    substr($e->getMessage(), 0, 200),
                    Http::headersSent()
                );
            }

            $out['result'] = $res;
            $out['candidate'] = $cand;
            $out['attempts'][] = [
                'source'  => $cand->id(),
                'status'  => $res->status,
                'failure' => $res->failure->value,
                'bytes'   => $res->bytesReceived,
                'ttfb_ms' => round($res->ttfbMs, 1),
                'hops'    => $res->redirectHops,
                'committed' => $res->committed,
            ];

            if ($onOutcome !== null) {
                $onOutcome($cand, $res, $budget);
            }

            if ($res->committed) {
                $out['stop'] = 'committed';
                break;
            }
            if ($res->ok()) {
                $out['stop'] = 'ok';
                break;
            }
            if ($res->failure->mustStopFailover()) {
                $out['stop'] = 'stop_' . $res->failure->value;
                break;
            }
            if ($res->status === 404 || $res->status === 410) {
                $out['stop'] = 'not_found';
                break;
            }
            if ($index === $n - 1) {
                $out['stop'] = 'exhausted';
            }
        }

        $out['elapsed_ms'] = (microtime(true) - $t0) * 1000.0;
        if ($out['stop'] === '') {
            $out['stop'] = $out['result'] === null ? 'no_candidates' : 'exhausted';
        }

        return $out;
    }

    /**
     * 单个候选的时间预算: clamp(predicted*1.8 + 400, 700, 剩余预算 - 为后续候选留的份)。
     *
     * 1.8 倍余量是因为 EWMA 是均值而用户等的是长尾; +400ms 是给 TLS 握手这类固定成本。
     * 下限 700ms 保证"至少能判出连不上"(connect_timeout 默认 1500ms 时由 curl 自己先断)。
     * 给后续候选留 reserve 的意义: 否则第 1 个源能把整条链的预算吃光, 后面几个源一次都没试过。
     *
     * @return float 毫秒; <=0 表示不值得再试这个候选
     */
    public static function budgetFor(float $predictedMs, float $remainingMs, int $left, int $reserveMs): float
    {
        $floor = 700.0;
        $room = $remainingMs - $reserveMs * max(0, $left - 1);
        if ($room < $floor) {
            return 0.0;
        }
        $want = max($floor, $predictedMs * 1.8 + 400.0);

        return min($want, $room);
    }

    /** 全链预算: min(配置上限, 入口给的剩余期限)。ctx['deadline_ms'] 是"还能用多少毫秒"。 */
    public function totalBudgetMs(array $ctx): float
    {
        $cap = max(1000.0, $this->cfg->float('budgets.max_total_ms', 12000.0));
        $deadline = isset($ctx['deadline_ms']) ? (float) $ctx['deadline_ms'] : 0.0;
        if ($deadline > 0.0) {
            return min($cap, $deadline);
        }

        return $cap;
    }
}
