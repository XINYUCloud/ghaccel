<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 两阶段(resolve -> stream)上游取字节。curl 零拷贝直出、逐跳手工复校、
 *             Range 与状态码镜像、假 200 嗅探门、字节上限、客户端断连检测、缓存旁路写入。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Transport;

use GhAccel\Cache\Key;
use GhAccel\Cache\PartialWriter;
use GhAccel\Cache\Policy;
use GhAccel\Cache\Store;
use GhAccel\Config;
use GhAccel\Enum\FailureKind;
use GhAccel\Enum\Scene;
use GhAccel\Errors\GhpError;
use GhAccel\Http;
use GhAccel\Ref\GitHubRef;
use GhAccel\Security\GuardResult;
use GhAccel\Security\IpRange;
use GhAccel\Security\UrlGuard;
use GhAccel\Source\Source;

/**
 * 为什么是"两阶段": Release 资产与绝对形态归档的真实地址是带一次性签名的
 * objects.githubusercontent.com, 必须先跟一跳才知道最终地址与它到底支持不支持 Range;
 * 而**响应头一旦发出就固化**, 到时候再发现"其实是 200 全量/内容是 HTML 错误页"就无路可退。
 * 所以先用一次 `Range: bytes=0-0` 的 GET 把地址与能力位测出来(1 字节 body 直接丢弃,
 * 且不向客户端输出任何字节), 再把要发的头算好, 最后才开闸流式。
 *
 * 为什么用 GET 而不是 HEAD: objects 的 SAS 签名把 HTTP 方法编进了签名串, HEAD 预检会
 * 直接 403 —— 用 HEAD 省下的那 1 字节会换来整条 Release 链路不可用。
 *
 * 为什么头必须在"第一个字节之前"发完: 这是任何回退可能性的唯一分界线。本实现用一道
 * "嗅探门"保证这件事 —— 前 512 字节先留在一个定长缓冲里, 判完假 200 才发头+发体。
 *
 * 实例字段只服务"当前这一次 transfer": 一个请求一个 Streamer、候选串行执行、没有
 * curl_multi(v1 明确不做竞速), 所以不存在两条传输互相踩状态的路径。
 */
final class Streamer
{
    /** 能力位的键名与 Source/Selector 用的是同一套, 不能自创别名。 */
    public const CAP_RANGE = 'range';
    public const CAP_FOLLOW = 'follows_redirect_internally';
    public const CAP_JSON_API = 'json_api_ok';

    /** 嗅探门: 512 字节足够判 HTML/ZIP/GZIP 魔数, 又小到不会让用户觉得首字节变慢。 */
    private const SNIFF_BYTES = 512;

    /** Phase R 最多留在缓冲里的字节数(超过就主动中止, 绝不为"探一下"拉下整个 10MB 归档)。 */
    private const PROBE_CAP_BYTES = 65536;

    /** fast-path 预取上限: 客户端只要了很小的区间时, 把这段字节直接交出去省一次往返。 */
    private const FASTPATH_MAX_BYTES = 262144;

    private bool $discard = false;

    /** @var resource|null */
    private $sink = null;

    private bool $sinkOwned = false;

    private int $discardCap = self::PROBE_CAP_BYTES;

    private int $maxBytes = 0;

    private int $clientBytes = 0;

    private int $wireBytes = 0;

    private string $head = '';

    private int $gateTarget = self::SNIFF_BYTES;

    private bool $gateOpen = false;

    private bool $emitted = false;

    private bool $clientAbort = false;

    private bool $oversize = false;

    private bool $fakeContent = false;

    private bool $budgetHit = false;

    private bool $probeTruncated = false;

    private bool $guardMismatch = false;

    /** ?sha256= 与实测摘要不符: 缓存已丢弃, 分型必须是 Integrity(权重 3.0 且降 trust)。 */
    private bool $integrityBad = false;

    /** Phase R 实测到的能力位与总体积, 供 Phase S 发表头时引用(不靠回调间的隐式顺序)。 */
    private array $caps = [];

    private int $probeTotal = 0;

    private float $tStart = 0.0;

    private float $tFirst = 0.0;

    private float $budgetMs = 0.0;

    private int $respStatus = 0;

    /** @var array<string,string> 小写键的上游响应头 */
    private array $respHeaders = [];

    private ?PartialWriter $writer = null;

    /** @var \HashContext|null 覆盖"交给客户端的字节"的增量摘要, 常数内存 */
    private $hashCtx = null;

    private ?GitHubRef $ref = null;

    private ?Source $src = null;

    private array $opts = [];

    /** .part 续传: 已确认的连续前缀长度与总体积 */
    private int $resumeFrom = 0;

    private int $resumeTotal = 0;

    /**
     * 续传补发本地前缀时为 true。
     *
     * 那批字节已经在 .part 里, 若再走 writer->write() 就是把它重复追加回同一个文件:
     * 文件长度立刻超过 expected_size, write() 判坏并 dropWriter, 于是"每一次断点续传都会
     * 悄悄毁掉那条缓存"。
     */
    private bool $replaying = false;

    private mixed $progress = null;

    public function __construct(
        private readonly Config $cfg,
        private readonly UrlGuard $guard,
        private readonly Headers $headers,
        private readonly Policy $policy,
        private readonly ?Store $store = null
    ) {
    }

    // ------------------------------------------------------------------
    // 对外入口
    // ------------------------------------------------------------------

    /**
     * 取一次资源: 必要时先跑 Phase R, 再跑 Phase S。
     *
     * @param array  $opts  range / method / out / max_bytes / budget_ms / client_headers /
     *                      progress / diag / diag_visible / cache(bool) / upstream_etag /
     *                      upstream_last_modified / download_name
     * @param array &$detail 交回 Phase R 实测到的能力与缓存结果(见 blankDetail())
     */
    public function fetch(Source $src, GitHubRef $ref, array $opts = [], ?array &$detail = null): UpstreamResult
    {
        $detail = $this->blankDetail();
        $this->reset($src, $ref, $opts);

        // 断连后还要收尾写观测与 .part 元数据, 所以必须 ignore_user_abort:
        // 默认的"客户端断开就终止脚本"会让观测整条丢失, 而观测是选路唯一的实测来源。
        @ignore_user_abort(true);

        // 1) 内层 GitHub URL 过安全判定链。这一步在包装之前: 用户能控制的只有内层,
        //    镜像域名来自部署者配置, 两者风险等级不同, 判定顺序必须反映这一点。
        try {
            $inner = $this->guard->assertAllowed($ref->upstreamUrl);
        } catch (GhpError $e) {
            $detail['error'] = $e->getMessage();

            return new UpstreamResult(FailureKind::GuardRejected, 0, [], 0, 0.0, 0.0, '', '', 0, 0, $e->getMessage());
        }
        $detail['inner_url'] = $inner->url;

        try {
            // 2) Phase R
            if ($ref->needsRedirectResolve) {
                $this->probe($src, $ref, $inner, $detail);
                $this->writeBackCaps($detail);
                if ($detail['stopped']) {
                    return $detail['stop_result'];
                }
            }

            // 3) 越界本地判定: 已知总体积就不必再打下游(省下的是真金白银的跨洋带宽)。
            $overTotal = $this->unsatisfiableTotal((string) ($opts['range'] ?? ''), (int) $detail['total_size']);
            if ($overTotal !== null) {
                $pack = $this->headers->rangeUnsatisfiable($overTotal);
                // 416 用空 body: Range 请求的任何非字节响应都可能被并发下载器当成一片写进文件,
                // 空 body + Content-Range 是既能表达错误又绝不可能污染产物的一种形状。
                $pack['headers']['content-length'] = '0';
                $this->headers->emit($pack['status'], $pack['headers']);
                Http::flush();
                $detail['emitted'] = true;

                // 416 是用户写错的区间而不是源的故障: Http4xx 权重 0.4、不进熔断, 且
                // committed=true 让 Failover 停止(换源也不会让这个区间存在)。
                return new UpstreamResult(
                    FailureKind::Http4xx,
                    416,
                    $pack['headers'],
                    0,
                    0.0,
                    0.0,
                    (string) $detail['final_url'],
                    (string) $detail['primary_ip'],
                    (int) $detail['hops'],
                    0,
                    'local_416',
                    true,
                    $detail['caps'],
                    $ref->downloadName
                );
            }

            // 4) Phase S
            $res = $this->streamPhase($src, $ref, $inner, $detail);
            $this->writeBackCaps($detail);

            return $res;
        } catch (GhpError $e) {
            // 跳转复校/判定链在任一阶段抛出都在这里收口成 UpstreamResult: Failover 只认
            // 结果对象, 让异常穿过去会让整条链的观测与统计全部丢失。
            $detail['error'] = $e->errorCode . ': ' . $e->getMessage();
            if ($e->errorCode === GhpError::GUARD_MISMATCH) {
                $this->guardMismatch = true;
            }

            return new UpstreamResult(
                $this->kindFromGhp($e),
                0,
                [],
                $this->clientBytes,
                $this->tFirst > 0.0 ? ($this->tFirst - $this->tStart) * 1000.0 : 0.0,
                (microtime(true) - $this->tStart) * 1000.0,
                (string) ($detail['final_url'] ?? ''),
                (string) ($detail['primary_ip'] ?? ''),
                (int) ($detail['hops'] ?? 0),
                0,
                $e->getMessage(),
                $this->emitted,
                (array) ($detail['caps'] ?? []),
                $ref->downloadName
            );
        }
    }

    /** 能力位与总体积同时写进 detail 与实例字段: 发表头发生在回调里, 拿不到 detail。 */
    private function writeBackCaps(array &$detail): void
    {
        $this->caps = (array) ($detail['caps'] ?? []);
        $this->probeTotal = (int) ($detail['total_size'] ?? 0);
    }

    /** GhpError -> 失败分型。判定链的拒绝必须与源的健康度无关, 但必须能终止回退链。 */
    private function kindFromGhp(GhpError $e): FailureKind
    {
        return match ($e->errorCode) {
            GhpError::REDIRECT_TOO_MANY => FailureKind::Connect, // 源的跳转链坏了, 属于链路故障
            GhpError::UPSTREAM_FAILED => FailureKind::Http5xx,
            default => FailureKind::GuardRejected,               // mustStopFailover=true
        };
    }

    private function reset(Source $src, GitHubRef $ref, array $opts): void
    {
        $this->src = $src;
        $this->ref = $ref;
        $this->opts = $opts;

        $this->discard = true;
        $this->sink = isset($opts['out']) && is_resource($opts['out']) ? $opts['out'] : null;
        $this->sinkOwned = false;
        if ($this->sink === null) {
            // 零拷贝的地基: 直接写 php://output, 字节不进 PHP 变量也不进 php://memory。
            $this->sink = Http::out();
            $this->sinkOwned = false;
        }
        $this->discardCap = self::PROBE_CAP_BYTES;
        $this->maxBytes = (int) ($opts['max_bytes'] ?? $this->cfg->int('limits.per_request_bytes', 0));
        if ($this->maxBytes < 0) {
            $this->maxBytes = 0;
        }
        $this->budgetMs = max(0.0, (float) ($opts['budget_ms'] ?? 0.0));
        $this->clientBytes = 0;
        $this->wireBytes = 0;
        $this->head = '';
        $this->gateOpen = false;
        $this->emitted = false;
        $this->clientAbort = false;
        $this->oversize = false;
        $this->fakeContent = false;
        $this->budgetHit = false;
        $this->probeTruncated = false;
        $this->guardMismatch = false;
        $this->integrityBad = false;
        $this->caps = [];
        $this->probeTotal = 0;
        $this->tStart = 0.0;
        $this->tFirst = 0.0;
        $this->respStatus = 0;
        $this->respHeaders = [];
        $this->writer = null;
        $this->hashCtx = null;
        $this->resumeFrom = 0;
        $this->resumeTotal = 0;
        $this->progress = $opts['progress'] ?? null;
        $this->gateTarget = self::SNIFF_BYTES;
    }

    // ------------------------------------------------------------------
    // Phase R: 解析最终地址与实测能力, 一字节都不给客户端
    // ------------------------------------------------------------------

    private function probe(Source $src, GitHubRef $ref, GuardResult $inner, array &$detail): void
    {
        $this->discard = true;
        $clientRange = (string) ($this->opts['range'] ?? '');

        // 探测用的 Range 固定从 0 开始且只要一点点: 支持 Range 的服务端回 206 +
        // Content-Range(里面带总体积), 不支持的(实测 codeload)回 200 全量 —— 两种结果
        // 都只需要表头就能判, 所以字节上限设得很小并主动中止。
        $probeEnd = 0;
        $fastPath = false;
        if ($ref->allowRange) {
            $single = Key::parseSingle($clientRange);
            // fast-path 只在"客户端区间起点为 0 且整段都在预取上限内"时成立: 这时 Phase R
            // 拿到的字节就是客户端要的那段, 直接交出去就省掉一次完整的往返。起点不为 0 时
            // 探针区间与请求区间不是同一段, 拼起来就是错位的文件, 所以宁可不优化。
            if ($single !== null && $single[0] === 0 && $single[1] >= 0
                && ($single[1] + 1) <= self::FASTPATH_MAX_BYTES) {
                $probeEnd = $single[1];
                $fastPath = true;
            }
            $probeRange = 'bytes=0-' . $probeEnd;
        } else {
            // allowRange=false: 不向源发明 Range(实测发了也被无视, 只是让诊断读数骗人)。
            $probeRange = '';
        }
        $this->discardCap = $fastPath ? max(self::SNIFF_BYTES, $probeEnd + 1) : self::PROBE_CAP_BYTES;
        $detail['fast_path'] = $fastPath ? ($probeEnd + 1) : 0;

        $url0 = $src->accelerate($inner->url);
        $res = $this->runHops($src, $url0, $probeRange, true);

        $detail['hops'] = $res['hops'];
        $detail['final_url'] = $res['url'];
        $detail['primary_ip'] = $res['primary_ip'];
        $detail['probe_status'] = $res['status'];
        $detail['resp_headers'] = $res['headers'];
        $detail['bytes'] = $res['bytes'];

        $st = (int) $res['status'];
        $up = $res['headers'];
        $cr = (string) ($up['content-range'] ?? '');
        $ar = strtolower((string) ($up['accept-ranges'] ?? ''));

        // 探测阶段的传输级失败(连不上/TLS 不通过/超时)直接判定这次交互失败。
        // 不能放它过去: Phase S 打的是同一个源、同一条链, 再试一次只是把超时时间翻倍,
        // 而 Failover 需要的是"现在就换源"的信号。probeTruncated 是我们自己主动中止, 不算失败。
        if (!$this->probeTruncated && ((int) $res['errno'] !== 0 || $st === 0)) {
            $detail['stopped'] = true;
            $detail['stop_result'] = new UpstreamResult(
                (int) $res['errno'] !== 0
                    ? UpstreamResult::classifyCurl((int) $res['errno'], (string) $res['error'])
                    : FailureKind::Connect,
                $st,
                $up,
                (int) $res['bytes'],
                (float) $res['ttfb_ms'],
                (float) $res['total_ms'],
                (string) $res['url'],
                (string) $res['primary_ip'],
                (int) $res['hops'],
                (int) $res['errno'],
                (string) $res['error'],
                false,
                $detail['caps'],
                $ref->downloadName
            );

            return;
        }

        // 能力位一律实测, 而且只在"我们真的发了 Range"时才下结论。
        // 唯一证据是 206 + Content-Range: 实测 codeload 对 bytes=0-64 回 200 全量, 若信配置
        // 里写的 allowRange/Accept-Ranges, 选路就会把不支持 Range 的源排进并发分片链路,
        // 用户拿到 N 份全量文件 —— 这是"配置声称"与"实测"必须分开的全部理由。
        $rangeOk = $probeRange !== '' && $st === 206 && $cr !== '';
        $detail['caps'][self::CAP_RANGE] = $rangeOk;
        // 镜像在第一跳就把 302 消化掉并直接给字节 = 它自己跟了跳转。这个能力决定 REDIRECT
        // 模式能不能用: 不能就绝不能 302 给客户端, 那等于让用户自己跳回跨洋直连。
        $detail['caps'][self::CAP_FOLLOW] = ($st >= 200 && $st < 300) && $res['hops'] === 0;
        if ($ref->scene === Scene::ApiJson) {
            $detail['caps'][self::CAP_JSON_API] = $st >= 200 && $st < 300;
        }

        $detail['total_size'] = $cr !== ''
            ? Headers::totalFromRange($cr)
            : (int) ($up['content-length'] ?? 0);
        // 200 全量被我们主动截断时, Content-Length 是"整个资源"的长度而不是已收字节, 仍然可信;
        // 但若是上游 chunked(无长度)则总体积未知, 后面禁止分片与 EDGE 直出。
        $detail['etag'] = (string) ($up['etag'] ?? '');
        $detail['last_modified'] = (string) ($up['last-modified'] ?? '');
        $detail['content_type'] = (string) ($up['content-type'] ?? '');
        $detail['probe_head'] = $this->head;
        // 同 openGate: 只在 200 全量上嗅探。探针拿到 206 时手里只有 1 个字节, 判魔数没有意义。
        $detail['probe_fake'] = $st === 200
            && UpstreamResult::looksLikeWrongContent($ref->scene, $this->head, $detail['content_type']);

        // 探测阶段就把"假 200"判掉: 内容是错误页时不该再发一次 Phase S 去拉完整的错误页,
        // 直接按 wrong_content 回退到下一个源(权重 1.5, 正是镜像失效该有的惩罚)。
        if ($st >= 200 && $st < 300 && $detail['probe_fake']) {
            $detail['stopped'] = true;
            $detail['stop_result'] = new UpstreamResult(
                FailureKind::WrongContent,
                $st,
                $up,
                (int) $res['bytes'],
                (float) $res['ttfb_ms'],
                (float) $res['total_ms'],
                (string) $res['url'],
                (string) $res['primary_ip'],
                (int) $res['hops'],
                0,
                'probe_fake_200',
                false,
                $detail['caps'],
                $ref->downloadName
            );

            return;
        }

        // 探测拿到 4xx/5xx 就没有必要再打一次 Phase S: 状态码不会因为多问一遍而变好。
        if ($st >= 400) {
            $detail['stopped'] = true;
            $detail['stop_result'] = new UpstreamResult(
                $this->kindFromStatus($st, $ref),
                $st,
                $up,
                0,
                (float) $res['ttfb_ms'],
                (float) $res['total_ms'],
                (string) $res['url'],
                (string) $res['primary_ip'],
                (int) $res['hops'],
                (int) $res['errno'],
                (string) $res['error'],
                false,
                $detail['caps'],
                $ref->downloadName
            );

            return;
        }

        if ($res['ttfb_ms'] > 0.0) {
            $detail['ttfb_ms'] = $res['ttfb_ms'];
        }
    }

    // ------------------------------------------------------------------
    // Phase S: 先发表头, 再流式发体
    // ------------------------------------------------------------------

    private function streamPhase(Source $src, GitHubRef $ref, GuardResult $inner, array &$detail): UpstreamResult
    {
        $this->discard = false;
        $method = strtoupper((string) ($this->opts['method'] ?? Http::method()));
        if (!in_array($method, ['GET', 'HEAD'], true)) {
            $method = 'GET';
        }
        $clientRange = (string) ($this->opts['range'] ?? '');
        // 源不支持 Range 时, 客户端的 Range 一律当不存在: 既不发给它, 也不许走下面的
        // fast-path 用探针缓冲冒充一个 206。实测 codeload 会回 200 全量, 若我们照着客户端
        // 的 bytes=0-64 去"满足"它, 交出去的就是一份声明了区间却只含探针字节的产物 ——
        // aria2/IDM 会把它当一个完整分片写进文件, 产出静默损坏的下载。
        // 正确形态是透传上游的 200 + 全量, 并由 Headers 标 X-GhAccel-Range: unsupported。
        if (!$ref->allowRange) {
            $clientRange = '';
        }
        $this->head = '';
        $this->wireBytes = 0;
        $this->clientBytes = 0;

        $startUrl = (string) ($detail['final_url'] !== '' ? $detail['final_url'] : $src->accelerate($inner->url));
        $range = $clientRange;

        // fast-path: 客户端区间已被 Phase R 完整预取 -> 直接把那段字节按上游状态交出去,
        // 省掉一次真实往返(国内到 GitHub 的一次 RTT 常常就是用户感知的全部延迟)。
        // 成立条件严格限定: 探针必须真的拿到 2xx 且缓冲非空, 否则就是拿一次失败的探测冒充响应。
        $probeSt = (int) $detail['probe_status'];
        if ($clientRange !== '' && (int) $detail['fast_path'] > 0
            && $probeSt >= 200 && $probeSt < 300 && (string) $detail['probe_head'] !== ''
            && str_starts_with($clientRange, 'bytes=0-')) {
            $this->gateOpen = true;
            $this->respStatus = (int) $detail['probe_status'];
            $this->respHeaders = (array) $detail['resp_headers'];
            $this->head = (string) $detail['probe_head'];
            $this->emitNow($this->respStatus, $ref, $src, true);
            if ($this->push($this->head)) {
                $this->finishCache($ref, $detail, false);
                $detail['emitted'] = $this->emitted;
                $detail['fast_path_used'] = true;

                return new UpstreamResult(
                    FailureKind::None,
                    $this->respStatus,
                    $this->respHeaders,
                    $this->clientBytes,
                    (float) $detail['ttfb_ms'],
                    (microtime(true) - $this->tStart) * 1000.0,
                    $startUrl,
                    (string) $detail['primary_ip'],
                    (int) $detail['hops'],
                    0,
                    '',
                    true,
                    $detail['caps'],
                    $ref->downloadName
                );
            }
            // 预取字节都发不出去说明客户端已经断了, 后面不必再打上游。
            $this->finishCache($ref, $detail, true);

            return $this->abortResult($ref, $detail, FailureKind::ClientAbort);
        }

        // 不缓存就不需要续传; 要续传就必须是"整份文件、GET、总体积已知"。
        // 这里只能认出"已有 .part"的续传场景 —— 新条体的体积要等响应头, 那时会在 openGate 再试一次。
        $this->prepareWriter();
        if ($this->resumeFrom > 0) {
            // 续传时我们自己请求尾部, 但客户端请求的是整份文件: 上游那个 206 不能镜像,
            // 否则客户端收到一个声明了整份长度却只有一半字节的响应。改发 200 + 整份长度,
            // 前缀由本地 .part 补发(见 openGate 里的 replayPrefix)。
            $range = 'bytes=' . $this->resumeFrom . '-';
        }

        $res = $this->runHops($src, $startUrl, $range, false);
        $st = (int) $res['status'];
        $this->respStatus = $st;
        $this->respHeaders = (array) $res['headers'];
        $detail['hops'] = $res['hops'];
        $detail['final_url'] = $res['url'];
        $detail['primary_ip'] = $res['primary_ip'];
        $detail['resp_headers'] = $res['headers'];
        if ($detail['total_size'] === 0) {
            $detail['total_size'] = $st === 206
                ? Headers::totalFromRange((string) ($res['headers']['content-range'] ?? ''))
                : (int) ($res['headers']['content-length'] ?? 0);
        }
        if ($detail['content_type'] === '') {
            $detail['content_type'] = (string) ($res['headers']['content-type'] ?? '');
        }
        if ($detail['etag'] === '') {
            $detail['etag'] = (string) ($res['headers']['etag'] ?? '');
        }
        if ($detail['last_modified'] === '') {
            $detail['last_modified'] = (string) ($res['headers']['last-modified'] ?? '');
        }
        // Phase S 也可能纠正 Phase R 的结论: 上游对真实 Range 请求回 200 就是不支持 Range。
        if ($clientRange !== '' && $st === 200) {
            $detail['caps'][self::CAP_RANGE] = false;
        }

        // 字节还没过嗅探门就结束的小响应(body < 阈值)、HEAD、以及 chunked 提前 EOF:
        // 在这里以 force 模式补发头, 保证"头先于体"这条不变量在任何形状下都成立。
        if (!$this->emitted && $st >= 200 && $st < 300 && $st !== 304 && !$this->clientAbort) {
            // 304 不在此列: 那是我们对上游的条件请求结果, 与客户端的 If-None-Match 无关,
            // 必须由 Dispatcher 拿去刷新 EDGE 新鲜度后自行发头(见 Dispatcher::serve 的 revalidate 分支)。
            if (!$this->openGate(true)) {
                $this->finishCache($ref, $detail, true);

                return $this->abortResult(
                    $ref,
                    $detail,
                    $this->fakeContent ? FailureKind::WrongContent
                        : ($this->oversize ? FailureKind::Oversize
                        : ($this->clientAbort ? FailureKind::ClientAbort : FailureKind::Stall))
                );
            }
        }
        $this->finishCache($ref, $detail, $this->clientAbort || $this->oversize || $this->fakeContent);
        $detail['emitted'] = $this->emitted;

        $kind = $this->failureFromTransfer($res, $ref, $st);
        $ttfb = $this->tFirst > 0.0 ? ($this->tFirst - $this->tStart) * 1000.0 : (float) $res['ttfb_ms'];

        $detail['sha256'] = $this->hashCtx !== null ? hash_final($this->hashCtx) : '';
        $this->hashCtx = null;

        return new UpstreamResult(
            $kind,
            $st,
            $this->respHeaders,
            $this->clientBytes,
            max(0.0, $ttfb),
            (float) $res['total_ms'],
            (string) $res['url'],
            (string) $res['primary_ip'],
            (int) $res['hops'],
            (int) $res['errno'],
            (string) $res['error'],
            $this->emitted,
            $detail['caps'],
            (string) ($this->opts['download_name'] ?? $ref->downloadName)
        );
    }

    // ------------------------------------------------------------------
    // 逐跳执行(FOLLOWLOCATION=false 才有每一步的复校点)
    // ------------------------------------------------------------------

    /**
     * @return array{url:string,status:int,headers:array<string,string>,primary_ip:string,
     *               errno:int,error:string,bytes:int,hops:int,ttfb_ms:float,total_ms:float}
     */
    private function runHops(Source $src, string $url, string $range, bool $discard): array
    {
        $maxHops = max(0, $this->cfg->int('security.max_redirect_hops', 3));
        $from = $url;
        $hop = 0;
        $last = null;

        while (true) {
            $g = $this->guardConnect($from, $src);
            $last = $this->oneTransfer($src, $g, $range, $discard);
            $st = (int) $last['status'];

            if ($st >= 300 && $st < 400 && $st !== 304) {
                $loc = (string) ($last['headers']['location'] ?? '');
                if ($loc === '') {
                    $last['error'] = 'redirect_without_location';
                    $last['errno'] = 1;
                    $last['hops'] = $hop;

                    return $last;
                }
                $hop++;
                // 每一跳都重新过整套判定链(scheme/userinfo/host/IP/回环/指回自身), 并且
                // 复用同一个 guardConnect: 跳转目标可能又回到 GitHub 域(302 -> objects),
                // 也可能是镜像自己的第二级前缀。
                try {
                    if ($this->guard->isOwnPrefix($this->absolutize($loc, (string) $last['url'])) !== '') {
                        throw GhpError::make(GhpError::REDIRECT_LOOP, 'Location 指回本网关前缀');
                    }
                    if ($hop > $maxHops) {
                        throw GhpError::make(GhpError::REDIRECT_TOO_MANY, sprintf('hop=%d limit=%d', $hop, $maxHops));
                    }
                    $re = $this->guard->assertRedirectResult($loc, (string) $last['url'], $hop);
                    $from = $re->url;
                } catch (GhpError $e) {
                    $last['error'] = $e->errorCode . ': ' . $e->getMessage();
                    $last['errno'] = 1;
                    $last['status'] = $st;
                    $last['hops'] = $hop;

                    return $last;
                }
                $this->respHeaders = [];
                $this->respStatus = 0;
                if ($discard) {
                    // 探针跳完后要重新按最终地址的能力判定, 上一跳的头与字节都不能带过来。
                    $this->head = '';
                    $this->wireBytes = 0;
                }
                continue;
            }

            $last['hops'] = $hop;

            return $last;
        }
    }

    /** 上游 302 的 Location 可能相对, 用发起地址绝对化(与 UrlGuard 同一套规则)。 */
    private function absolutize(string $location, string $from): string
    {
        if (preg_match('#\Ahttps?://#i', $location) === 1) {
            return $location;
        }
        // 复用 guard 的绝对化能力: 相对 Location 交给 assertRedirectResult 内部处理,
        // 这里只为 isOwnPrefix 的判定提供一个可解析的串。
        $parts = parse_url($from);
        $scheme = (string) ($parts['scheme'] ?? 'https');
        $host = (string) ($parts['host'] ?? '');
        if ($host === '') {
            return $location;
        }
        if (str_starts_with($location, '//')) {
            return $scheme . ':' . $location;
        }
        if (str_starts_with($location, '/')) {
            return $scheme . '://' . $host . $location;
        }
        $dir = (string) ($parts['path'] ?? '/');
        $dir = substr($dir, 0, (int) strrpos($dir, '/') + 1);

        return $scheme . '://' . $host . $dir . $location;
    }

    /**
     * 连接目标的校验。
     *
     * GitHub 域走完整判定链(用户的输入全在这里); 判定链回 HOST_NOT_ALLOWED 且 host 正好是
     * 该源配置的镜像域名时, 走一条同等严格的自建校验: 只允许 https、端口 443/80、无 userinfo、
     * 只解析 A 记录、逐个 IP 过 IpRange、并把结果同样钉进 CURLOPT_RESOLVE。
     * 为什么允许这一条: 镜像域名来自部署者的 sources 配置而不是请求方, 而"不在 GitHub 白名单"
     * 不等于"可以拿去内网横移" —— 上面那几步拦的正是这件事。
     */
    private function guardConnect(string $url, Source $src): GuardResult
    {
        try {
            return $this->guard->assertAllowed($url);
        } catch (GhpError $e) {
            if ($e->errorCode !== GhpError::HOST_NOT_ALLOWED) {
                throw $e;
            }
        }

        $host = strtolower((string) (parse_url($url, PHP_URL_HOST) ?: ''));
        $mirrorHost = strtolower((string) (parse_url($src->baseUrl, PHP_URL_HOST) ?: ''));
        $scheme = strtolower((string) (parse_url($url, PHP_URL_SCHEME) ?: ''));
        $port = (int) (parse_url($url, PHP_URL_PORT) ?: 443);

        if ($host === '' || $mirrorHost === '' || $host !== $mirrorHost || $scheme !== 'https'
            || ($port !== 443 && $port !== 80) || str_contains((string) (parse_url($url, PHP_URL_USER) ?: ''), '@')) {
            // 跳到第三个域名去了: 既不是 GitHub 也不是这个源自己的前缀, 一律拒绝。
            throw GhpError::make(GhpError::HOST_NOT_ALLOWED, $host === '' ? '(空 host)' : $host);
        }
        if (preg_match('/\A[a-z0-9.-]+\z/', $host) !== 1) {
            throw GhpError::make(GhpError::ILLEGAL_HOST_CHARS, $host);
        }

        $ips = $this->guard->resolveA($host);
        if ($ips === []) {
            throw GhpError::make(GhpError::IP_DENIED, $host . ' 无 A 记录');
        }
        $extraDeny = (array) $this->cfg->arr('security.extra_deny_cidrs');
        foreach ($ips as $ip) {
            if (!IpRange::isPubliclyRoutable((string) $ip, $extraDeny)) {
                throw GhpError::make(GhpError::IP_DENIED, sprintf('%s 解析到受保护地址 %s', $host, $ip));
            }
        }
        $entries = [];
        foreach ($ips as $ip) {
            $entries[] = sprintf('%s:%d:%s', $host, $port, $ip);
        }

        return new GuardResult($url, $host, (string) ($ips[0] ?? ''), $entries);
    }

    /**
     * 一次 curl 传输。所有选项都是"实测过必须这么配"的结果, 逐条有理由, 见行内注释。
     */
    private function oneTransfer(Source $src, GuardResult $g, string $range, bool $discard): array
    {
        $ch = curl_init();
        if ($ch === false) {
            return $this->blankHop($g->url, 'curl_init failed');
        }

        $this->discard = $discard;
        $this->respStatus = 0;
        $this->respHeaders = [];
        $this->wireBytes = 0;
        if (!$discard) {
            $this->head = '';
            $this->tFirst = 0.0;
        }
        $this->tStart = microtime(true);
        $method = strtoupper((string) ($this->opts['method'] ?? 'GET'));
        if ($discard) {
            $method = 'GET'; // 绝不用 HEAD: SAS 签名与方法绑定, HEAD 预检必 403
        }

        $connectMs = max(200, (int) ($src->connectTimeoutMs > 0
            ? $src->connectTimeoutMs
            : $this->cfg->int('budgets.connect_timeout_ms', 1500)));

        curl_setopt($ch, CURLOPT_URL, $g->url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method === 'HEAD' ? 'HEAD' : 'GET');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, false); // 严禁 true: 整包进内存, 零拷贝当场作废
        curl_setopt($ch, CURLOPT_HEADER, false);         // 头只经 HEADERFUNCTION 拿, 不与 body 混在返回值里
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // 手工逐跳, 才有每一跳的复校与中间状态
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, $connectMs);
        // TIMEOUT=0: 总时长不设硬上限。大文件本来就该跑很久, 而"连上了但假活"由
        // LOW_SPEED_* 掐 —— 这一条对国内到 GitHub 的链路比任何选路算法都有效。
        curl_setopt($ch, CURLOPT_TIMEOUT, 0);
        curl_setopt($ch, CURLOPT_LOW_SPEED_LIMIT, max(1, $this->cfg->int('budgets.stall_limit_bytes', 1024)));
        curl_setopt($ch, CURLOPT_LOW_SPEED_TIME, max(1, (int) ceil($this->cfg->int('budgets.stall_time_ms', 25000) / 1000)));
        curl_setopt($ch, CURLOPT_TCP_KEEPALIVE, 1);
        if (defined('CURLOPT_TCP_KEEPIDLE')) {
            curl_setopt($ch, CURLOPT_TCP_KEEPIDLE, 30);
        }
        if (defined('CURLOPT_TCP_KEEPINTVL')) {
            curl_setopt($ch, CURLOPT_TCP_KEEPINTVL, 15);
        }
        // 绝不为"能连通"而关掉证书校验: 关掉之后 wrong_content/integrity 就成了唯一防线,
        // 而那是内容层的判定, 挡不住一个能终结 TLS 的中间人。失败按 TlsVerify 让该源降级。
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_HTTP_VERSION, defined('CURL_HTTP_VERSION_1_1') ? CURL_HTTP_VERSION_1_1 : 1);
        curl_setopt($ch, CURLOPT_NOSIGNAL, 1); // 多线程/插件运行时 SIGNAL 报警会直接杀掉进程
        curl_setopt($ch, CURLOPT_DNS_CACHE_TIMEOUT, 600);
        curl_setopt($ch, CURLOPT_IPRESOLVE, defined('CURL_IPRESOLVE_V4') ? CURL_IPRESOLVE_V4 : 1);
        // 故意**不设** CURLOPT_ENCODING: 空串在 libcurl 语义里是"请求并自动解压全部支持的编码",
        // 那会让我们收到解压后的字节却仍然带着上游的 Content-Length(压缩长度), 于是
        // 长度与实际字节不符、断点续传偏移错位、sha256 校验对不上。Accept-Encoding 由
        // Headers 层显式发 identity, 让上游原样给字节。
        if ($g->resolveEntries !== []) {
            curl_setopt($ch, CURLOPT_RESOLVE, $g->resolveEntries);
        }
        if (defined('CURLOPT_PROTOCOLS')) {
            curl_setopt($ch, CURLOPT_PROTOCOLS, defined('CURL_PROTOCOL_HTTPS') ? CURL_PROTOCOL_HTTPS : 2);
        }
        if (defined('CURLOPT_REDIR_PROTOCOLS')) {
            curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, defined('CURL_PROTOCOL_HTTPS') ? CURL_PROTOCOL_HTTPS : 2);
        }
        // 协议白名单也走字符串常量版本(部分构建里数值常量与字符串常量导出情况不一致)。
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            @curl_setopt($ch, CURLOPT_PROTOCOLS_STR, 'https');
        }
        if (defined('CURLOPT_REDIR_PROTOCOLS_STR')) {
            @curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS_STR, 'https');
        }

        $ref = $this->ref;
        if ($ref === null) {
            return $this->blankHop($g->url, 'internal: ref not bound');
        }
        // 探测阶段绝不带上一次存下来的条件头: 那会让上游直接回 304, 而我们这一次要的
        // 恰恰是"完整响应头 + 状态码"来判断这源到底支不支持 Range、会不会自己跟跳转。
        $lines = $this->headers->requestLines($ref, [
            'method' => $discard ? 'GET' : $method,
            'range' => $range,
            'client_headers' => (array) ($this->opts['client_headers'] ?? []),
            'api' => $ref->scene === Scene::ApiJson,
            'upstream_etag' => $discard ? '' : (string) ($this->opts['upstream_etag'] ?? ''),
            'upstream_last_modified' => $discard ? '' : (string) ($this->opts['upstream_last_modified'] ?? ''),
        ]);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $lines);
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, string $line): int {
            return $this->onHeader($line);
        });
        curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($ch, string $data): int {
            return $this->onWrite($data);
        });

        // 字节上限与统计回调走进度函数: 它在 curl 自己的循环里被调, 不需要等 body 块到齐,
        // 所以"超时预算耗尽"和"体积超标"能在下一个包之前就中止, 而不是又多拉 64KB。
        if (defined('CURLOPT_XFERINFOFUNCTION')) {
            curl_setopt($ch, CURLOPT_NOPROGRESS, false);
            curl_setopt($ch, CURLOPT_XFERINFOFUNCTION, function ($ch, int $dls, int $dl, int $uls, int $ul): int {
                return $this->onProgress($dl);
            });
        } elseif (defined('CURLOPT_PROGRESSFUNCTION')) {
            curl_setopt($ch, CURLOPT_NOPROGRESS, false);
            curl_setopt($ch, CURLOPT_PROGRESSFUNCTION, function ($ch, float $dls, float $dl, float $uls, float $ul): int {
                return $this->onProgress((int) $dl);
            });
        } else {
            curl_setopt($ch, CURLOPT_NOPROGRESS, true);
        }

        $ok = @curl_exec($ch);
        $errno = (int) curl_errno($ch);
        $error = (string) curl_error($ch);
        $info = curl_getinfo($ch);
        @curl_close($ch);

        $primaryIp = (string) ($info['primary_ip'] ?? '');
        $status = (int) ($this->respStatus ?: (int) ($info['response_code'] ?? 0));

        // 事后兜底: 实际连上的地址必须落在本次解析出的集合里(DNS 重绑定/解析器分歧)。
        if ($primaryIp !== '' && !$this->guardMismatch) {
            try {
                $this->guard->verifyPrimaryIp($g, $primaryIp);
            } catch (GhpError $e) {
                $this->guardMismatch = true;
                $error = $e->getMessage();
            }
        }

        $total = max(0.0, (float) ($info['total_time'] ?? 0.0)) * 1000.0;
        $ttfb = $this->tFirst > 0.0
            ? ($this->tFirst - $this->tStart) * 1000.0
            : max(0.0, ((float) ($info['starttransfer_time'] ?? 0.0) - (float) ($info['pretransfer_time'] ?? 0.0)) * 1000.0);

        return [
            'url'        => $g->url,
            'status'     => $status,
            'headers'    => $this->respHeaders,
            'primary_ip' => $primaryIp,
            'errno'      => $errno,
            'error'      => $error,
            'bytes'      => $this->wireBytes,
            'hops'       => 0, // 由 runHops 的调用侧累计, 这里每条只是单跳记录
            'ttfb_ms'    => max(0.0, $ttfb),
            'total_ms'   => $total,
            'ok'         => $ok !== false,
        ];
    }

    private function blankHop(string $url, string $error): array
    {
        return [
            'url' => $url, 'status' => 0, 'headers' => [], 'primary_ip' => '', 'errno' => 0,
            'error' => $error, 'bytes' => 0, 'hops' => 0, 'ttfb_ms' => 0.0, 'total_ms' => 0.0, 'ok' => false,
        ];
    }

    // ------------------------------------------------------------------
    // curl 回调
    // ------------------------------------------------------------------

    private function onHeader(string $line): int
    {
        $len = strlen($line);
        $trim = rtrim($line, "\r\n");
        if ($trim === '') {
            return $len;
        }
        // 状态行: 以它重置头表, 这样跳转链上任何一次"多段 HTTP/1.x 100 Continue"都不会
        // 把上一跳的头混进这一跳(实测企业代理会插 100 行, 混了就发错 Content-Length)。
        if (preg_match('#\AHTTP/[0-9.]+\s+(\d{3})#i', $trim, $m) === 1) {
            $code = (int) $m[1];
            if ($code >= 200) {
                $this->respStatus = $code;
                $this->respHeaders = [];
            }

            return $len;
        }
        $pos = strpos($trim, ':');
        if ($pos === false) {
            return $len;
        }
        $name = strtolower(trim(substr($trim, 0, $pos)));
        $value = trim(substr($trim, $pos + 1));
        if ($name === '') {
            return $len;
        }
        $this->respHeaders[$name] = isset($this->respHeaders[$name])
            ? $this->respHeaders[$name] . ', ' . $value
            : $value;

        return $len;
    }

    /**
     * 写回调。返回长度表示"消费掉了", 返回 0 表示"中止这次传输"。
     *
     * 客户端断连的判定只用 fwrite 的短写: connection_aborted() 在 FPM 下要等脚本结束才准,
     * 用它就等于断开之后还继续替用户向下游拉几十 MB —— 这是这类代理最烧钱的 bug。
     */
    private function onWrite(string $data): int
    {
        $len = strlen($data);
        if ($len === 0) {
            return 0;
        }
        if ($this->tFirst === 0.0) {
            $this->tFirst = microtime(true);
        }
        $this->wireBytes += $len;

        // 3xx 的正文("Redirecting to ...")永远不给客户端: 我们从不把 302 转出去。
        if ($this->respStatus >= 300 && $this->respStatus < 400 && $this->respStatus !== 304) {
            if ($this->discard) {
                $this->appendHead($len < self::SNIFF_BYTES ? $data : substr($data, 0, self::SNIFF_BYTES));
            }

            return $len;
        }

        if ($this->discard) {
            // Phase R: 只留够判"假 200"的头, 其余丢弃, 绝不进客户端。到量就主动中止,
            // 这样即使上游无视 Range 回全量(实测 codeload 就是), 探测也只花 64KB。
            $this->appendHead($data);
            if ($this->wireBytes >= $this->discardCap) {
                $this->probeTruncated = true;

                return 0;
            }

            return $len;
        }

        if (!$this->gateOpen) {
            $this->appendHead($data);
            if (strlen($this->head) >= $this->gateTarget) {
                if (!$this->openGate()) {
                    return 0;
                }
            }

            return $len;
        }

        // 体积上限: 先截断到允许的部分再中止。宁可给一个不完整但长度自洽的响应 +
        // oversize 观测(权重 0, 不怪源), 也不能突破 limits.per_request_bytes。
        if ($this->maxBytes > 0 && $this->clientBytes + $len > $this->maxBytes) {
            $allow = $this->maxBytes - $this->clientBytes;
            if ($allow > 0) {
                $this->push(substr($data, 0, $allow));
            }
            $this->oversize = true;
            // 缓存的收尾交给 streamPhase: 这里只中止传输。半途的 .part 由 finishCache(bad) 丢弃,
            // 在回调里做落地决策会让"已提交字节数"与 meta.bytes 不一致, 那正好造出一个坏条目。
            return 0;
        }

        return $this->push($data) ? $len : 0;
    }

    private function appendHead(string $data): void
    {
        $room = $this->gateTarget + self::FASTPATH_MAX_BYTES - strlen($this->head);
        if ($room <= 0) {
            return;
        }
        // 缓冲有上限: head 同时承担嗅探与 fast-path 复用两件事, 上限都在常量里,
        // 所以"大文件峰值内存恒定"这件事不依赖调用方传对了 max_bytes。
        $this->head .= strlen($data) <= $room ? $data : substr($data, 0, $room);
    }

    private function onProgress(int $downloaded): int
    {
        $elapsed = (microtime(true) - $this->tStart) * 1000.0;
        if ($this->progress !== null && is_callable($this->progress)) {
            // 进度回调里的异常不能冒出去: PHP 会把它变成"回调返回值未定义"进而中断传输且
            // 报一个看不懂的 curl 错误, 统计崩了不该让下载崩。
            try {
                ($this->progress)($downloaded, $elapsed);
            } catch (\Throwable) {
            }
        }
        if ($this->maxBytes > 0 && $downloaded > $this->maxBytes) {
            $this->oversize = true;

            return 1;
        }
        // 预算只约束"建流": 一旦已经向客户端交出过字节, 掐断wall-clock 就是在杀死一条
        // 正在健康推进的大文件下载。实测证据: 16MB 归档在直接调用时完整成功, 经选路的
        // 按预测耗时算出的 1.5s 预算里却每次都在几百 KB 处被切。
        // 死链路交给 CURLOPT_LOW_SPEED_LIMIT/TIME 判, 那才是与"有没有在推进"挂钩的信号。
        if ($this->budgetMs > 0.0 && !$this->gateOpen && $elapsed > $this->budgetMs) {
            $this->budgetHit = true;

            return 1;
        }

        return 0;
    }

    /**
     * 开闸: 判假 200 -> 发表头 -> 补发 .part 前缀 -> 发已缓冲的字节。
     * 返回 false 表示必须中止这次传输(假内容 / 客户端已断 / 超体积)。
     *
     * $force 由"上游已经没有任何字节要来"的路径(小 body、HEAD、传输结束)传入:
     * 嗅探门必须有"凑不满也要判"的出口, 否则一个 200 字节的文件永远发不出去。
     */
    private function openGate(bool $force = false): bool
    {
        if ($this->gateOpen) {
            return true;
        }
        $ref = $this->ref;
        $src = $this->src;
        if ($ref === null || $src === null) {
            return false;
        }
        $st = $this->respStatus;
        $ct = (string) ($this->respHeaders['content-type'] ?? '');
        $cl = (int) ($this->respHeaders['content-length'] ?? 0);

        // 缓冲够一个判定窗口才继续: 声明长度小于阈值的小 body 要等它整份到齐,
        // 否则会拿半个文件去判魔数。
        $need = $cl > 0 ? min($cl, $this->gateTarget) : $this->gateTarget;
        if (!$force && strlen($this->head) < $need) {
            return true;
        }

        // 只在"整份响应"上嗅探。206 是从文件中间切出来的, 本来就不带 ZIP/GZIP 魔数,
        // 拿它判假 200 会把每一个合法分片请求都判成源故障。
        if ($st === 200) {
            $complete = $cl > 0 ? strlen($this->head) >= $cl : $force;
            // API JSON 的判定必须读完整份文档: 512 字节的截断 JSON 无法解析,
            // 在半截上判 wrong_content 会把所有大 JSON 响应都误杀。
            if ($ref->scene !== Scene::ApiJson || $complete) {
                if (UpstreamResult::looksLikeWrongContent($ref->scene, $this->head, $ct)) {
                    $this->fakeContent = true;

                    return false;
                }
            }
        }

        // 响应头就绪、内容形态已判定、尚未向客户端发出一个字节 —— 这是新建缓存 writer 的
        // 唯一安全时机(见 prepareWriter 的注释)。
        $this->prepareWriter();

        $this->emitNow($st, $ref, $src, false);
        $this->gateOpen = true;

        if ($this->resumeFrom > 0 && !$this->replayPrefix()) {
            return false;
        }

        if ($this->head !== '') {
            $bytes = $this->head;
            $this->head = '';

            return $this->push($bytes);
        }

        return true;
    }

    /** 组装并立刻发出要给客户端的状态码与头。此后不可能再回退。 */
    private function emitNow(int $status, GitHubRef $ref, Source $src, bool $fromProbe): void
    {
        $variant = $ref->allowRange ? 'full' : 'norng';
        $etag = (string) ($this->opts['etag'] ?? '');
        if ($etag === '' && $ref->cacheEligible() && $status >= 200 && $status < 300 && $status !== 204) {
            // 自造 ETag, 与 Cache\Store::begin() 用同一个 variant 规则, 保证"边下边存"与
            // "命中直出"两次给客户端的 ETag 相同 —— 否则客户端第二次带 If-None-Match 来
            // 会撞出一个谁也对不上的第三态。
            $etag = $this->policy->etagFor(Key::of($ref), $variant);
        }

        $opts = [
            'range_requested' => (string) ($this->opts['range'] ?? '') !== '',
            'range_supported' => $this->rangeSupported($ref),
            'etag'            => $etag,
            'diag'            => (array) ($this->opts['diag'] ?? []),
            'diag_visible'    => (bool) ($this->opts['diag_visible'] ?? false),
            'download_name'   => (string) ($this->opts['download_name'] ?? $ref->downloadName),
        ];
        if ($this->resumeFrom > 0) {
            // 续传时上游回的是 206 尾段, 客户端要的是整份文件: 状态与长度都必须改写成整份形态。
            $opts['content_length'] = $this->resumeTotal;
            $resp = $this->respHeaders;
            unset($resp['content-range']);
            $resp['content-length'] = (string) $this->resumeTotal;
            $this->headers->emit(200, $this->headers->response($ref, $src, 200, $resp, $opts));
        } else {
            $this->headers->emit($status, $this->headers->response($ref, $src, $status, $this->respHeaders, $opts));
        }
        $this->emitted = true;
        if (!$fromProbe) {
            Http::noBuffering(); // 必须在第一个字节之前清缓冲, 否则前面全白做
        }
    }

    /**
     * 能不能向客户端承诺 Accept-Ranges: bytes。
     *
     * 只有实测支持才注入。归档场景(allowRange=false)不注入, 否则 aria2 会发起并发分片,
     * 而实测 codeload 对每一片都回全量 —— 用户看到的是"16 个分片各下一遍完整仓库"。
     */
    private function rangeSupported(GitHubRef $ref): bool
    {
        if (!$ref->allowRange) {
            return false;
        }
        if (array_key_exists(self::CAP_RANGE, $this->caps)) {
            return (bool) $this->caps[self::CAP_RANGE];
        }
        // 没做过 Phase R 时(直连 raw 场景)只能看这一条响应自己的证据。
        if (str_contains((string) ($this->respHeaders['content-range'] ?? ''), 'bytes ')) {
            return true;
        }

        return strtolower((string) ($this->respHeaders['accept-ranges'] ?? '')) === 'bytes';
    }

    /** 把一段字节交给客户端 + 旁路缓存 + 增量摘要。三件事必须同一份字节, 顺序无关但都不能漏。 */
    private function push(string $bytes): bool
    {
        if ($bytes === '') {
            return true;
        }
        // hashCtx 覆盖的是"交给客户端的字节", 续传时前缀确实也会发给客户端, 所以照常计入;
        // 只有下面这个文件写入必须跳过 —— 那批字节已经在 .part 里了。
        if ($this->hashCtx !== null) {
            hash_update($this->hashCtx, $bytes);
        }
        if (!$this->replaying && $this->writer !== null && !$this->writer->write($bytes)) {
            // 缓存写坏了不能连累下载: 丢掉这条缓存(下一次重新攒), 客户端照常收字节。
            $this->dropWriter();
        }
        if (!is_resource($this->sink)) {
            $this->clientAbort = true;

            return false;
        }
        $written = @fwrite($this->sink, $bytes);
        if ($written !== strlen($bytes)) {
            $this->clientAbort = true;

            return false;
        }
        $this->clientBytes += $written;
        @fflush($this->sink);

        return true;
    }

    /** 续传时把 .part 已有的前缀补发给客户端(常数内存分块读, 绝不整读)。 */
    private function replayPrefix(): bool
    {
        if ($this->writer === null || $this->resumeFrom <= 0) {
            return true;
        }
        $fh = @fopen($this->writer->partPath, 'rb');
        if ($fh === false) {
            $this->clientAbort = true;

            return false;
        }
        $left = $this->resumeFrom;
        $this->replaying = true;
        while ($left > 0) {
            $buf = fread($fh, (int) min(65536, $left));
            if ($buf === false || $buf === '') {
                break;
            }
            $left -= strlen($buf);
            if (!$this->push($buf)) {
                fclose($fh);
                $this->replaying = false;

                return false;
            }
        }
        fclose($fh);
        $this->replaying = false;

        return true;
    }

    // ------------------------------------------------------------------
    // 缓存旁路
    // ------------------------------------------------------------------

    /**
     * 决定这次要不要边下边存, 以及能不能续传已有 .part。
     *
     * 只在"客户端要整份、GET、200、体积已知"时缓存: 半份内容进缓存是此类系统最坏的故障
     * (第二次请求会把它当完整条目直出, 用户拿到一个静默截断的 zip)。
     *
     * 幂等, 且被刻意调用两次:
     *  - 请求之前: 只有已存在 .part 才可能成功(体积从旁路 meta 拿), 这决定续传要的 Range 偏移。
     *  - openGate 里响应头就绪之后: 这是 raw/archive 这类**没有预探测**的场景唯一能拿到
     *    Content-Length 的时机。早先版本只在请求前调用它, 于是那些场景的 total 恒为 0、
     *    mayCache 恒为 false —— EDGE 缓存对 raw 永远不会写入, 而 Release 反而"看起来正常"。
     */
    private function prepareWriter(): void
    {
        if ($this->writer !== null || $this->store === null || ($this->opts['cache'] ?? null) === false) {
            return;
        }
        $ref = $this->ref;
        $src = $this->src;
        if ($ref === null || $src === null) {
            return;
        }
        if (strtoupper((string) ($this->opts['method'] ?? Http::method())) !== 'GET') {
            return;
        }
        if ((string) ($this->opts['range'] ?? '') !== '') {
            return;
        }
        // respStatus 为 0 表示还在预请求阶段, 那时只有续传一条路可走。
        if ($this->respStatus >= 400 || $this->respStatus === 304) {
            return;
        }

        $peek = null;
        $total = $this->probeTotal > 0 ? $this->probeTotal : (int) ($this->respHeaders['content-length'] ?? 0);
        if ($total <= 0) {
            $peek = $this->store->peekPartial($ref);
            $total = (int) ($peek['expected_size'] ?? 0);
        }
        if ($total <= 0 || !$this->policy->mayCache($ref, $src, $total)) {
            return;
        }

        $w = $this->store->begin($ref, [
            'expected_size'          => $total,
            'content_type'           => (string) ($this->opts['content_type'] ?? ($this->respHeaders['content-type'] ?? '')),
            'status'                 => 200,
            'source_id'              => $src->id,
            'upstream_etag'          => (string) ($this->opts['upstream_etag'] ?? ($this->respHeaders['etag'] ?? '')),
            'upstream_last_modified' => (string) ($this->opts['upstream_last_modified'] ?? ($this->respHeaders['last-modified'] ?? '')),
            'range_spec'             => '',
            'verified_against'       => $ref->expectedSha256 !== '' ? 'client' : 'none',
        ]);
        if ($w === null) {
            return;
        }

        $this->hashCtx = hash_init('sha256');
        if ($w->receivedBytes > 0 && $w->expectedSize > $w->receivedBytes) {
            // 续传只在总体积已知时成立: 前缀 + 尾段必须刚好拼成声明的那份完整内容。
            $this->writer = $w;
            $this->resumeFrom = $w->receivedBytes;
            $this->resumeTotal = $w->expectedSize;

            return;
        }
        if ($w->receivedBytes > 0) {
            // 长度不明或已经写满, 这种 .part 拼不回一份自洽的完整文件, 只能作废重下。
            $w->discard();

            return;
        }
        $this->writer = $w;
    }

    /**
     * 收尾: 完整且校验通过才落地。
     *
     * 顺序不能换: 先 close/校验, 再决定 rename 还是 discard, 半途而废的 .part 绝不能被
     * 当成完整条目 —— 那会让下一次命中直接供出一份坏文件。
     */
    private function finishCache(?GitHubRef $ref, array &$detail, bool $bad): void
    {
        if ($this->writer === null || $ref === null) {
            return;
        }
        $sha = $this->hashCtx !== null ? hash_final($this->hashCtx) : '';
        $this->hashCtx = null;

        if ($bad) {
            $this->writer->close();
            $this->writer->discard();
            $this->writer = null;
            $detail['cache_committed'] = false;

            return;
        }

        // 客户端没断、体积对得上、(可选)sha256 与客户端给定值一致, 才有落地资格。
        $expected = $ref->expectedSha256;
        $verified = $expected !== '' && $sha !== '' && hash_equals($expected, $this->lower($sha));
        if ($expected !== '' && !$verified) {
            // 摘要不符: 丢弃缓存 + 让上层按 integrity 处理(权重 3.0 且直接降 trust)。
            $this->writer->close();
            $this->writer->discard();
            $this->writer = null;
            $this->integrityBad = true;
            $detail['integrity_ok'] = false;
            $detail['sha256'] = $sha;

            return;
        }

        $known = $this->writer->expectedSize;
        if ($known > 0 && $this->writer->receivedBytes !== $known) {
            // 上游少给了字节(chunked 或提前 EOF): 这份东西不完整, 不能进缓存。
            $this->writer->close();
            $this->writer->discard();
            $this->writer = null;
            $detail['cache_committed'] = false;

            return;
        }

        $entry = $this->store->commit($this->writer, $sha, $verified || $expected === '');
        $this->writer = null;
        if ($entry !== null) {
            $detail['entry'] = $entry;
            $detail['cache_committed'] = true;
            $detail['sha256'] = $sha;
        } else {
            $detail['cache_committed'] = false;
        }
    }

    private function dropWriter(): void
    {
        if ($this->writer !== null) {
            $this->writer->close();
            $this->writer->discard();
            $this->writer = null;
        }
    }

    private function lower(string $s): string
    {
        return strtolower(trim($s));
    }

    // ------------------------------------------------------------------
    // 失败分型
    // ------------------------------------------------------------------

    private function failureFromTransfer(array $res, GitHubRef $ref, int $status): FailureKind
    {
        // 自己的标记优先于 curl 的 errno: 主动中止在 curl 看来都是 WRITE_ERROR(23)/
        // ABORTED_BY_CALLBACK(42), 按它的表分类就会把"客户端断了"记成源的故障。
        if ($this->guardMismatch) {
            return FailureKind::GuardRejected;
        }
        if ($this->clientAbort) {
            return FailureKind::ClientAbort;
        }
        if ($this->oversize) {
            return FailureKind::Oversize;
        }
        if ($this->fakeContent) {
            return FailureKind::WrongContent;
        }
        if ($this->integrityBad) {
            return FailureKind::Integrity;
        }
        $errno = (int) $res['errno'];
        if ($errno !== 0) {
            if ($this->budgetHit) {
                return $this->clientBytes > 0 ? FailureKind::Stall : FailureKind::TimeoutTtfb;
            }

            return UpstreamResult::classifyCurl($errno, (string) $res['error']);
        }
        if ($status >= 400) {
            return $this->kindFromStatus($status, $ref);
        }
        if ($status >= 300) {
            // 30x 且不带 Location: 上游行为异常, 按连接类硬故障处理(它确实是链路问题)。
            return (string) ($res['error'] ?? '') !== '' ? FailureKind::Connect : FailureKind::Http5xx;
        }
        if ($status === 0) {
            return FailureKind::Connect;
        }

        return FailureKind::None;
    }

    private function kindFromStatus(int $status, GitHubRef $ref): FailureKind
    {
        if ($status === 429) {
            return FailureKind::RateLimited;
        }
        if ($status === 403 && $ref->scene === Scene::ApiJson) {
            // 实测 api.github.com 回的是"Request forbidden by administrative rule",
            // 语义上是被拦而不是被限速, 但同样必须停止换源: 换镜像接着刷 API 是全源被封
            // 最快的路径(而 ghfast 实测对 API 也回同一个 403, 换源连"可能成功"都没有)。
            return FailureKind::RateLimited;
        }
        if ($status === 401 || $status === 451 || $status === 403) {
            return FailureKind::Blocked;
        }
        if ($status >= 500) {
            return FailureKind::Http5xx;
        }

        return FailureKind::Http4xx;
    }

    private function abortResult(GitHubRef $ref, array $detail, FailureKind $kind): UpstreamResult
    {
        return new UpstreamResult(
            $kind,
            $this->respStatus > 0 ? $this->respStatus : (int) ($detail['probe_status'] ?? 0),
            $this->respHeaders,
            $this->clientBytes,
            $this->tFirst > 0.0 ? ($this->tFirst - $this->tStart) * 1000.0 : 0.0,
            (microtime(true) - $this->tStart) * 1000.0,
            (string) ($detail['final_url'] ?? ''),
            (string) ($detail['primary_ip'] ?? ''),
            (int) ($detail['hops'] ?? 0),
            0,
            $kind->value,
            $this->emitted,
            (array) ($detail['caps'] ?? []),
            $ref->downloadName
        );
    }

    /**
     * 单段 Range 的起点越过总体积时返回总体积(用于本地 416), 否则返回 null。
     *
     * Key::parseSingle 的约定要照用: 多段/非法返回 null, 后缀式返回 [-1, -n], 开区间端点是 -1。
     * 这几种一律不在本地判: 猜错一次的代价是给客户端一个错误的 416, 而那本来是上游该说的话。
     */
    private function unsatisfiableTotal(string $range, int $total): ?int
    {
        if ($range === '' || $total <= 0) {
            return null;
        }
        $single = Key::parseSingle($range);
        if ($single === null) {
            return null; // 多段 Range: 交给上游, 连 boundary 都得是它说了算
        }
        $start = (int) $single[0];
        if ($start < 0) {
            return null; // 后缀 Range: 没有总体积就没有绝对偏移, 由上游判
        }
        if ($start >= $total) {
            return $total;
        }

        return null;
    }

    private function blankDetail(): array
    {
        return [
            'inner_url'     => '',
            'final_url'     => '',
            'primary_ip'    => '',
            'hops'          => 0,
            'probe_status'  => 0,
            'resp_headers'  => [],
            'caps'          => [],
            'total_size'    => 0,
            'etag'          => '',
            'last_modified' => '',
            'content_type'  => '',
            'probe_head'    => '',
            'probe_fake'    => false,
            'bytes'         => 0,
            'emitted'       => false,
            'stopped'       => false,
            'stop_result'   => null,
            'entry'         => null,
            'cache_committed' => false,
            'sha256'        => '',
            'integrity_ok'  => true,
            'ttfb_ms'       => 0.0,
            'fast_path'     => 0,
            'fast_path_used' => false,
            'error'         => '',
        ];
    }
}
