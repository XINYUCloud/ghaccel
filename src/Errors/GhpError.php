<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 全部对外错误码与 application/problem+json 载荷。本项目的相当一部分用户是
 *             AI Agent, 所以错误必须机器可解析、可决策(下一步该等、该换链接、还是放弃),
 *             不能只给一段人看的 HTML。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Errors;

/**
 * 用法: throw GhpError::make(GhpError::HOST_NOT_ALLOWED, '...')
 * 顶层 catch 后调用 ->toProblem($requestId) 输出。
 */
final class GhpError extends \RuntimeException
{
    // ---- 入参与路由 (400) ----
    public const URL_TOO_LONG        = 'url_too_long';
    public const UNPARSEABLE         = 'unparseable_url';
    public const BACKSLASH_IN_URL    = 'backslash_in_url';
    public const USERINFO_NOT_ALLOWED = 'userinfo_not_allowed';
    public const NUMERIC_HOST_LITERAL = 'numeric_host_literal';
    public const ILLEGAL_HOST_CHARS  = 'illegal_host_chars';
    public const PATH_TRAVERSAL      = 'path_traversal';
    public const AMBIGUOUS_REF       = 'ambiguous_ref';
    public const UNSUPPORTED_METHOD  = 'unsupported_method';

    // ---- 安全判定 (403) ----
    public const HOST_NOT_ALLOWED    = 'host_not_allowed';
    public const IP_DENIED           = 'ip_denied';
    public const SCHEME_NOT_ALLOWED  = 'scheme_not_allowed';
    public const PORT_NOT_ALLOWED    = 'port_not_allowed';
    public const REDIRECT_LOOP       = 'redirect_loop';
    public const UA_REQUIRED         = 'ua_required';
    public const UA_BLOCKED          = 'ua_blocked';
    public const GUARD_MISMATCH      = 'ssrf_audit_mismatch';
    /** owner/repo 被部署者下架。用于被投诉时的实际处置手段, 也是一个可核查的合规姿态。 */
    public const REPO_TAKEN_DOWN     = 'repo_taken_down';

    // ---- 配额与限流 (429 / 503) ----
    public const RATE_LIMITED        = 'rate_limited';
    public const UPSTREAM_RATE_LIMITED = 'upstream_rate_limited';
    public const QUOTA_EXCEEDED      = 'quota_exceeded';
    public const OVERSIZE            = 'oversize';
    public const OVERLOADED          = 'overloaded';

    // ---- 路由与源池 (409 / 502 / 503) ----
    public const NO_ELIGIBLE_SOURCE  = 'no_eligible_source';
    public const MODE_UNSUPPORTED    = 'mode_not_supported_in_v1';
    public const SPLIT_REQUIRES_CACHED = 'split_requires_cached';
    public const BREAKER_ALL_OPEN    = 'all_sources_tripped';

    // ---- 上游结果 (404 / 502 / 504) ----
    public const UPSTREAM_NOT_FOUND  = 'upstream_not_found';
    public const UPSTREAM_FAILED     = 'upstream_failed';
    public const REDIRECT_TOO_MANY   = 'redirect_too_many';
    public const UPSTREAM_TIMEOUT    = 'upstream_timeout';
    public const TLS_VERIFY_FAILED   = 'tls_verify_failed';

    // ---- 完整性 (422) ----
    public const INTEGRITY_MISMATCH  = 'integrity_mismatch';
    public const CONTENT_DIVERGENCE  = 'content_divergence';
    public const WRONG_CONTENT       = 'wrong_content';

    // ---- 面板与会话 (401 / 403 / 404) ----
    public const UNAUTHENTICATED     = 'unauthenticated';
    public const CSRF_FAILED         = 'csrf_failed';
    public const SCOPE_REQUIRED      = 'scope_required';
    public const CONFIRM_REQUIRED    = 'confirm_required';
    public const NOT_FOUND           = 'not_found';
    /**
     * 面板写接口的入参校验失败。必须在这里声明: 未声明的码会回落到 500 + "未知错误",
     * 于是"你把 hosts 填错了"在面板上显示成服务端故障, 运维会去查日志而不会改表单。
     */
    public const INVALID_ARGUMENT    = 'invalid_argument';
    /**
     * 兜底内部错误。也必须登记: 未登记的码会回落成 status()=500 且 title()="未知错误",
     * 于是面板弹出"未知错误"而运维不知道该做什么。标题写清楚"去看服务端日志 + 带 request_id",
     * 才是这条兜底分支该有的样子。
     */
    public const INTERNAL_ERROR      = 'internal_error';

    /** @var array<string, array{status:int, title:string, retryable:bool, hint:string}> */
    private const CATALOG = [
        self::URL_TOO_LONG => [400, 'URL 过长', false, '把超长 query 精简后重试, 或改用 ?u= 形式。'],
        self::UNPARSEABLE => [400, '无法解析目标 URL', false, '确认加速前缀后面跟的是完整可解析的 GitHub URL。'],
        self::BACKSLASH_IN_URL => [400, 'URL 含反斜杠', false, '反斜杠会让不同 URL 解析器对域名归属产生分歧, 一律拒绝。'],
        self::USERINFO_NOT_ALLOWED => [400, 'URL 不允许含凭据段', false, '去掉 https://user@host 形式的 userinfo; 该写法是 SSRF 绕过的常见入口。'],
        self::NUMERIC_HOST_LITERAL => [400, '不接受数字形式的 host', false, '请使用域名。十进制/八进制/十六进制整型 IP 写法会被拒。'],
        self::ILLEGAL_HOST_CHARS => [400, 'host 含非法字符', false, 'host 只允许 LDH(字母、数字、连字符、点)。'],
        self::PATH_TRAVERSAL => [400, '路径穿越', false, '路径中不允许出现 . 或 .. 段。'],
        self::AMBIGUOUS_REF => [400, '引用名歧义', false, '分支名含 / 时请用完整写法 refs/heads/xxx 或 refs/tags/xxx。'],
        self::UNSUPPORTED_METHOD => [405, '只支持 GET 与 HEAD', false, '本接口是只读加速网关, 不接受 POST/PUT/DELETE。'],

        self::HOST_NOT_ALLOWED => [403, '目标域名不在白名单', false, '只代理 GitHub 官方域名。这是本项目的安全边界, 不可放开。'],
        self::IP_DENIED => [403, '目标解析到受保护地址', false, '解析结果为内网/环回/链路本地/云元数据地址, 已拒绝。'],
        self::SCHEME_NOT_ALLOWED => [403, '只允许 https', false, '上游一律使用 https, 不接受降级。'],
        self::PORT_NOT_ALLOWED => [403, '端口不允许', false, '只允许 443 与 80。'],
        self::REDIRECT_LOOP => [403, '重定向指回本机前缀', false, '检查源配置, 加速地址不应指回本网关。'],
        self::UA_REQUIRED => [403, '必须携带 User-Agent', false, '匿名扫描器一律拒绝, 请在请求里设置可识别的 UA。'],
        self::UA_BLOCKED => [403, 'User-Agent 被拒绝', false, '若你是下载工具被误杀, 请管理员把 UA 移出黑名单配置。'],
        self::GUARD_MISMATCH => [502, '实际连接地址与校验结果不一致', false, 'DNS 重绑定或解析器分歧的征兆, 本次请求已中止并在面板告警。'],
        self::REPO_TAKEN_DOWN => [403, '该仓库已被部署者下架', false, '此 owner/repo 在 var/state/blocklist.json 的下架清单里。恢复请移除条目, 已落地的缓存需另行清理。'],

        self::RATE_LIMITED => [429, '请求过于频繁', true, '按 Retry-After 等待后重试, 不要紧密循环。大文件请改用 ?part= 分片(需先有一次完整缓存)。'],
        self::UPSTREAM_RATE_LIMITED => [429, '上游或镜像已限速', true, '已停止切换其他源继续请求。换源硬刷会让所有源同时被封。'],
        self::QUOTA_EXCEEDED => [429, '本 IP 流量配额已用完', true, '配额按小时/日补充。或改为自带 302 模式以省下本机带宽。'],
        self::OVERSIZE => [413, '超出单请求体积上限', false, '提高 limits.per_request_bytes, 或配置可信大文件源并放宽其 max_size_bytes。'],
        self::OVERLOADED => [503, '并发已满', true, '并发槽耗尽。该结果不计入源健康度, 稍后重试即可。'],

        self::NO_ELIGIBLE_SOURCE => [503, '没有符合条件的加速源', true, '面板决策视图已列出每个源被剔除的原因码, 按原因放开源或补配置。'],
        self::MODE_UNSUPPORTED => [400, '该模式 v1 未实现', false, 'hedge 竞速在 v2 提供, 请去掉 mode=hedge 改用默认 failover。'],
        self::SPLIT_REQUIRES_CACHED => [409, '分片请求需要缓存命中', true, '未缓存时分片会把同一文件向源拉 N 次。请先完整取一次(不带 part), 再分片并发。'],
        self::BREAKER_ALL_OPEN => [503, '全部源处于熔断', true, '面板可对单个源手动复位熔断或立即探活。'],

        self::UPSTREAM_NOT_FOUND => [404, '资源不存在', false, 'GitHub 返回 404。确认 owner/repo/ref/path 与大小写。'],
        self::UPSTREAM_FAILED => [502, '所有源均未能取回资源', true, '诊断 JSON 里有每个源的具体失败分型, 据此判断是配置还是链路问题。'],
        self::REDIRECT_TOO_MANY => [502, '重定向跳数超限', true, '正常链路最多 2 跳, 超过说明上游结构变化, 需更新白名单。'],
        self::UPSTREAM_TIMEOUT => [504, '上游超时', true, '整条 failover 的时间预算耗尽。可适当提高 budgets.max_total_ms。'],
        self::TLS_VERIFY_FAILED => [502, 'TLS 证书校验失败', true, '该源证书或证书链异常, 已按源侧故障处理, 不会关闭校验绕过。'],

        self::INTEGRITY_MISMATCH => [422, 'sha256 校验不一致', false, '下载内容与期望摘要不符, 结果已丢弃且未进缓存。请核对校验值来源。'],
        self::CONTENT_DIVERGENCE => [422, '不同源返回内容不一致', true, '同一不可变引用出现分歧, 涉及源已降级。宁可失败也不猜哪个是对的。'],
        self::WRONG_CONTENT => [502, '源返回了疑似错误页', true, '源以假 200 回了 HTML, 已按源侧故障处理, 未写入缓存。'],

        self::UNAUTHENTICATED => [401, '未认证', false, '用 bin/token.php 签发的管理 Token 登录。'],
        self::CSRF_FAILED => [403, 'CSRF 校验未通过', false, '请求需带 X-CSRF-Token 且 Origin/Sec-Fetch-Site 与配置的同源基准一致。'],
        self::SCOPE_REQUIRED => [403, '令牌缺少 write 作用域', false, '当前令牌只读, 请签发带 write 的令牌。'],
        self::CONFIRM_REQUIRED => [428, '需要显式确认', false, '该操作有破坏性, 请在请求体里加 confirm:true。'],
        self::INVALID_ARGUMENT => [422, '入参校验未通过', false, '按 detail 里的字段名改正后重提; 这是表单问题而不是服务故障。'],
        self::INTERNAL_ERROR => [500, '内部错误', false, '带上 request_id 查服务端日志。响应里刻意不含异常类型、路径与堆栈。'],
        self::NOT_FOUND => [404, '不存在', false, '面板未登录时统一返回 404, 不暴露"这里有个面板"。'],
    ];

    /**
     * 注意属性名不能叫 $code: \Exception 已有非 readonly 的 $code, 子类重新声明会直接
     * 致命错误(Fatal error: Cannot redeclare non-readonly property Exception::$code)。
     */
    public function __construct(
        public readonly string $errorCode,
        string $detail = '',
        public readonly array $context = [],
        ?\Throwable $previous = null
    ) {
        parent::__construct($detail !== '' ? $errorCode . ': ' . $detail : $errorCode, 0, $previous);
    }

    public static function make(string $code, string $detail = '', array $context = [], ?\Throwable $previous = null): self
    {
        return new self($code, $detail, $context, $previous);
    }

    public function status(): int
    {
        return self::CATALOG[$this->errorCode][0] ?? 500;
    }

    public function title(): string
    {
        return self::CATALOG[$this->errorCode][1] ?? '未知错误';
    }

    public function retryable(): bool
    {
        return self::CATALOG[$this->errorCode][2] ?? false;
    }

    public function hint(): string
    {
        return self::CATALOG[$this->errorCode][3] ?? '';
    }

    /** 建议的重试间隔秒, 只有重试型错误才有。 */
    public function retryAfter(): ?int
    {
        return isset($this->context['retry_after']) ? max(1, (int) $this->context['retry_after']) : null;
    }

    /**
     * RFC7807 风格的问题详情。type 用固定字符串枚举而不引真实 URI,
     * 避免 Agent 去解析一个不存在的文档地址。
     */
    public function toProblem(string $requestId, string $typeBase = 'error'): array
    {
        $problem = [
            'type'       => $typeBase . '/' . $this->errorCode,
            'title'      => $this->title(),
            'status'     => $this->status(),
            'code'       => $this->errorCode,
            'retryable'  => $this->retryable(),
            'request_id' => $requestId,
        ];

        $detail = $this->getMessage();
        if ($detail !== $this->errorCode) {
            $problem['detail'] = $detail;
        }
        if ($this->hint() !== '') {
            $problem['hint'] = $this->hint();
        }
        if ($this->context !== []) {
            $problem['context'] = self::scrub($this->context);
        }
        $ra = $this->retryAfter();
        if ($ra !== null) {
            $problem['retry_after'] = $ra;
            $problem['next_action'] = ['kind' => 'wait', 'seconds' => $ra];
        }

        return $problem;
    }

    /**
     * 错误上下文不得泄露服务器路径、Token、真实上游最终地址与解析到的 IP。
     * final_url 一类的值只在管理员 debug 会话下由 Headers 层单独注入, 不走这里。
     */
    public static function scrub(array $context): array
    {
        $drop = ['token', 'password', 'secret', 'csrf', 'path', 'file', 'final_url', 'primary_ip', 'server', 'auth'];
        $out = [];
        foreach ($context as $k => $v) {
            $low = strtolower((string) $k);
            $hit = false;
            foreach ($drop as $d) {
                if (str_contains($low, $d)) {
                    $hit = true;
                    break;
                }
            }
            if ($hit) {
                continue;
            }
            $out[$k] = is_array($v) ? self::scrub($v) : (is_string($v) ? substr($v, 0, 300) : $v);
        }

        return $out;
    }

    /** 面向人类浏览器的错误页文案(仍然只含安全字段)。 */
    public function safeMessage(): string
    {
        return $this->title();
    }

    public static function exists(string $code): bool
    {
        return isset(self::CATALOG[$code]);
    }
}
