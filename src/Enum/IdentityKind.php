<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 定义资源身份类型。缓存资格与 TTL 只由它决定, 不允许靠"键前缀看起来像
 *             不可变"来猜 —— 脏缓存被长期服务的具体路径就是 (tag, filename) 当身份。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Enum;

/**
 * 一条资源引用有多少资格被称为"不可变"。
 *
 * 关键区分: 同名 Release 资产被作者重新上传时 asset_id 会变, 而 (tag, filename) 不变。
 * 只有前三种身份可以标 immutable 并享受长 TTL 与 EDGE 直出。
 */
enum IdentityKind: string
{
    /** 明确指向 40 位 commit sha 的 raw 引用或归档引用, 内容寻址 */
    case CommitSha = 'commit_sha';

    /** 数字 asset id 定位的 Release 资产, 比文件名稳 */
    case AssetId = 'asset_id';

    /** gist 的 revision sha */
    case GistRev = 'gist_rev';

    /** 分支名或 tag 名定位, 作者随时可移动, 实质可变 */
    case RefName = 'ref_name';

    /** api.github.com 的可变 JSON */
    case MutableApi = 'mutable_api';

    /** 无法判定, 例如 branch 与 tag 同名的歧义 */
    case Ambiguous = 'ambiguous';

    /** 内容寻址: 同一引用永远返回同一字节。 */
    public function isContentImmutable(): bool
    {
        return $this === self::CommitSha || $this === self::AssetId || $this === self::GistRev;
    }

    /** 是否有资格进入 EDGE 缓存并被直出。 */
    public function cacheEligible(): bool
    {
        return $this !== self::MutableApi && $this !== self::Ambiguous;
    }

    /**
     * 命中后的最大 fresh TTL(秒)。这是上限, 实际 TTL 再与 config 的场景表取小。
     * RefName 与 Ambiguous 被死死压在 120s: 陈旧分支内容对 Agent 是误导而非加速。
     */
    public function maxTtl(): int
    {
        return match ($this) {
            self::CommitSha  => 604800,
            self::AssetId    => 1209600,
            self::GistRev    => 86400,
            self::RefName    => 120,
            self::MutableApi => 30,
            self::Ambiguous  => 60,
        };
    }
}
