<?php
/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 并发槽。用 lock-slot 文件数组表达"当前有几个请求在跑", 超出的请求直接
 *             503 而不是排队把 worker 占满。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 */

declare(strict_types=1);

namespace GhAccel\Security;

/**
 * 为什么是 N 个锁文件而不是一个计数器文件:
 * 计数器(读 n / 写 n+1)在 PHP-CGI 崩溃、请求超时被强杀、进程 OOM 时会留下永久漂移的
 * 计数 —— 少减一次就永久少一个槽, 跑几天后并发数归零, 而且看不出原因。
 * 锁文件的生命周期绑在 fd 上: 进程一死(无论什么原因)内核自动释放锁, 槽位自己回到池里。
 * 本机 sysvsem 扩展缺失也印证了"信号量不能当依赖"。
 *
 * 一个进程实例同时只持有一个槽: acquire() 可重入(返回已持有的 index), release() 幂等。
 */
final class Slots
{
    /** @var array<int, resource>|null */
    private ?array $handles;

    private int $index = -1;

    /**
     * @param string $root 项目根, 槽文件写在 var/concurrency/
     * @param int    $count 槽数, 建议 pm.max_children * 0.8: 超过 children 数就没人执行
     *                        释放, 反而把并发压力换成超时。
     */
    public function __construct(private readonly string $root, private readonly int $count)
    {
        $this->handles = [];
    }

    /**
     * 占用一个槽。
     *
     * @return int|null 槽号; null 表示并发已满, 调用方应立刻回 503 + Retry-After
     */
    public function acquire(): ?int
    {
        if ($this->index >= 0) {
            // 可重入: 同一次请求里 cache/transport 都调 acquire 不该把槽吃成 2。
            return $this->index;
        }

        $count = max(1, $this->count);
        $dir = $this->root . '/var/concurrency';
        if (!is_dir($dir) && !@mkdir($dir, 0770, true) && !is_dir($dir)) {
            // 目录建不出来(权限或只读盘): 此时限并发已经没有意义, 放行比报错好。
            return $this->index = 0;
        }

        for ($i = 0; $i < $count; $i++) {
            $file = $this->slotFile($i);
            $fh = @fopen($file, 'c');
            if ($fh === false) {
                continue;
            }
            if (@flock($fh, LOCK_EX | LOCK_NB)) {
                $this->handles[$i] = $fh;
                $this->index = $i;

                return $i;
            }
            fclose($fh);
        }

        return null;
    }

    /** 释放槽。显式 flock(LOCK_UN) + fclose: 只 fclose 在部分平台会延后到 GC 才解锁。 */
    public function release(): void
    {
        if ($this->index < 0) {
            return;
        }
        $fh = $this->handles[$this->index] ?? null;
        unset($this->handles[$this->index]);
        if (is_resource($fh)) {
            @flock($fh, LOCK_UN);
            @fclose($fh);
        }
        $this->index = -1;
    }

    /**
     * 当前占用数(瞬时观测值)。
     *
     * 探测本身会给每个空闲槽上一次锁再立刻放开, 所以这是"面板用"的近似值: 恰好用到
     * 满前一格时可能多算 1。热路径不调用它 —— 面板与 selftest 才是它的读者。
     */
    public function used(): int
    {
        $n = 0;
        $count = max(1, $this->count);
        for ($i = 0; $i < $count; $i++) {
            $file = $this->slotFile($i);
            if (!is_file($file)) {
                continue;
            }
            $fh = @fopen($file, 'c');
            if ($fh === false) {
                $n++;
                continue;
            }
            if (@flock($fh, LOCK_EX | LOCK_NB) === false) {
                $n++;
            } else {
                @flock($fh, LOCK_UN);
            }
            fclose($fh);
        }

        return $n;
    }

    /** 自己是否持有槽。 */
    public function held(): bool
    {
        return $this->index >= 0;
    }

    public function count(): int
    {
        return max(1, $this->count);
    }

    /** 进程退出时兜底释放; 真的崩了也没关系, 锁由内核回收。 */
    public function __destruct()
    {
        $this->release();
    }

    private function slotFile(int $i): string
    {
        return sprintf('%s/var/concurrency/slot_%02d', $this->root, $i);
    }
}
