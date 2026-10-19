// 审计日志异步管道(寓言集第 28、35 讲)
//
// 做法:请求线程只把日志丢进无锁队列(纳秒级),后台线程批量落库。
// 攒够 N 条 或 距第一条满 T 秒,谁先到算谁。
//
// 代价:进程崩溃会丢队列里未落库的日志 —— 这是有意的取舍。
// 审计是旁路需求,不能反过来拖慢主链路。
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <thread>
#include <vector>

#include "db/dao.h"
#include "util/mpsc_queue.h"

namespace secguard {

struct AuditWriterConfig {
    // 容量是编译期常量(无锁队列要定长),这里只做运行期校验
    std::size_t batch_size = 500;         // 攒够多少条写一次
    int         flush_interval_ms = 1000; // 或满多久写一次
};

class AuditWriter {
public:
    static constexpr std::size_t kCapacity = 1 << 14;   // 队列 16384 条

    AuditWriter(Dao* dao, const AuditWriterConfig& cfg);
    ~AuditWriter();

    AuditWriter(const AuditWriter&) = delete;
    AuditWriter& operator=(const AuditWriter&) = delete;

    // 主链路调用:只入队,立即返回。队列满则丢弃并计数。
    void submit(const AuditLogRow& row);

    void start();

    // 停止:把队列里剩下的全部写完再退出(第 69 讲:收尾不能丢数据)
    void stop();

    [[nodiscard]] std::size_t dropped() const { return dropped_.load(); }
    [[nodiscard]] std::size_t written() const { return written_.load(); }
    [[nodiscard]] std::size_t queued() const { return queue_.size_approx(); }

private:
    void run();
    bool flush_batch(std::vector<AuditLogRow>& batch);

    Dao* dao_;
    AuditWriterConfig cfg_;
    MpscQueue<AuditLogRow, kCapacity> queue_;

    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::atomic<std::size_t> dropped_{0};
    std::atomic<std::size_t> written_{0};

    std::thread worker_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
};

}  // namespace secguard
