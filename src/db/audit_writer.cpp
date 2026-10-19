#include "db/audit_writer.h"

#include <chrono>

#include "util/log.h"

namespace secguard {
namespace {
constexpr const char* kTag = "[审计管道] ";
}

AuditWriter::AuditWriter(Dao* dao, const AuditWriterConfig& cfg)
    : dao_(dao), cfg_(cfg) {
    if (cfg_.batch_size == 0) cfg_.batch_size = 500;
    if (cfg_.batch_size > kCapacity) cfg_.batch_size = kCapacity;
    if (cfg_.flush_interval_ms <= 0) cfg_.flush_interval_ms = 1000;
    LOG_INFO(kTag, "初始化:队列容量=", kCapacity,
             " 批量=", cfg_.batch_size, " 间隔=", cfg_.flush_interval_ms, "ms");
}

AuditWriter::~AuditWriter() {
    stop();
}

void AuditWriter::start() {
    if (running_.exchange(true)) return;
    stop_requested_.store(false);
    worker_ = std::thread([this] { run(); });
}

void AuditWriter::submit(const AuditLogRow& row) {
    if (!running_.load()) return;
    if (!queue_.push(row)) {
        // 队列满:丢弃并计数。审计不能反压主链路(第 28 讲)
        dropped_.fetch_add(1);
    }
}

void AuditWriter::run() {
    std::vector<AuditLogRow> batch;
    batch.reserve(cfg_.batch_size);

    auto last_flush = std::chrono::steady_clock::now();

    while (!stop_requested_.load()) {
        AuditLogRow row;
        bool got = false;
        while (batch.size() < cfg_.batch_size && queue_.pop(row)) {
            batch.push_back(std::move(row));
            got = true;
        }

        const auto now = std::chrono::steady_clock::now();
        const auto since = std::chrono::duration_cast<std::chrono::milliseconds>(
                               now - last_flush).count();

        // 攒够一批,或者等够一个间隔,就写
        if (!batch.empty() && (batch.size() >= cfg_.batch_size
                               || since >= cfg_.flush_interval_ms)) {
            flush_batch(batch);
            batch.clear();
            last_flush = now;
        }

        if (!got) {
            // 没活干:小睡一会儿,别空转烧 CPU
            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait_for(lk, std::chrono::milliseconds(20), [this] {
                return stop_requested_.load();
            });
        }
    }

    // 收尾:把队列剩下的全部写完(第 69 讲)
    AuditLogRow row;
    while (queue_.pop(row)) {
        batch.push_back(std::move(row));
        if (batch.size() >= cfg_.batch_size) {
            flush_batch(batch);
            batch.clear();
        }
    }
    if (!batch.empty()) flush_batch(batch);

    LOG_INFO(kTag, "已停止:共写 ", written_.load(), " 条,丢弃 ", dropped_.load(), " 条");
}

bool AuditWriter::flush_batch(std::vector<AuditLogRow>& batch) {
    if (batch.empty()) return true;
    if (!dao_) return false;

    // 失败重试几次,还不行就丢弃并计数(别把队列堵死)
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (dao_->write_audit_batch(batch)) {
            written_.fetch_add(batch.size());
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50 * (attempt + 1)));
    }
    LOG_WARN(kTag, "落库失败,丢弃 ", batch.size(), " 条");
    dropped_.fetch_add(batch.size());
    return false;
}

void AuditWriter::stop() {
    if (!running_.exchange(false)) return;
    stop_requested_.store(true);
    {
        std::lock_guard<std::mutex> lk(mu_);
        cv_.notify_all();
    }
    if (worker_.joinable()) worker_.join();
}

}  // namespace secguard
