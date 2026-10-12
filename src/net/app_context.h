// 应用上下文:各模块共享的状态 + 中间件(寓言集第 38、39、41 讲)
//
// 这里放三样东西:
//   1. 全局句柄(配置、连接池、DAO、引擎)
//   2. 限流与封禁状态(令牌桶 + 滑动窗口计数,第 38、41 讲)
//   3. 请求进入检测引擎的翻译逻辑(把 HTTP 翻成待检文本,第 17 讲)
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "db/connection_pool.h"
#include "db/dao.h"
#include "engine.h"
#include "util/config.h"

namespace secguard {

// 令牌桶:rate 控制平均速率,capacity 控制允许的突发(第 38 讲)
class TokenBucket {
public:
    TokenBucket(double rate_per_sec, double capacity)
        : rate_(rate_per_sec), capacity_(capacity), tokens_(capacity), last_(0.0) {}

    // 取一个令牌;拿不到返回 false(该限流了)
    // now_seconds:由 AppContext::now_seconds() 提供的秒数(无需是绝对时间,单调即可)
    bool try_acquire(double now_seconds) {
        std::lock_guard<std::mutex> lk(mu_);
        if (last_ == 0.0) last_ = now_seconds;      // 第一次调用时初始化
        const double elapsed = now_seconds - last_;
        // 惰性补给:不靠定时器,用的时候现算
        tokens_ = std::min(capacity_, tokens_ + elapsed * rate_);
        last_ = now_seconds;
        if (tokens_ >= 1.0) { tokens_ -= 1.0; return true; }
        return false;
    }

private:
    double rate_;
    double capacity_;
    double tokens_;
    double last_;
    std::mutex mu_;
};

// 命中计数窗口:同一 IP 在 window 秒内命中 N 次 -> 封禁 ban 秒(第 41 讲)
struct IpRecord {
    std::vector<double> hits;      // 命中时间戳
    double banned_until = 0.0;
    int    login_fails = 0;
    double login_fail_first = 0.0;
};

class Guard {
public:
    Guard() = default;

    // 记一次命中。返回是否因此触发封禁。
    bool record_hit(const std::string& ip, double now, int window_sec,
                    int threshold, int ban_sec);
    [[nodiscard]] bool is_banned(const std::string& ip, double now);
    [[nodiscard]] int  banned_count(double now);
    [[nodiscard]] int  hits_in_window(const std::string& ip, double now, int window_sec);

    // 登录失败计数(第 43 讲:防爆破)
    bool record_login_fail(const std::string& key, double now, int window_sec, int limit);
    void clear_login_fail(const std::string& key);

private:
    std::mutex mu_;
    std::unordered_map<std::string, IpRecord> recs_;
    double last_gc_ = 0.0;
};

struct AppContext {
    Config          cfg;
    ConnectionPool* pool = nullptr;
    Dao*            dao = nullptr;
    Engine*         engine = nullptr;
    Guard*          guard = nullptr;
    TokenBucket*    limiter = nullptr;

    std::atomic<std::int64_t> requests_total{0};
    std::atomic<std::int64_t> requests_blocked{0};
    std::chrono::steady_clock::time_point started_at{std::chrono::steady_clock::now()};

    [[nodiscard]] double now_seconds() const {
        using namespace std::chrono;
        return duration<double>(steady_clock::now() - started_at).count();
    }
};

// ---------------------------------------------------------------------------
// 把 HTTP 请求翻译成"待检文本"(第 17 讲)
//
// 三条硬要求:
//   1. 分段拼接,段与段之间不算相邻 —— 否则会造出请求里没有的相邻关系(假命中)
//   2. 每段都有长度上限,超长截断
//   3. 引擎不认识 HTTP,这一层负责翻译
// ---------------------------------------------------------------------------
[[nodiscard]] std::string build_scan_text(const std::string& path,
                                          const std::string& query,
                                          const std::string& body,
                                          const std::string& user_agent,
                                          std::size_t max_bytes,
                                          bool& truncated);

// 请求参数摘要(脱敏后),落 audit_log.params_digest(第 29、49 讲)
[[nodiscard]] std::string build_params_digest(const std::string& query,
                                              const std::string& body);

// 从 Authorization 头里取出 Bearer 令牌
[[nodiscard]] std::string extract_bearer(const std::string& authorization);

// 生成 trace_id
[[nodiscard]] std::string make_trace_id();

}  // namespace secguard
