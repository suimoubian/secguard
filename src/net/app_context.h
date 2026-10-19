// 应用上下文:各模块共享的状态(寓言集第 38、39、41 讲)
//
// 这里放:
//   1. 全局句柄(配置、连接池、DAO、引擎、Redis、分布式防护、审计管道)
//   2. 登录爆破防护(单机内存足够:失败次数天然低频)
//   3. 请求进入检测引擎的翻译逻辑(把 HTTP 翻成待检文本,第 17 讲)
//
// 注意:限流与 IP 封禁已经移到 DistributedGuard(Redis 共享),
// 不在这一层做本地状态 —— 否则多实例部署时各限各的,等于没限。
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "cache/distributed_guard.h"
#include "cache/redis_client.h"
#include "db/audit_writer.h"
#include "db/connection_pool.h"
#include "db/dao.h"
#include "engine.h"
#include "util/config.h"

namespace secguard {

// 登录爆破防护:同一 用户名+IP 连续失败 N 次 -> 短暂锁定(第 43 讲)
// 放在本地:登录失败是低频事件,不需要跨实例共享;
// 即便多实例各锁各的,也只是锁定时间略有差异,不影响安全性。
class LoginThrottle {
public:
    // 记一次失败。返回 true 表示已达上限,应锁定。
    bool record_fail(const std::string& key, int window_sec, int limit);
    void clear(const std::string& key);
    [[nodiscard]] bool is_locked(const std::string& key, int window_sec, int limit);

private:
    struct Rec {
        int    fails = 0;
        double first_fail = 0.0;
    };
    [[nodiscard]] static double now_sec();

    std::mutex mu_;
    std::unordered_map<std::string, Rec> recs_;
};

struct AppContext {
    Config           cfg;
    ConnectionPool*  pool = nullptr;
    Dao*             dao = nullptr;
    Engine*          engine = nullptr;
    RedisClient*     redis = nullptr;
    DistributedGuard* guard = nullptr;
    AuditWriter*     audit = nullptr;
    LoginThrottle*   login_throttle = nullptr;

    std::atomic<std::int64_t> requests_total{0};
    std::atomic<std::int64_t> requests_blocked{0};
    std::atomic<std::int64_t> replay_rejected{0};
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
