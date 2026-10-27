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

#include "ai/analyzer.h"
#include "ai/llm_client.h"
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

// ---------------------------------------------------------------------------
// 封禁请求的审计降采样
//
// 背景(实测数据):上线第二天被一个云凭据扫描器打了 3.3 万次,
// 命中规则后被封禁,但它继续刷了 7.5 小时,又发来 28,451 个请求。
// 这些请求每一条都写了一条审计 —— 占全库 79%,而且全是同一句话
// (action=BLOCK, rule_hit=IP_BANNED),没有任何信息量。
//
// 结果:审计表被垃圾撑大、AI 分析队列里塞满无意义记录、磁盘涨得快。
//
// 做法:同一个 IP 在被封禁期间,最多每 N 秒记一条审计。
// 请求照样拒绝(403)、照样计入 requests_blocked —— 只是不再逐条落库。
// 被压掉的条数记到 suppressed 计数器,/metrics 里能看到,不是悄悄丢。
//
// 为什么用内存 map 而不是 Redis:这是纯本地节流,不需要跨实例一致;
// 多实例各管各的,最多多记几条,不影响正确性。走 Redis 反而给每个被 ban
// 的请求加一次往返,与"封禁是为了省成本"的初衷相悖。
// ---------------------------------------------------------------------------
class BanAuditSampler {
public:
    // 返回 true = 这次应当写审计
    bool should_record(const std::string& ip, int interval_sec) {
        if (interval_sec <= 0) return true;      // 0 = 关掉采样

        const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

        std::lock_guard<std::mutex> lk(mu_);
        auto it = last_.find(ip);
        if (it != last_.end() && now - it->second < interval_sec) {
            ++suppressed_;
            return false;
        }
        // 防止 map 无限增长:攻击者可以换几万个 IP 来刷。
        // 超过上限直接清空 —— 代价是清空那一刻会多记几条,可以接受。
        if (last_.size() > 20000) last_.clear();
        last_[ip] = now;
        return true;
    }

    [[nodiscard]] std::int64_t suppressed() const { return suppressed_.load(); }

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::int64_t> last_;
    std::atomic<std::int64_t> suppressed_{0};
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
    LlmClient*       llm = nullptr;
    Analyzer*        analyzer = nullptr;
    BanAuditSampler* ban_sampler = nullptr;   // 可为 nullptr(不采样)

    std::atomic<std::int64_t> requests_total{0};
    std::atomic<std::int64_t> requests_blocked{0};
    // 只命中 ALERT 级规则、放行但留痕的次数。和 blocked 分开统计:
    // 两个数一起看才知道策略调得对不对(blocked 降、alerted 涨 = 正常)
    std::atomic<std::int64_t> requests_alerted{0};
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
