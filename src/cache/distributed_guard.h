// 分布式防护:令牌桶限流 / IP 封禁 / 重放防护(寓言集第 38、39、40、41 讲)
//
// 三件事都依赖"共享状态",所以都放 Redis:
//   限流   —— 多实例共享一份令牌,否则 3 个实例等于限额放大 3 倍
//   封禁   —— 在 A 实例上被封,不能换个实例就复活
//   重放   —— nonce 必须全局唯一
//
// 全部带降级:Redis 不可用时退回单机内存版并记日志,
// 宁可保护变弱,也不能让服务变哑。
#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "cache/redis_client.h"
#include "util/config.h"

namespace secguard {

// 一次请求的放行判定
enum class GuardDecision {
    kAllow,
    kRateLimited,
    kBanned,
};

class DistributedGuard {
public:
    DistributedGuard(RedisClient* redis, const GuardConfig& cfg);

    // ---- 封禁 + 限流:一次 Redis 往返搞定 ----
    //
    // 为什么合并:原来封禁检查一次、令牌桶一次,每请求两次往返。
    // 压测显示这两次往返就是吞吐瓶颈(2 核上 26k vs 关掉 Redis 70k)。
    // 封禁检查可以直接放进 token bucket 的 Lua 里,反正都是 read-only,
    // 而且"先看封没封,封着就不必再算令牌"本身也更省。
    GuardDecision check(const std::string& key_suffix);

    // 兼容接口:只要"放不放行"的结论
    bool allow(const std::string& key_suffix);

    // ---- IP 封禁:滑动窗口计数 ----
    // 记一次命中;返回 true 表示因此触发封禁
    bool record_hit(const std::string& ip, int threshold, int window_sec, int ban_sec);
    [[nodiscard]] bool is_banned(const std::string& ip);
    [[nodiscard]] int hits_in_window(const std::string& ip, int window_sec);

    // ---- 重放防护:nonce + timestamp ----
    // 检查并占用一个 nonce。返回 true 表示第一次见到(放行),
    // false 表示已经用过(重放)或校验失败。
    bool consume_nonce(const std::string& nonce, int ttl_sec);
    // 校验时间戳是否在窗口内
    [[nodiscard]] static bool timestamp_fresh(std::int64_t ts_sec, int window_sec);

    // ---- 状态 ----
    [[nodiscard]] bool redis_available() const;
    [[nodiscard]] long long fallback_count() const { return fallback_count_; }

private:
    // 降级用的单机状态
    struct LocalBucket {
        double tokens = 0.0;
        double last = 0.0;
    };
    struct LocalIp {
        std::vector<double> hits;
        double banned_until = 0.0;
    };

    bool allow_local(const std::string& key_suffix);
    GuardDecision check_local(const std::string& key_suffix);
    [[nodiscard]] static double now_sec();

    RedisClient* redis_ = nullptr;
    GuardConfig cfg_;

    mutable std::mutex mu_;
    std::unordered_map<std::string, LocalBucket> local_buckets_;
    std::unordered_map<std::string, LocalIp> local_ips_;
    std::unordered_map<std::string, double> local_nonces_;
    long long fallback_count_ = 0;
};

}  // namespace secguard
