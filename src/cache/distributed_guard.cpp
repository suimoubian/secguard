#include "cache/distributed_guard.h"

#include <algorithm>
#include <chrono>

#include "util/log.h"

namespace secguard {
namespace {

constexpr const char* kTag = "[分布式防护] ";

// ---------------------------------------------------------------------------
// Lua:封禁检查 + 令牌桶,一次往返(寓言集第 39、41 讲)
//
// 为什么把两件事合进一个脚本:
//   压测发现每请求两次 Redis 往返就是吞吐瓶颈(2 核上 26k,关掉 Redis 能到 70k)。
//   合并成一次 EVAL,既省一半往返,又省一次连接借还。
//   顺便:先判封禁,封着的请求连令牌都不用算。
//
// 为什么用 Lua:"看"和"取"之间会被别人插一脚,整段必须原子。
//
// KEYS[1] 桶   KEYS[2] 封禁键
// ARGV[1] rate ARGV[2] capacity ARGV[3] now_us ARGV[4] cost
// 返回 -1 = 封禁中,0 = 限流,1 = 放行
// ---------------------------------------------------------------------------
const char* kGuardLua = R"LUA(
-- 先看封没封。封禁是"硬状态",不必再算令牌。
if redis.call('EXISTS', KEYS[2]) == 1 then
  return -1
end

local rate     = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local now      = tonumber(ARGV[3])
local cost     = tonumber(ARGV[4])

local data = redis.call('HMGET', KEYS[1], 'tokens', 'last')
local tokens = tonumber(data[1])
local last   = tonumber(data[2])

if tokens == nil then tokens = capacity end
if last == nil then last = now end

local elapsed = (now - last) / 1000000.0
if elapsed < 0 then
  -- 时钟回拨:保守起见按满桶处理,别让回拨反而限死正常流量
  tokens = capacity
else
  tokens = math.min(capacity, tokens + elapsed * rate)
end

local ok = 0
if tokens >= cost then
  tokens = tokens - cost
  ok = 1
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'last', now)
-- 桶空了以后 idle 多久能补满,就留多久;再加一点余量
local ttl = math.ceil(capacity / math.max(rate, 0.001)) + 60
redis.call('EXPIRE', KEYS[1], ttl)
return ok
)LUA";

// ---------------------------------------------------------------------------
// Lua:命中计数 + 封禁(寓言集第 41 讲)
//
// 关键一处:EXPIRE 只在第一次计数时设。
// 若是每次命中都续期,窗口就永远不滑动 —— 攻击者只要持续低频命中,
// 计数就永远不会归零,反而触发不了封禁。
//
// KEYS[1] 计数 key   KEYS[2] 封禁 key
// ARGV[1] threshold  ARGV[2] window_sec  ARGV[3] ban_sec
// 返回 1 = 本次触发封禁(或本来就在封禁中)
// ---------------------------------------------------------------------------
const char* kHitBanLua = R"LUA(
local threshold  = tonumber(ARGV[1])
local window_sec = tonumber(ARGV[2])
local ban_sec    = tonumber(ARGV[3])

-- 已经封着就直接返回
if redis.call('EXISTS', KEYS[2]) == 1 then
  return 1
end

local n = redis.call('INCR', KEYS[1])
if n == 1 then
  -- 只在第一次设置过期时间,窗口才会滑动
  redis.call('EXPIRE', KEYS[1], window_sec)
end

if n >= threshold then
  redis.call('SET', KEYS[2], '1', 'EX', ban_sec)
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
)LUA";

// ---------------------------------------------------------------------------
// Lua:重放防护(寓言集第 40 讲)
//
// SET NX EX 一步完成"检查 + 记录",天然原子。
// 换成 EXISTS 再 SET 两步,中间就有竞态窗口。
//
// KEYS[1] nonce key   ARGV[1] ttl 秒
// 返回 1 = 首次(放行),0 = 重复(重放)
// ---------------------------------------------------------------------------
const char* kNonceLua = R"LUA(
local r = redis.call('SET', KEYS[1], '1', 'NX', 'EX', tonumber(ARGV[1]))
if r then return 1 else return 0 end
)LUA";

}  // namespace

DistributedGuard::DistributedGuard(RedisClient* redis, const GuardConfig& cfg)
    : redis_(redis), cfg_(cfg) {
    if (redis_ && redis_->available()) {
        LOG_INFO(kTag, "使用 Redis 共享状态(支持多实例部署)");
    } else {
        LOG_WARN(kTag, "Redis 不可用,降级为单机内存版(多实例部署会失效)");
    }
}

double DistributedGuard::now_sec() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

// ---------------------------------------------------------------------------
// 封禁 + 限流(一次 Redis 往返)
// ---------------------------------------------------------------------------
GuardDecision DistributedGuard::check(const std::string& key_suffix) {
    if (!redis_ || !redis_->available()) {
        std::lock_guard<std::mutex> lk(mu_);
        ++fallback_count_;
        return check_local(key_suffix);
    }

    const auto now_us = static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    const std::vector<std::string> keys = {
        "sg:rl:" + key_suffix,
        "sg:ban:" + key_suffix,
    };
    const std::vector<std::string> args = {
        std::to_string(cfg_.rate_per_sec),
        std::to_string(cfg_.burst),
        std::to_string(now_us),
        "1"};

    const auto v = redis_->eval_int(kGuardLua, keys, args);
    if (!v) {
        // Redis 出错:降级到本地,不把请求卡死
        std::lock_guard<std::mutex> lk(mu_);
        ++fallback_count_;
        return check_local(key_suffix);
    }
    if (*v < 0) return GuardDecision::kBanned;
    return (*v == 1) ? GuardDecision::kAllow : GuardDecision::kRateLimited;
}

bool DistributedGuard::allow(const std::string& key_suffix) {
    return check(key_suffix) == GuardDecision::kAllow;
}

// 降级路径:同样先看封禁,再算令牌
GuardDecision DistributedGuard::check_local(const std::string& key_suffix) {
    // 调用方已持锁
    const double now = now_sec();
    auto it = local_ips_.find(key_suffix);
    if (it != local_ips_.end() && it->second.banned_until > now) {
        return GuardDecision::kBanned;
    }
    return allow_local(key_suffix) ? GuardDecision::kAllow
                                   : GuardDecision::kRateLimited;
}

bool DistributedGuard::allow_local(const std::string& key_suffix) {
    // 调用方已持锁
    const double now = now_sec();
    auto& b = local_buckets_[key_suffix];
    if (b.last == 0.0) { b.last = now; b.tokens = cfg_.burst; }
    const double elapsed = std::max(0.0, now - b.last);
    b.tokens = std::min(cfg_.burst, b.tokens + elapsed * cfg_.rate_per_sec);
    b.last = now;
    if (b.tokens >= 1.0) { b.tokens -= 1.0; return true; }
    return false;
}

// ---------------------------------------------------------------------------
// 封禁
// ---------------------------------------------------------------------------
bool DistributedGuard::record_hit(const std::string& ip, int threshold,
                                  int window_sec, int ban_sec) {
    if (!redis_ || !redis_->available()) {
        std::lock_guard<std::mutex> lk(mu_);
        ++fallback_count_;
        const double now = now_sec();
        auto& r = local_ips_[ip];
        r.hits.push_back(now);
        r.hits.erase(std::remove_if(r.hits.begin(), r.hits.end(),
                        [&](double t) { return now - t > window_sec; }),
                     r.hits.end());
        if (static_cast<int>(r.hits.size()) >= threshold) {
            r.banned_until = now + ban_sec;
            r.hits.clear();
            return true;
        }
        return false;
    }

    const std::vector<std::string> keys = {"sg:hit:" + ip, "sg:ban:" + ip};
    const std::vector<std::string> args = {
        std::to_string(threshold), std::to_string(window_sec),
        std::to_string(ban_sec)};

    const auto v = redis_->eval_int(kHitBanLua, keys, args);
    if (!v) {
        std::lock_guard<std::mutex> lk(mu_);
        ++fallback_count_;
        return false;   // 计数失败就不封,别误封
    }
    if (*v == 1) {
        LOG_WARN(kTag, "IP 触发自动封禁 ", ip, "(阈值 ", threshold, " 次/",
                 window_sec, "秒,封 ", ban_sec, " 秒)");
    }
    return *v == 1;
}

bool DistributedGuard::is_banned(const std::string& ip) {
    if (!redis_ || !redis_->available()) {
        std::lock_guard<std::mutex> lk(mu_);
        const auto it = local_ips_.find(ip);
        return it != local_ips_.end() && it->second.banned_until > now_sec();
    }
    // EXISTS 返回 1 表示封禁中
    const auto v = redis_->exec_int({"EXISTS", "sg:ban:" + ip});
    if (!v) {
        std::lock_guard<std::mutex> lk(mu_);
        const auto it = local_ips_.find(ip);
        return it != local_ips_.end() && it->second.banned_until > now_sec();
    }
    return *v == 1;
}

int DistributedGuard::hits_in_window(const std::string& ip, int window_sec) {
    if (!redis_ || !redis_->available()) {
        std::lock_guard<std::mutex> lk(mu_);
        const double now = now_sec();
        const auto it = local_ips_.find(ip);
        if (it == local_ips_.end()) return 0;
        int n = 0;
        for (double t : it->second.hits) if (now - t <= window_sec) ++n;
        return n;
    }
    const auto v = redis_->exec_int({"GET", "sg:hit:" + ip});
    return v ? static_cast<int>(*v) : 0;
}

// ---------------------------------------------------------------------------
// 重放防护
// ---------------------------------------------------------------------------
bool DistributedGuard::consume_nonce(const std::string& nonce, int ttl_sec) {
    if (nonce.empty() || nonce.size() > 128) return false;

    if (!redis_ || !redis_->available()) {
        std::lock_guard<std::mutex> lk(mu_);
        ++fallback_count_;
        const double now = now_sec();
        // 顺手清理过期项,防止 map 无限增长
        for (auto it = local_nonces_.begin(); it != local_nonces_.end();) {
            if (it->second < now) it = local_nonces_.erase(it);
            else ++it;
        }
        const auto it = local_nonces_.find(nonce);
        if (it != local_nonces_.end()) return false;   // 重放
        local_nonces_[nonce] = now + ttl_sec;
        return true;
    }

    const std::vector<std::string> keys = {"sg:nonce:" + nonce};
    const std::vector<std::string> args = {std::to_string(ttl_sec)};
    const auto v = redis_->eval_int(kNonceLua, keys, args);
    if (!v) {
        std::lock_guard<std::mutex> lk(mu_);
        ++fallback_count_;
        return true;   // Redis 出错时不误杀正常请求
    }
    return *v == 1;
}

bool DistributedGuard::timestamp_fresh(std::int64_t ts_sec, int window_sec) {
    const auto now = static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    const std::int64_t diff = now - ts_sec;
    // 允许少许超前(客户端时钟略快),但不能太离谱
    if (diff > window_sec) return false;
    if (diff < -60) return false;
    return true;
}

bool DistributedGuard::redis_available() const {
    return redis_ && redis_->available();
}

}  // namespace secguard
