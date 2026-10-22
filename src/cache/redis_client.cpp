#include "cache/redis_client.h"

#include <hiredis/hiredis.h>

#include <cstring>
#include <mutex>
#include <unordered_set>

#include "util/log.h"

namespace secguard {
namespace {
constexpr const char* kTag = "[Redis] ";

// ---------------------------------------------------------------------------
// 存活客户端登记表
//
// 解决一个真实的坑:线程局部缓存的连接由 thread_local 的析构函数归还,
// 但 TLS 析构发生在线程退出时 —— 如果 RedisClient 此时已经销毁,
// 归还动作就会去锁一个已销毁的 mutex,直接死锁。
// (单元测试里主线程同时持有两者,一跑就卡在 futex_do_wait。)
//
// 所以析构前先从登记表里摘掉自己,TLS 析构时先查表:
// 查不到就说明客户端已经没了,直接把连接丢掉即可(它的析构会 redisFree)。
// ---------------------------------------------------------------------------
std::mutex g_alive_mu;
std::unordered_set<const void*> g_alive_clients;

void mark_client_alive(const void* p) {
    std::lock_guard<std::mutex> lk(g_alive_mu);
    g_alive_clients.insert(p);
}
void mark_client_dead(const void* p) {
    std::lock_guard<std::mutex> lk(g_alive_mu);
    g_alive_clients.erase(p);
}
bool client_still_alive(const void* p) {
    std::lock_guard<std::mutex> lk(g_alive_mu);
    return g_alive_clients.count(p) > 0;
}

}  // namespace

struct RedisClient::Conn {
    redisContext* ctx = nullptr;
    ~Conn() {
        if (ctx) { redisFree(ctx); ctx = nullptr; }
    }
    Conn() = default;
    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;
};

RedisClient::RedisClient(const RedisConfig& cfg) : cfg_(cfg) {
    mark_client_alive(this);
    if (!cfg_.enabled) {
        LOG_INFO(kTag, "未启用(配置里关掉了)");
        return;
    }
    auto c = make_conn();
    if (!c) {
        LOG_WARN(kTag, "连接失败,限流/封禁将退回单机内存版");
        return;
    }
    available_ = true;
    idle_.push_back(std::move(c));
    LOG_INFO(kTag, "已连接 ", cfg_.host, ":", cfg_.port, " 池大小=", cfg_.pool_size);
}

RedisClient::~RedisClient() {
    // 先摘牌,再动自己的成员 —— 顺序很重要:
    // 摘牌之后到达的 TLS 析构就不会再调到这里。
    mark_client_dead(this);
    std::lock_guard<std::mutex> lk(mu_);
    idle_.clear();          // Conn 的析构会 redisFree
}

std::unique_ptr<RedisClient::Conn> RedisClient::make_conn() {
    auto c = std::make_unique<Conn>();

    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = cfg_.timeout_ms * 1000;

    c->ctx = redisConnectWithTimeout(cfg_.host.c_str(), cfg_.port, tv);
    if (!c->ctx || c->ctx->err) {
        if (c->ctx) LOG_WARN(kTag, "连接失败: ", c->ctx->errstr);
        return nullptr;
    }
    if (redisSetTimeout(c->ctx, tv) != REDIS_OK) {
        LOG_WARN(kTag, "设置命令超时失败");
    }
    if (!cfg_.password.empty()) {
        const char* argv[] = {"AUTH", cfg_.password.c_str()};
        std::size_t lens[] = {4, cfg_.password.size()};
        auto* r = static_cast<redisReply*>(
            redisCommandArgv(c->ctx, 2, argv, lens));
        const bool ok = r && r->type != REDIS_REPLY_ERROR;
        if (r) freeReplyObject(r);
        if (!ok) {
            LOG_WARN(kTag, "AUTH 失败");
            return nullptr;
        }
    }
    if (cfg_.db != 0) {
        const std::string db_str = std::to_string(cfg_.db);
        const char* argv[] = {"SELECT", db_str.c_str()};
        std::size_t lens[] = {6, db_str.size()};
        auto* r = static_cast<redisReply*>(redisCommandArgv(c->ctx, 2, argv, lens));
        if (r) freeReplyObject(r);
    }
    return c;
}

std::unique_ptr<RedisClient::Conn> RedisClient::acquire() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!idle_.empty()) {
        auto c = std::move(idle_.back());
        idle_.pop_back();
        return c;
    }
    // 池空:建一条临时用。限流路径上宁可多建一条,也不能让请求卡住。
    return make_conn();
}

void RedisClient::release(std::unique_ptr<Conn> c) {
    if (!c) return;
    std::lock_guard<std::mutex> lk(mu_);
    if (static_cast<int>(idle_.size()) < cfg_.pool_size) {
        idle_.push_back(std::move(c));
    }
    // 否则 c 离开作用域,Conn 析构会 redisFree,连接数自然回落
}

// ---------------------------------------------------------------------------
// 每线程一条连接
//
// 压测发现:每请求一次 Redis 往返就让吞吐从 57k 掉到 20k。一次 loopback
// 往返不该贵成这样 —— 真正贵的是 64 个工作线程抢同一把 pool 互斥锁,
// 每次请求都要加锁两次(借、还)。
//
// 做法:工作线程第一次用 Redis 时领一条连接,之后一直用自己这条,
// 热路径上完全不碰锁。线程退出时由 thread_local 的析构归还。
// ---------------------------------------------------------------------------
struct RedisClient::TlsSlot {
    RedisClient* owner = nullptr;
    std::unique_ptr<Conn> conn;
    ~TlsSlot() {
        // 只有在客户端还活着的时候才能归还;否则直接丢弃,
        // 由 conn 自己的析构去 redisFree(见上面登记表的说明)
        if (owner && conn && client_still_alive(owner)) {
            owner->release(std::move(conn));
        }
    }
};

static thread_local RedisClient::TlsSlot t_redis_slot;

std::optional<std::string> RedisClient::exec(const std::vector<std::string>& argv) {
    if (!cfg_.enabled || argv.empty()) return std::nullopt;

    // --- 取连接:优先用本线程缓存的,省掉两次加锁 ---
    if (t_redis_slot.owner != this) {
        // 换了客户端实例(理论上一进程只有一个):把旧的还掉
        if (t_redis_slot.owner && t_redis_slot.conn) {
            t_redis_slot.owner->release(std::move(t_redis_slot.conn));
        }
        t_redis_slot.owner = this;
        t_redis_slot.conn = nullptr;
    }
    if (!t_redis_slot.conn) {
        t_redis_slot.conn = acquire();
        if (!t_redis_slot.conn) {
            failures_.fetch_add(1, std::memory_order_relaxed);
            available_.store(false, std::memory_order_relaxed);
            return std::nullopt;
        }
    }
    Conn* c = t_redis_slot.conn.get();

    // 转成 redisCommandArgv 要的形式:指针数组 + 长度数组
    std::vector<const char*> cargv;
    std::vector<std::size_t> clens;
    cargv.reserve(argv.size());
    clens.reserve(argv.size());
    for (const auto& a : argv) {
        cargv.push_back(a.data());
        clens.push_back(a.size());
    }

    auto* r = static_cast<redisReply*>(
        redisCommandArgv(c->ctx, static_cast<int>(cargv.size()),
                         cargv.data(), clens.data()));
    if (!r) {
        LOG_WARN(kTag, "命令失败(连接可能已断): ",
                 c->ctx ? c->ctx->errstr : "ctx=null");
        failures_.fetch_add(1, std::memory_order_relaxed);
        available_.store(false, std::memory_order_relaxed);
        // 这条连接已坏:直接销毁,别还回池子。
        // 下次调用会重新领一条(见上面的取连接逻辑)。
        t_redis_slot.conn.reset();
        return std::nullopt;
    }

    std::optional<std::string> out;
    switch (r->type) {
        case REDIS_REPLY_STRING:
        case REDIS_REPLY_STATUS:
            out = std::string(r->str, r->len);
            break;
        case REDIS_REPLY_INTEGER:
            out = std::to_string(r->integer);
            break;
        case REDIS_REPLY_NIL:
            out = std::nullopt;
            break;
        case REDIS_REPLY_ERROR:
            LOG_WARN(kTag, "Redis 返回错误: ", std::string(r->str, r->len));
            out = std::nullopt;
            break;
        default:
            out = std::nullopt;
            break;
    }
    freeReplyObject(static_cast<void*>(r));

    // 统计用原子计数(relaxed 就够:只是给监控看,不参与同步)
    commands_.fetch_add(1, std::memory_order_relaxed);
    available_.store(true, std::memory_order_relaxed);
    return out;
}

std::optional<std::int64_t> RedisClient::exec_int(const std::vector<std::string>& argv) {
    const auto r = exec(argv);
    if (!r) return std::nullopt;
    try { return std::stoll(*r); } catch (...) { return std::nullopt; }
}

std::optional<std::int64_t> RedisClient::eval_int(
    const std::string& script, const std::vector<std::string>& keys,
    const std::vector<std::string>& args) {
    if (!cfg_.enabled) return std::nullopt;

    auto build = [&](const std::string& target, bool use_sha) {
        std::vector<std::string> argv;
        argv.reserve(3 + keys.size() + args.size());
        argv.push_back(use_sha ? "EVALSHA" : "EVAL");
        argv.push_back(target);
        argv.push_back(std::to_string(keys.size()));
        for (const auto& k : keys) argv.push_back(k);
        for (const auto& a : args) argv.push_back(a);
        return argv;
    };

    // 查脚本缓存
    std::string sha;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (const auto& [s, h] : script_shas_) {
            if (s == script) { sha = h; break; }
        }
    }

    auto run = [&](const std::string& target, bool use_sha)
        -> std::optional<std::int64_t> {
        const auto r = exec(build(target, use_sha));
        if (!r) return std::nullopt;
        try { return std::stoll(*r); } catch (...) { return std::nullopt; }
    };

    if (!sha.empty()) {
        if (auto v = run(sha, true)) return v;
        // 失败可能是 NOSCRIPT(Redis 重启过):下面重载一次
    }

    // 首次或缓存失效:SCRIPT LOAD 拿 sha,再 EVALSHA
    const auto loaded = exec({"SCRIPT", "LOAD", script});
    if (!loaded) return std::nullopt;

    {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<std::pair<std::string, std::string>> keep;
        for (auto& p : script_shas_) {
            if (p.first != script) keep.push_back(p);
        }
        keep.emplace_back(script, *loaded);
        script_shas_.swap(keep);
    }
    return run(*loaded, true);
}

bool RedisClient::ping() {
    const auto r = exec({"PING"});
    return r.has_value() && *r == "PONG";
}

}  // namespace secguard
