#include "util/config.h"

#include <cstdlib>
#include <sstream>
#include <thread>

namespace secguard {
namespace {

// 读环境变量,缺失则保留原值
std::string env_str(const char* name, const std::string& fallback) {
    if (const char* v = std::getenv(name); v && *v) return v;
    return fallback;
}

bool env_int(const char* name, int& out) {
    const char* v = std::getenv(name);
    if (!v || !*v) return true;                 // 未设置 -> 用默认值
    char* end = nullptr;
    const long n = std::strtol(v, &end, 10);
    if (end == v || *end != '\0') return false; // 有值但不是数字 -> 报错
    out = static_cast<int>(n);
    return true;
}

bool env_size(const char* name, std::size_t& out) {
    const char* v = std::getenv(name);
    if (!v || !*v) return true;
    char* end = nullptr;
    const long long n = std::strtoll(v, &end, 10);
    if (end == v || *end != '\0' || n < 0) return false;
    out = static_cast<std::size_t>(n);
    return true;
}

}  // namespace

bool Config::load(Config& out, std::string& err) {
    // --- 数据库 ---
    out.db.host     = env_str("SECGUARD_DB_HOST", out.db.host);
    out.db.user     = env_str("SECGUARD_DB_USER", "");
    out.db.password = env_str("SECGUARD_DB_PASS", "");
    out.db.schema   = env_str("SECGUARD_DB_NAME", out.db.schema);
    if (!env_int("SECGUARD_DB_PORT", out.db.port)) { err = "SECGUARD_DB_PORT 不是整数"; return false; }
    if (!env_int("SECGUARD_DB_POOL", out.db.pool_size)) { err = "SECGUARD_DB_POOL 不是整数"; return false; }
    if (!env_int("SECGUARD_DB_TIMEOUT_MS", out.db.acquire_timeout_ms)) { err = "SECGUARD_DB_TIMEOUT_MS 不是整数"; return false; }

    if (out.db.user.empty())     { err = "缺少 SECGUARD_DB_USER"; return false; }
    if (out.db.password.empty()) { err = "缺少 SECGUARD_DB_PASS"; return false; }
    if (out.db.pool_size <= 0)   { err = "SECGUARD_DB_POOL 必须为正"; return false; }

    // --- 鉴权 ---
    out.auth.jwt_secret = env_str("SECGUARD_JWT_SECRET", "");
    if (out.auth.jwt_secret.empty()) {
        err = "缺少 SECGUARD_JWT_SECRET(JWT 签名密钥,必须显式设置)";
        return false;
    }
    if (out.auth.jwt_secret.size() < 16) {
        err = "SECGUARD_JWT_SECRET 太短(至少 16 字符)";
        return false;
    }
    if (!env_int("SECGUARD_TOKEN_TTL", out.auth.token_ttl_seconds)) { err = "SECGUARD_TOKEN_TTL 不是整数"; return false; }
    if (!env_int("SECGUARD_PBKDF2_ITER", out.auth.pbkdf2_iterations)) { err = "SECGUARD_PBKDF2_ITER 不是整数"; return false; }
    if (!env_int("SECGUARD_LOGIN_FAIL_LIMIT", out.auth.login_fail_limit)) { err = "SECGUARD_LOGIN_FAIL_LIMIT 不是整数"; return false; }
    if (!env_int("SECGUARD_LOGIN_LOCK_SEC", out.auth.login_lock_seconds)) { err = "SECGUARD_LOGIN_LOCK_SEC 不是整数"; return false; }
    if (out.auth.pbkdf2_iterations < 10000) {
        err = "SECGUARD_PBKDF2_ITER 至少 10000(否则密码哈希太弱)";
        return false;
    }

    // --- 服务 ---
    out.server.bind_addr = env_str("SECGUARD_BIND", out.server.bind_addr);
    if (!env_int("SECGUARD_PORT", out.server.port)) { err = "SECGUARD_PORT 不是整数"; return false; }
    if (!env_int("SECGUARD_THREADS", out.server.threads)) { err = "SECGUARD_THREADS 不是整数"; return false; }
    if (!env_int("SECGUARD_BACKLOG", out.server.backlog)) { err = "SECGUARD_BACKLOG 不是整数"; return false; }
    if (out.server.threads <= 0) {
        const unsigned hw = std::thread::hardware_concurrency();
        out.server.threads = static_cast<int>(hw ? hw : 4);
    }

    // --- 引擎 ---
    out.engine.pattern_file = env_str("SECGUARD_PATTERN_FILE", "rules/attack_patterns.txt");
    if (!env_size("SECGUARD_MAX_PATTERN_LEN", out.engine.max_pattern_len)) { err = "SECGUARD_MAX_PATTERN_LEN 不是整数"; return false; }
    if (!env_size("SECGUARD_MAX_TEXT", out.engine.max_text_bytes)) { err = "SECGUARD_MAX_TEXT 不是整数"; return false; }
    if (!env_size("SECGUARD_MAX_HITS", out.engine.max_hits)) { err = "SECGUARD_MAX_HITS 不是整数"; return false; }
    if (!env_int("SECGUARD_RELOAD_SEC", out.engine.reload_interval_seconds)) { err = "SECGUARD_RELOAD_SEC 不是整数"; return false; }

    // --- 日志 ---
    out.log_level = env_str("SECGUARD_LOG_LEVEL", out.log_level);

    // --- 防护:限流与封禁 ---
    {
        const char* rate = std::getenv("SECGUARD_RATE_PER_SEC");
        if (rate && *rate) out.guard.rate_per_sec = std::strtod(rate, nullptr);
        const char* burst = std::getenv("SECGUARD_RATE_BURST");
        if (burst && *burst) out.guard.burst = std::strtod(burst, nullptr);
    }
    if (!env_int("SECGUARD_HIT_WINDOW", out.guard.window_seconds)) { err = "SECGUARD_HIT_WINDOW 不是整数"; return false; }
    if (!env_int("SECGUARD_HIT_THRESHOLD", out.guard.hit_threshold)) { err = "SECGUARD_HIT_THRESHOLD 不是整数"; return false; }
    if (!env_int("SECGUARD_BAN_SECONDS", out.guard.ban_seconds)) { err = "SECGUARD_BAN_SECONDS 不是整数"; return false; }

    // 合理性检查:不合法就拒绝启动,别带着错配置跑(第 67 讲)
    if (out.server.port <= 0 || out.server.port > 65535) { err = "SECGUARD_PORT 超出范围"; return false; }
    if (out.server.backlog <= 0) { err = "SECGUARD_BACKLOG 必须为正"; return false; }
    if (out.engine.max_pattern_len == 0) { err = "SECGUARD_MAX_PATTERN_LEN 必须为正"; return false; }
    if (out.engine.max_text_bytes == 0)  { err = "SECGUARD_MAX_TEXT 必须为正"; return false; }
    return true;
}

std::string Config::describe() const {
    std::ostringstream oss;
    oss << "配置一览:\n"
        << "  数据库   " << db.host << ":" << db.port << "/" << db.schema
        << "  用户=" << db.user << "  口令=***  连接池=" << db.pool_size << "\n"
        << "  服务     " << server.bind_addr << ":" << server.port
        << "  线程=" << server.threads << "  监听队列=" << server.backlog << "\n"
        << "  鉴权     令牌有效期=" << auth.token_ttl_seconds << "s"
        << "  PBKDF2迭代=" << auth.pbkdf2_iterations
        << "  登录失败上限=" << auth.login_fail_limit << "  密钥=***\n"
        << "  引擎     特征库=" << engine.pattern_file
        << "  文本上限=" << engine.max_text_bytes << "B"
        << "  命中上限=" << engine.max_hits
        << "  热加载间隔=" << engine.reload_interval_seconds << "s\n"
        << "  日志     级别=" << log_level;
    return oss.str();
}

}  // namespace secguard
