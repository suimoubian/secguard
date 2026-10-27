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

    // 管理员名单:逗号分隔。空 = 管理接口全关(fail-closed)
    {
        const std::string raw = env_str("SECGUARD_ADMIN_USERS", "");
        std::string cur;
        for (char c : raw) {
            if (c == ',') {
                if (!cur.empty()) out.auth.admin_users.push_back(cur);
                cur.clear();
            } else if (c != ' ' && c != '\t') {
                cur.push_back(c);
            }
        }
        if (!cur.empty()) out.auth.admin_users.push_back(cur);
    }

    // --- 服务 ---
    out.server.bind_addr = env_str("SECGUARD_BIND", out.server.bind_addr);
    if (!env_int("SECGUARD_PORT", out.server.port)) { err = "SECGUARD_PORT 不是整数"; return false; }
    if (!env_int("SECGUARD_THREADS", out.server.threads)) { err = "SECGUARD_THREADS 不是整数"; return false; }
    if (!env_int("SECGUARD_BACKLOG", out.server.backlog)) { err = "SECGUARD_BACKLOG 不是整数"; return false; }
    out.server.trust_proxy = env_str("SECGUARD_TRUST_PROXY", "0") == "1";
    if (out.server.threads <= 0) {
        const unsigned hw = std::thread::hardware_concurrency();
        out.server.threads = static_cast<int>(hw ? hw : 4);
    }

    // --- 引擎 ---
    out.engine.pattern_file = env_str("SECGUARD_PATTERN_FILE", "rules/attack_patterns.txt");
    out.engine.allowlist_file = env_str("SECGUARD_ALLOWLIST_FILE", out.engine.allowlist_file);
    out.engine.policy_file = env_str("SECGUARD_POLICY_FILE", out.engine.policy_file);
    if (!env_size("SECGUARD_MAX_PATTERN_LEN", out.engine.max_pattern_len)) { err = "SECGUARD_MAX_PATTERN_LEN 不是整数"; return false; }
    if (!env_size("SECGUARD_MAX_TEXT", out.engine.max_text_bytes)) { err = "SECGUARD_MAX_TEXT 不是整数"; return false; }
    if (!env_size("SECGUARD_MAX_HITS", out.engine.max_hits)) { err = "SECGUARD_MAX_HITS 不是整数"; return false; }
    if (!env_int("SECGUARD_RELOAD_SEC", out.engine.reload_interval_seconds)) { err = "SECGUARD_RELOAD_SEC 不是整数"; return false; }
    // 归一化遍:默认开。设成 0 可回滚到"只做字面匹配"(用于消融实验和线上止损)。
    out.engine.extra_normalization = env_str("SECGUARD_ENGINE_NORMALIZE", "1") == "1";
    if (!env_int("SECGUARD_ENGINE_NORMALIZE_ROUNDS", out.engine.normalize_decode_rounds)) {
        err = "SECGUARD_ENGINE_NORMALIZE_ROUNDS 不是整数";
        return false;
    }

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
    if (!env_int("SECGUARD_BAN_AUDIT_INTERVAL", out.guard.ban_audit_interval_sec)) {
        err = "SECGUARD_BAN_AUDIT_INTERVAL 不是整数";
        return false;
    }
    if (out.guard.ban_audit_interval_sec < 0) {
        err = "SECGUARD_BAN_AUDIT_INTERVAL 不能为负(0 表示每条都记)";
        return false;
    }

    // --- Redis:限流 / 封禁 / 重放的共享状态(第 39 讲) ---
    out.redis.host     = env_str("SECGUARD_REDIS_HOST", out.redis.host);
    out.redis.password = env_str("SECGUARD_REDIS_PASS", out.redis.password);
    if (!env_int("SECGUARD_REDIS_PORT", out.redis.port)) { err = "SECGUARD_REDIS_PORT 不是整数"; return false; }
    if (!env_int("SECGUARD_REDIS_DB", out.redis.db)) { err = "SECGUARD_REDIS_DB 不是整数"; return false; }
    if (!env_int("SECGUARD_REDIS_POOL", out.redis.pool_size)) { err = "SECGUARD_REDIS_POOL 不是整数"; return false; }
    if (!env_int("SECGUARD_REDIS_TIMEOUT_MS", out.redis.timeout_ms)) { err = "SECGUARD_REDIS_TIMEOUT_MS 不是整数"; return false; }
    out.redis.enabled = env_str("SECGUARD_REDIS_ENABLE", "1") != "0";

    // --- 重放防护(第 40 讲) ---
    out.replay.require = env_str("SECGUARD_REPLAY_REQUIRE", "0") == "1";
    if (!env_int("SECGUARD_REPLAY_WINDOW", out.replay.window_seconds)) { err = "SECGUARD_REPLAY_WINDOW 不是整数"; return false; }
    if (out.replay.window_seconds <= 0 || out.replay.window_seconds > 3600) {
        err = "SECGUARD_REPLAY_WINDOW 必须在 1~3600 秒之间";
        return false;
    }

    // --- 审计管道(第 28、35 讲) ---
    out.audit.async = env_str("SECGUARD_AUDIT_ASYNC", "1") != "0";
    if (!env_size("SECGUARD_AUDIT_BATCH", out.audit.batch_size)) { err = "SECGUARD_AUDIT_BATCH 不是整数"; return false; }
    if (!env_int("SECGUARD_AUDIT_FLUSH_MS", out.audit.flush_interval_ms)) { err = "SECGUARD_AUDIT_FLUSH_MS 不是整数"; return false; }
    if (out.audit.batch_size == 0) { err = "SECGUARD_AUDIT_BATCH 必须为正"; return false; }
    if (!env_int("SECGUARD_AUDIT_RETENTION_DAYS", out.audit.retention_days)) { err = "SECGUARD_AUDIT_RETENTION_DAYS 不是整数"; return false; }
    if (out.audit.retention_days < 0 || out.audit.retention_days > 3650) {
        err = "SECGUARD_AUDIT_RETENTION_DAYS 必须在 0~3650 之间";
        return false;
    }

    // --- LLM(第 61 讲):密钥只从环境变量来,不设默认值 ---
    out.llm.provider = env_str("SECGUARD_LLM_PROVIDER", out.llm.provider);
    out.llm.base_url = env_str("SECGUARD_LLM_BASE_URL", out.llm.base_url);
    out.llm.model    = env_str("SECGUARD_LLM_MODEL", out.llm.model);
    out.llm.api_key  = env_str("SECGUARD_LLM_KEY", "");
    if (!env_int("SECGUARD_LLM_TIMEOUT_MS", out.llm.timeout_ms)) { err = "SECGUARD_LLM_TIMEOUT_MS 不是整数"; return false; }
    if (!env_int("SECGUARD_LLM_MAX_RETRIES", out.llm.max_retries)) { err = "SECGUARD_LLM_MAX_RETRIES 不是整数"; return false; }
    if (!env_int("SECGUARD_LLM_MAX_TOKENS", out.llm.max_tokens)) { err = "SECGUARD_LLM_MAX_TOKENS 不是整数"; return false; }
    {
        const char* t = std::getenv("SECGUARD_LLM_TEMPERATURE");
        if (t && *t) out.llm.temperature = std::strtod(t, nullptr);
    }
    if (out.llm.timeout_ms <= 0 || out.llm.timeout_ms > 120000) {
        err = "SECGUARD_LLM_TIMEOUT_MS 必须在 1~120000 之间";
        return false;
    }
    if (out.llm.max_retries < 0 || out.llm.max_retries > 5) {
        err = "SECGUARD_LLM_MAX_RETRIES 必须在 0~5 之间";
        return false;
    }
    if (out.llm.provider != "mock" && out.llm.provider != "openai") {
        err = "SECGUARD_LLM_PROVIDER 只支持 mock 或 openai";
        return false;
    }

    // --- AI 分析层(第 59、63 讲) ---
    out.ai.enabled = env_str("SECGUARD_AI_ENABLE", "0") == "1";
    if (!env_int("SECGUARD_AI_INTERVAL", out.ai.interval_seconds)) { err = "SECGUARD_AI_INTERVAL 不是整数"; return false; }
    if (!env_int("SECGUARD_AI_STARTUP_DELAY", out.ai.startup_delay_seconds)) { err = "SECGUARD_AI_STARTUP_DELAY 不是整数"; return false; }
    if (!env_int("SECGUARD_AI_BATCH", out.ai.batch_size)) { err = "SECGUARD_AI_BATCH 不是整数"; return false; }
    if (!env_int("SECGUARD_AI_MAX_GROUPS", out.ai.max_groups_per_round)) { err = "SECGUARD_AI_MAX_GROUPS 不是整数"; return false; }
    if (!env_int("SECGUARD_AI_RPM", out.ai.max_requests_per_minute)) { err = "SECGUARD_AI_RPM 不是整数"; return false; }
    if (!env_int("SECGUARD_AI_LOOKBACK_HOURS", out.ai.lookback_hours)) { err = "SECGUARD_AI_LOOKBACK_HOURS 不是整数"; return false; }
    if (!env_int("SECGUARD_AI_MERGE_IPS", out.ai.merge_threshold_ips)) { err = "SECGUARD_AI_MERGE_IPS 不是整数"; return false; }
    if (out.ai.merge_threshold_ips < 0) {
        err = "SECGUARD_AI_MERGE_IPS 不能为负(0 或 1 表示不聚合)";
        return false;
    }
    {
        const char* mc = std::getenv("SECGUARD_AI_MIN_CONFIDENCE");
        if (mc && *mc) out.ai.min_confidence = std::strtod(mc, nullptr);
    }
    if (!(out.ai.min_confidence >= 0.0 && out.ai.min_confidence <= 1.0)) {
        err = "SECGUARD_AI_MIN_CONFIDENCE 必须在 0~1 之间";
        return false;
    }
    if (out.ai.max_requests_per_minute <= 0) {
        err = "SECGUARD_AI_RPM 必须为正";
        return false;
    }
    if (out.ai.enabled && out.ai.interval_seconds <= 0) {
        err = "SECGUARD_AI_INTERVAL 必须为正";
        return false;
    }
    // 开了分析层却没有可用的 LLM,直接拒绝启动 ——
    // 否则它会静默地什么都不做,还让人以为在跑
    if (out.ai.enabled && out.llm.provider != "mock" && out.llm.api_key.empty()) {
        err = "SECGUARD_AI_ENABLE=1 但缺少 SECGUARD_LLM_KEY"
              "(要离线试跑请设 SECGUARD_LLM_PROVIDER=mock)";
        return false;
    }

    // --- 告警通知(第 65 讲) ---
    out.webhook.url = env_str("SECGUARD_ALERT_WEBHOOK", "");
    out.webhook.min_severity = env_str("SECGUARD_ALERT_MIN_SEVERITY",
                                       out.webhook.min_severity);
    if (!env_int("SECGUARD_ALERT_TIMEOUT_MS", out.webhook.timeout_ms)) {
        err = "SECGUARD_ALERT_TIMEOUT_MS 不是整数";
        return false;
    }
    if (severity_rank(out.webhook.min_severity) == 0) {
        err = "SECGUARD_ALERT_MIN_SEVERITY 只能是 LOW/MEDIUM/HIGH/CRITICAL";
        return false;
    }
    // 通知端点是可选功能,但配错了应该在启动时就知道,而不是等第一次告警
    if (!out.webhook.url.empty()
        && out.webhook.url.rfind("http://", 0) != 0
        && out.webhook.url.rfind("https://", 0) != 0) {
        err = "SECGUARD_ALERT_WEBHOOK 必须以 http:// 或 https:// 开头";
        return false;
    }

    // 合理性检查:不合法就拒绝启动,别带着错配置跑(第 67 讲)
    if (out.server.port <= 0 || out.server.port > 65535) { err = "SECGUARD_PORT 超出范围"; return false; }
    if (out.server.backlog <= 0) { err = "SECGUARD_BACKLOG 必须为正"; return false; }
    if (out.engine.max_pattern_len == 0) { err = "SECGUARD_MAX_PATTERN_LEN 必须为正"; return false; }
    if (out.engine.max_text_bytes == 0)  { err = "SECGUARD_MAX_TEXT 必须为正"; return false; }
    if (out.engine.normalize_decode_rounds < 0 || out.engine.normalize_decode_rounds > 8) {
        err = "SECGUARD_ENGINE_NORMALIZE_ROUNDS 必须在 0..8 之间";
        return false;
    }
    if (out.guard.rate_per_sec <= 0)     { err = "SECGUARD_RATE_PER_SEC 必须为正"; return false; }
    if (out.guard.hit_threshold <= 0)    { err = "SECGUARD_HIT_THRESHOLD 必须为正"; return false; }
    if (out.redis.pool_size <= 0)        { err = "SECGUARD_REDIS_POOL 必须为正"; return false; }
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
        << "  管理接口 " << (auth.admin_users.empty()
               ? std::string("已关闭(未配置 SECGUARD_ADMIN_USERS)")
               : ("管理员=" + [this] {
                     std::string s;
                     for (const auto& u : auth.admin_users) {
                         if (!s.empty()) s += ',';
                         s += u;
                     }
                     return s;
                 }()))
        << "\n"
        << "  引擎     特征库=" << engine.pattern_file
        << "  文本上限=" << engine.max_text_bytes << "B"
        << "  命中上限=" << engine.max_hits
        << "  热加载间隔=" << engine.reload_interval_seconds << "s\n"
        // 归一化开关和策略文件必须打出来:线上排查时最常问的两句话就是
        // "归一化开了吗"和"策略生效了吗",看不到就只能登机器翻环境变量。
        << "  检测     归一化=" << (engine.extra_normalization
               ? ("开(最多解 " + std::to_string(engine.normalize_decode_rounds) + " 层)")
               : std::string("关(只做字面匹配)"))
        << "  策略=" << engine.policy_file
        << "  白名单=" << engine.allowlist_file << "\n"
        << "  防护     速率=" << guard.rate_per_sec << "/s 突发=" << guard.burst
        << "  封禁=" << guard.hit_threshold << "次/" << guard.window_seconds
        << "s -> " << guard.ban_seconds << "s\n"
        << "  Redis    " << (redis.enabled
               ? (redis.host + ":" + std::to_string(redis.port) + " 池=" + std::to_string(redis.pool_size))
               : std::string("未启用"))
        << "  口令=***\n"
        << "  重放     " << (replay.require ? "强制要求" : "可选")
        << "  窗口=" << replay.window_seconds << "s\n"
        << "  审计     " << (audit.async ? "异步" : "同步")
        << "  批量=" << audit.batch_size << "  间隔=" << audit.flush_interval_ms << "ms\n"
        << "  LLM      " << llm.provider << " 模型=" << llm.model
        << " 地址=" << llm.base_url
        << " 密钥=" << (llm.api_key.empty() ? std::string("未设置") : std::string("***"))
        << " 超时=" << llm.timeout_ms << "ms 重试=" << llm.max_retries << "\n"
        << "  分析层   " << (ai.enabled ? "启用" : "关闭")
        << "  间隔=" << ai.interval_seconds << "s"
        << " 批量=" << ai.batch_size
        << " 每分钟调用上限=" << ai.max_requests_per_minute
        << " 置信度门槛=" << ai.min_confidence << "\n"
        << "  日志     级别=" << log_level;
    return oss.str();
}

}  // namespace secguard
