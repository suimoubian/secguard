#include "net/app_context.h"

#include <algorithm>

#include "crypto/auth_crypto.h"
#include "util/log.h"

namespace secguard {
namespace {
constexpr const char* kTag = "[防护] ";
}

// ---------------------------------------------------------------------------
// Guard
// ---------------------------------------------------------------------------
bool Guard::record_hit(const std::string& ip, double now, int window_sec,
                       int threshold, int ban_sec) {
    std::lock_guard<std::mutex> lk(mu_);

    // 顺手做一次清理,防止 map 无限增长
    if (now - last_gc_ > 60.0) {
        for (auto it = recs_.begin(); it != recs_.end();) {
            auto& r = it->second;
            r.hits.erase(std::remove_if(r.hits.begin(), r.hits.end(),
                            [&](double t) { return now - t > window_sec * 2.0; }),
                         r.hits.end());
            if (r.hits.empty() && r.banned_until < now && r.login_fails == 0) {
                it = recs_.erase(it);
            } else {
                ++it;
            }
        }
        last_gc_ = now;
    }

    auto& rec = recs_[ip];
    rec.hits.push_back(now);
    // 只留窗口内的
    rec.hits.erase(std::remove_if(rec.hits.begin(), rec.hits.end(),
                       [&](double t) { return now - t > window_sec; }),
                   rec.hits.end());

    if (static_cast<int>(rec.hits.size()) >= threshold && rec.banned_until < now) {
        rec.banned_until = now + ban_sec;
        LOG_WARN(kTag, "IP 触发自动封禁 ", ip, " 窗口内命中=", rec.hits.size(),
                 " 封禁 ", ban_sec, "s");
        return true;
    }
    return false;
}

bool Guard::is_banned(const std::string& ip, double now) {
    std::lock_guard<std::mutex> lk(mu_);
    const auto it = recs_.find(ip);
    if (it == recs_.end()) return false;
    if (it->second.banned_until > now) return true;
    return false;
}

int Guard::banned_count(double now) {
    std::lock_guard<std::mutex> lk(mu_);
    int n = 0;
    for (const auto& [ip, r] : recs_) {
        if (r.banned_until > now) ++n;
    }
    return n;
}

int Guard::hits_in_window(const std::string& ip, double now, int window_sec) {
    std::lock_guard<std::mutex> lk(mu_);
    const auto it = recs_.find(ip);
    if (it == recs_.end()) return 0;
    int n = 0;
    for (double t : it->second.hits) {
        if (now - t <= window_sec) ++n;
    }
    return n;
}

bool Guard::record_login_fail(const std::string& key, double now, int window_sec,
                              int limit) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& rec = recs_["login:" + key];
    if (rec.login_fails == 0 || now - rec.login_fail_first > window_sec) {
        rec.login_fails = 1;
        rec.login_fail_first = now;
        return false;
    }
    ++rec.login_fails;
    if (rec.login_fails >= limit) {
        rec.banned_until = now + window_sec;   // 借用同一套封禁字段
        LOG_WARN(kTag, "登录失败过多,短暂锁定 ", key);
        return true;
    }
    return false;
}

void Guard::clear_login_fail(const std::string& key) {
    std::lock_guard<std::mutex> lk(mu_);
    recs_.erase("login:" + key);
}

// ---------------------------------------------------------------------------
// HTTP -> 待检文本
// ---------------------------------------------------------------------------
std::string build_scan_text(const std::string& path, const std::string& query,
                            const std::string& body, const std::string& user_agent,
                            std::size_t max_bytes, bool& truncated) {
    truncated = false;
    std::string out;
    out.reserve(std::min<std::size_t>(max_bytes, path.size() + query.size() + body.size() + 64));

    // 每一段单独结束,段与段之间用换行分隔 —— 换行不是任何特征的组成部分,
    // 这样就不会在两个不相邻的段之间造出假的相邻关系(第 17 讲)
    auto append_segment = [&](const std::string& label, const std::string& value) {
        if (value.empty() || truncated) return;
        if (out.size() + value.size() + label.size() + 2 > max_bytes) {
            const std::size_t room = (max_bytes > out.size() + label.size() + 2)
                                   ? max_bytes - out.size() - label.size() - 2 : 0;
            out += label;
            out.append(value, 0, room);
            truncated = true;
            out.push_back('\n');
            return;
        }
        out += label;
        out += value;
        out.push_back('\n');
    };

    append_segment("PATH:", path);
    append_segment("QUERY:", query);          // 原样,不解码
    append_segment("BODY:", body);            // 原样,不解码
    append_segment("UA:", user_agent);        // 头也算可疑信号(第 46 讲)

    return out;
}

std::string build_params_digest(const std::string& query, const std::string& body) {
    // 只存摘要:要能对比"两次请求是不是一样",但看不出原文(第 45 讲)
    const std::string joined = query + "\n" + body;
    if (joined.size() <= 1) return {};
    const std::string hex = crypto::sha256_hex(joined);
    std::string out = "sha256:";
    out += hex.substr(0, 32);
    out += " len=";
    out += std::to_string(query.size() + body.size());
    return out;
}

std::string extract_bearer(const std::string& authorization) {
    constexpr const char* kPrefix = "Bearer ";
    if (authorization.rfind(kPrefix, 0) != 0) return {};
    std::string token = authorization.substr(9);
    while (!token.empty() && (token.back() == ' ' || token.back() == '\r')) token.pop_back();
    return token;
}

std::string make_trace_id() {
    // 16 字节随机,取前 16 个 hex 字符
    const std::string raw = crypto::random_bytes(8);
    if (raw.empty()) return "trace-unknown";
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(raw.size() * 2);
    for (unsigned char c : raw) {
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0x0F]);
    }
    return out;
}

}  // namespace secguard
