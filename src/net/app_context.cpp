#include "net/app_context.h"

#include <algorithm>
#include <chrono>

#include "crypto/auth_crypto.h"
#include "util/log.h"

namespace secguard {
namespace {
constexpr const char* kTag = "[登录防护] ";
}  // namespace

// ---------------------------------------------------------------------------
// LoginThrottle
// ---------------------------------------------------------------------------
double LoginThrottle::now_sec() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

bool LoginThrottle::record_fail(const std::string& key, int window_sec, int limit) {
    std::lock_guard<std::mutex> lk(mu_);
    const double now = now_sec();

    // 顺手清理过期记录,防止 map 无限增长
    if (recs_.size() > 10000) {
        for (auto it = recs_.begin(); it != recs_.end();) {
            if (now - it->second.first_fail > window_sec) it = recs_.erase(it);
            else ++it;
        }
    }

    auto& r = recs_[key];
    if (r.fails == 0 || now - r.first_fail > window_sec) {
        r.fails = 1;
        r.first_fail = now;
        return false;
    }
    ++r.fails;
    if (r.fails >= limit) {
        LOG_WARN(kTag, "登录失败过多,短暂锁定 ", key);
        return true;
    }
    return false;
}

void LoginThrottle::clear(const std::string& key) {
    std::lock_guard<std::mutex> lk(mu_);
    recs_.erase(key);
}

bool LoginThrottle::is_locked(const std::string& key, int window_sec, int limit) {
    std::lock_guard<std::mutex> lk(mu_);
    const auto it = recs_.find(key);
    if (it == recs_.end()) return false;
    const double now = now_sec();
    if (now - it->second.first_fail > window_sec) return false;
    return it->second.fails >= limit;
}

// ---------------------------------------------------------------------------
// HTTP -> 待检文本
// ---------------------------------------------------------------------------
std::string build_scan_text(const std::string& path, const std::string& query,
                            const std::string& body, const std::string& user_agent,
                            std::size_t max_bytes, bool& truncated) {
    truncated = false;
    std::string out;
    out.reserve(std::min<std::size_t>(max_bytes,
                                      path.size() + query.size() + body.size() + 64));

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
    // 必须用 prefix_len 而不是写死数字。
    // (踩过的坑:这里曾写成 substr(9),而 "Bearer " 只有 7 个字符,
    //  于是每个令牌都被切掉前 2 个字符,所有带令牌的请求都 401 ——
    //  而登录本身是成功的,所以表面上看不出问题。)
    constexpr std::size_t prefix_len = sizeof("Bearer ") - 1;   // 7
    if (authorization.size() <= prefix_len) return {};
    if (authorization.compare(0, prefix_len, kPrefix) != 0) return {};

    std::string token = authorization.substr(prefix_len);
    while (!token.empty() && (token.back() == ' ' || token.back() == '\r'
                              || token.back() == '\n')) {
        token.pop_back();
    }
    return token;
}

std::string make_trace_id() {
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
