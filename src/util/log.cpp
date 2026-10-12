#include "util/log.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <mutex>

namespace secguard::log {
namespace {

std::atomic<int> g_level{static_cast<int>(Level::kInfo)};
std::mutex g_mu;

const char* kNames[] = {"DEBUG", "INFO ", "WARN ", "ERROR"};

std::string basename_of(const char* path) {
    std::string s(path ? path : "");
    const auto pos = s.find_last_of("/\\");
    return (pos == std::string::npos) ? s : s.substr(pos + 1);
}

std::string now_string() {
    using namespace std::chrono;
    const auto tp = system_clock::now();
    const auto t = system_clock::to_time_t(tp);
    const auto ms = duration_cast<milliseconds>(tp.time_since_epoch()).count() % 1000;
    std::tm tm{};
    localtime_r(&t, &tm);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d",
                  tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<int>(ms));
    return buf;
}

// 敏感字段名(小写包含匹配)
const char* kSensitive[] = {
    "password", "passwd", "pwd", "secret", "token", "authorization",
    "api_key", "apikey", "cookie", "credential", "private",
};

}  // namespace

void set_level(Level lv) { g_level.store(static_cast<int>(lv)); }

void set_level_from_string(std::string_view s) {
    std::string v(s);
    std::transform(v.begin(), v.end(), v.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (v == "debug")      set_level(Level::kDebug);
    else if (v == "info")  set_level(Level::kInfo);
    else if (v == "warn" || v == "warning") set_level(Level::kWarn);
    else if (v == "error") set_level(Level::kError);
    // 认不出的值保持原级别,不静默改动
}

bool enabled(Level lv) { return static_cast<int>(lv) >= g_level.load(); }

const char* level_name(Level lv) { return kNames[static_cast<int>(lv)]; }

bool is_sensitive_key(std::string_view key) {
    std::string k(key);
    std::transform(k.begin(), k.end(), k.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const char* s : kSensitive) {
        if (k.find(s) != std::string::npos) return true;
    }
    return false;
}

std::string kv(std::string_view key, std::string_view value) {
    std::string out(key);
    out += '=';
    out += is_sensitive_key(key) ? "***" : std::string(value);
    return out;
}

namespace detail {

void write(Level lv, const char* file, int line, const std::string& msg) {
    // 单条日志一次加锁,保证多行不交错
    std::lock_guard<std::mutex> lk(g_mu);
    std::fprintf(stdout, "%s %s %s:%d  %s\n",
                 now_string().c_str(), level_name(lv),
                 basename_of(file).c_str(), line, msg.c_str());
    if (lv == Level::kError) std::fflush(stdout);   // 错误立即落盘
}

}  // namespace detail
}  // namespace secguard::log
