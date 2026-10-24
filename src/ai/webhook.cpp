#include "ai/webhook.h"

#include <curl/curl.h>

#include <cstring>
#include <mutex>

#include <nlohmann/json.hpp>

#include "db/dao.h"     // AlertRow 的完整定义(头文件里只有前置声明)
#include "util/log.h"

namespace secguard {
namespace {

constexpr const char* kTag = "[通知] ";

void ensure_curl() {
    static std::once_flag f;
    std::call_once(f, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

// 丢弃响应体:我们只关心送没送到,不解析对端返回什么
std::size_t sink(char*, std::size_t size, std::size_t nmemb, void*) {
    return size * nmemb;
}

}  // namespace

Notifier::Notifier(const WebhookConfig& cfg) : cfg_(cfg) {
    if (cfg_.url.empty()) {
        LOG_INFO(kTag, "未配置告警通知端点(SECGUARD_ALERT_WEBHOOK),跳过");
        return;
    }
    if (cfg_.url.rfind("http://", 0) != 0 && cfg_.url.rfind("https://", 0) != 0) {
        LOG_WARN(kTag, "通知端点必须是 http(s):// 开头,已停用:", cfg_.url);
        return;
    }
    if (cfg_.timeout_ms <= 0 || cfg_.timeout_ms > 30000) cfg_.timeout_ms = 3000;
    enabled_ = true;
    LOG_INFO(kTag, "已启用: 端点=", cfg_.url,
             " 最低级别=", cfg_.min_severity,
             " 超时=", cfg_.timeout_ms, "ms");
}

Notifier::~Notifier() = default;

bool Notifier::notify(const AlertRow& alert, std::int64_t alert_id) {
    if (!enabled_) return false;

    // 级别不够就不推。默认 HIGH 以上 —— 谁会愿意被 MEDIUM 的噪声淹掉?
    if (severity_rank(alert.severity) < severity_rank(cfg_.min_severity)) {
        LOG_DEBUG(kTag, "级别不足,不通知:", alert.severity);
        return false;
    }

    nlohmann::json j;
    j["event"] = "alert.created";
    j["alert_id"] = alert_id;
    j["ip"] = alert.ip;
    j["threat_type"] = alert.threat_type;
    j["severity"] = alert.severity;
    j["confidence"] = alert.confidence;
    j["reasoning"] = alert.reasoning;
    j["log_ids"] = alert.log_ids;

    const std::string payload = j.dump();

    ensure_curl();
    CURL* curl = curl_easy_init();
    if (!curl) {
        ++failed_;
        return false;
    }

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "X-SecGuard-Event: alert.created");

    curl_easy_setopt(curl, CURLOPT_URL, cfg_.url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(payload.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sink);
    // 超时必须短:这个调用跑在分析线程里,卡住会拖死整轮分析
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(cfg_.timeout_ms));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS,
                     static_cast<long>(cfg_.timeout_ms));
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "secguard/1.0");

    const CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    // 尽力而为:失败只记一条日志,不重试、不排队。
    if (rc != CURLE_OK) {
        ++failed_;
        LOG_WARN(kTag, "推送失败 alert_id=", alert_id, " 原因=",
                 curl_easy_strerror(rc));
        return false;
    }
    if (status < 200 || status >= 300) {
        ++failed_;
        LOG_WARN(kTag, "推送被拒 alert_id=", alert_id, " HTTP ", status);
        return false;
    }
    ++sent_;
    LOG_INFO(kTag, "已推送告警 alert_id=", alert_id, " -> ", cfg_.url,
             "(HTTP ", status, ")");
    return true;
}

}  // namespace secguard
