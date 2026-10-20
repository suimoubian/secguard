#include "ai/llm_client.h"

#include <curl/curl.h>

#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>

#include <nlohmann/json.hpp>

#include "util/log.h"

namespace secguard {
namespace {

constexpr const char* kTag = "[LLM] ";

// curl 的全局初始化只需一次,而且必须在任何线程用它之前完成
void ensure_curl_init() {
    static std::once_flag flag;
    std::call_once(flag, [] {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
            LOG_ERROR(kTag, "curl_global_init 失败");
        }
    });
}

// 收响应用的。必须设上限:对端如果吐了几百 MB,不能跟着吞(第 61 讲)
struct WriteCtx {
    std::string body;
    std::size_t max_bytes = 256 * 1024;
    bool overflow = false;
};

std::size_t on_write(char* data, std::size_t size, std::size_t nmemb, void* userp) {
    auto* ctx = static_cast<WriteCtx*>(userp);
    const std::size_t n = size * nmemb;
    if (ctx->body.size() + n > ctx->max_bytes) {
        ctx->overflow = true;
        return 0;      // 返回 0 让 curl 中止传输
    }
    ctx->body.append(data, n);
    return n;
}

// 429 与 5xx 值得重试;4xx(除 429)是请求本身的问题,重试没有意义
bool retryable(int http_status) {
    if (http_status == 0) return true;          // 网络层失败
    if (http_status == 429) return true;
    return http_status >= 500 && http_status < 600;
}

}  // namespace

LlmClient::LlmClient(const LlmConfig& cfg) : cfg_(cfg) {
    if (cfg_.provider == "mock") {
        LOG_INFO(kTag, "使用 mock 模式(不联网)。用于跑通链路与测试。");
        return;
    }
    if (cfg_.api_key.empty()) {
        LOG_WARN(kTag, "没有配置 API Key,LLM 不可用(分析层会自动跳过)");
        return;
    }
    ensure_curl_init();
    LOG_INFO(kTag, "已配置:", cfg_.provider, " 模型=", cfg_.model,
             " 地址=", cfg_.base_url, " 密钥=***");
}

bool LlmClient::available() const {
    if (cfg_.provider == "mock") return true;
    return cfg_.provider == "openai" && !cfg_.api_key.empty();
}

LlmResult LlmClient::chat(const std::string& system_prompt,
                          const std::string& user_prompt) {
    if (!available()) {
        LlmResult r;
        r.error = "LLM 未配置(缺 API Key 或 provider 不认识)";
        return r;
    }

    if (cfg_.provider == "mock") {
        // mock 也计入请求数,否则统计面板会显示"0 次调用"却没少干活
        ++requests_;
        return call_mock(user_prompt);
    }

    LlmResult result;
    const int max_attempts = cfg_.max_retries + 1;
    for (int attempt = 1; attempt <= max_attempts; ++attempt) {
        ++requests_;
        result = call_once(system_prompt, user_prompt);
        result.attempts = attempt;
        if (result.ok) return result;

        if (!retryable(result.http_status) || attempt == max_attempts) break;

        ++retries_;
        // 指数退避:1s、2s、4s。别把对端的限流当成故障猛捶(第 61 讲)
        const int wait_ms = 1000 * (1 << (attempt - 1));
        LOG_WARN(kTag, "调用失败(http=", result.http_status, "),",
                 wait_ms, "ms 后重试(", attempt, "/", cfg_.max_retries, ")");
        std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
    }

    ++failures_;
    return result;
}

LlmResult LlmClient::call_once(const std::string& system_prompt,
                               const std::string& user_prompt) {
    const auto t0 = std::chrono::steady_clock::now();
    LlmResult out;

    CURL* curl = curl_easy_init();
    if (!curl) {
        out.error = "curl_easy_init 失败";
        return out;
    }

    // 拼请求体(OpenAI chat completions 格式)
    nlohmann::json body;
    try {
        body = {
            {"model", cfg_.model},
            {"temperature", cfg_.temperature},
            {"max_tokens", cfg_.max_tokens},
            {"messages", nlohmann::json::array({
                {{"role", "system"}, {"content", system_prompt}},
                {{"role", "user"},   {"content", user_prompt}},
            })},
        };
    } catch (const std::exception& e) {
        curl_easy_cleanup(curl);
        out.error = std::string("拼请求体失败: ") + e.what();
        return out;
    }
    const std::string payload = body.dump();

    const std::string url = cfg_.base_url + "/chat/completions";
    WriteCtx ctx;
    ctx.max_bytes = cfg_.max_response_bytes;

    char errbuf[CURL_ERROR_SIZE] = {0};
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    // 密钥只在请求头里出现,不进日志
    const std::string auth = "Authorization: Bearer " + cfg_.api_key;
    headers = curl_slist_append(headers, auth.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(payload.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    // 超时是硬要求:对端不回,程序不能跟着吊死
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(cfg_.timeout_ms));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS,
                     static_cast<long>(cfg_.connect_timeout_ms));
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);       // 多线程下必须关信号
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L); // 不跟跳转:少一层风险
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "secguard/1.0");

    const CURLcode rc = curl_easy_perform(curl);
    long http_status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
    out.http_status = static_cast<int>(http_status);

    const auto t1 = std::chrono::steady_clock::now();
    out.latency_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        out.error = ctx.overflow ? "响应超过上限,已中止"
                                 : std::string("网络错误: ") + errbuf;
        return out;
    }
    if (http_status != 200) {
        // 错误响应体可能含服务端信息,截断后再记
        std::string snippet = ctx.body.substr(0, 200);
        out.error = "HTTP " + std::to_string(http_status) + " " + snippet;
        return out;
    }

    // 解析 OpenAI 格式:choices[0].message.content
    try {
        const auto j = nlohmann::json::parse(ctx.body);
        if (j.contains("choices") && j["choices"].is_array() && !j["choices"].empty()) {
            const auto& c0 = j["choices"][0];
            if (c0.contains("message") && c0["message"].contains("content")) {
                out.content = c0["message"]["content"].get<std::string>();
                out.ok = true;
                return out;
            }
        }
        out.error = "响应格式不认识(没有 choices[0].message.content)";
    } catch (const std::exception& e) {
        out.error = std::string("响应不是合法 JSON: ") + e.what();
    }
    return out;
}

// ---------------------------------------------------------------------------
// mock:不联网,按输入内容给出确定性结果
//
// 用途:没有 API Key 时也能把整条链路跑通(拉数据 -> 组 prompt -> 解析 ->
// 过滤 -> 落 alert),而不至于"因为没网所以整块功能没法验证"(第 62 讲)。
// ---------------------------------------------------------------------------
LlmResult LlmClient::call_mock(const std::string& user_prompt) {
    LlmResult out;
    out.http_status = 200;
    out.attempts = 1;

    // 根据提示里出现的规则前缀判断"像什么攻击",让结果有区分度
    std::string threat = "SUSPICIOUS_REQUEST";
    std::string severity = "MEDIUM";
    double confidence = 0.55;
    std::string reasoning;

    auto has = [&user_prompt](const char* s) {
        return user_prompt.find(s) != std::string::npos;
    };

    if (has("SQL-")) {
        threat = "SQL_INJECTION"; severity = "HIGH"; confidence = 0.92;
        reasoning = "命中多条 SQL 注入特征(union/select 组合),且出现在查询参数中,"
                    "符合注入尝试的典型形态。";
    } else if (has("XSS-")) {
        threat = "XSS"; severity = "HIGH"; confidence = 0.88;
        reasoning = "命中 script 标签与事件属性特征,构造可执行脚本的意图明确。";
    } else if (has("PAT-")) {
        threat = "PATH_TRAVERSAL"; severity = "HIGH"; confidence = 0.90;
        reasoning = "包含多级目录回溯并指向系统敏感文件,典型路径穿越尝试。";
    } else if (has("CMD-")) {
        threat = "COMMAND_INJECTION"; severity = "CRITICAL"; confidence = 0.95;
        reasoning = "出现命令分隔符拼接系统命令的模式,且目标为敏感文件,"
                    "具备直接命令执行意图。";
    } else {
        reasoning = "命中了规则但模式不够明确,建议人工复核。";
    }

    nlohmann::json j;
    j["is_attack"] = confidence >= 0.5;
    j["threat_type"] = threat;
    j["severity"] = severity;
    j["confidence"] = confidence;

    // 自检回显:数一数收到的数据区里出现了几次闭合标记。
    // 正常情况必须恰好 1 次(只有我们加的那一个)。
    // 如果攻击者能在参数里塞进第二个,这里就会 >1 —— 说明清洗失效了。
    // 这个计数会被写进 alert.reasoning,端到端测试可以直接断言。
    std::size_t close_count = 0;
    for (std::size_t pos = 0;
         (pos = user_prompt.find("</untrusted>", pos)) != std::string::npos;
         pos += 12) {
        ++close_count;
    }

    j["reasoning"] = std::string("[mock] ") + reasoning
                   + " | delim_close=" + std::to_string(close_count);
    out.content = j.dump();
    out.ok = true;

    // 稍微延迟一点,模拟真实网络,便于观察并发行为
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    out.latency_ms = 20;
    return out;
}

}  // namespace secguard
