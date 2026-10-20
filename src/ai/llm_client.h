// LLM 客户端:OpenAI 兼容的 chat completions(寓言集第 59~62 讲)
//
// 为什么自己用 libcurl 写而不是套 SDK:
//   需求只有"发一个 JSON、收一个 JSON",为这点事引一个 SDK 不划算,
//   而且 SDK 常常把超时、重试、响应上限这些关键细节藏起来 ——
//   出了问题反而更难查。
//
// 四条硬要求(第 61 讲):
//   1. 必须设超时。对端不回,程序不能跟着吊死。
//   2. 必须设响应上限。对端如果吐了 10GB,不能把内存吃光。
//   3. 必须区分"可重试"和"不可重试"。429/5xx/网络错误可重试,401 重试没意义。
//   4. 密钥只从环境变量来,日志里绝不出现。
#pragma once

#include <cstdint>
#include <string>

namespace secguard {

struct LlmConfig {
    // mock = 不联网,返回固定结构的假结果,用来跑通链路与测试(第 62 讲)
    std::string provider = "mock";        // mock | openai
    std::string base_url = "https://api.deepseek.com/v1";
    std::string model = "deepseek-chat";
    std::string api_key;                  // 只从环境变量来
    int         timeout_ms = 20000;
    int         connect_timeout_ms = 3000;
    int         max_retries = 2;
    int         max_tokens = 512;
    double      temperature = 0.0;        // 判定类任务要确定性,温度压到 0
    std::size_t max_response_bytes = 256 * 1024;   // 响应上限
};

// 一次调用的结果
struct LlmResult {
    bool         ok = false;
    int          http_status = 0;
    std::string  content;          // 模型返回的正文
    std::string  error;            // 失败原因(已脱敏)
    long long    latency_ms = 0;
    int          attempts = 0;
};

class LlmClient {
public:
    explicit LlmClient(const LlmConfig& cfg);

    // 是否配置齐全、可以真正调用
    [[nodiscard]] bool available() const;
    [[nodiscard]] const std::string& model() const { return cfg_.model; }
    [[nodiscard]] const std::string& provider() const { return cfg_.provider; }

    // 发一轮对话。system_prompt 定规则,user_prompt 放数据。
    LlmResult chat(const std::string& system_prompt, const std::string& user_prompt);

    [[nodiscard]] long long requests() const { return requests_; }
    [[nodiscard]] long long failures() const { return failures_; }
    [[nodiscard]] long long retries() const { return retries_; }

private:
    LlmResult call_once(const std::string& system_prompt,
                        const std::string& user_prompt);
    LlmResult call_mock(const std::string& user_prompt);

    LlmConfig cfg_;
    long long requests_ = 0;
    long long failures_ = 0;
    long long retries_ = 0;
};

}  // namespace secguard
