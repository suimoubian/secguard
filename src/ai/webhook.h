// 告警通知:把新告警推到一个 HTTP 端点(寓言集第 65 讲)
//
// 为什么必须有:告警写进数据库,不会有人主动去查。
// 一个只在库里堆数据的告警系统,等于没有告警。
//
// 设计上的三条取舍:
//   1. **只推一次,不无限重试**。通知是"尽力而为":失败就记日志,
//      不阻塞分析线程,也不把没发出去的消息堆在内存里。
//      真要保证送达,应该走消息队列 + 消费端确认,那是另一个量级的事。
//   2. **超时短**(默认 3 秒)。它跑在分析线程里,一个卡住的通知端点
//      会把整轮分析拖死。
//   3. **载荷是通用 JSON**,不绑死某个平台。想接钉钉/Slack/飞书,
//      在中间加一个转发器就行,不用改这里。
#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace secguard {

// 前置声明:这里只需要 const 引用,不必把 dao.h 拉进来。
// (拉进来的话会形成 config.h -> webhook.h -> dao.h ->
//  connection_pool.h -> config.h 的循环包含)
struct AlertRow;

struct WebhookConfig {
    std::string url;                    // 空 = 不通知
    std::string min_severity = "HIGH";  // LOW/MEDIUM/HIGH/CRITICAL
    int         timeout_ms = 3000;
};

class Notifier {
public:
    explicit Notifier(const WebhookConfig& cfg);
    ~Notifier();

    Notifier(const Notifier&) = delete;
    Notifier& operator=(const Notifier&) = delete;

    [[nodiscard]] bool enabled() const { return enabled_; }

    // 推一条告警。返回是否成功(失败只记日志,不影响调用方)。
    bool notify(const AlertRow& alert, std::int64_t alert_id);

    [[nodiscard]] long long sent() const { return sent_; }
    [[nodiscard]] long long failed() const { return failed_; }

private:
    WebhookConfig cfg_;
    bool enabled_ = false;
    long long sent_ = 0;
    long long failed_ = 0;
};

// 严重级别的序(用于比较,"HIGH" 及以上才通知)
// 放在头里内联:config.cpp 做配置校验时也要用它,
// 不值得为三行函数把整个 webhook 模块链进每个目标。
[[nodiscard]] inline int severity_rank(const std::string& s) {
    if (s == "CRITICAL") return 4;
    if (s == "HIGH")     return 3;
    if (s == "MEDIUM")   return 2;
    if (s == "LOW")      return 1;
    return 0;
}

}  // namespace secguard
