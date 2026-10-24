// Prometheus 指标导出(文本格式)
//
// 为什么要做:现在只有 /health 和几个 /api/*/stats,都是给人看的 JSON。
// 机器看不懂,也没法做时间序列 —— 出问题时你只能看"此刻是多少",
// 看不到"什么时候开始变坏的"。
//
// 为什么用 Prometheus 文本格式而不是自己发明 JSON:
//   这是事实标准,Prometheus / VictoriaMetrics / 很多采集器直接能抓,
//   不用为每个系统写适配。
//
// 关于鉴权:指标里会暴露请求量、连接池占用、封禁次数这些运营信息,
// 所以和其它管理接口一样要求管理员令牌。Prometheus 的抓取配置里可以带
// bearer_token,不影响自动化采集。
#pragma once

#include <string>

#include "net/app_context.h"

namespace secguard {

// 生成 Prometheus 文本格式的指标(body 内容)
[[nodiscard]] std::string render_metrics(AppContext& ctx);

}  // namespace secguard
