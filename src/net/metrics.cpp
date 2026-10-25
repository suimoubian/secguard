#include "net/metrics.h"

#include <sstream>

#include "util/log.h"

namespace secguard {
namespace {

constexpr const char* kTag = "[指标] ";

// 计数器必须带 _total 后缀、且类型标 counter —— 这是 Prometheus 的约定,
// 不符合约定的名字会让 rate() 之类的函数用不了。
void counter(std::ostringstream& o, const char* name, const char* help,
             long long value, const char* type = "counter") {
    o << "# HELP " << name << ' ' << help << '\n'
      << "# TYPE " << name << ' ' << type << '\n'
      << name << ' ' << value << '\n';
}

void gauge(std::ostringstream& o, const char* name, const char* help,
           long long value) {
    counter(o, name, help, value, "gauge");
}

void gauge_d(std::ostringstream& o, const char* name, const char* help,
             double value) {
    o << "# HELP " << name << ' ' << help << '\n'
      << "# TYPE " << name << " gauge\n"
      << name << ' ' << value << '\n';
}

}  // namespace

std::string render_metrics(AppContext& ctx) {
    std::ostringstream o;

    // --- 存活与运行时长 ---
    gauge(o, "secguard_up", "服务是否在跑(恒为 1)", 1);
    gauge_d(o, "secguard_uptime_seconds", "进程启动至今的秒数",
            ctx.now_seconds());

    // --- 请求量 ---
    counter(o, "secguard_requests_total", "进入过检测的请求总数",
            ctx.requests_total.load());
    counter(o, "secguard_requests_blocked_total", "被拦截的请求总数",
            ctx.requests_blocked.load());
    counter(o, "secguard_requests_alerted_total",
            "只命中 ALERT 级规则、放行但留痕的请求数",
            ctx.requests_alerted.load());
    counter(o, "secguard_replay_rejected_total", "重放请求被拒的次数",
            ctx.replay_rejected.load());

    // --- 引擎 ---
    if (ctx.engine) {
        gauge(o, "secguard_engine_rules", "已加载的攻击特征条数",
              static_cast<long long>(ctx.engine->rule_count()));
        gauge(o, "secguard_engine_nodes", "AC 自动机节点数",
              static_cast<long long>(ctx.engine->node_count()));
        gauge(o, "secguard_engine_memory_bytes", "自动机占用内存(字节)",
              static_cast<long long>(ctx.engine->memory_bytes()));
        gauge(o, "secguard_engine_allowlist_entries", "白名单条目数",
              static_cast<long long>(ctx.engine->allowlist_size()));
        counter(o, "secguard_engine_reloads_total", "特征库热加载成功次数",
                static_cast<long long>(ctx.engine->generation()) - 1,
                "counter");
    }

    // --- 数据库连接池 ---
    if (ctx.pool) {
        gauge(o, "secguard_db_pool_total", "连接池里的连接总数",
              static_cast<long long>(ctx.pool->total_count()));
        gauge(o, "secguard_db_pool_idle", "连接池当前空闲连接数",
              static_cast<long long>(ctx.pool->idle_count()));
    }

    // --- Redis / 分布式防护 ---
    // guard_mode 用两个互斥的 gauge 表示,而不是带标签的枚举:
    // 这样告警规则可以直接写 secguard_guard_mode_redis == 1,不用处理标签。
    const bool redis_ok = ctx.redis && ctx.redis->available();
    gauge(o, "secguard_redis_up", "Redis 是否可用(1 可用 / 0 降级)",
          redis_ok ? 1 : 0);
    gauge(o, "secguard_guard_mode_redis",
          "限流与封禁是否用 Redis 共享状态(1 是 / 0 单机降级)",
          redis_ok ? 1 : 0);
    if (ctx.redis) {
        counter(o, "secguard_redis_commands_total", "发往 Redis 的命令数",
                ctx.redis->commands());
        counter(o, "secguard_redis_failures_total", "Redis 命令失败次数",
                ctx.redis->failures());
    }

    // --- 审计管道 ---
    if (ctx.audit) {
        gauge(o, "secguard_audit_queued", "审计队列里待写的条数",
              static_cast<long long>(ctx.audit->queued()));
        counter(o, "secguard_audit_written_total", "成功写入的审计条数",
                ctx.audit->written());
        counter(o, "secguard_audit_dropped_total", "因队列满被丢弃的审计条数",
                ctx.audit->dropped());
    }

    // --- AI 分析层 ---
    if (ctx.analyzer && ctx.analyzer->enabled()) {
        const auto& st = ctx.analyzer->stats();
        gauge(o, "secguard_ai_enabled", "分析层是否启用(恒为 1)", 1);
        counter(o, "secguard_ai_rounds_total", "跑过的分析轮数", st.rounds);
        counter(o, "secguard_ai_calls_total", "LLM 调用次数", st.calls);
        counter(o, "secguard_ai_call_errors_total", "LLM 调用失败次数",
                st.transport_errors);
        counter(o, "secguard_ai_parse_errors_total", "LLM 返回解析失败次数",
                st.parse_errors);
        counter(o, "secguard_ai_alerts_total", "生成的告警数",
                st.alerts_created);
        counter(o, "secguard_ai_notify_sent_total", "成功推送的通知数",
                st.notified);
        counter(o, "secguard_ai_notify_failed_total", "推送失败的通知数",
                st.notify_failed);
    } else {
        gauge(o, "secguard_ai_enabled", "分析层是否启用(0 表示未启用)", 0);
    }

    LOG_DEBUG(kTag, "已生成指标");
    return o.str();
}

}  // namespace secguard
