// 审计接口:统计 / 按 IP 查拦截记录 / 特征库信息 / 热加载
// 对应寓言集第 50(索引)、56(防篡改)、14(热加载)讲
#include "net/http_server.h"

#include <nlohmann/json.hpp>

#include "util/log.h"

namespace secguard {
namespace {

constexpr const char* kTag = "[审计] ";

bool valid_ip_like(const std::string& s) {
    if (s.empty() || s.size() > 64) return false;
    for (unsigned char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                     || (c >= 'A' && c <= 'F') || c == '.' || c == ':' || c == '-';
        if (!ok) return false;
    }
    return true;
}

}  // namespace

void register_audit_routes(httplib::Server& svr, AppContext& ctx) {
    // ---- 总体统计 ----
    svr.Get("/api/audit/stats", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord rec;
        if (!run_guard(ctx, req, res, rec)) return;

        const auto st = ctx.dao->audit_stats();
        nlohmann::json j;
        j["audit_total"] = st.total;
        j["audit_blocked"] = st.blocked;
        j["audit_passed"] = st.passed;
        j["distinct_ips"] = st.hits_by_ip;
        j["requests_total"] = ctx.requests_total.load();
        j["requests_blocked"] = ctx.requests_blocked.load();
        j["replay_rejected"] = ctx.replay_rejected.load();
        j["db_pool_total"] = ctx.pool->total_count();
        j["db_pool_idle"] = ctx.pool->idle_count();
        j["db_conn_created"] = ctx.pool->create_count();
        j["db_conn_reused"] = ctx.pool->reuse_count();
        // 防护状态是共享的还是单机的,直接影响多实例部署下的正确性
        j["guard_mode"] = ctx.guard->redis_available() ? "redis" : "local";
        j["redis"] = ctx.redis ? ctx.redis->available() : false;
        if (ctx.redis) {
            j["redis_commands"] = ctx.redis->commands();
            j["redis_failures"] = ctx.redis->failures();
        }
        j["guard_fallbacks"] = ctx.guard->fallback_count();
        if (ctx.audit) {
            j["audit_queued"] = ctx.audit->queued();
            j["audit_written"] = ctx.audit->written();
            j["audit_dropped"] = ctx.audit->dropped();
        }

        rec.status_code = 200;
        record_audit(ctx, rec);
        json_ok(res, j.dump());
    });

    // ---- 按 IP 查最近的拦截记录(走 idx_ip_time 索引) ----
    svr.Get("/api/audit/by-ip", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord rec;
        if (!run_guard(ctx, req, res, rec)) return;

        if (!req.has_param("ip")) { json_err(res, 400, "缺少 ip 参数"); return; }
        const std::string ip = req.get_param_value("ip");
        if (!valid_ip_like(ip)) { json_err(res, 400, "ip 参数格式不合法"); return; }

        int limit = 20;
        if (req.has_param("limit")) {
            try { limit = std::stoi(req.get_param_value("limit")); } catch (...) {}
            if (limit < 1) limit = 1;
            if (limit > 200) limit = 200;
        }

        const auto rows = ctx.dao->recent_blocked(ip, limit);
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& r : rows) {
            arr.push_back({{"trace_id", r.trace_id}, {"uri", r.uri}, {"method", r.method},
                           {"rule_hit", r.rule_hit}, {"matched_len", r.matched_len},
                           {"cost_us", r.cost_us}});
        }
        nlohmann::json j;
        j["ip"] = ip;
        j["items"] = arr;
        j["hits_in_window"] = ctx.guard->hits_in_window(
            ip, ctx.cfg.guard.window_seconds);
        j["banned"] = ctx.guard->is_banned(ip);

        rec.status_code = 200;
        record_audit(ctx, rec);
        json_ok(res, j.dump());
    });

    // ---- 特征库信息 ----
    svr.Get("/api/rules", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord rec;
        if (!run_guard(ctx, req, res, rec)) return;

        nlohmann::json j;
        j["rule_count"] = ctx.engine->rule_count();
        j["node_count"] = ctx.engine->node_count();
        j["memory_kb"] = ctx.engine->memory_bytes() / 1024;
        j["generation"] = ctx.engine->generation();

        rec.status_code = 200;
        record_audit(ctx, rec);
        json_ok(res, j.dump());
    });

    // ---- 热加载:不停止服务换规则(第 14 讲) ----
    svr.Post("/api/rules/reload", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord rec;
        if (!run_guard(ctx, req, res, rec)) return;

        std::size_t n = 0;
        const bool changed = ctx.engine->reload_if_changed(
            ctx.cfg.engine.pattern_file, ctx.cfg.engine, n);

        nlohmann::json j;
        j["reloaded"] = changed;
        j["rule_count"] = ctx.engine->rule_count();
        j["generation"] = ctx.engine->generation();
        if (changed) {
            LOG_INFO(kTag, "热加载成功,规则数=", ctx.engine->rule_count());
        } else {
            j["note"] = "文件未变化或加载失败(失败时保留旧表)";
        }

        rec.status_code = 200;
        record_audit(ctx, rec);
        json_ok(res, j.dump());
    });
}

}  // namespace secguard
