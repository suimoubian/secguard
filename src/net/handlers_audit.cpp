// 审计接口:统计 / 按 IP 查拦截记录 / 特征库信息 / 热加载 / Prometheus 指标
// 对应寓言集第 50(索引)、56(防篡改)、14(热加载)讲
#include "net/http_server.h"

#include <nlohmann/json.hpp>

#include "net/metrics.h"
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
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;
        // 管理接口:必须管理员令牌。原来这 8 个接口是裸的,
        // 谁都能看审计数据、还能把攻击标成"误报"删证据。
        std::string admin;
        if (!require_admin(ctx, req, res, admin)) return;

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
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;
        // 管理接口:必须管理员令牌。原来这 8 个接口是裸的,
        // 谁都能看审计数据、还能把攻击标成"误报"删证据。
        std::string admin;
        if (!require_admin(ctx, req, res, admin)) return;

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
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;
        // 管理接口:必须管理员令牌。原来这 8 个接口是裸的,
        // 谁都能看审计数据、还能把攻击标成"误报"删证据。
        std::string admin;
        if (!require_admin(ctx, req, res, admin)) return;

        nlohmann::json j;
        j["rule_count"] = ctx.engine->rule_count();
        j["node_count"] = ctx.engine->node_count();
        j["memory_kb"] = ctx.engine->memory_bytes() / 1024;
        j["generation"] = ctx.engine->generation();
        j["allowlist"] = ctx.engine->allowlist_size();

        rec.status_code = 200;
        record_audit(ctx, rec);
        json_ok(res, j.dump());
    });

    // ---- 热加载:不停止服务换规则(第 14 讲) ----
    svr.Post("/api/rules/reload", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;
        // 管理接口:必须管理员令牌。原来这 8 个接口是裸的,
        // 谁都能看审计数据、还能把攻击标成"误报"删证据。
        std::string admin;
        if (!require_admin(ctx, req, res, admin)) return;

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

    // -----------------------------------------------------------------------
    // W6:告警与 AI 分析
    // -----------------------------------------------------------------------

    // ---- 告警列表 ----
    svr.Get("/api/alerts", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;
        // 管理接口:必须管理员令牌。原来这 8 个接口是裸的,
        // 谁都能看审计数据、还能把攻击标成"误报"删证据。
        std::string admin;
        if (!require_admin(ctx, req, res, admin)) return;

        int limit = 20;
        int offset = 0;
        if (req.has_param("limit")) {
            try { limit = std::stoi(req.get_param_value("limit")); } catch (...) {}
            if (limit < 1) limit = 1;
            if (limit > 200) limit = 200;
        }
        if (req.has_param("offset")) {
            try { offset = std::stoi(req.get_param_value("offset")); } catch (...) {}
            if (offset < 0) offset = 0;
        }

        const auto rows = ctx.dao->list_alerts(limit, offset);
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& a : rows) {
            arr.push_back({{"id", a.id},
                           {"ip", a.ip},
                           {"threat_type", a.threat_type},
                           {"severity", a.severity},
                           {"confidence", a.confidence},
                           {"reasoning", a.reasoning},
                           {"log_ids", a.log_ids},
                           {"status", a.status},
                           {"created_at", a.created_at}});
        }

        const auto st = ctx.dao->alert_stats();
        nlohmann::json j;
        j["items"] = arr;
        j["stats"] = {{"total", st.total},
                      {"pending", st.pending},
                      {"confirmed", st.confirmed},
                      {"false_positive", st.false_positive},
                      {"critical", st.critical},
                      {"high", st.high}};
        j["limit"] = limit;
        j["offset"] = offset;

        rec.status_code = 200;
        record_audit(ctx, rec);
        json_ok(res, j.dump());
    });

    // ---- 人工改告警状态:1 已确认 / 2 误报 ----
    //
    // 为什么要有这个:LLM 一定有误判。误判不可怕,
    // 可怕的是误判没地方纠正、也没记录 —— 那样连"模型准不准"都无从评估。
    svr.Post(R"(/api/alerts/(\d+)/status)",
             [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;
        // 管理接口:必须管理员令牌。原来这 8 个接口是裸的,
        // 谁都能看审计数据、还能把攻击标成"误报"删证据。
        std::string admin;
        if (!require_admin(ctx, req, res, admin)) return;

        std::int64_t id = 0;
        {
            const std::string s = req.matches[1].str();
            if (s.empty() || s.size() > 19) { json_err(res, 400, "id 不合法"); return; }
            try { id = std::stoll(s); } catch (...) { json_err(res, 400, "id 不合法"); return; }
            if (id <= 0) { json_err(res, 400, "id 不合法"); return; }
        }

        int status = -1;
        if (req.has_param("status")) {
            try { status = std::stoi(req.get_param_value("status")); } catch (...) {}
        } else {
            const auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (!body.is_discarded() && body.is_object() && body.contains("status")
                && body["status"].is_number_integer()) {
                status = body["status"].get<int>();
            }
        }
        if (status != 1 && status != 2) {
            json_err(res, 400, "status 只能是 1(已确认)或 2(误报)");
            return;
        }

        if (ctx.dao->set_alert_status(id, status) != WriteResult::kOk) {
            json_err(res, 404, "告警不存在或更新失败");
            return;
        }

        rec.status_code = 200;
        record_audit(ctx, rec);

        nlohmann::json j;
        j["id"] = id;
        j["status"] = status;
        j["meaning"] = (status == 1 ? "已确认" : "误报");
        json_ok(res, j.dump());
    });

    // ---- 手动触发一轮分析(演示与运维用) ----
    svr.Post("/api/analyze/run", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;
        // 管理接口:必须管理员令牌。原来这 8 个接口是裸的,
        // 谁都能看审计数据、还能把攻击标成"误报"删证据。
        std::string admin;
        if (!require_admin(ctx, req, res, admin)) return;

        if (!ctx.analyzer) { json_err(res, 503, "分析层未初始化"); return; }
        if (!ctx.cfg.ai.enabled) {
            json_err(res, 409, "分析层未启用(设 SECGUARD_AI_ENABLE=1)");
            return;
        }
        if (!ctx.llm || !ctx.llm->available()) {
            json_err(res, 409, "LLM 不可用,检查 SECGUARD_LLM_KEY / PROVIDER");
            return;
        }

        const auto before = ctx.analyzer->stats();
        const bool did = ctx.analyzer->run_once_manual();
        const auto& after = ctx.analyzer->stats();

        nlohmann::json j;
        j["ran"] = did;
        j["calls"] = after.calls - before.calls;
        j["ok_calls"] = after.ok_calls - before.ok_calls;
        j["transport_errors"] = after.transport_errors - before.transport_errors;
        j["parse_errors"] = after.parse_errors - before.parse_errors;
        j["alerts_created"] = after.alerts_created - before.alerts_created;
        j["skipped_low_confidence"] = after.skipped_low_confidence
                                    - before.skipped_low_confidence;
        j["skipped_not_attack"] = after.skipped_not_attack - before.skipped_not_attack;
        j["provider"] = ctx.llm->provider();
        j["model"] = ctx.llm->model();
        if (!did) j["note"] = "没有可分析的记录(或达到每分钟调用上限)";

        rec.status_code = 200;
        record_audit(ctx, rec);
        json_ok(res, j.dump());
    });

    // ---- 分析层状态 ----
    svr.Get("/api/analyze/stats", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;
        // 管理接口:必须管理员令牌。原来这 8 个接口是裸的,
        // 谁都能看审计数据、还能把攻击标成"误报"删证据。
        std::string admin;
        if (!require_admin(ctx, req, res, admin)) return;

        nlohmann::json j;
        j["enabled"] = ctx.cfg.ai.enabled;
        j["provider"] = ctx.llm ? ctx.llm->provider() : "none";
        j["model"] = ctx.llm ? ctx.llm->model() : "none";
        j["llm_available"] = ctx.llm ? ctx.llm->available() : false;
        j["min_confidence"] = ctx.cfg.ai.min_confidence;
        j["interval_seconds"] = ctx.cfg.ai.interval_seconds;
        if (ctx.analyzer) {
            const auto& s = ctx.analyzer->stats();
            j["rounds"] = s.rounds;
            j["records_seen"] = s.records_seen;
            j["groups"] = s.groups;
            j["calls"] = s.calls;
            j["ok_calls"] = s.ok_calls;
            j["transport_errors"] = s.transport_errors;
            j["parse_errors"] = s.parse_errors;
            j["alerts_created"] = s.alerts_created;
            j["skipped_low_confidence"] = s.skipped_low_confidence;
            j["skipped_not_attack"] = s.skipped_not_attack;
            j["rate_limited"] = s.rate_limited;
            j["last_round_ms"] = s.last_round_ms;
        }
        if (ctx.llm) {
            j["llm_requests"] = ctx.llm->requests();
            j["llm_retries"] = ctx.llm->retries();
            j["llm_failures"] = ctx.llm->failures();
        }
        const auto st = ctx.dao->alert_stats();
        j["alerts"] = {{"total", st.total}, {"pending", st.pending},
                       {"confirmed", st.confirmed}, {"false_positive", st.false_positive}};

        rec.status_code = 200;
        record_audit(ctx, rec);
        json_ok(res, j.dump());
    });

    // ---- Prometheus 指标 ----
    //
    // 返回文本格式而不是 JSON:这是事实标准,采集器直接能用。
    // 它和别的人看的接口不同 —— 这个接口是给机器看的,
    // 所以 Content-Type 是 text/plain 而不是 application/json。
    svr.Get("/metrics", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        if (!scan_body(ctx, req, res, rec)) return;
        // 指标里有请求量、连接池占用这些运营信息,和别的人管理接口一样要令牌。
        // Prometheus 的抓取配置里可以带 bearer_token,不影响自动化。
        std::string admin;
        if (!require_admin(ctx, req, res, admin)) return;

        res.status = 200;
        res.set_content(render_metrics(ctx), "text/plain; version=0.0.4; charset=utf-8");
        rec.status_code = 200;
        record_audit(ctx, rec);
    });
}

}  // namespace secguard
