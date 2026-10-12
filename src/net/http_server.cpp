#include "net/http_server.h"

#include <chrono>
#include <thread>

#include <nlohmann/json.hpp>

#include "crypto/auth_crypto.h"
#include "util/log.h"

namespace secguard {
namespace {
constexpr const char* kTag = "[服务] ";

const char* action_of(bool blocked) { return blocked ? "BLOCK" : "PASS"; }
}  // namespace

// ---------------------------------------------------------------------------
// 响应助手
// ---------------------------------------------------------------------------
void json_ok(httplib::Response& res, const std::string& body) {
    res.status = 200;
    res.set_content(body, "application/json; charset=utf-8");
}

void json_err(httplib::Response& res, int status, const std::string& message) {
    nlohmann::json j;
    j["error"] = message;
    j["status"] = status;
    res.status = status;
    res.set_content(j.dump(), "application/json; charset=utf-8");
}

// ---------------------------------------------------------------------------
// 取真实 IP:线上走 Nginx 反代,req.remote_addr 会是 Nginx 的地址
// ---------------------------------------------------------------------------
static std::string client_ip(const httplib::Request& req) {
    if (req.has_header("X-Forwarded-For")) {
        const std::string xff = req.get_header_value("X-Forwarded-For");
        const auto comma = xff.find(',');
        std::string first = (comma == std::string::npos) ? xff : xff.substr(0, comma);
        while (!first.empty() && first.front() == ' ') first.erase(first.begin());
        while (!first.empty() && first.back() == ' ') first.pop_back();
        if (!first.empty()) return first;
    }
    if (req.has_header("X-Real-IP")) {
        return req.get_header_value("X-Real-IP");
    }
    return req.remote_addr;
}

// ---------------------------------------------------------------------------
// 限流 / 封禁 / 检测
// ---------------------------------------------------------------------------
bool run_guard(AppContext& ctx, const httplib::Request& req,
               httplib::Response& res, ScanRecord& rec) {
    const auto t0 = std::chrono::steady_clock::now();
    const double now = ctx.now_seconds();

    rec.trace_id = make_trace_id();
    rec.ip = client_ip(req);
    rec.uri = req.path;
    if (!req.params.empty()) rec.uri = req.path;   // 查询串单独落 digest
    rec.method = req.method;
    rec.params_digest = build_params_digest(req.target.find('?') != std::string::npos
                                            ? req.target.substr(req.target.find('?') + 1)
                                            : std::string(),
                                            req.body);

    ctx.requests_total.fetch_add(1);

    // 1) 封禁检查(第 41 讲)
    if (ctx.guard->is_banned(rec.ip, now)) {
        rec.action = "BLOCK";
        rec.rule_hit = "IP_BANNED";
        rec.status_code = 403;
        rec.was_banned = true;
        ctx.requests_blocked.fetch_add(1);
        json_err(res, 403, "IP 已被临时封禁");
        const auto t1 = std::chrono::steady_clock::now();
        rec.cost_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        record_audit(ctx, rec);
        return false;
    }

    // 2) 令牌桶限流(第 38 讲)
    if (ctx.limiter && !ctx.limiter->try_acquire(now)) {
        rec.action = "BLOCK";
        rec.rule_hit = "RATE_LIMITED";
        rec.status_code = 429;
        rec.rate_limited = true;
        ctx.requests_blocked.fetch_add(1);
        json_err(res, 429, "请求过于频繁,请稍后再试");
        const auto t1 = std::chrono::steady_clock::now();
        rec.cost_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        record_audit(ctx, rec);
        return false;
    }

    // 3) 把 HTTP 翻成待检文本,交给引擎(第 17 讲)
    const std::string query = (req.target.find('?') != std::string::npos)
                            ? req.target.substr(req.target.find('?') + 1) : std::string();
    const std::string ua = req.has_header("User-Agent")
                         ? req.get_header_value("User-Agent") : std::string();

    bool truncated = false;
    const std::string scan_text = build_scan_text(
        req.path, query, req.body, ua, ctx.cfg.engine.max_text_bytes, truncated);

    const MatchResult mr = ctx.engine->search(scan_text);
    rec.scan_bytes = mr.scanned_bytes;
    rec.matched_len = static_cast<int>(mr.max_matched_len);

    if (!mr.rule_indices.empty()) {
        // 命中的规则 ID 拼起来(最多列 8 条,避免超长)
        std::string ids;
        const std::size_t limit = std::min<std::size_t>(mr.rule_indices.size(), 8);
        for (std::size_t i = 0; i < limit; ++i) {
            if (i) ids.push_back(',');
            ids += ctx.engine->rule(mr.rule_indices[i]).id;
        }
        if (mr.rule_indices.size() > limit) ids += ",...";
        rec.rule_hit = ids;
        if (mr.truncated) rec.rule_hit += "(截断)";

        // 记一次命中,达到阈值就自动封禁
        ctx.guard->record_hit(rec.ip, now, ctx.cfg.guard.window_seconds,
                              ctx.cfg.guard.hit_threshold,
                              ctx.cfg.guard.ban_seconds);

        // 命中即拦截(第 37 讲:规则引擎负责实时拦截)
        rec.action = "BLOCK";
        rec.status_code = 403;
        ctx.requests_blocked.fetch_add(1);
        nlohmann::json j;
        j["error"] = "请求被安全策略拦截";
        j["trace_id"] = rec.trace_id;
        j["rule_hit"] = rec.rule_hit;
        res.status = 403;
        res.set_content(j.dump(), "application/json; charset=utf-8");

        const auto t1 = std::chrono::steady_clock::now();
        rec.cost_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        record_audit(ctx, rec);
        return false;
    }

    // 没命中:放行。审计记录在处理完之后由处理器补齐状态码
    rec.action = "PASS";
    const auto t1 = std::chrono::steady_clock::now();
    rec.cost_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    (void)action_of;
    return true;
}

void record_audit(AppContext& ctx, const ScanRecord& rec) {
    if (!ctx.dao) return;
    AuditLogRow row;
    row.trace_id      = rec.trace_id;
    row.ip            = rec.ip;
    if (rec.user_id > 0) row.user_id = rec.user_id;
    row.uri           = rec.uri.substr(0, 500);
    row.method        = rec.method.substr(0, 15);
    row.params_digest = rec.params_digest.substr(0, 1000);
    row.rule_hit      = rec.rule_hit.substr(0, 120);
    row.matched_len   = rec.matched_len;
    row.action        = rec.action;
    row.status_code   = rec.status_code;
    row.cost_us       = rec.cost_us;

    std::vector<AuditLogRow> batch;
    batch.push_back(std::move(row));
    if (!ctx.dao->write_audit_batch(batch)) {
        LOG_WARN(kTag, "审计落库失败 trace=", rec.trace_id);
    }
}

// ---------------------------------------------------------------------------
// 当前用户
// ---------------------------------------------------------------------------
bool current_user(AppContext& ctx, const httplib::Request& req,
                  std::int64_t& user_id, std::string& username) {
    if (!req.has_header("Authorization")) return false;
    const std::string token = extract_bearer(req.get_header_value("Authorization"));
    if (token.empty()) return false;

    crypto::JwtClaims claims;
    const auto st = crypto::jwt_verify(token, ctx.cfg.auth.jwt_secret, claims);
    if (st != crypto::JwtStatus::kOk) {
        LOG_DEBUG(kTag, "令牌校验失败,状态=", static_cast<int>(st));
        return false;
    }
    user_id = claims.user_id;
    username = claims.username;
    return true;
}

// ---------------------------------------------------------------------------
// 路由注册
// ---------------------------------------------------------------------------
static void register_core_routes(httplib::Server& svr, AppContext& ctx) {
    // 健康检查:绑 0.0.0.0 才能被外部探活(第 47 讲)
    svr.Get("/health", [&ctx](const httplib::Request&, httplib::Response& res) {
        const bool db_ok = ctx.dao ? ctx.dao->ping() : false;
        nlohmann::json j;
        j["service"] = "secguard";
        j["status"] = db_ok ? "ok" : "degraded";
        j["uptime_sec"] = static_cast<std::int64_t>(ctx.now_seconds());
        j["rules"] = ctx.engine ? ctx.engine->rule_count() : 0;
        j["nodes"] = ctx.engine ? ctx.engine->node_count() : 0;
        j["engine_mem_kb"] = ctx.engine ? ctx.engine->memory_bytes() / 1024 : 0;
        j["engine_generation"] = ctx.engine ? ctx.engine->generation() : 0;
        j["db"] = db_ok;
        j["db_pool_total"] = ctx.pool ? ctx.pool->total_count() : 0;
        j["db_pool_idle"] = ctx.pool ? ctx.pool->idle_count() : 0;
        j["requests_total"] = ctx.requests_total.load();
        j["requests_blocked"] = ctx.requests_blocked.load();
        res.status = db_ok ? 200 : 503;
        res.set_content(j.dump(), "application/json; charset=utf-8");
    });

    // 前端页面:一个查询框 + 结果
    // 注意:这一条也要过检测 —— 所有路由都该被检测,不能只护 /api/*。
    // (踩过这个坑:只把 /api/* 接进引擎,首面就成了没设防的入口。)
    svr.Get("/", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord rec;
        if (!run_guard(ctx, req, res, rec)) return;   // 命中攻击直接拦在这里
        rec.status_code = 200;
        record_audit(ctx, rec);

        res.set_content(
            "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
            "<title>SecGuard 安全审计引擎</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:60px auto;"
            "padding:0 20px;line-height:1.8;color:#222}"
            "code{background:#f2f2f2;padding:2px 6px;border-radius:3px}"
            ".box{border:1px solid #ddd;border-radius:6px;padding:16px;margin:16px 0}</style>"
            "</head><body>"
            "<h1>SecGuard 安全审计引擎</h1>"
            "<p>这是个演示页。引擎会对每个请求做攻击特征匹配,命中即拦截并写审计日志。</p>"
            "<div class=\"box\"><b>试试这些:</b><ul>"
            "<li><a href=\"/?q=hello\">正常请求</a></li>"
            "<li><a href=\"/?id=1%27%20or%20%271%27=%271\">注入尝试</a></li>"
            "<li><a href=\"/?q=%3Cscript%3Ealert(1)%3C/script%3E\">XSS 尝试</a></li>"
            "<li><a href=\"/?file=../../../../etc/passwd\">路径穿越尝试</a></li>"
            "</ul></div>"
            "<p>接口: <code>/health</code> <code>/api/register</code> "
            "<code>/api/login</code> <code>/api/posts</code> "
            "<code>/api/audit/stats</code> <code>/api/check</code></p>"
            "</body></html>",
            "text/html; charset=utf-8");
    });

    // 检测接口:只做检测,不落业务数据
    svr.Post("/api/check", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord rec;
        if (!run_guard(ctx, req, res, rec)) return;

        const auto t0 = std::chrono::steady_clock::now();
        nlohmann::json j;
        j["trace_id"] = rec.trace_id;
        j["action"] = "PASS";
        j["scanned_bytes"] = rec.scan_bytes;
        j["cost_us"] = rec.cost_us;
        j["rule_count"] = ctx.engine->rule_count();
        const auto t1 = std::chrono::steady_clock::now();
        rec.status_code = 200;
        rec.cost_us += std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        record_audit(ctx, rec);
        json_ok(res, j.dump());
    });
}

void register_routes(httplib::Server& svr, AppContext& ctx) {
    register_core_routes(svr, ctx);
    register_auth_routes(svr, ctx);
    register_content_routes(svr, ctx);
    register_audit_routes(svr, ctx);
}

}  // namespace secguard
