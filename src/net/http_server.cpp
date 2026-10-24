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
// 当前请求的检测记录
//
// 为什么用 thread_local 而不是往 Request 里塞:
//   httplib 的 Request 没有留给中间件的字段。每个工作线程同一时刻只处理
//   一个请求,所以"线程局部的当前记录"是安全的,也不需要加锁。
// ---------------------------------------------------------------------------
static thread_local ScanRecord t_scan;

ScanRecord& current_scan() { return t_scan; }

// ---------------------------------------------------------------------------
// 取真实 IP
//
// 只有配置里显式打开 trust_proxy 时才看 X-Forwarded-For。
// 否则一律用 TCP 连接的对端地址 —— 因为 XFF 是客户端能随便填的头,
// 无条件信任它等于把"按 IP 限流/封禁"拱手送人。
// ---------------------------------------------------------------------------
static std::string client_ip(const httplib::Request& req, bool trust_proxy) {
    if (!trust_proxy) return req.remote_addr;

    if (req.has_header("X-Forwarded-For")) {
        const std::string xff = req.get_header_value("X-Forwarded-For");
        const auto comma = xff.find(',');
        std::string first = (comma == std::string::npos) ? xff : xff.substr(0, comma);
        while (!first.empty() && first.front() == ' ') first.erase(first.begin());
        while (!first.empty() && first.back() == ' ') first.pop_back();
        if (!first.empty()) return first;
    }
    if (req.has_header("X-Real-IP")) {
        const std::string rip = req.get_header_value("X-Real-IP");
        if (!rip.empty()) return rip;
    }
    return req.remote_addr;
}

// ---------------------------------------------------------------------------
// 限流 / 封禁 / 检测
// ---------------------------------------------------------------------------
bool run_guard(AppContext& ctx, const httplib::Request& req,
               httplib::Response& res, ScanRecord& rec) {
    const auto t0 = std::chrono::steady_clock::now();

    rec.trace_id = make_trace_id();
    rec.ip = client_ip(req, ctx.cfg.server.trust_proxy);
    rec.uri = req.path;
    if (!req.params.empty()) rec.uri = req.path;   // 查询串单独落 digest
    rec.method = req.method;
    rec.params_digest = build_params_digest(req.target.find('?') != std::string::npos
                                            ? req.target.substr(req.target.find('?') + 1)
                                            : std::string(),
                                            req.body);

    ctx.requests_total.fetch_add(1);

    // 1) 封禁 + 限流:合成一次 Redis 往返(第 38、41 讲)
    //
    // 原来拆成两步:先 EXISTS 查封禁,再 EVAL 取令牌 —— 每请求两次往返。
    // 压测显示这两次往返就是吞吐瓶颈(2 核上 26k;关掉 Redis 能到 70k)。
    // 现在封禁检查进了令牌桶的 Lua,一次 EVAL 出结论。
    switch (ctx.guard->check(rec.ip)) {
        case GuardDecision::kBanned:
            rec.action = "BLOCK";
            rec.rule_hit = "IP_BANNED";
            rec.status_code = 403;
            rec.was_banned = true;
            ctx.requests_blocked.fetch_add(1);
            json_err(res, 403, "IP 已被临时封禁");
            {
                const auto t1 = std::chrono::steady_clock::now();
                rec.cost_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
            }
            record_audit(ctx, rec);
            return false;

        case GuardDecision::kRateLimited:
            rec.action = "BLOCK";
            rec.rule_hit = "RATE_LIMITED";
            rec.status_code = 429;
            rec.rate_limited = true;
            ctx.requests_blocked.fetch_add(1);
            json_err(res, 429, "请求过于频繁,请稍后再试");
            {
                const auto t1 = std::chrono::steady_clock::now();
                rec.cost_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
            }
            record_audit(ctx, rec);
            return false;

        case GuardDecision::kAllow:
            break;
    }

    // 3) 重放防护(第 40 讲):时间戳 + nonce
    //
    //    只在写请求上做 —— GET 天然幂等,拦截它没有意义。
    //    require=true 时,缺头就拒;否则只在带了头的时候校验。
    if (req.method == "POST" || req.method == "PUT" || req.method == "DELETE") {
        const bool has_ts = req.has_header("X-Timestamp");
        const bool has_nonce = req.has_header("X-Nonce");

        if (ctx.cfg.replay.require && !(has_ts && has_nonce)) {
            rec.action = "BLOCK";
            rec.rule_hit = "REPLAY_MISSING_HEADERS";
            rec.status_code = 400;
            ctx.requests_blocked.fetch_add(1);
            ctx.replay_rejected.fetch_add(1);
            json_err(res, 400, "缺少 X-Timestamp / X-Nonce 头");
            const auto t1 = std::chrono::steady_clock::now();
            rec.cost_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
            record_audit(ctx, rec);
            return false;
        }

        if (has_ts && has_nonce) {
            std::int64_t ts = 0;
            try {
                ts = std::stoll(req.get_header_value("X-Timestamp"));
            } catch (...) {
                ts = 0;
            }
            const std::string nonce = req.get_header_value("X-Nonce");

            // 先看时间戳(便宜),再看 nonce(要访问 Redis)
            if (!DistributedGuard::timestamp_fresh(ts, ctx.cfg.replay.window_seconds)) {
                rec.action = "BLOCK";
                rec.rule_hit = "REPLAY_STALE";
                rec.status_code = 403;
                ctx.requests_blocked.fetch_add(1);
                ctx.replay_rejected.fetch_add(1);
                json_err(res, 403, "请求时间戳超出允许窗口");
                const auto t1 = std::chrono::steady_clock::now();
                rec.cost_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
                record_audit(ctx, rec);
                return false;
            }
            // SET NX EX 一步完成"检查 + 记录",天然原子
            if (!ctx.guard->consume_nonce(nonce, ctx.cfg.replay.window_seconds)) {
                rec.action = "BLOCK";
                rec.rule_hit = "REPLAY_DUPLICATE";
                rec.status_code = 409;
                ctx.requests_blocked.fetch_add(1);
                ctx.replay_rejected.fetch_add(1);
                json_err(res, 409, "该请求已被处理过(重放)");
                const auto t1 = std::chrono::steady_clock::now();
                rec.cost_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
                record_audit(ctx, rec);
                return false;
            }
        }
    }

    // 4) 把 HTTP 翻成待检文本,交给引擎(第 17 讲)
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

    // 用白名单过滤命中结果。
    //
    // 注意这里的信任模型:白名单是"路径 + 规则"的声明,由运维写在文件里。
    // 攻击者无法通过构造载荷来触发它 —— 他只能让自己的请求落到某个路径上,
    // 而那个路径排除了哪条规则,是运维事先决定的。
    // 这也是为什么白名单必须小、必须有人审。
    std::vector<std::int32_t> effective_hits;
    effective_hits.reserve(mr.rule_indices.size());
    std::string allowlisted_ids;
    for (std::int32_t idx : mr.rule_indices) {
        const std::string& rid = ctx.engine->rule(idx).id;
        if (ctx.engine->is_allowlisted(req.path, rid)) {
            if (!allowlisted_ids.empty()) allowlisted_ids.push_back(',');
            allowlisted_ids += rid;
            continue;
        }
        effective_hits.push_back(idx);
    }
    if (!allowlisted_ids.empty()) {
        LOG_INFO(kTag, "白名单放行 path=", req.path, " 规则=", allowlisted_ids);
    }

    if (!effective_hits.empty()) {
        // 命中的规则 ID 拼起来(最多列 8 条,避免超长)
        std::string ids;
        const std::size_t limit = std::min<std::size_t>(effective_hits.size(), 8);
        for (std::size_t i = 0; i < limit; ++i) {
            if (i) ids.push_back(',');
            ids += ctx.engine->rule(effective_hits[i]).id;
        }
        if (effective_hits.size() > limit) ids += ",...";
        rec.rule_hit = ids;
        if (mr.truncated) rec.rule_hit += "(截断)";

        // 记一次命中,达到阈值就自动封禁(计数也在 Redis,多实例一致)
        ctx.guard->record_hit(rec.ip, ctx.cfg.guard.hit_threshold,
                              ctx.cfg.guard.window_seconds,
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

// ---------------------------------------------------------------------------
// 扫请求体
//
// 前置钩子拿不到 body(httplib 在 dispatch 时才读),所以接收请求体的
// 处理器要在开头调用这个函数补一次检测。
//
// 只扫 body,不重复扫路径和查询串 —— 那部分前置钩子已经扫过了,
// 重复扫会让同一个命中被计两次。
// ---------------------------------------------------------------------------
bool scan_body(AppContext& ctx, const httplib::Request& req,
               httplib::Response& res, ScanRecord& rec) {
    if (req.body.empty()) return true;          // 没有 body,没什么可扫
    if (!ctx.engine) return true;

    const MatchResult mr = ctx.engine->search(req.body);
    if (mr.rule_indices.empty()) return true;

    // 白名单过滤(与前置钩子里的口径一致)
    std::vector<std::int32_t> effective;
    std::string allowlisted_ids;
    for (std::int32_t idx : mr.rule_indices) {
        const std::string& rid = ctx.engine->rule(idx).id;
        if (ctx.engine->is_allowlisted(req.path, rid)) {
            if (!allowlisted_ids.empty()) allowlisted_ids.push_back(',');
            allowlisted_ids += rid;
            continue;
        }
        effective.push_back(idx);
    }
    if (!allowlisted_ids.empty()) {
        LOG_INFO(kTag, "白名单放行(请求体) path=", req.path, " 规则=", allowlisted_ids);
    }
    if (effective.empty()) return true;

    std::string ids;
    const std::size_t limit = std::min<std::size_t>(effective.size(), 8);
    for (std::size_t i = 0; i < limit; ++i) {
        if (i) ids.push_back(',');
        ids += ctx.engine->rule(effective[i]).id;
    }
    if (effective.size() > limit) ids += ",...";

    // 合并到当前记录的命中列表里(前置钩子可能已经记了一些)
    if (rec.rule_hit.empty()) rec.rule_hit = ids;
    else rec.rule_hit += "," + ids;
    rec.matched_len = static_cast<int>(std::max<std::size_t>(
        static_cast<std::size_t>(rec.matched_len), mr.max_matched_len));
    rec.scan_bytes += mr.scanned_bytes;

    ctx.guard->record_hit(rec.ip, ctx.cfg.guard.hit_threshold,
                          ctx.cfg.guard.window_seconds,
                          ctx.cfg.guard.ban_seconds);

    rec.action = "BLOCK";
    rec.status_code = 403;
    ctx.requests_blocked.fetch_add(1);

    nlohmann::json j;
    j["error"] = "请求体被安全策略拦截";
    j["trace_id"] = rec.trace_id;
    j["rule_hit"] = rec.rule_hit;
    res.status = 403;
    res.set_content(j.dump(), "application/json; charset=utf-8");

    LOG_INFO(kTag, "请求体命中: path=", req.path, " 规则=", ids);
    record_audit(ctx, rec);
    return false;
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

    // 异步:只入队(纳秒级),后台线程批量落库,不拖慢请求(第 28 讲)
    if (ctx.audit) {
        ctx.audit->submit(row);
        return;
    }

    // 降级:同步写库(审计管道没起来时的兜底)
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
// 管理接口守卫
//
// 这里必须 fail-closed:名单为空时一律拒绝,而不是"没人配就全放开"。
// 后者是配置类漏洞最典型的一种 —— 忘了配等于没锁。
// ---------------------------------------------------------------------------
bool require_admin(AppContext& ctx, const httplib::Request& req,
                   httplib::Response& res, std::string& username) {
    std::int64_t uid = 0;
    if (!current_user(ctx, req, uid, username)) {
        json_err(res, 401, "需要管理员令牌(先登录,再带 Authorization: Bearer <token>)");
        return false;
    }
    const auto& list = ctx.cfg.auth.admin_users;
    if (list.empty()) {
        // 没配名单 = 管理接口关闭。明确告诉运维怎么开,别让人猜。
        LOG_WARN(kTag, "管理接口被访问但未配置管理员名单,已拒绝: ",
                 req.path, " user=", username);
        json_err(res, 403,
                 "管理接口未启用(需在环境变量 SECGUARD_ADMIN_USERS 里配置管理员用户名)");
        return false;
    }
    for (const auto& u : list) {
        if (u == username) return true;
    }
    LOG_WARN(kTag, "非管理员访问管理接口: ", req.path, " user=", username);
    json_err(res, 403, "需要管理员权限");
    return false;
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
        j["replay_rejected"] = ctx.replay_rejected.load();
        // Redis 共享状态:多实例部署时这一项才真正有意义
        j["redis"] = ctx.redis ? ctx.redis->available() : false;
        j["guard_mode"] = (ctx.guard && ctx.guard->redis_available()) ? "redis" : "local";
        // 审计管道:异步时队列深度是关键观察点
        if (ctx.audit) {
            j["audit_async"] = true;
            j["audit_queued"] = ctx.audit->queued();
            j["audit_written"] = ctx.audit->written();
            j["audit_dropped"] = ctx.audit->dropped();
        } else {
            j["audit_async"] = false;
        }
        res.status = db_ok ? 200 : 503;
        res.set_content(j.dump(), "application/json; charset=utf-8");
    });

    // 前端页面:一个查询框 + 结果
    // 注意:这一条也要过检测 —— 所有路由都该被检测,不能只护 /api/*。
    // (踩过这个坑:只把 /api/* 接进引擎,首面就成了没设防的入口。)
    svr.Get("/", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;
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
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;

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
    // -----------------------------------------------------------------------
    // 前置钩子:所有请求的检测都在这里做(第 37 讲)
    //
    // 位置很关键 —— 它在路由匹配**之前**执行。这一点决定了:
    //   1. 未注册的路径(扫描器最爱打的 /admin、/.env、/wp-login.php)
    //      也会被特征匹配、也会留审计,而不是静默 404 什么都不留
    //   2. 检测逻辑只写一遍,不用每个处理器开头各抄一遍
    //      (抄 N 遍的后果是:新加一个接口忘了抄,那个接口就是没设防的)
    //
    // 返回 Handled 表示已拦下,请求不会再进业务逻辑。
    // -----------------------------------------------------------------------
    svr.set_pre_routing_handler(
        [&ctx](const httplib::Request& req, httplib::Response& res) {
            // 每个请求都从干净的记录开始(同一线程会复用这块存储)
            t_scan = ScanRecord{};
            if (run_guard(ctx, req, res, t_scan)) {
                return httplib::Server::HandlerResponse::Unhandled;  // 放行,继续路由
            }
            return httplib::Server::HandlerResponse::Handled;        // 已拦下
        });

    // 真实路由必须先注册:httplib 取第一个匹配的 pattern,
    // 兜底的 .* 若排在前面会把所有接口吃掉。
    register_core_routes(svr, ctx);
    register_auth_routes(svr, ctx);
    register_content_routes(svr, ctx);
    register_audit_routes(svr, ctx);

    // 兜底:没匹配到任何路由(404)。
    // 有了上面的前置钩子,这些请求已经过检测、也已经写了审计,
    // 所以这里只需把状态码记进审计再返回。
    // (扫描器探测 /admin、/.env 这类路径时,正是走这里。)
    auto fallback = [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;
        rec.status_code = 404;
        record_audit(ctx, rec);
        json_err(res, 404, "没有这个接口");
    };
    svr.Get(R"(.*)", fallback);
    svr.Post(R"(.*)", fallback);
    svr.Put(R"(.*)", fallback);
    svr.Delete(R"(.*)", fallback);
    svr.Patch(R"(.*)", fallback);
}

}  // namespace secguard
