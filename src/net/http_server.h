// HTTP 服务与路由(寓言集第 37、41、47 讲)
//
// 请求的处理顺序:
//   1. 取真实 IP(考虑 X-Forwarded-For,因为线上走 Nginx 反代)
//   2. 封禁检查
//   3. 令牌桶限流
//   4. 把请求翻译成待检文本 -> 交给引擎匹配
//   5. 命中则拦截;无论如何都写一条审计记录
//   6. 交给业务处理器
#pragma once

#include <cstdint>
#include <string>

// 需要完整定义:json_ok/json_err 直接用 Response 的成员
#include <cpp-httplib/httplib.h>

#include "net/app_context.h"

namespace secguard {

// 一次请求的检测结果,审计落库时用到
struct ScanRecord {
    std::string  trace_id;
    std::string  ip;
    std::string  uri;
    std::string  method;
    std::string  action;            // PASS / BLOCK
    std::string  rule_hit;          // 命中的规则 ID,逗号分隔
    int          matched_len = 0;
    int          status_code = 0;
    long long    cost_us = 0;
    std::size_t  scan_bytes = 0;
    bool         rate_limited = false;
    bool         was_banned = false;
    std::string  params_digest;
    std::int64_t user_id = 0;       // 0 表示未登录
};

// 限流 / 封禁 / 重放 / 特征匹配。返回 true 放行;false 表示已拦下(response 已写好)
//
// 注意执行位置:它由 set_pre_routing_handler 在**路由匹配之前**调用。
// 这样未注册的路径(扫描器常打的 /admin、/.env 之类)也会被检测、也会留审计,
// 而不是静默 404 —— 那是 WAF 最容易被绕过的地方。
bool run_guard(AppContext& ctx, const httplib::Request& req,
               httplib::Response& res, ScanRecord& rec);

// 当前请求的检测记录(由前置钩子填好,处理器只读)。
// 每个工作线程同一时刻只处理一个请求,所以 thread_local 是安全的。
[[nodiscard]] ScanRecord& current_scan();

void record_audit(AppContext& ctx, const ScanRecord& rec);

bool current_user(AppContext& ctx, const httplib::Request& req,
                  std::int64_t& user_id, std::string& username);

void register_routes(httplib::Server& svr, AppContext& ctx);
void register_auth_routes(httplib::Server& svr, AppContext& ctx);
void register_content_routes(httplib::Server& svr, AppContext& ctx);
void register_audit_routes(httplib::Server& svr, AppContext& ctx);

void json_ok(httplib::Response& res, const std::string& body);
void json_err(httplib::Response& res, int status, const std::string& message);

}  // namespace secguard
