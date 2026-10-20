// 鉴权相关的接口:注册 / 登录 / 续期 / 我是谁
// 对应寓言集第 43(密码哈希)、44(JWT)、45(不存明文)、47(参数校验)讲
#include "net/http_server.h"

#include <cctype>

#include <nlohmann/json.hpp>

#include "crypto/auth_crypto.h"
#include "util/log.h"

namespace secguard {
namespace {

constexpr const char* kTag = "[鉴权] ";

// 用户名规则:3~32 位,字母数字下划线
bool valid_username(const std::string& s) {
    if (s.size() < 3 || s.size() > 32) return false;
    for (unsigned char c : s) {
        if (!(std::isalnum(c) || c == '_')) return false;
    }
    return true;
}

// 口令规则:8~128 位。不强制复杂度,但要求长度(第 47 讲:有边界)
bool valid_password(const std::string& s) { return s.size() >= 8 && s.size() <= 128; }

bool valid_email(const std::string& s) {
    if (s.empty()) return true;                 // 邮箱可选
    if (s.size() > 128) return false;
    const auto at = s.find('@');
    if (at == std::string::npos || at == 0 || at + 1 >= s.size()) return false;
    if (s.find(' ') != std::string::npos) return false;
    return s.find('.', at) != std::string::npos;
}

// 从请求体里取字段,顺便做长度上限
std::string field(const nlohmann::json& j, const char* key, std::size_t max_len) {
    if (!j.contains(key) || !j[key].is_string()) return {};
    std::string v = j[key].get<std::string>();
    if (v.size() > max_len) v.resize(max_len);
    return v;
}

// 从请求体解析 JSON;失败返回 false
bool parse_body(const httplib::Request& req, nlohmann::json& out) {
    if (req.body.empty()) return false;
    out = nlohmann::json::parse(req.body, nullptr, false);
    return !out.is_discarded() && out.is_object();
}

}  // namespace

void register_auth_routes(httplib::Server& svr, AppContext& ctx) {
    // ---- 注册 ----
    svr.Post("/api/register", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();

        nlohmann::json body;
        if (!parse_body(req, body)) { json_err(res, 400, "请求体必须是 JSON 对象"); return; }

        const std::string username = field(body, "username", 64);
        const std::string password = field(body, "password", 128);
        const std::string email    = field(body, "email", 128);

        // 入口校验(第 47 讲):把脏数据挡在业务逻辑之外
        if (!valid_username(username)) {
            json_err(res, 400, "用户名需为 3~32 位的字母、数字或下划线"); return;
        }
        if (!valid_password(password)) {
            json_err(res, 400, "口令长度需为 8~128 位"); return;
        }
        if (!valid_email(email)) { json_err(res, 400, "邮箱格式不正确"); return; }

        // 口令永远不明文存(第 45 讲):PBKDF2 + 每用户随机盐 + 多轮迭代
        const std::string hash = crypto::hash_password(password, ctx.cfg.auth.pbkdf2_iterations);
        if (hash.empty()) { json_err(res, 500, "口令处理失败"); return; }

        std::int64_t new_id = 0;
        const auto wr = ctx.dao->create_user(username, hash, email, new_id);
        if (wr == WriteResult::kDuplicate) {
            json_err(res, 409, "用户名已被占用"); return;
        }
        if (wr == WriteResult::kDeadlock) {
            json_err(res, 503, "服务繁忙,请重试"); return;   // 死锁可重试(第 53 讲)
        }
        if (wr != WriteResult::kOk) { json_err(res, 500, "注册失败"); return; }

        rec.user_id = new_id;
        rec.status_code = 201;
        record_audit(ctx, rec);

        nlohmann::json j;
        j["id"] = new_id;
        j["username"] = username;
        res.status = 201;
        res.set_content(j.dump(), "application/json; charset=utf-8");
        LOG_INFO(kTag, "新用户注册 id=", new_id, " name=", log::kv("username", username));
    });

    // ---- 登录 ----
    svr.Post("/api/login", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();

        // IP 只从 run_guard 里取,不在这里另算一遍 ——
        // 两处各算各的,迟早会出现"限流用的是 A 口径、锁定用的是 B 口径"。
        const std::string& ip = rec.ip;

        nlohmann::json body;
        if (!parse_body(req, body)) { json_err(res, 400, "请求体必须是 JSON 对象"); return; }

        const std::string username = field(body, "username", 64);
        const std::string password = field(body, "password", 128);

        if (username.empty() || password.empty()) {
            json_err(res, 400, "用户名和口令都不能为空"); return;
        }

        // 爆破防护:连续失败到上限就短暂锁定(第 43 讲)
        const std::string lock_key = ip + ":" + username;
        if (ctx.login_throttle->is_locked(lock_key,
                                          ctx.cfg.guard.login_window_seconds,
                                          ctx.cfg.guard.login_fail_limit)) {
            json_err(res, 429, "登录尝试过于频繁,请稍后再试"); return;
        }

        const auto user = ctx.dao->find_user_by_name(username);

        // 注意:用户不存在与口令错误要返回同样的信息,
        // 否则可以被用来枚举用户名(第 45 讲)
        bool ok = false;
        if (user && user->status == 1) {
            ok = crypto::verify_password(password, user->password_hash);
        }

        if (!ok) {
            const bool locked = ctx.login_throttle->record_fail(
                lock_key, ctx.cfg.guard.login_window_seconds,
                ctx.cfg.guard.login_fail_limit);
            rec.action = "BLOCK";
            rec.rule_hit = "LOGIN_FAIL";
            rec.status_code = 401;
            record_audit(ctx, rec);
            LOG_WARN(kTag, "登录失败 ", log::kv("username", username),
                     " ip=", ip, locked ? " -> 已锁定" : "");
            json_err(res, 401, "用户名或口令不正确");
            return;
        }

        ctx.login_throttle->clear(lock_key);

        crypto::JwtClaims claims;
        claims.user_id = user->id;
        claims.username = user->username;
        claims.issued_at = crypto::now_unix();
        claims.expires_at = claims.issued_at + ctx.cfg.auth.token_ttl_seconds;

        const std::string token = crypto::jwt_sign(claims, ctx.cfg.auth.jwt_secret);
        if (token.empty()) { json_err(res, 500, "令牌签发失败"); return; }

        rec.user_id = user->id;
        rec.status_code = 200;
        record_audit(ctx, rec);

        nlohmann::json j;
        j["token"] = token;
        j["expires_in"] = ctx.cfg.auth.token_ttl_seconds;
        j["user"] = {{"id", user->id}, {"username", user->username}};
        json_ok(res, j.dump());
        LOG_INFO(kTag, "登录成功 id=", user->id);
    });

    // ---- 续期:只验签名不验口令,所以很便宜(第 44 讲) ----
    svr.Post("/api/refresh", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();

        std::int64_t uid = 0;
        std::string uname;
        if (!current_user(ctx, req, uid, uname)) {
            json_err(res, 401, "令牌无效或已过期"); return;
        }

        crypto::JwtClaims claims;
        claims.user_id = uid;
        claims.username = uname;
        claims.issued_at = crypto::now_unix();
        claims.expires_at = claims.issued_at + ctx.cfg.auth.token_ttl_seconds;

        const std::string token = crypto::jwt_sign(claims, ctx.cfg.auth.jwt_secret);
        if (token.empty()) { json_err(res, 500, "令牌签发失败"); return; }

        rec.user_id = uid;
        rec.status_code = 200;
        record_audit(ctx, rec);

        nlohmann::json j;
        j["token"] = token;
        j["expires_in"] = ctx.cfg.auth.token_ttl_seconds;
        json_ok(res, j.dump());
    });

    // ---- 我是谁 ----
    svr.Get("/api/me", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();

        std::int64_t uid = 0;
        std::string uname;
        if (!current_user(ctx, req, uid, uname)) { json_err(res, 401, "未登录"); return; }

        rec.user_id = uid;
        rec.status_code = 200;
        record_audit(ctx, rec);

        nlohmann::json j;
        j["id"] = uid;
        j["username"] = uname;
        json_ok(res, j.dump());
    });
}

}  // namespace secguard
