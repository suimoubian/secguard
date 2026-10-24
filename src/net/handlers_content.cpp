// 内容接口:帖子与评论的 CRUD
// 对应寓言集第 42(SQL 注入的正解)、47(参数校验)、52(DAO)讲
#include "net/http_server.h"

#include <nlohmann/json.hpp>

#include "util/log.h"

namespace secguard {
namespace {
constexpr const char* kTag = "[内容] ";

std::string field(const nlohmann::json& j, const char* key, std::size_t max_len) {
    if (!j.contains(key) || !j[key].is_string()) return {};
    std::string v = j[key].get<std::string>();
    if (v.size() > max_len) v.resize(max_len);
    return v;
}

bool parse_body(const httplib::Request& req, nlohmann::json& out) {
    if (req.body.empty()) return false;
    out = nlohmann::json::parse(req.body, nullptr, false);
    return !out.is_discarded() && out.is_object();
}

// 分页参数:必须有上限,否则 ?size=100000000 能把数据库拖死(第 47 讲)
int int_param(const httplib::Request& req, const char* name, int dflt, int lo, int hi) {
    if (!req.has_param(name)) return dflt;
    try {
        const int v = std::stoi(req.get_param_value(name));
        if (v < lo) return lo;
        if (v > hi) return hi;
        return v;
    } catch (...) {
        return dflt;
    }
}

// 从 URL 里解析 id。
// 必须包 try:std::stoll 遇到 "99999999999999999999" 会抛 out_of_range,
// 不接住的话工作线程直接没了 —— 一个请求就能打挂一个线程。
bool parse_id(const std::string& s, std::int64_t& out) {
    if (s.empty() || s.size() > 19) return false;   // bigint 上限 19 位
    for (unsigned char c : s) {
        if (c < '0' || c > '9') return false;       // 只接受纯数字
    }
    try {
        out = std::stoll(s);
        return out > 0;
    } catch (...) {
        return false;
    }
}

}  // namespace

void register_content_routes(httplib::Server& svr, AppContext& ctx) {
    // ---- 发帖 ----
    svr.Post("/api/posts", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;

        std::int64_t uid = 0;
        std::string uname;
        if (!current_user(ctx, req, uid, uname)) { json_err(res, 401, "请先登录"); return; }
        rec.user_id = uid;

        nlohmann::json body;
        if (!parse_body(req, body)) { json_err(res, 400, "请求体必须是 JSON 对象"); return; }

        const std::string title = field(body, "title", 255);
        const std::string content = field(body, "content", 65535);
        if (title.empty()) { json_err(res, 400, "标题不能为空"); return; }
        if (content.empty()) { json_err(res, 400, "内容不能为空"); return; }

        std::int64_t new_id = 0;
        const auto wr = ctx.dao->create_post(uid, title, content, new_id);
        if (wr != WriteResult::kOk) { json_err(res, 500, "发帖失败"); return; }

        rec.status_code = 201;
        record_audit(ctx, rec);

        nlohmann::json j;
        j["id"] = new_id;
        j["title"] = title;
        res.status = 201;
        res.set_content(j.dump(), "application/json; charset=utf-8");
        LOG_INFO(kTag, "发帖 id=", new_id, " user=", uid);
    });

    // ---- 帖子列表 ----
    svr.Get("/api/posts", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;

        const int limit = int_param(req, "limit", 20, 1, 100);
        const int offset = int_param(req, "offset", 0, 0, 1000000);

        const auto posts = ctx.dao->list_posts(limit, offset);
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& p : posts) {
            arr.push_back({{"id", p.id}, {"user_id", p.user_id}, {"title", p.title},
                           {"content", p.content}, {"created_at", p.created_at}});
        }
        rec.status_code = 200;
        record_audit(ctx, rec);

        nlohmann::json j;
        j["items"] = arr;
        j["limit"] = limit;
        j["offset"] = offset;
        json_ok(res, j.dump());
    });

    // ---- 单个帖子 ----
    svr.Get(R"(/api/posts/(\d+))", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;

        std::int64_t id = 0;
        if (!parse_id(req.matches[1].str(), id)) { json_err(res, 400, "id 不合法"); return; }
        const auto post = ctx.dao->find_post(id);
        if (!post) { json_err(res, 404, "帖子不存在"); return; }

        rec.status_code = 200;
        record_audit(ctx, rec);

        nlohmann::json j;
        j["id"] = post->id;
        j["user_id"] = post->user_id;
        j["title"] = post->title;
        j["content"] = post->content;
        j["created_at"] = post->created_at;
        json_ok(res, j.dump());
    });

    // ---- 删帖:只能删自己的 ----
    svr.Delete(R"(/api/posts/(\d+))", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;

        std::int64_t uid = 0;
        std::string uname;
        if (!current_user(ctx, req, uid, uname)) { json_err(res, 401, "请先登录"); return; }
        rec.user_id = uid;

        std::int64_t id = 0;
        if (!parse_id(req.matches[1].str(), id)) { json_err(res, 400, "id 不合法"); return; }
        const auto wr = ctx.dao->delete_post(id, uid);
        if (wr != WriteResult::kOk) { json_err(res, 404, "帖子不存在或无权删除"); return; }

        rec.status_code = 200;
        record_audit(ctx, rec);

        nlohmann::json j;
        j["deleted"] = id;
        json_ok(res, j.dump());
    });

    // ---- 评论 ----
    svr.Post(R"(/api/posts/(\d+)/comments)", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;

        std::int64_t uid = 0;
        std::string uname;
        if (!current_user(ctx, req, uid, uname)) { json_err(res, 401, "请先登录"); return; }
        rec.user_id = uid;

        std::int64_t post_id = 0;
        if (!parse_id(req.matches[1].str(), post_id)) { json_err(res, 400, "id 不合法"); return; }
        if (!ctx.dao->find_post(post_id)) { json_err(res, 404, "帖子不存在"); return; }

        nlohmann::json body;
        if (!parse_body(req, body)) { json_err(res, 400, "请求体必须是 JSON 对象"); return; }
        const std::string content = field(body, "content", 65535);
        if (content.empty()) { json_err(res, 400, "评论内容不能为空"); return; }

        std::int64_t new_id = 0;
        const auto wr = ctx.dao->create_comment(post_id, uid, content, new_id);
        if (wr != WriteResult::kOk) { json_err(res, 500, "评论失败"); return; }

        rec.status_code = 201;
        record_audit(ctx, rec);

        nlohmann::json j;
        j["id"] = new_id;
        res.status = 201;
        res.set_content(j.dump(), "application/json; charset=utf-8");
    });

    // ---- 评论列表 ----
    svr.Get(R"(/api/posts/(\d+)/comments)", [&ctx](const httplib::Request& req, httplib::Response& res) {
        ScanRecord& rec = current_scan();
        // 请求体检测。前置钩子拿不到 body(httplib 在 dispatch 时才读),
        // 所以每个处理器在这里补一次。body 为空时立即返回,GET 零成本。
        if (!scan_body(ctx, req, res, rec)) return;

        std::int64_t post_id = 0;
        if (!parse_id(req.matches[1].str(), post_id)) { json_err(res, 400, "id 不合法"); return; }
        const int limit = int_param(req, "limit", 50, 1, 200);
        const int offset = int_param(req, "offset", 0, 0, 1000000);

        const auto rows = ctx.dao->list_comments(post_id, limit, offset);
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& c : rows) {
            arr.push_back({{"id", c.id}, {"user_id", c.user_id},
                           {"content", c.content}, {"created_at", c.created_at}});
        }
        rec.status_code = 200;
        record_audit(ctx, rec);

        nlohmann::json j;
        j["items"] = arr;
        json_ok(res, j.dump());
    });
}

}  // namespace secguard
