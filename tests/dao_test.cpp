// DAO 层测试:直接打数据库,验证增删改查与几个关键语义
//
// 为什么单独写一个:端到端测试走 HTTP,一次要过限流、检测、审计一堆东西,
// 出问题时分不清是 DAO 错了还是上面某层错了。这一层单独测,
// 定位会快很多。
//
// 连不上数据库时**直接跳过并返回成功** —— CI 里没有 MySQL,
// 不能让一个"环境没装"变成"代码有 bug"。
//
// 运行:
//   SECGUARD_DB_USER=secguard SECGUARD_DB_PASS=... ./build/dao_test
//
// 注意:测试数据用明显可辨的值(用户名带时间戳、IP 用 203.0.113.x),
// 跑完会自己清理,不会污染正常数据。

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "db/connection_pool.h"
#include "db/dao.h"
#include "util/log.h"

using namespace secguard;

static int g_fail = 0;
static void check(bool ok, const std::string& what, const std::string& detail = "") {
    std::printf("  %-46s %s", what.c_str(), ok ? "通过" : "失败");
    if (!ok && !detail.empty()) std::printf("  (%s)", detail.c_str());
    std::printf("\n");
    if (!ok) ++g_fail;
}

int main() {
    log::set_level(log::Level::kWarn);   // DAO 的 INFO 日志太吵

    DatabaseConfig cfg;
    cfg.host = std::getenv("SECGUARD_DB_HOST") ? std::getenv("SECGUARD_DB_HOST") : "127.0.0.1";
    cfg.user = std::getenv("SECGUARD_DB_USER") ? std::getenv("SECGUARD_DB_USER") : "";
    cfg.password = std::getenv("SECGUARD_DB_PASS") ? std::getenv("SECGUARD_DB_PASS") : "";
    cfg.schema = std::getenv("SECGUARD_DB_NAME") ? std::getenv("SECGUARD_DB_NAME") : "secguard";
    if (const char* p = std::getenv("SECGUARD_DB_PORT")) cfg.port = std::atoi(p);

    if (cfg.user.empty() || cfg.password.empty()) {
        std::printf("跳过:没有设置 SECGUARD_DB_USER / SECGUARD_DB_PASS\n");
        return 0;
    }

    std::unique_ptr<ConnectionPool> pool;
    try {
        pool = std::make_unique<ConnectionPool>(cfg);
    } catch (const std::exception& e) {
        std::printf("跳过:连接池初始化异常(%s)\n", e.what());
        return 0;
    }
    Dao dao(*pool);
    if (!dao.ping()) {
        std::printf("跳过:连不上数据库\n");
        return 0;
    }

    const std::string tag = std::to_string(::getpid());
    const std::string uname = "dt_" + tag;
    std::printf("DAO 测试(数据前缀 dt_%s)\n", tag.c_str());

    // -----------------------------------------------------------------------
    std::printf("\n=== user ===\n");
    std::int64_t uid = 0;
    auto r = dao.create_user(uname, "pbkdf2$sha256$1$a$b", "dt@example.com", uid);
    check(r == WriteResult::kOk && uid > 0, "创建用户");

    if (r == WriteResult::kError) {
        std::printf("创建用户就失败了,后面的用例没有意义\n");
        return 1;
    }

    r = dao.create_user(uname, "x", "", uid);
    check(r == WriteResult::kDuplicate, "重复用户名返回 kDuplicate");

    auto u = dao.find_user_by_name(uname);
    check(u.has_value() && u->username == uname, "按用户名查到");
    check(u && u->status == 1, "新用户 status=1");
    check(u && u->created_at.size() >= 10, "created_at 有值");

    auto u2 = dao.find_user_by_id(u ? u->id : 0);
    check(u2.has_value() && u2->username == uname, "按 id 查到");

    check(!dao.find_user_by_name(uname + "_nope").has_value(), "查不存在的用户返回空");

    const std::int64_t my_uid = u ? u->id : 0;

    // -----------------------------------------------------------------------
    std::printf("\n=== post ===\n");
    std::int64_t pid = 0;
    r = dao.create_post(my_uid, "标题 " + tag, "内容", pid);
    check(r == WriteResult::kOk && pid > 0, "发帖");

    auto p = dao.find_post(pid);
    check(p.has_value() && p->title == "标题 " + tag, "按 id 查到帖子");
    check(p && p->user_id == my_uid, "帖子归属正确");

    auto posts = dao.list_posts(10, 0);
    check(!posts.empty(), "列表非空");

    // 删别人的帖子必须失败(越权防护)
    r = dao.delete_post(pid, my_uid + 99999);
    check(r != WriteResult::kOk, "删别人的帖子被拒");
    check(dao.find_post(pid).has_value(), "被拒后帖子仍然存在");

    // -----------------------------------------------------------------------
    std::printf("\n=== comment ===\n");
    std::int64_t cid = 0;
    r = dao.create_comment(pid, my_uid, "评论内容", cid);
    check(r == WriteResult::kOk && cid > 0, "发评论");

    auto cs = dao.list_comments(pid, 50, 0);
    check(!cs.empty() && cs.front().content == "评论内容", "评论列表正确");

    // -----------------------------------------------------------------------
    std::printf("\n=== audit_log ===\n");
    // IP 每次运行都不一样。用固定 IP 的话,上一次跑留下的行还在,
    // "按 IP 查应当只有 3 条"就会变成 6 条 —— 测试第二次跑就红了。
    // (踩过:第一次过,第二次失败,原因只是数据没清)
    const std::string test_ip =
        "203.0.113." + std::to_string((::getpid() % 200) + 1);   // TEST-NET-3
    std::printf("测试 IP: %s\n", test_ip.c_str());

    std::vector<AuditLogRow> batch;
    for (int i = 0; i < 3; ++i) {
        AuditLogRow row;
        row.trace_id = "dt-" + tag + "-" + std::to_string(i);
        row.ip = test_ip;
        row.uri = "/dt-test";
        row.method = "GET";
        row.rule_hit = "SQL-003";          // 可分析(不在策略性拦截名单里)
        row.action = "BLOCK";
        row.status_code = 403;
        row.matched_len = 9;
        row.cost_us = 123;
        batch.push_back(row);
    }
    check(dao.write_audit_batch(batch), "批量写审计");

    auto st = dao.audit_stats();
    check(st.total > 0, "审计统计有数据");
    check(st.blocked > 0, "拦截数 > 0");

    // fetch_unanalyzed 应该能拿到刚写的那几条(按 IP 过滤确认)
    auto un = dao.fetch_unanalyzed(100, 24 * 30);
    int mine = 0;
    std::vector<std::int64_t> ids;
    for (const auto& row : un) {
        if (row.ip == test_ip) { ++mine; ids.push_back(row.id); }
    }
    check(mine == 3, "fetch_unanalyzed 取到 3 条", "实际 " + std::to_string(mine));

    if (!ids.empty()) {
        check(dao.mark_analyzed(ids), "标记已分析");

        auto un2 = dao.fetch_unanalyzed(100, 24 * 30);
        int still = 0;
        for (const auto& row : un2) if (row.ip == test_ip) ++still;
        check(still == 0, "标记后不再被取出", "仍有 " + std::to_string(still));
    }

    auto blocked = dao.recent_blocked(test_ip, 10);
    check(blocked.size() == 3, "按 IP 查拦截记录", "实际 " + std::to_string(blocked.size()));

    // -----------------------------------------------------------------------
    std::printf("\n=== alert ===\n");
    AlertRow a;
    a.ip = test_ip;
    a.threat_type = "SQL_INJECTION";
    a.severity = "HIGH";
    a.confidence = 0.92;
    a.reasoning = "DAO 测试";
    a.log_ids = "1,2,3";
    a.status = 0;
    std::int64_t aid = 0;
    r = dao.insert_alert(a, aid);
    check(r == WriteResult::kOk && aid > 0, "插入告警");

    auto alerts = dao.list_alerts(10, 0);
    check(!alerts.empty(), "告警列表非空");

    auto ast = dao.alert_stats();
    check(ast.total > 0, "告警统计有数据");

    check(dao.set_alert_status(aid, 2) == WriteResult::kOk, "改成误报");
    {
        bool found = false;
        for (const auto& x : dao.list_alerts(50, 0)) {
            if (x.id == aid && x.status == 2) found = true;
        }
        check(found, "状态确实变成 2");
    }
    check(dao.set_alert_status(aid, 9) != WriteResult::kOk, "非法状态被拒");

    // -----------------------------------------------------------------------
    std::printf("\n=== 保留策略 ===\n");
    check(dao.purge_audit_before(0, 100) == 0, "days=0 时不删任何东西");
    check(dao.audit_row_count() > 0, "能统计行数");

    // 清理本次测试写进去的数据
    std::printf("\n=== 清理 ===\n");
    dao.delete_post(pid, my_uid);
    std::printf("  已删除测试帖子(软删)\n");

    std::printf("\n====================\n");
    if (g_fail == 0) { std::printf("全部通过\n"); return 0; }
    std::printf("失败 %d 处\n", g_fail);
    return 1;
}
