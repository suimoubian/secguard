// 数据访问层(寓言集第 52 讲)
//
// 为什么要有这一层:
//   1. SQL 集中在四处,才能统一用预编译参数化 —— 从源头消除注入,
//      而不是靠 WAF 特征兜(第 42 讲)
//   2. 连接管理集中,业务层不可能忘归还
//   3. 表结构变化只影响这一层
//
// 全部使用 PreparedStatement,不允许字符串拼 SQL。
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "db/connection_pool.h"

namespace secguard {

struct UserRow {
    std::int64_t id = 0;
    std::string  username;
    std::string  password_hash;
    std::string  email;
    int          status = 1;            // 1 正常 0 封禁
    std::string  created_at;
};

struct PostRow {
    std::int64_t id = 0;
    std::int64_t user_id = 0;
    std::string  title;
    std::string  content;
    int          status = 1;
    std::string  created_at;
};

struct CommentRow {
    std::int64_t id = 0;
    std::int64_t post_id = 0;
    std::int64_t user_id = 0;
    std::string  content;
    int          status = 1;
    std::string  created_at;
};

struct AuditLogRow {
    std::string  trace_id;
    std::string  ip;
    std::optional<std::int64_t> user_id;
    std::string  uri;
    std::string  method;
    std::string  params_digest;
    std::string  rule_hit;
    int          matched_len = 0;
    std::string  action;                // PASS / BLOCK / ALERT
    int          status_code = 0;
    std::int64_t cost_us = 0;
};

struct AuditStats {
    std::int64_t total = 0;
    std::int64_t blocked = 0;
    std::int64_t passed = 0;
    std::int64_t hits_by_ip = 0;
};

// 写入结果:业务性失败(如用户名已存在)用枚举返回,不用异常
enum class WriteResult { kOk, kDuplicate, kDeadlock, kError };

class Dao {
public:
    explicit Dao(ConnectionPool& pool) : pool_(pool) {}

    // ---- user ----
    [[nodiscard]] std::optional<UserRow> find_user_by_name(const std::string& username);
    [[nodiscard]] std::optional<UserRow> find_user_by_id(std::int64_t id);
    // 成功返回新用户 id;用户名冲突返回 kDuplicate
    WriteResult create_user(const std::string& username,
                            const std::string& password_hash,
                            const std::string& email,
                            std::int64_t& new_id);

    // ---- post ----
    WriteResult create_post(std::int64_t user_id, const std::string& title,
                            const std::string& content, std::int64_t& new_id);
    [[nodiscard]] std::vector<PostRow> list_posts(int limit, int offset);
    [[nodiscard]] std::optional<PostRow> find_post(std::int64_t id);
    WriteResult delete_post(std::int64_t id, std::int64_t user_id);   // 只能删自己的

    // ---- comment ----
    WriteResult create_comment(std::int64_t post_id, std::int64_t user_id,
                               const std::string& content, std::int64_t& new_id);
    [[nodiscard]] std::vector<CommentRow> list_comments(std::int64_t post_id,
                                                        int limit, int offset);

    // ---- audit_log ----
    // 一批日志 + 它触发的告警放在一个事务里(第 54 讲):要么全进,要么全不进
    bool write_audit_batch(const std::vector<AuditLogRow>& rows);
    [[nodiscard]] AuditStats audit_stats();
    [[nodiscard]] std::vector<AuditLogRow> recent_blocked(const std::string& ip, int limit);

    // 连通性自检,给 /health 用
    [[nodiscard]] bool ping();

private:
    ConnectionPool& pool_;
};

}  // namespace secguard
