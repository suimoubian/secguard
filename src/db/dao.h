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
    std::int64_t id = 0;                // 主键(W6 标记 analyzed 要用)
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
    std::string  created_at;
};

// 一条告警(LLM 分析产出)
struct AlertRow {
    std::int64_t id = 0;
    std::string  ip;
    std::string  threat_type;
    std::string  severity;              // LOW/MEDIUM/HIGH/CRITICAL
    double       confidence = 0.0;      // 0.000 ~ 1.000
    std::string  reasoning;
    std::string  log_ids;               // 逗号分隔的 audit_log.id
    int          status = 0;            // 0待处理 1已确认 2误报
    std::string  created_at;
};

struct AlertStats {
    std::int64_t total = 0;
    std::int64_t pending = 0;
    std::int64_t confirmed = 0;
    std::int64_t false_positive = 0;
    std::int64_t critical = 0;
    std::int64_t high = 0;
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

    // ---- W6:给 AI 分析层用 ----
    // 取待分析的记录:只挑"值得分析"的 —— 被拦截过、且不是限流/封禁这类
    // 纯策略性拦截(那种不需要 LLM 再判断一遍,浪费钱)。
    // 按时间倒序,走 idx_analyzed 索引。
    [[nodiscard]] std::vector<AuditLogRow> fetch_unanalyzed(int limit, int lookback_hours);

    // 标记已分析。批量更新,避免一条一条 round-trip。
    bool mark_analyzed(const std::vector<std::int64_t>& ids);

    WriteResult insert_alert(const AlertRow& alert, std::int64_t& new_id);
    [[nodiscard]] std::vector<AlertRow> list_alerts(int limit, int offset);
    [[nodiscard]] AlertStats alert_stats();
    // 人工改告警状态(1 已确认 / 2 误报)
    WriteResult set_alert_status(std::int64_t id, int status);

    // 连通性自检,给 /health 用
    [[nodiscard]] bool ping();

private:
    ConnectionPool& pool_;
};

}  // namespace secguard
