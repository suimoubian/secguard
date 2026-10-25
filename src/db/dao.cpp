#include "db/dao.h"

#include <cppconn/exception.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>

#include "util/log.h"

namespace secguard {
namespace {

constexpr const char* kTag = "[DAO] ";

// MySQL 错误码分类(第 53 讲)
//   1062 唯一键冲突 -> 业务错误,不重试
//   1213 死锁       -> 数据库已回滚,可以重试
//   2006/2013       -> 连接断开,交给连接池换一条
constexpr int kErrDupEntry = 1062;
constexpr int kErrDeadlock = 1213;

// sql::SQLString 与 std::string 是两个类型,这里显式转一次
std::string col_str(sql::ResultSet* rs, const char* name) {
    if (rs->isNull(name)) return {};
    return std::string(rs->getString(name).c_str());
}

std::int64_t col_i64(sql::ResultSet* rs, const char* name) {
    return rs->isNull(name) ? 0 : rs->getInt64(name);
}

int col_int(sql::ResultSet* rs, const char* name) {
    return rs->isNull(name) ? 0 : rs->getInt(name);
}

}  // namespace

bool Dao::ping() {
    auto lease = pool_.acquire();
    if (!lease) return false;
    try {
        std::unique_ptr<sql::Statement> st(lease->createStatement());
        std::unique_ptr<sql::ResultSet> rs(st->executeQuery("SELECT 1"));
        return rs->next();
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "ping 失败:", e.what());
        return false;
    }
}

// ---------------------------------------------------------------------------
// user
// ---------------------------------------------------------------------------
std::optional<UserRow> Dao::find_user_by_name(const std::string& username) {
    auto lease = pool_.acquire();
    if (!lease) return std::nullopt;
    try {
        // 预编译 + 参数绑定:值永远不拼进 SQL 文本(第 42 讲)
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "SELECT id, username, password_hash, email, status, created_at "
            "FROM user WHERE username = ? LIMIT 1"));
        ps->setString(1, username);
        std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
        if (!rs->next()) return std::nullopt;
        UserRow u;
        u.id            = col_i64(rs.get(), "id");
        u.username      = col_str(rs.get(), "username");
        u.password_hash = col_str(rs.get(), "password_hash");
        u.email         = col_str(rs.get(), "email");
        u.status        = col_int(rs.get(), "status");
        u.created_at    = col_str(rs.get(), "created_at");
        return u;
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "find_user_by_name 失败 code=", e.getErrorCode(),
                  " what=", e.what());
        return std::nullopt;
    }
}

std::optional<UserRow> Dao::find_user_by_id(std::int64_t id) {
    auto lease = pool_.acquire();
    if (!lease) return std::nullopt;
    try {
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "SELECT id, username, password_hash, email, status, created_at "
            "FROM user WHERE id = ? LIMIT 1"));
        ps->setInt64(1, id);
        std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
        if (!rs->next()) return std::nullopt;
        UserRow u;
        u.id            = col_i64(rs.get(), "id");
        u.username      = col_str(rs.get(), "username");
        u.password_hash = col_str(rs.get(), "password_hash");
        u.email         = col_str(rs.get(), "email");
        u.status        = col_int(rs.get(), "status");
        u.created_at    = col_str(rs.get(), "created_at");
        return u;
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "find_user_by_id 失败 code=", e.getErrorCode(),
                  " what=", e.what());
        return std::nullopt;
    }
}

WriteResult Dao::create_user(const std::string& username,
                             const std::string& password_hash,
                             const std::string& email,
                             std::int64_t& new_id) {
    auto lease = pool_.acquire();
    if (!lease) return WriteResult::kError;
    try {
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "INSERT INTO user (username, password_hash, email, status) VALUES (?, ?, ?, 1)"));
        ps->setString(1, username);
        ps->setString(2, password_hash);
        if (email.empty()) ps->setNull(3, sql::DataType::VARCHAR);
        else               ps->setString(3, email);
        ps->executeUpdate();

        std::unique_ptr<sql::Statement> st(lease->createStatement());
        std::unique_ptr<sql::ResultSet> rs(st->executeQuery("SELECT LAST_INSERT_ID()"));
        if (rs->next()) new_id = rs->getInt64(1);
        return WriteResult::kOk;
    } catch (const sql::SQLException& e) {
        if (e.getErrorCode() == kErrDupEntry) return WriteResult::kDuplicate;
        if (e.getErrorCode() == kErrDeadlock) return WriteResult::kDeadlock;
        LOG_ERROR(kTag, "create_user 失败 code=", e.getErrorCode(),
                  " what=", e.what());
        return WriteResult::kError;
    }
}

// ---------------------------------------------------------------------------
// post
// ---------------------------------------------------------------------------
WriteResult Dao::create_post(std::int64_t user_id, const std::string& title,
                             const std::string& content, std::int64_t& new_id) {
    auto lease = pool_.acquire();
    if (!lease) return WriteResult::kError;
    try {
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "INSERT INTO post (user_id, title, content, status) VALUES (?, ?, ?, 1)"));
        ps->setInt64(1, user_id);
        ps->setString(2, title);
        ps->setString(3, content);
        ps->executeUpdate();

        std::unique_ptr<sql::Statement> st(lease->createStatement());
        std::unique_ptr<sql::ResultSet> rs(st->executeQuery("SELECT LAST_INSERT_ID()"));
        if (rs->next()) new_id = rs->getInt64(1);
        return WriteResult::kOk;
    } catch (const sql::SQLException& e) {
        if (e.getErrorCode() == kErrDeadlock) return WriteResult::kDeadlock;
        LOG_ERROR(kTag, "create_post 失败 code=", e.getErrorCode(), " what=", e.what());
        return WriteResult::kError;
    }
}

std::vector<PostRow> Dao::list_posts(int limit, int offset) {
    std::vector<PostRow> out;
    auto lease = pool_.acquire();
    if (!lease) return out;
    try {
        // 上限由调用方把关,这里再兜一次,防止 LIMIT 被塞进天文数字
        if (limit <= 0 || limit > 100) limit = 20;
        if (offset < 0) offset = 0;
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "SELECT id, user_id, title, content, status, created_at "
            "FROM post WHERE status = 1 ORDER BY created_at DESC, id DESC "
            "LIMIT ? OFFSET ?"));
        ps->setInt(1, limit);
        ps->setInt(2, offset);
        std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
        while (rs->next()) {
            PostRow p;
            p.id         = col_i64(rs.get(), "id");
            p.user_id    = col_i64(rs.get(), "user_id");
            p.title      = col_str(rs.get(), "title");
            p.content    = col_str(rs.get(), "content");
            p.status     = col_int(rs.get(), "status");
            p.created_at = col_str(rs.get(), "created_at");
            out.push_back(std::move(p));
        }
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "list_posts 失败 code=", e.getErrorCode(), " what=", e.what());
    }
    return out;
}

std::optional<PostRow> Dao::find_post(std::int64_t id) {
    auto lease = pool_.acquire();
    if (!lease) return std::nullopt;
    try {
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "SELECT id, user_id, title, content, status, created_at "
            "FROM post WHERE id = ? LIMIT 1"));
        ps->setInt64(1, id);
        std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
        if (!rs->next()) return std::nullopt;
        PostRow p;
        p.id         = col_i64(rs.get(), "id");
        p.user_id    = col_i64(rs.get(), "user_id");
        p.title      = col_str(rs.get(), "title");
        p.content    = col_str(rs.get(), "content");
        p.status     = col_int(rs.get(), "status");
        p.created_at = col_str(rs.get(), "created_at");
        return p;
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "find_post 失败 code=", e.getErrorCode(), " what=", e.what());
        return std::nullopt;
    }
}

WriteResult Dao::delete_post(std::int64_t id, std::int64_t user_id) {
    auto lease = pool_.acquire();
    if (!lease) return WriteResult::kError;
    try {
        // 软删除,并且限定 user_id —— 只能删自己的
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "UPDATE post SET status = 0 WHERE id = ? AND user_id = ? AND status = 1"));
        ps->setInt64(1, id);
        ps->setInt64(2, user_id);
        const int n = ps->executeUpdate();
        return n > 0 ? WriteResult::kOk : WriteResult::kError;
    } catch (const sql::SQLException& e) {
        if (e.getErrorCode() == kErrDeadlock) return WriteResult::kDeadlock;
        LOG_ERROR(kTag, "delete_post 失败 code=", e.getErrorCode(), " what=", e.what());
        return WriteResult::kError;
    }
}

// ---------------------------------------------------------------------------
// comment
// ---------------------------------------------------------------------------
WriteResult Dao::create_comment(std::int64_t post_id, std::int64_t user_id,
                                const std::string& content, std::int64_t& new_id) {
    auto lease = pool_.acquire();
    if (!lease) return WriteResult::kError;
    try {
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "INSERT INTO comment (post_id, user_id, content, status) VALUES (?, ?, ?, 1)"));
        ps->setInt64(1, post_id);
        ps->setInt64(2, user_id);
        ps->setString(3, content);
        ps->executeUpdate();

        std::unique_ptr<sql::Statement> st(lease->createStatement());
        std::unique_ptr<sql::ResultSet> rs(st->executeQuery("SELECT LAST_INSERT_ID()"));
        if (rs->next()) new_id = rs->getInt64(1);
        return WriteResult::kOk;
    } catch (const sql::SQLException& e) {
        if (e.getErrorCode() == kErrDeadlock) return WriteResult::kDeadlock;
        LOG_ERROR(kTag, "create_comment 失败 code=", e.getErrorCode(), " what=", e.what());
        return WriteResult::kError;
    }
}

std::vector<CommentRow> Dao::list_comments(std::int64_t post_id, int limit, int offset) {
    std::vector<CommentRow> out;
    auto lease = pool_.acquire();
    if (!lease) return out;
    try {
        if (limit <= 0 || limit > 200) limit = 50;
        if (offset < 0) offset = 0;
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "SELECT id, post_id, user_id, content, status, created_at "
            "FROM comment WHERE post_id = ? AND status = 1 "
            "ORDER BY created_at ASC, id ASC LIMIT ? OFFSET ?"));
        ps->setInt64(1, post_id);
        ps->setInt(2, limit);
        ps->setInt(3, offset);
        std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
        while (rs->next()) {
            CommentRow c;
            c.id         = col_i64(rs.get(), "id");
            c.post_id    = col_i64(rs.get(), "post_id");
            c.user_id    = col_i64(rs.get(), "user_id");
            c.content    = col_str(rs.get(), "content");
            c.status     = col_int(rs.get(), "status");
            c.created_at = col_str(rs.get(), "created_at");
            out.push_back(std::move(c));
        }
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "list_comments 失败 code=", e.getErrorCode(), " what=", e.what());
    }
    return out;
}

// ---------------------------------------------------------------------------
// audit_log
// ---------------------------------------------------------------------------
bool Dao::write_audit_batch(const std::vector<AuditLogRow>& rows) {
    if (rows.empty()) return true;
    auto lease = pool_.acquire();
    if (!lease) return false;

    // 这个版本的 Connector/C++ 没有 addBatch,
    // 所以改用"多行 INSERT":一条语句插 N 行,同样是一次事务(第 28、54 讲)。
    constexpr std::size_t kChunk = 50;            // 每批 50 行,12 列 -> 600 个占位符

    try {
        lease->setAutoCommit(false);              // 关自动提交,批量才有意义

        for (std::size_t base = 0; base < rows.size(); base += kChunk) {
            const std::size_t n = std::min(kChunk, rows.size() - base);

            std::string sql =
                "INSERT INTO audit_log (trace_id, ip, user_id, uri, method, params_digest, "
                "rule_hit, matched_len, action, status_code, cost_us, analyzed) VALUES ";
            for (std::size_t i = 0; i < n; ++i) {
                if (i) sql += ',';
                sql += "(?,?,?,?,?,?,?,?,?,?,?,0)";
            }

            std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(sql));
            unsigned int p = 1;
            for (std::size_t i = 0; i < n; ++i) {
                const auto& r = rows[base + i];
                ps->setString(p++, r.trace_id);
                ps->setString(p++, r.ip);
                if (r.user_id) ps->setInt64(p++, *r.user_id);
                else           ps->setNull(p++, sql::DataType::BIGINT);
                ps->setString(p++, r.uri);
                ps->setString(p++, r.method);
                if (r.params_digest.empty()) ps->setNull(p++, sql::DataType::VARCHAR);
                else                         ps->setString(p++, r.params_digest);
                if (r.rule_hit.empty()) ps->setNull(p++, sql::DataType::VARCHAR);
                else                    ps->setString(p++, r.rule_hit);
                ps->setInt(p++, r.matched_len);
                ps->setString(p++, r.action);
                ps->setInt(p++, r.status_code);
                ps->setInt64(p++, r.cost_us);
            }
            ps->executeUpdate();
        }

        lease->commit();
        lease->setAutoCommit(true);
        return true;
    } catch (const sql::SQLException& e) {
        try { lease->rollback(); } catch (...) {}
        try { lease->setAutoCommit(true); } catch (...) {}
        LOG_ERROR(kTag, "写审计批次失败(", rows.size(), " 条) code=", e.getErrorCode(),
                  " what=", e.what());
        return false;
    }
}

AuditStats Dao::audit_stats() {
    AuditStats s;
    auto lease = pool_.acquire();
    if (!lease) return s;
    try {
        std::unique_ptr<sql::Statement> st(lease->createStatement());
        std::unique_ptr<sql::ResultSet> rs(st->executeQuery(
            "SELECT COUNT(*) AS total, "
            "SUM(action = 'BLOCK') AS blocked, "
            "SUM(action = 'ALERT') AS alerted, "
            "SUM(action = 'PASS')  AS passed, "
            "COUNT(DISTINCT ip)    AS ips FROM audit_log"));
        if (rs->next()) {
            s.total   = col_i64(rs.get(), "total");
            s.blocked = col_i64(rs.get(), "blocked");
            s.alerted = col_i64(rs.get(), "alerted");
            s.passed  = col_i64(rs.get(), "passed");
            s.hits_by_ip = col_i64(rs.get(), "ips");
        }
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "audit_stats 失败 code=", e.getErrorCode(), " what=", e.what());
    }
    return s;
}

std::vector<AuditLogRow> Dao::recent_blocked(const std::string& ip, int limit) {
    std::vector<AuditLogRow> out;
    auto lease = pool_.acquire();
    if (!lease) return out;
    try {
        if (limit <= 0 || limit > 200) limit = 20;
        // 走 idx_ip_time 索引(第 50 讲:索引要照"人怎么问"设计)
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "SELECT trace_id, ip, user_id, uri, method, rule_hit, matched_len, "
            "action, status_code, cost_us FROM audit_log "
            "WHERE ip = ? AND action = 'BLOCK' ORDER BY created_at DESC LIMIT ?"));
        ps->setString(1, ip);
        ps->setInt(2, limit);
        std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
        while (rs->next()) {
            AuditLogRow r;
            r.trace_id    = col_str(rs.get(), "trace_id");
            r.ip          = col_str(rs.get(), "ip");
            if (!rs->isNull("user_id")) r.user_id = rs->getInt64("user_id");
            r.uri         = col_str(rs.get(), "uri");
            r.method      = col_str(rs.get(), "method");
            r.rule_hit    = col_str(rs.get(), "rule_hit");
            r.matched_len = col_int(rs.get(), "matched_len");
            r.action      = col_str(rs.get(), "action");
            r.status_code = col_int(rs.get(), "status_code");
            r.cost_us     = col_i64(rs.get(), "cost_us");
            out.push_back(std::move(r));
        }
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "recent_blocked 失败 code=", e.getErrorCode(), " what=", e.what());
    }
    return out;
}

// ---------------------------------------------------------------------------
// W6:AI 分析层用的读写
// ---------------------------------------------------------------------------

// 这些 rule_hit 是"策略性拦截",不是攻击特征命中:
// 限流、被封禁、登录失败、重放 —— 它们已经说明问题了,
// 再送 LLM 判断一遍纯属浪费钱。
std::vector<AuditLogRow> Dao::fetch_unanalyzed(int limit, int lookback_hours) {
    std::vector<AuditLogRow> out;
    auto lease = pool_.acquire();
    if (!lease) return out;
    try {
        if (limit <= 0 || limit > 200) limit = 10;
        if (lookback_hours <= 0 || lookback_hours > 24 * 30) lookback_hours = 24;

        // 走 idx_analyzed (analyzed, created_at):先按 analyzed 过滤,再按时间
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "SELECT id, trace_id, ip, user_id, uri, method, params_digest, rule_hit, "
            "matched_len, action, status_code, cost_us, created_at "
            "FROM audit_log "
            "WHERE analyzed = 0 "
            "  AND action = 'BLOCK' "
            "  AND rule_hit IS NOT NULL AND rule_hit <> '' "
            "  AND rule_hit NOT IN ('RATE_LIMITED','IP_BANNED','LOGIN_FAIL',"
            "                       'REPLAY_MISSING_HEADERS','REPLAY_STALE','REPLAY_DUPLICATE') "
            "  AND created_at >= (NOW() - INTERVAL ? HOUR) "
            "ORDER BY id DESC LIMIT ?"));
        ps->setInt(1, lookback_hours);
        ps->setInt(2, limit);
        std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
        while (rs->next()) {
            AuditLogRow r;
            r.id            = col_i64(rs.get(), "id");
            r.trace_id      = col_str(rs.get(), "trace_id");
            r.ip            = col_str(rs.get(), "ip");
            if (!rs->isNull("user_id")) r.user_id = rs->getInt64("user_id");
            r.uri           = col_str(rs.get(), "uri");
            r.method        = col_str(rs.get(), "method");
            r.params_digest = col_str(rs.get(), "params_digest");
            r.rule_hit      = col_str(rs.get(), "rule_hit");
            r.matched_len   = col_int(rs.get(), "matched_len");
            r.action        = col_str(rs.get(), "action");
            r.status_code   = col_int(rs.get(), "status_code");
            r.cost_us       = col_i64(rs.get(), "cost_us");
            r.created_at    = col_str(rs.get(), "created_at");
            out.push_back(std::move(r));
        }
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "fetch_unanalyzed 失败 code=", e.getErrorCode(),
                  " what=", e.what());
    }
    return out;
}

bool Dao::mark_analyzed(const std::vector<std::int64_t>& ids) {
    if (ids.empty()) return true;
    auto lease = pool_.acquire();
    if (!lease) return false;
    try {
        // 一条 UPDATE 改一批:避免逐条 round-trip
        std::string sql = "UPDATE audit_log SET analyzed = 1 WHERE id IN (";
        for (std::size_t i = 0; i < ids.size(); ++i) {
            if (i) sql += ',';
            sql += '?';
        }
        sql += ')';
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(sql));
        for (std::size_t i = 0; i < ids.size(); ++i) {
            ps->setInt64(static_cast<unsigned int>(i + 1), ids[i]);
        }
        ps->executeUpdate();
        return true;
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "mark_analyzed 失败 code=", e.getErrorCode(),
                  " what=", e.what());
        return false;
    }
}

WriteResult Dao::insert_alert(const AlertRow& alert, std::int64_t& new_id) {
    auto lease = pool_.acquire();
    if (!lease) return WriteResult::kError;
    try {
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "INSERT INTO alert (ip, threat_type, severity, confidence, reasoning, "
            "log_ids, status) VALUES (?, ?, ?, ?, ?, ?, ?)"));
        ps->setString(1, alert.ip);
        ps->setString(2, alert.threat_type);
        ps->setString(3, alert.severity);
        ps->setDouble(4, alert.confidence);
        ps->setString(5, alert.reasoning);
        if (alert.log_ids.empty()) ps->setNull(6, sql::DataType::VARCHAR);
        else                      ps->setString(6, alert.log_ids);
        ps->setInt(7, alert.status);
        ps->executeUpdate();

        std::unique_ptr<sql::Statement> st(lease->createStatement());
        std::unique_ptr<sql::ResultSet> rs(st->executeQuery("SELECT LAST_INSERT_ID()"));
        if (rs->next()) new_id = rs->getInt64(1);
        return WriteResult::kOk;
    } catch (const sql::SQLException& e) {
        if (e.getErrorCode() == kErrDeadlock) return WriteResult::kDeadlock;
        LOG_ERROR(kTag, "insert_alert 失败 code=", e.getErrorCode(), " what=", e.what());
        return WriteResult::kError;
    }
}

std::vector<AlertRow> Dao::list_alerts(int limit, int offset) {
    std::vector<AlertRow> out;
    auto lease = pool_.acquire();
    if (!lease) return out;
    try {
        if (limit <= 0 || limit > 200) limit = 20;
        if (offset < 0) offset = 0;
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "SELECT id, ip, threat_type, severity, confidence, reasoning, log_ids, "
            "status, created_at FROM alert "
            "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"));
        ps->setInt(1, limit);
        ps->setInt(2, offset);
        std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
        while (rs->next()) {
            AlertRow a;
            a.id          = col_i64(rs.get(), "id");
            a.ip          = col_str(rs.get(), "ip");
            a.threat_type = col_str(rs.get(), "threat_type");
            a.severity    = col_str(rs.get(), "severity");
            a.confidence  = rs->isNull("confidence") ? 0.0 : rs->getDouble("confidence");
            a.reasoning   = col_str(rs.get(), "reasoning");
            a.log_ids     = col_str(rs.get(), "log_ids");
            a.status      = col_int(rs.get(), "status");
            a.created_at  = col_str(rs.get(), "created_at");
            out.push_back(std::move(a));
        }
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "list_alerts 失败 code=", e.getErrorCode(), " what=", e.what());
    }
    return out;
}

AlertStats Dao::alert_stats() {
    AlertStats s;
    auto lease = pool_.acquire();
    if (!lease) return s;
    try {
        std::unique_ptr<sql::Statement> st(lease->createStatement());
        std::unique_ptr<sql::ResultSet> rs(st->executeQuery(
            "SELECT COUNT(*) AS total, "
            "SUM(status = 0) AS pending, "
            "SUM(status = 1) AS confirmed, "
            "SUM(status = 2) AS fp, "
            "SUM(severity = 'CRITICAL') AS critical, "
            "SUM(severity = 'HIGH') AS high FROM alert"));
        if (rs->next()) {
            s.total          = col_i64(rs.get(), "total");
            s.pending        = col_i64(rs.get(), "pending");
            s.confirmed      = col_i64(rs.get(), "confirmed");
            s.false_positive = col_i64(rs.get(), "fp");
            s.critical       = col_i64(rs.get(), "critical");
            s.high           = col_i64(rs.get(), "high");
        }
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "alert_stats 失败 code=", e.getErrorCode(), " what=", e.what());
    }
    return s;
}

WriteResult Dao::set_alert_status(std::int64_t id, int status) {
    if (status < 0 || status > 2) return WriteResult::kError;
    auto lease = pool_.acquire();
    if (!lease) return WriteResult::kError;
    try {
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "UPDATE alert SET status = ? WHERE id = ?"));
        ps->setInt(1, status);
        ps->setInt64(2, id);
        const int n = ps->executeUpdate();
        return n > 0 ? WriteResult::kOk : WriteResult::kError;
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "set_alert_status 失败 code=", e.getErrorCode(),
                  " what=", e.what());
        return WriteResult::kError;
    }
}

// ---------------------------------------------------------------------------
// 审计保留策略
//
// 为什么必须有:审计表是"每请求一行",只会涨。压测跑了 3 分钟就写了 320 万行、
// 占 584MB。没有清理策略的审计表迟早把磁盘吃光,而且删不动(索引膨胀)。
//
// 为什么分批删:一条 DELETE 删几百万行会长时间持锁、把 IO 打满,
// 线上表现就是"服务突然变慢"。带 LIMIT 一批批删,对线上几乎无感。
// ---------------------------------------------------------------------------
int Dao::purge_audit_before(int days, int batch_limit) {
    if (days <= 0) return 0;
    if (batch_limit <= 0 || batch_limit > 100000) batch_limit = 10000;

    auto lease = pool_.acquire();
    if (!lease) return 0;
    try {
        std::unique_ptr<sql::PreparedStatement> ps(lease->prepareStatement(
            "DELETE FROM audit_log "
            "WHERE created_at < (NOW() - INTERVAL ? DAY) "
            "LIMIT ?"));
        ps->setInt(1, days);
        ps->setInt(2, batch_limit);
        return ps->executeUpdate();
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "purge_audit_before 失败 code=", e.getErrorCode(),
                  " what=", e.what());
        return 0;
    }
}

std::int64_t Dao::audit_row_count() {
    auto lease = pool_.acquire();
    if (!lease) return -1;
    try {
        std::unique_ptr<sql::Statement> st(lease->createStatement());
        std::unique_ptr<sql::ResultSet> rs(st->executeQuery(
            "SELECT COUNT(*) AS n FROM audit_log"));
        return rs->next() ? rs->getInt64("n") : -1;
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "audit_row_count 失败 code=", e.getErrorCode(),
                  " what=", e.what());
        return -1;
    }
}

}  // namespace secguard
