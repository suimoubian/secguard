// 数据库连接池(寓言集第 51 讲)
//
// 为什么要有它:建一条 MySQL 连接要 TCP 握手 + 认证,约 1~10ms,
// 而一条简单查询可能只要 0.1ms —— 建连接比干活贵。
//
// 四条纪律:
//   1. 借用必须走 RAII(Lease),否则异常路径漏归还 -> 池子枯竭(第 31 讲)
//   2. 借出前探活(连接可能已被服务端超时断开)
//   3. 归还时清理会话状态(回滚未提交事务),下一条不能继承上一条的状态
//   4. 借不到要超时失败,不能让请求无限堆积
#pragma once

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <cppconn/connection.h>

#include "util/config.h"

namespace secguard {

class ConnectionPool {
public:
    // 借用凭证。析构自动归还 —— 这就是 RAII(第 31 讲)。
    class Lease {
    public:
        Lease() = default;
        Lease(ConnectionPool* pool, sql::Connection* conn) : pool_(pool), conn_(conn) {}
        ~Lease() { reset(); }

        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& o) noexcept : pool_(o.pool_), conn_(o.conn_) {
            o.pool_ = nullptr;
            o.conn_ = nullptr;
        }
        Lease& operator=(Lease&& o) noexcept {
            if (this != &o) {
                reset();
                pool_ = o.pool_;
                conn_ = o.conn_;
                o.pool_ = nullptr;
                o.conn_ = nullptr;
            }
            return *this;
        }

        [[nodiscard]] sql::Connection* operator->() const { return conn_; }
        [[nodiscard]] sql::Connection* get() const { return conn_; }
        [[nodiscard]] bool valid() const { return conn_ != nullptr; }
        explicit operator bool() const { return valid(); }

        void reset() {
            if (pool_ && conn_) pool_->give_back(conn_);
            pool_ = nullptr;
            conn_ = nullptr;
        }

    private:
        ConnectionPool* pool_ = nullptr;
        sql::Connection* conn_ = nullptr;
    };

    explicit ConnectionPool(const DatabaseConfig& cfg);
    ~ConnectionPool();

    ConnectionPool(const ConnectionPool&) = delete;
    ConnectionPool& operator=(const ConnectionPool&) = delete;

    // 借一条连接。超时或池不可用返回无效 Lease。
    [[nodiscard]] Lease acquire();

    // 定期探活:把被服务端断开的连接剔除并按需补足
    void health_check();

    [[nodiscard]] int idle_count() const;
    [[nodiscard]] int total_count() const;
    [[nodiscard]] std::size_t waiters() const;
    [[nodiscard]] long long reuse_count() const;   // 复用次数,用于证明"没在反复建连"
    [[nodiscard]] long long create_count() const;  // 实际建连次数

private:
    friend class Lease;
    void give_back(sql::Connection* conn);
    sql::Connection* make_connection();     // 出错返回 nullptr

    DatabaseConfig cfg_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::vector<sql::Connection*> idle_;
    int total_ = 0;
    int waiters_ = 0;
    bool closed_ = false;
    long long reuse_count_ = 0;
    long long create_count_ = 0;
};

}  // namespace secguard
