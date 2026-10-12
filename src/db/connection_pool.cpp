#include "db/connection_pool.h"

#include <cppconn/exception.h>
#include <cppconn/statement.h>
#include <mysql_driver.h>

#include "util/log.h"

namespace secguard {
namespace {
constexpr const char* kTag = "[连接池] ";
}

ConnectionPool::ConnectionPool(const DatabaseConfig& cfg) : cfg_(cfg) {
    std::lock_guard<std::mutex> lk(mu_);
    // 预热:先建 min(pool_size, 2) 条,避免首个请求吃冷启动延迟
    const int warm = cfg_.pool_size < 2 ? cfg_.pool_size : 2;
    for (int i = 0; i < warm; ++i) {
        if (sql::Connection* c = make_connection()) {
            idle_.push_back(c);
            ++total_;
        } else {
            LOG_WARN(kTag, "预热第 ", i + 1, " 条连接失败,跳过");
        }
    }
    LOG_INFO(kTag, "已启动:池大小=", cfg_.pool_size, " 预热=", idle_.size());
}

ConnectionPool::~ConnectionPool() {
    std::lock_guard<std::mutex> lk(mu_);
    closed_ = true;
    for (sql::Connection* c : idle_) {
        try { c->close(); } catch (...) {}
        delete c;
    }
    idle_.clear();
    total_ = 0;
    cv_.notify_all();
}

sql::Connection* ConnectionPool::make_connection() {
    try {
        sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();
        sql::Connection* conn = driver->connect(
            "tcp://" + cfg_.host + ":" + std::to_string(cfg_.port),
            cfg_.user, cfg_.password);
        conn->setSchema(cfg_.schema);
        conn->setAutoCommit(true);      // 默认自动提交;批量写时由调用方临时关掉
        ++create_count_;
        return conn;
    } catch (const sql::SQLException& e) {
        LOG_ERROR(kTag, "建连接失败 code=", e.getErrorCode(),
                  " state=", e.getSQLState(), " what=", e.what());
        return nullptr;
    }
}

ConnectionPool::Lease ConnectionPool::acquire() {
    std::unique_lock<std::mutex> lk(mu_);
    if (closed_) return {};

    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(cfg_.acquire_timeout_ms);

    for (;;) {
        if (!idle_.empty()) {
            sql::Connection* c = idle_.back();
            idle_.pop_back();
            ++reuse_count_;
            lk.unlock();

            // 借出前探活:连接可能已被服务端 wait_timeout 断开
            bool alive = false;
            try {
                std::unique_ptr<sql::Statement> st(c->createStatement());
                std::unique_ptr<sql::ResultSet> rs(st->executeQuery("SELECT 1"));
                alive = rs->next();
            } catch (const sql::SQLException&) {
                alive = false;
            }

            if (alive) return Lease(this, c);

            // 死连接:丢掉,再试一次
            LOG_WARN(kTag, "剔除一条失效连接");
            delete c;
            {
                std::lock_guard<std::mutex> lk2(mu_);
                --total_;
            }
            lk.lock();
            continue;
        }

        // 池没满就新建
        if (total_ < cfg_.pool_size) {
            ++total_;                       // 先占额度,避免并发重复建
            lk.unlock();
            sql::Connection* c = make_connection();
            if (c) return Lease(this, c);
            lk.lock();
            --total_;
            return {};                      // 建不出来就是建不出来,别死循环
        }

        // 池满:等别人归还
        ++waiters_;
        const bool got = (cv_.wait_until(lk, deadline) != std::cv_status::timeout);
        --waiters_;
        if (!got) {
            LOG_WARN(kTag, "等待连接超时(", cfg_.acquire_timeout_ms, "ms) 池满:",
                     " total=", total_, " idle=", idle_.size());
            return {};
        }
    }
}

void ConnectionPool::give_back(sql::Connection* conn) {
    if (!conn) return;

    // 归还时清理会话状态:上一条若开了事务,下一条不能继承
    bool reusable = true;
    try {
        if (!conn->getAutoCommit()) {
            conn->rollback();
            conn->setAutoCommit(true);
        }
    } catch (const sql::SQLException& e) {
        LOG_WARN(kTag, "归还时重置会话失败,丢弃该连接:", e.what());
        reusable = false;
    }

    std::lock_guard<std::mutex> lk(mu_);
    if (!reusable || closed_) {
        try { conn->close(); } catch (...) {}
        delete conn;
        --total_;
    } else {
        idle_.push_back(conn);
    }
    cv_.notify_one();
}

void ConnectionPool::health_check() {
    std::vector<sql::Connection*> dead;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = idle_.begin(); it != idle_.end();) {
            bool alive = false;
            try {
                std::unique_ptr<sql::Statement> st((*it)->createStatement());
                std::unique_ptr<sql::ResultSet> rs(st->executeQuery("SELECT 1"));
                alive = rs->next();
            } catch (const sql::SQLException&) {
                alive = false;
            }
            if (alive) {
                ++it;
            } else {
                dead.push_back(*it);
                it = idle_.erase(it);
                --total_;
            }
        }
    }
    for (sql::Connection* c : dead) {
        try { c->close(); } catch (...) {}
        delete c;
    }
    if (!dead.empty()) LOG_INFO(kTag, "健康检查剔除 ", dead.size(), " 条失效连接");
}

int ConnectionPool::idle_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return static_cast<int>(idle_.size());
}
int ConnectionPool::total_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return total_;
}
std::size_t ConnectionPool::waiters() const {
    std::lock_guard<std::mutex> lk(mu_);
    return static_cast<std::size_t>(waiters_);
}
long long ConnectionPool::reuse_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return reuse_count_;
}
long long ConnectionPool::create_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return create_count_;
}

}  // namespace secguard
