// SecGuard - 高性能安全审计引擎
//
// 各模块与寓言集的对应:
//   配置     第 67 讲   全程环境变量,启动时打印并校验
//   日志     第 68 讲   四档分级,输出 stdout
//   引擎     第 1~26 讲 AC 自动机 + 特征库热加载
//   连接池   第 51 讲   借还走 RAII,超时快速失败
//   DAO      第 52 讲   全部预编译参数化
//   鉴权     第 43~45 讲 PBKDF2 口令 + JWT
//   防护     第 38、41 讲 令牌桶限流 + 命中自动封禁
//   停机     第 69 讲   收请求、收线程、收连接
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <cpp-httplib/httplib.h>

#include "cache/distributed_guard.h"
#include "cache/redis_client.h"
#include "db/audit_writer.h"
#include "db/connection_pool.h"
#include "db/dao.h"
#include "engine.h"
#include "net/http_server.h"
#include "util/config.h"
#include "util/log.h"

namespace {

constexpr const char* kTag = "[主程序] ";

std::atomic<bool> g_stop_requested{false};

void on_signal(int sig) {
    // 信号处理里只做一件事:置标志。真正的收尾在主流程里做。
    (void)sig;
    g_stop_requested.store(true);
}

std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> v;
    std::string cur;
    for (char c : s) {
        if (c == '\n') { v.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    if (!cur.empty()) v.push_back(cur);
    return v;
}

}  // namespace

int main() {
    using namespace secguard;

    // ---- 1. 配置 ----
    Config cfg;
    std::string err;
    if (!Config::load(cfg, err)) {
        // 配置不对就别启动。带着错配置跑,出问题更难查(第 67 讲)
        std::fprintf(stderr, "配置错误: %s\n", err.c_str());
        return 1;
    }
    log::set_level_from_string(cfg.log_level);

    LOG_INFO(kTag, "SecGuard 启动中");
    for (const auto& line : split_lines(cfg.describe())) {
        LOG_INFO(kTag, line);
    }

    // ---- 2. 引擎:载入特征库并建表 ----
    Engine engine;
    if (!engine.load_from_file(cfg.engine.pattern_file, cfg.engine, err)) {
        LOG_ERROR(kTag, "特征库载入失败: ", err);
        LOG_ERROR(kTag, "提示:检查 SECGUARD_PATTERN_FILE 指向的文件是否存在");
        return 1;
    }

    // ---- 3. 数据库连接池 ----
    std::unique_ptr<ConnectionPool> pool;
    try {
        pool = std::make_unique<ConnectionPool>(cfg.db);
    } catch (const std::exception& e) {
        LOG_ERROR(kTag, "连接池初始化异常: ", e.what());
        return 1;
    }
    Dao dao(*pool);
    if (!dao.ping()) {
        LOG_ERROR(kTag, "数据库连接不通。检查 SECGUARD_DB_HOST/USER/PASS,",
                  " 以及 MySQL 是否已启动、secguard 库是否已建表");
        return 1;   // 连不上库就别装作健康
    }

    // ---- 4. Redis:限流 / 封禁 / 重放的共享状态(第 39 讲) ----
    // 连不上不阻断启动:DistributedGuard 会自动降级为单机版并打日志。
    auto redis = std::make_unique<RedisClient>(cfg.redis);
    if (cfg.redis.enabled && !redis->available()) {
        LOG_WARN(kTag, "Redis 不可用 —— 限流与封禁退回单机版,",
                 "多实例部署时限额会被放大,请检查 Redis");
    }

    // ---- 5. 分布式防护 ----
    DistributedGuard guard(redis.get(), cfg.guard);

    // ---- 6. 审计管道:无锁队列 + 后台批量落库(第 28、35 讲) ----
    AuditWriterConfig aw_cfg;
    aw_cfg.batch_size = cfg.audit.batch_size;
    aw_cfg.flush_interval_ms = cfg.audit.flush_interval_ms;
    std::unique_ptr<AuditWriter> audit;
    if (cfg.audit.async) {
        audit = std::make_unique<AuditWriter>(&dao, aw_cfg);
        audit->start();
    } else {
        LOG_INFO(kTag, "审计走同步写库(配置里关掉了异步)");
    }

    LoginThrottle login_throttle;

    AppContext ctx;
    ctx.cfg = cfg;
    ctx.pool = pool.get();
    ctx.dao = &dao;
    ctx.engine = &engine;
    ctx.redis = redis.get();
    ctx.guard = &guard;
    ctx.audit = audit.get();
    ctx.login_throttle = &login_throttle;

    // ---- 5. 信号:优雅停机 ----
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);   // 客户端断开不该把进程带走

    // ---- 6. HTTP 服务 ----
    httplib::Server svr;
    svr.set_payload_max_length(1024 * 1024);        // 请求体上限 1MB(第 47 讲)
    svr.set_read_timeout(10, 0);
    svr.set_write_timeout(10, 0);
    const int threads = cfg.server.threads;
    svr.new_task_queue = [threads] {
        return new httplib::ThreadPool(static_cast<std::size_t>(threads));
    };

    register_routes(svr, ctx);

    if (!svr.bind_to_port(cfg.server.bind_addr.c_str(), cfg.server.port)) {
        LOG_ERROR(kTag, "端口被占用或无权绑定: ", cfg.server.bind_addr,
                  ":", cfg.server.port);
        return 1;
    }
    LOG_INFO(kTag, "监听 http://", cfg.server.bind_addr, ":", cfg.server.port,
             "  线程数=", cfg.server.threads);

    // ---- 7. 后台线程 ----
    // 7a. 停机哨兵:收到信号就停服,并定期剔除失效连接
    std::thread reaper([&] {
        int tick = 0;
        while (!g_stop_requested.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            if (++tick % 60 == 0) {
                pool->health_check();
                LOG_DEBUG(kTag, "连接池巡检:total=", pool->total_count(),
                          " idle=", pool->idle_count(),
                          " 建连=", pool->create_count(),
                          " 复用=", pool->reuse_count());
            }
        }
        LOG_INFO(kTag, "收到停止信号,停止接受新请求");
        svr.stop();                 // 第一步:停止接受新请求(第 69 讲)
    });

    // 7b. 特征库热加载:不停止服务换规则(第 14 讲)
    std::thread reloader([&] {
        const int interval = cfg.engine.reload_interval_seconds;
        if (interval <= 0) return;
        while (!g_stop_requested.load()) {
            for (int i = 0; i < interval * 2 && !g_stop_requested.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            if (g_stop_requested.load()) break;
            std::size_t n = 0;
            engine.reload_if_changed(cfg.engine.pattern_file, cfg.engine, n);
        }
    });

    // ---- 8. 跑起来(阻塞直到 stop) ----
    const bool ok = svr.listen_after_bind();
    if (!ok) LOG_WARN(kTag, "服务退出时返回非正常状态");

    // ---- 9. 收尾:三样都要收(第 69 讲) ----
    g_stop_requested.store(true);
    if (reloader.joinable()) reloader.join();
    if (reaper.joinable()) reaper.join();

    // 审计管道必须最后停:它要把队列里剩下的日志全部写完再退出。
    // 提前停 = 丢数据;不停 = 进程卡住。
    if (audit) {
        audit->stop();
        LOG_INFO(kTag, "审计管道收尾:写入=", audit->written(),
                 " 丢弃=", audit->dropped(), " 剩余=", audit->queued());
    }

    const auto st = dao.audit_stats();
    LOG_INFO(kTag, "收尾:本次运行共审计 ", st.total, " 条记录,拦截 ", st.blocked, " 条");
    LOG_INFO(kTag, "限流与封禁:降级次数=", guard.fallback_count(),
             (guard.redis_available() ? " (Redis 共享)" : " (单机内存)"));
    if (redis) {
        LOG_INFO(kTag, "Redis:命令=", redis->commands(), " 失败=", redis->failures());
    }
    LOG_INFO(kTag, "连接池统计:建连=", pool->create_count(),
             " 复用=", pool->reuse_count());
    // pool 是 unique_ptr,离开作用域时析构会关闭所有连接 —— 这就是 RAII(第 31 讲)
    LOG_INFO(kTag, "SecGuard 已停止");
    return 0;
}
