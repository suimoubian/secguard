// 配置:全部走环境变量,不写死在代码里(寓言集第 67 讲)
//
// 三个问题决定一个配置该放哪:
//   跟着代码走(默认端口、超时)  -> 代码里给默认值
//   跟着环境走(数据库地址)      -> 环境变量覆盖
//   是秘密的(口令、密钥)        -> 只走环境变量,代码里连默认值都不留
#pragma once

#include <cstdint>
#include <string>

namespace secguard {

struct DatabaseConfig {
    std::string host = "127.0.0.1";
    int         port = 3306;
    std::string user;
    std::string password;
    std::string schema = "secguard";
    int         pool_size = 8;          // 连接池大小,别超过 MySQL max_connections
    int         acquire_timeout_ms = 3000;
};

struct AuthConfig {
    std::string jwt_secret;             // 必填,不设默认值
    int         token_ttl_seconds = 7200;      // 令牌有效期,默认 2 小时
    int         pbkdf2_iterations = 120000;    // 故意算得慢(第 43 讲)
    int         login_fail_limit = 5;          // 连续失败几次就锁
    int         login_lock_seconds = 300;      // 锁多久
};

struct ServerConfig {
    std::string bind_addr = "0.0.0.0";  // 绑 0.0.0.0 才能被外部探活
    int         port = 8080;
    int         threads = 0;            // 0 = 按核心数自动
    int         backlog = 512;          // 监听队列(第 47 讲:连接一多就容易满)
};

struct EngineConfig {
    std::string pattern_file;           // 特征库路径
    std::size_t max_pattern_len = 4096; // 超长模式拒收(第 13 讲)
    std::size_t max_text_bytes = 256 * 1024;   // 待检文本上限(第 17 讲)
    std::size_t max_hits = 512;         // 单次匹配最多报多少条(第 25 讲)
    int         reload_interval_seconds = 60;  // 特征库热加载检查间隔(第 14 讲)
};

// 防护:限流与自动封禁(第 38、41 讲)
struct GuardConfig {
    double rate_per_sec = 200.0;        // 令牌桶:平均速率
    double burst = 400.0;               // 令牌桶:允许的突发
    int    window_seconds = 300;        // 命中计数的窗口长度
    int    hit_threshold = 20;          // 窗口内命中多少次触发封禁
    int    ban_seconds = 1800;          // 封禁时长
    int    login_fail_limit = 5;        // 登录连续失败上限(第 43 讲)
    int    login_window_seconds = 300;  // 失败计数窗口
};

struct Config {
    DatabaseConfig db;
    AuthConfig     auth;
    ServerConfig   server;
    EngineConfig   engine;
    GuardConfig    guard;
    std::string    log_level = "info";  // debug|info|warn|error(第 68 讲)

    // 从环境变量装载。缺失必填项时返回 false 并说明原因。
    static bool load(Config& out, std::string& err);

    // 启动时把关键配置打出来(脱敏后),便于确认"它在按什么跑"(第 67 讲)
    [[nodiscard]] std::string describe() const;
};

}  // namespace secguard
