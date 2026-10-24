// 配置:全部走环境变量,不写死在代码里(寓言集第 67 讲)
//
// 三个问题决定一个配置该放哪:
//   跟着代码走(默认端口、超时)  -> 代码里给默认值
//   跟着环境走(数据库地址)      -> 环境变量覆盖
//   是秘密的(口令、密钥)        -> 只走环境变量,代码里连默认值都不留
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "ai/llm_client.h"
#include "cache/redis_client.h"

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
    // 管理员用户名名单(逗号分隔)。只有名单里的用户能访问管理接口。
    // 空 = 管理接口全部关闭(fail-closed),启动时打警告。
    std::vector<std::string> admin_users;
};

struct ServerConfig {
    std::string bind_addr = "0.0.0.0";  // 绑 0.0.0.0 才能被外部探活
    int         port = 8080;
    int         threads = 0;            // 0 = 按核心数自动
    int         backlog = 512;          // 监听队列(第 47 讲:连接一多就容易满)

    // 是否信任 X-Forwarded-For 头来取客户端 IP。
    //
    // 默认关闭。原因:XFF 是客户端可以随便填的头。如果程序直接对外,
    // 攻击者发一个 "X-Forwarded-For: 1.2.3.4" 就能伪装成任意 IP,
    // 从而绕过按 IP 的限流和封禁。
    // 只有在**确定前面有一层反向代理**、且代理会覆盖(而不是追加)这个头时,
    // 才应该打开 —— docker-compose.yml 里就是这么配的。
    bool        trust_proxy = false;
};

struct EngineConfig {
    std::string pattern_file;           // 特征库路径
    // 白名单:某个路径下放行某些规则。缺失不算错误。
    std::string allowlist_file = "rules/allowlist.conf";
    std::size_t max_pattern_len = 4096; // 超长模式拒收(第 13 讲)
    std::size_t max_text_bytes = 256 * 1024;   // 待检文本上限(第 17 讲)
    std::size_t max_hits = 512;         // 单次匹配最多报多少条(第 25 讲)
    int         reload_interval_seconds = 60;  // 特征库热加载检查间隔(第 14 讲)
};

// 防护:限流与自动封禁(第 38、41 讲)
struct GuardConfig {
    // 注意口径:限流是**按 IP** 算的(每个 IP 一个令牌桶)。
    // 全局单桶会让一个攻击者把所有人的额度吃光;按 IP 分桶更合理,
    // 代价是对"大量分散 IP"的慢速攻击不敏感 —— 靠封禁阈值那层兜。
    double rate_per_sec = 200.0;        // 令牌桶:每 IP 平均速率
    double burst = 400.0;               // 令牌桶:每 IP 允许的突发
    int    window_seconds = 300;        // 命中计数的窗口长度
    int    hit_threshold = 20;          // 窗口内命中多少次触发封禁
    int    ban_seconds = 1800;          // 封禁时长
    int    login_fail_limit = 5;        // 登录连续失败上限(第 43 讲)
    int    login_window_seconds = 300;  // 失败计数窗口
};

// 重放防护(第 40 讲)
struct ReplayConfig {
    bool require = false;          // true = 拒绝没有 nonce/timestamp 的写请求
    int  window_seconds = 300;     // 时间戳有效期(同时是 nonce 的 TTL)
};

// 审计管道(第 28、35 讲)
struct AuditConfig {
    std::size_t batch_size = 500;      // 攒够多少条写一次
    int         flush_interval_ms = 1000;  // 或满多久写一次
    bool        async = true;          // false = 退回同步写库(便于对比)
    // 保留天数。审计表会无限增长 —— 压测跑了 3 分钟就写了 320 万条、占了 584MB。
    // 0 表示不清理(交给外部定时任务),默认 7 天。
    int         retention_days = 7;
};

// AI 分析层(第 59~63 讲)
struct AiConfig {
    bool   enabled = false;          // 默认关:没有 API Key 就别跑
    int    interval_seconds = 60;    // 多久跑一轮
    int    startup_delay_seconds = 5;// 启动后等多久跑第一轮(别和 DB 预热抢资源)
    int    batch_size = 10;          // 每轮最多拉多少条待分析记录
    int    max_groups_per_round = 5; // 每轮最多调几次 LLM(按 IP 分组)
    double min_confidence = 0.6;     // 置信度门槛,低于此不写告警
    int    max_requests_per_minute = 10;   // 成本控制
    int    lookback_hours = 24;      // 只看最近多久的记录
};

struct Config {
    DatabaseConfig db;
    AuthConfig     auth;
    ServerConfig   server;
    EngineConfig   engine;
    GuardConfig    guard;
    RedisConfig    redis;
    ReplayConfig   replay;
    AuditConfig    audit;
    LlmConfig      llm;
    AiConfig       ai;
    std::string    log_level = "info";  // debug|info|warn|error(第 68 讲)

    // 从环境变量装载。缺失必填项时返回 false 并说明原因。
    static bool load(Config& out, std::string& err);

    // 启动时把关键配置打出来(脱敏后),便于确认"它在按什么跑"(第 67 讲)
    [[nodiscard]] std::string describe() const;
};

}  // namespace secguard
