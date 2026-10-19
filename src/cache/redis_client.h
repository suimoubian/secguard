// Redis 客户端:连接池 + Lua 脚本(寓言集第 39 讲)
//
// 为什么要走 Redis:
//   单机的内存版限流在"多实例部署"下完全失效 —— 每个实例各有一份计数,
//   3 个实例等于把限额放大 3 倍。共享状态必须放在 Redis。
//
// 为什么要用 Lua:
//   "先查再改"两步之间会被别人插一脚(check-then-act 竞态)。
//   Redis 执行 Lua 时是单线程、不处理其他命令的,整段 read-modify-write 天然原子。
//
// 命令一律用 argv 形式发(redisCommandArgv),不拼命令行字符串。
// 踩过的坑:redisCommand(ctx, "%s", "DEL a b") 会把整串当成**一个参数**,
// Redis 于是认为命令名是 `DEL "a b"`,直接报 unknown command。
//
// 降级原则:Redis 不可用时不能把服务搞哑,退回单机内存版并记日志。
#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

struct redisContext;   // hiredis 前置声明,避免头文件污染

namespace secguard {

struct RedisConfig {
    std::string host = "127.0.0.1";
    int         port = 6379;
    std::string password;             // 空表示无密码
    int         db = 0;
    int         pool_size = 4;
    int         timeout_ms = 300;     // 连接与命令超时;限流路径上不能久等
    bool        enabled = true;
};

class RedisClient {
public:
    explicit RedisClient(const RedisConfig& cfg);
    ~RedisClient();

    RedisClient(const RedisClient&) = delete;
    RedisClient& operator=(const RedisClient&) = delete;

    // 执行一条命令(argv[0] 是命令名)。返回原始字符串回复;nil / 错误返回 nullopt
    std::optional<std::string> exec(const std::vector<std::string>& argv);

    // 同上,但把回复当整数解析
    std::optional<std::int64_t> exec_int(const std::vector<std::string>& argv);

    // 运行 Lua 脚本。首次调用会 SCRIPT LOAD,之后用 EVALSHA;
    // 遇到 NOSCRIPT(Redis 重启过)会自动重载一次再试。
    // 返回脚本的整数返回值。
    std::optional<std::int64_t> eval_int(const std::string& script,
                                         const std::vector<std::string>& keys,
                                         const std::vector<std::string>& args);

    [[nodiscard]] bool ping();
    [[nodiscard]] bool available() const { return available_; }
    [[nodiscard]] long long failures() const { return failures_; }
    [[nodiscard]] long long commands() const { return commands_; }

private:
    struct Conn;
    std::unique_ptr<Conn> acquire();
    void release(std::unique_ptr<Conn> c);
    std::unique_ptr<Conn> make_conn();

    RedisConfig cfg_;
    std::mutex mu_;
    std::vector<std::unique_ptr<Conn>> idle_;
    bool available_ = false;
    long long failures_ = 0;
    long long commands_ = 0;
    // 脚本缓存:script -> sha1
    std::vector<std::pair<std::string, std::string>> script_shas_;
};

}  // namespace secguard
