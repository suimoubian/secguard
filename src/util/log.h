// 日志:分级、线程安全、输出到 stdout(寓言集第 68 讲)
//
// 三条规矩:
//   1. 调试级要能动态打开,排查时开、查完关
//   2. 错误必须带上下文 —— 判断标准:不看代码能不能知道出了什么事
//   3. 日志里不能有秘密 —— 脱敏做在日志模块里,不在调用处(第 45 讲)
//
// 输出到 stdout 而不是写死文件路径:Docker 里 stdout 才是正道。
#pragma once

#include <sstream>
#include <string>
#include <string_view>

namespace secguard::log {

enum class Level { kDebug = 0, kInfo, kWarn, kError };

void set_level(Level lv);
void set_level_from_string(std::string_view s);
[[nodiscard]] bool enabled(Level lv);
[[nodiscard]] const char* level_name(Level lv);

// 按字段名脱敏:名字里带 password/token/secret 之类的,值一律换成 ***
[[nodiscard]] bool is_sensitive_key(std::string_view key);

// 把 "键=值" 拼成脱敏后的字符串。名字敏感则值打码。
[[nodiscard]] std::string kv(std::string_view key, std::string_view value);

namespace detail {

void write(Level lv, const char* file, int line, const std::string& msg);

// 变参模板:把每个参数依次流入流对象。
// 不用宏里的折叠表达式 —— 宏展开后的 __VA_ARGS__ 不是可命名的参数包,
// `oss << ... << __VA_ARGS__` 编译不过。
template <class... Args>
void emit(Level lv, const char* file, int line, Args&&... args) {
    if (!enabled(lv)) return;              // 先判断级别,避免白拼字符串
    std::ostringstream oss;
    (oss << ... << args);
    write(lv, file, line, oss.str());
}

}  // namespace detail

}  // namespace secguard::log

// 用法:LOG_INFO("载入特征库 ", path, " 共 ", n, " 条");
#define SG_LOG_IMPL(lv, ...)                                                    \
    do {                                                                        \
        ::secguard::log::detail::emit(lv, __FILE__, __LINE__, __VA_ARGS__);     \
    } while (false)

#define LOG_DEBUG(...) SG_LOG_IMPL(::secguard::log::Level::kDebug, __VA_ARGS__)
#define LOG_INFO(...)  SG_LOG_IMPL(::secguard::log::Level::kInfo,  __VA_ARGS__)
#define LOG_WARN(...)  SG_LOG_IMPL(::secguard::log::Level::kWarn,  __VA_ARGS__)
#define LOG_ERROR(...) SG_LOG_IMPL(::secguard::log::Level::kError, __VA_ARGS__)
