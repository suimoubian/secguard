// prompt 构造与输出校验(寓言集第 60、62 讲)
//
// 这两件事都是从 Analyzer 里拆出来的,因为它们**不依赖数据库**,
// 只跟字符串和 JSON 打交道。拆开的直接好处:单元测试能直接测它们,
// 不用为了测一句 prompt 就去连 MySQL 和 Redis。
//
// 这里是 W6 最关键的安全点。送进 LLM 的数据全部来自攻击者,
// 而 LLM 分不清"数据"和"指令" —— 除非你替它分清。
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "db/dao.h"

namespace secguard {

// 模型给出的判定
struct Verdict {
    bool        is_attack = false;
    std::string threat_type;
    std::string severity;          // LOW/MEDIUM/HIGH/CRITICAL
    double      confidence = 0.0;  // 0.0 ~ 1.0
    std::string reasoning;
};

// 解析并严格校验模型返回的内容。
// 校验不通过返回 false —— 宁可丢掉一个结果,也不能把脏数据写进告警表。
[[nodiscard]] bool parse_verdict(const std::string& content, Verdict& out,
                                 std::string& err);

[[nodiscard]] std::string build_system_prompt();

// rows 里的内容全部视为不可信数据
[[nodiscard]] std::string build_user_prompt(const std::string& ip,
                                            const std::vector<AuditLogRow>& rows);

// 把不可信文本清洗成可以安全放进定界块的形态:
// 剔掉定界符、控制字符,并截断长度
[[nodiscard]] std::string sanitize_untrusted(const std::string& s, std::size_t max_len);

// 把字符串收敛成安全标识符(只留字母数字下划线,转大写)
[[nodiscard]] std::string normalize_ident(const std::string& s, std::size_t max_len);

[[nodiscard]] bool valid_severity(const std::string& s);

}  // namespace secguard
