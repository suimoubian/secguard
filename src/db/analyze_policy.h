// 一条审计记录是否需要送 LLM 分析
//
// 这个判断原来散在两个地方、而且**两处不一致**:
//
//   1. Dao::fetch_unanalyzed 的 SQL:
//        WHERE analyzed=0 AND action='BLOCK' AND rule_hit NOT IN (策略性拦截)
//      —— 只取 BLOCK。
//
//   2. Analyzer::is_analyzable(rule_hit):
//      —— 只看 rule_hit,不管 action。
//
// 结果:2026-11-04 审查时发现 **ALERT 级记录一条都没被分析过**
// (187 条 ALERT,analyzed=1 的是 0)。而文档里写的是"ALERT 仍然记录、
// 仍然进 AI 分析" —— 这个功能从上线起就没生效。
//
// 影响很实在:为了"让宽规则也能被看见"而加的 PAT-037(phpmyadmin)、
// PAT-036/039(phpinfo)、PAT-038(claude.md) 全都是 ALERT 级,
// 命中了几百次,一次 AI 判断都没触发,也就一条告警都没产生。
//
// 所以把判断收敛到这里,SQL 和代码都引用同一套规则。
#pragma once

#include <string>

namespace secguard {

// 策略性拦截:不是攻击特征命中,已经说明问题了,不必再让 LLM 判断一遍。
inline bool is_policy_hit(const std::string& rule_hit) {
    static const char* kPolicyOnly[] = {
        "RATE_LIMITED", "IP_BANNED", "LOGIN_FAIL",
        "REPLAY_MISSING_HEADERS", "REPLAY_STALE", "REPLAY_DUPLICATE",
    };
    for (const char* p : kPolicyOnly) {
        if (rule_hit == p) return true;
    }
    return false;
}

// 需要分析 = 被拦或被降级留痕(有命中规则),且不是策略性拦截。
// 注意 action 允许 ALERT —— 这正是原来漏掉的那一半。
inline bool needs_llm_analysis(const std::string& action, const std::string& rule_hit) {
    if (action != "BLOCK" && action != "ALERT") return false;
    if (rule_hit.empty()) return false;
    return !is_policy_hit(rule_hit);
}

}  // namespace secguard
