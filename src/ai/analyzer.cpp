#include "ai/analyzer.h"

#include <algorithm>
#include <chrono>
#include <unordered_map>

#include "util/log.h"

namespace secguard {
namespace {

constexpr const char* kTag = "[AI分析] ";

std::int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

}  // namespace

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------
Analyzer::Analyzer(LlmClient* client, Dao* dao, const AiConfig& cfg,
                   Notifier* notifier)
    : client_(client), dao_(dao), notifier_(notifier), cfg_(cfg) {
    if (cfg_.enabled && (!client_ || !client_->available())) {
        LOG_WARN(kTag, "分析层已启用但 LLM 不可用,自动跳过(检查 SECGUARD_LLM_KEY)");
    } else if (cfg_.enabled) {
        LOG_INFO(kTag, "已启用:模型=", client_->model(),
                 " 间隔=", cfg_.interval_seconds, "s",
                 " 批量=", cfg_.batch_size,
                 " 置信度门槛=", cfg_.min_confidence);
    }
}

bool Analyzer::is_analyzable(const std::string& rule_hit) {
    // 这些是"策略性拦截",不是攻击特征命中:已经说明问题了,
    // 再送 LLM 判断一遍纯属浪费钱。
    static const char* kPolicyOnly[] = {
        "RATE_LIMITED", "IP_BANNED", "LOGIN_FAIL",
        "REPLAY_MISSING_HEADERS", "REPLAY_STALE", "REPLAY_DUPLICATE",
    };
    for (const char* p : kPolicyOnly) {
        if (rule_hit == p) return false;
    }
    return !rule_hit.empty();
}

bool Analyzer::take_rate_token() {
    const std::int64_t now = now_ms();
    if (now - minute_start_ms_ >= 60000) {
        minute_start_ms_ = now;
        calls_this_minute_ = 0;
    }
    if (calls_this_minute_ >= cfg_.max_requests_per_minute) {
        ++stats_.rate_limited;
        return false;
    }
    ++calls_this_minute_;
    return true;
}

bool Analyzer::run_once() {
    return do_round(cfg_.batch_size, false);
}

bool Analyzer::run_once_manual() {
    const int batch = std::max(cfg_.batch_size, cfg_.batch_size * 5);
    return do_round(batch, true);
}

bool Analyzer::do_round(int batch, bool manual) {
    if (!cfg_.enabled) return false;
    if (!client_ || !client_->available()) return false;
    if (!dao_) return false;

    const auto t0 = std::chrono::steady_clock::now();
    ++stats_.rounds;

    auto rows = dao_->fetch_unanalyzed(batch, cfg_.lookback_hours);
    if (rows.empty()) {
        LOG_DEBUG(kTag, "没有待分析的记录");
        return false;
    }
    stats_.records_seen += static_cast<long long>(rows.size());

    // 按 IP 分组:alert 表是按 IP 记的,log_ids 存一组 id。
    // 同一个 IP 的多条记录合起来判断,比一条一条问更准也更省钱。
    std::unordered_map<std::string, std::vector<AuditLogRow>> by_ip;
    for (auto& r : rows) {
        if (!is_analyzable(r.rule_hit)) continue;
        by_ip[r.ip].push_back(std::move(r));
    }
    if (by_ip.empty()) {
        LOG_DEBUG(kTag, "本轮记录都属于策略性拦截,无需 LLM 判断");
        return false;
    }

    int groups_done = 0;
    int alerts = 0;
    std::vector<std::int64_t> analyzed_ids;
    bool any_transport_error = false;

    for (auto& [ip, group] : by_ip) {
        if (!manual && groups_done >= cfg_.max_groups_per_round) break;
        if (!take_rate_token()) {
            LOG_WARN(kTag, "本轮达到每分钟调用上限(",
                     cfg_.max_requests_per_minute, "),暂停");
            break;
        }
        ++groups_done;
        ++stats_.groups;

        const std::string sys = build_system_prompt();
        const std::string usr = build_user_prompt(ip, group);

        ++stats_.calls;
        const auto res = client_->chat(sys, usr);

        if (!res.ok) {
            ++stats_.transport_errors;
            any_transport_error = true;
            LOG_WARN(kTag, "调用失败 ip=", ip, " 原因=", res.error);
            // 传输出错**不**标记 analyzed:下一轮再试,别把记录永久丢掉
            continue;
        }
        ++stats_.ok_calls;

        Verdict v;
        std::string perr;
        if (!parse_verdict(res.content, v, perr)) {
            ++stats_.parse_errors;
            LOG_WARN(kTag, "模型返回无法解析 ip=", ip, " 原因=", perr,
                     " 原文前 120 字=", res.content.substr(0, 120));
            // 解析失败也标记,否则这条会永远卡在队列里反复烧钱
            for (const auto& r : group) analyzed_ids.push_back(r.id);
            continue;
        }

        LOG_INFO(kTag, "判定 ip=", ip,
                 " 攻击=", (v.is_attack ? "是" : "否"),
                 " 类型=", v.threat_type,
                 " 级别=", v.severity,
                 " 置信度=", v.confidence,
                 " 耗时=", res.latency_ms, "ms");

        if (v.is_attack && v.confidence >= cfg_.min_confidence) {
            AlertRow a;
            a.ip = ip;
            a.threat_type = v.threat_type;
            a.severity = v.severity;
            a.confidence = v.confidence;
            a.reasoning = v.reasoning;
            a.status = 0;   // 待处理

            // log_ids:逗号分隔,注意列宽是 1024
            std::string ids;
            for (const auto& r : group) {
                const std::string one = std::to_string(r.id);
                if (ids.size() + one.size() + 2 > 1000) break;
                if (!ids.empty()) ids.push_back(',');
                ids += one;
            }
            a.log_ids = ids;

            std::int64_t new_id = 0;
            if (dao_->insert_alert(a, new_id) == WriteResult::kOk) {
                ++stats_.alerts_created;
                ++alerts;
                LOG_INFO(kTag, "已生成告警 id=", new_id, " ip=", ip,
                         " 类型=", a.threat_type, " 置信度=", a.confidence);
                // 推一次通知。失败不影响流程 —— 告警已经落库了,
                // 通知只是"让人尽快知道",不是可靠投递。
                if (notifier_ && notifier_->enabled()) {
                    if (notifier_->notify(a, new_id)) ++stats_.notified;
                    else ++stats_.notify_failed;
                }
            } else {
                LOG_ERROR(kTag, "写告警失败 ip=", ip);
                continue;   // 写失败就不标记,下轮再试
            }
        } else if (!v.is_attack) {
            ++stats_.skipped_not_attack;
        } else {
            ++stats_.skipped_low_confidence;
        }

        for (const auto& r : group) analyzed_ids.push_back(r.id);
    }

    if (!analyzed_ids.empty()) {
        if (!dao_->mark_analyzed(analyzed_ids)) {
            LOG_WARN(kTag, "标记 analyzed 失败,下一轮可能重复分析");
        }
    }

    const auto t1 = std::chrono::steady_clock::now();
    stats_.last_round_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    LOG_INFO(kTag, "本轮完成:", groups_done, " 组 / ", rows.size(),
             " 条记录,新增告警 ", alerts, " 条,耗时 ", stats_.last_round_ms, "ms",
             any_transport_error ? "(有调用失败,相关记录下轮重试)" : "");
    return groups_done > 0;
}

}  // namespace secguard
