#include "ai/analyzer.h"

#include <algorithm>
#include <chrono>
#include <map>
#include <set>
#include <unordered_map>

#include "util/log.h"
#include "util/utf8.h"

namespace secguard {
namespace {

constexpr const char* kTag = "[AI分析] ";

std::int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// ---------------------------------------------------------------------------
// 威胁类型的规范化(只用于聚合分组,不改写告警里的原文)
//
// 为什么要这一步:实测同一个"敏感文件探测"行为,模型这轮说
// SENSITIVE_FILE_PROBE,下轮说 SENSITIVE_FILE_PROBING,另一台 IP 又是
// SENSITIVE_FILE_SCANNING。按字符串精确分组的话,这些全被当成不同类,
// 聚合永远不触发 —— 第一次实现就踩了这个坑。
//
// 规则:按 '_' 分词后取前两段。
//   SENSITIVE_FILE_PROBE / _PROBING / _SCANNING / _ACCESS -> SENSITIVE_FILE
//   SQL_INJECTION                                        -> SQL_INJECTION
//   XSS                                                  -> XSS
//   MULTI_VECTOR_SCAN                                    -> MULTI_VECTOR
// ---------------------------------------------------------------------------
std::string canonical_threat(const std::string& t) {
    std::string out;
    int parts = 0;
    std::string cur;
    for (char c : t) {
        if (c == '_') {
            if (!cur.empty()) {
                if (parts) out.push_back('_');
                out += cur;
                ++parts;
                cur.clear();
                if (parts >= 2) return out;
            }
        } else {
            cur.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        }
    }
    if (!cur.empty()) {
        if (parts) {
            if (parts < 2) { out.push_back('_'); out += cur; }
        } else {
            out += cur;
        }
    }
    return out.empty() ? t : out;
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

    // -----------------------------------------------------------------------
    // 先攒着,不立刻写库。
    //
    // 为什么要攒:实测一天下来 204 条告警里 191 条(93.6%)是
    // SENSITIVE_FILE_PROBE,来自 200 个不同 IP、每个只打十几下 ——
    // 典型的分布式凭据扫描。逐条写的结果是真正的 6 条 SQL 注入被淹没。
    //
    // 所以本轮先把候选告警收集起来,循环结束后按威胁类型聚合:
    // 同类型来自 >= merge_threshold_ips 个不同 IP 时,合成一条"分布式"告警。
    // -----------------------------------------------------------------------
    struct Pending {
        AlertRow row;
        std::string ip;
    };
    std::vector<Pending> pending;

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
                     " 原文前 120 字=", utf8::truncate(res.content, 120));
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

            // 先攒着,循环结束后统一决定"逐条写"还是"聚合成一条"
            pending.push_back(Pending{std::move(a), ip});
        } else if (!v.is_attack) {
            ++stats_.skipped_not_attack;
        } else {
            ++stats_.skipped_low_confidence;
        }

        for (const auto& r : group) analyzed_ids.push_back(r.id);
    }

    // -----------------------------------------------------------------------
    // 告警聚合:把"很多 IP 做同一件事"合成一条
    //
    // 判据:同一 threat_type 来自 >= merge_threshold_ips 个不同 IP。
    // 分布式扫描的特征就是"每个 IP 都只打几下",按 IP 分组后全是碎片,
    // 逐条发告警会把真正的高危事件淹没。
    // -----------------------------------------------------------------------
    {
        // 分组用规范化后的类型:模型对同一行为会给出 PROBE / PROBING / SCANNING,
        // 按原文精确分组会让聚合永远不触发(第一次实现就是这个坑)。
        std::map<std::string, std::vector<std::size_t>> by_type;
        for (std::size_t i = 0; i < pending.size(); ++i) {
            by_type[canonical_threat(pending[i].row.threat_type)].push_back(i);
        }

        for (auto& [type, idxs] : by_type) {
            std::set<std::string> ips;
            for (auto i : idxs) ips.insert(pending[i].ip);

            const bool merge = cfg_.merge_threshold_ips > 1 &&
                               static_cast<int>(ips.size()) >= cfg_.merge_threshold_ips;

            if (!merge) {
                for (auto i : idxs) {
                    std::int64_t new_id = 0;
                    const AlertRow& row = pending[i].row;
                    if (dao_->insert_alert(row, new_id) == WriteResult::kOk) {
                        ++stats_.alerts_created;
                        ++alerts;
                        LOG_INFO(kTag, "已生成告警 id=", new_id, " ip=", pending[i].ip,
                                 " 类型=", row.threat_type, " 置信度=", row.confidence);
                        if (notifier_ && notifier_->enabled()) {
                            if (notifier_->notify(row, new_id)) ++stats_.notified;
                            else ++stats_.notify_failed;
                        }
                    } else {
                        LOG_ERROR(kTag, "写告警失败 ip=", pending[i].ip);
                    }
                }
                continue;
            }

            // ---- 聚合成一条 ----
            AlertRow agg;
            agg.ip = "multi(" + std::to_string(ips.size()) + ")";
            // 类型用出现最多的那个原始写法(不是规范化后的键),
            // 否则告警里会出现 "SENSITIVE_FILE" 这种被截断的名字。
            {
                std::map<std::string, int> freq;
                for (auto i : idxs) ++freq[pending[i].row.threat_type];
                std::string best_type;
                int best_n = -1;
                for (const auto& [t, n] : freq) {
                    if (n > best_n) { best_n = n; best_type = t; }
                }
                agg.threat_type = best_type;
            }
            agg.severity = "MEDIUM";
            agg.confidence = 0.0;
            agg.status = 0;

            // 级别取最高、置信度取最高;理由以置信度最高的那条为主
            int best = idxs[0];
            for (auto i : idxs) {
                if (severity_rank(pending[i].row.severity) > severity_rank(agg.severity)) {
                    agg.severity = pending[i].row.severity;
                }
                if (pending[i].row.confidence > agg.confidence) {
                    agg.confidence = pending[i].row.confidence;
                    best = static_cast<int>(i);
                }
            }

            // 来源 IP 列表(最多列 8 个)
            std::string ip_list;
            int shown = 0;
            for (const auto& one : ips) {
                if (shown++ >= 8) { ip_list += "..."; break; }
                if (!ip_list.empty()) ip_list += ", ";
                ip_list += one;
            }

            std::string rep = pending[best].row.reasoning;
            // 必须按 UTF-8 边界截断:中文一个字符占 3 字节,substr 会切断字符,
            // 产生非法 UTF-8,MySQL 直接拒收(code=1366)。实测踩过这个坑。
            rep = utf8::truncate_with_ellipsis(rep, 200);

            agg.reasoning = "本轮有 " + std::to_string(ips.size()) +
                            " 个不同来源 IP 命中同类规则(" + type +
                            "),判定为**分布式扫描**而非单点攻击。来源: " + ip_list +
                            "。代表判定(来自 " + pending[best].ip + "):" + rep;

            // 合并 log_ids(注意列宽 1024)
            std::string ids;
            for (auto i : idxs) {
                const std::string& one = pending[i].row.log_ids;
                if (one.empty()) continue;
                if (ids.size() + one.size() + 2 > 1000) break;
                if (!ids.empty()) ids.push_back(',');
                ids += one;
            }
            agg.log_ids = ids;

            std::int64_t new_id = 0;
            if (dao_->insert_alert(agg, new_id) == WriteResult::kOk) {
                ++stats_.alerts_created;
                ++alerts;
                ++stats_.alerts_merged;
                LOG_INFO(kTag, "已聚合告警 id=", new_id, " 类型=", type,
                         " 合并 ", ips.size(), " 个 IP / ", idxs.size(), " 条个体告警");
                if (notifier_ && notifier_->enabled()) {
                    if (notifier_->notify(agg, new_id)) ++stats_.notified;
                    else ++stats_.notify_failed;
                }
            } else {
                LOG_ERROR(kTag, "写聚合告警失败 类型=", type);
            }
        }
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
