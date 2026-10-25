// 引擎包装层:特征库的加载、热更新与匹配入口(寓言集第 14、17 讲)
//
// 热加载的做法(第 14 讲):
//   1. 新建一张完整的表,而不是原地改旧表
//   2. 建好之后一次性换指针
//   3. 旧表由最后一个用完的线程释放(shared_ptr 引用计数)
// 这样正在跑的匹配继续跑完旧的,新来的用新的,谁也不等谁。
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "aho_corasick.h"
#include "engine/normalize.h"
#include "util/config.h"

namespace secguard {

// 一条特征
struct Rule {
    std::string  text;          // 特征串
    std::string  id;            // 规则 ID,落 audit_log.rule_hit
    std::string  category;      // SQL_INJECTION / XSS / CMD_INJECTION / PATH_TRAVERSAL
    std::string  severity;      // LOW / MEDIUM / HIGH / CRITICAL
};

// 规则命中之后的处置动作。
//
// 为什么要把"检出"和"处置"分成两层:
//   规则库回答"这条流量像不像攻击",策略回答"像到什么程度才值得拦"。
//   混在一起写,想降误报就只能删规则 —— 删了这条线索也就没了。
//   分开之后,过宽的规则可以降成 ALERT:仍然记录、仍然能查、仍然参与
//   AI 分析,只是不返回 403。这是可以量化取舍的,不是拍脑袋。
//
// 实测依据:评测语料里 9 条误报有 8 条来自 SQL-003(select)、SQL-058(0x)、
// PAT-034(/home/) 这类"单字面量"规则,把它们降级比删掉安全得多。
enum class RuleAction : std::uint8_t {
    kBlock,   // 拦下(403)
    kAlert,   // 放行 + 记一条 action=ALERT 的审计
};

// 一次匹配的结果
struct MatchResult {
    std::vector<std::int32_t> rule_indices;   // 命中的规则下标(去重、有序)
    std::size_t max_matched_len = 0;          // 最长命中长度,落 audit_log.matched_len
    std::size_t scanned_bytes = 0;            // 两遍加起来实际扫过的字节数
    bool truncated = false;                   // 命中数超上限被截断(第 25 讲)

    // 以下两项用于观测"归一化遍到底有没有生效",不影响判定结果
    bool        canonical_pass = false;       // 第二遍是否真的跑了(规范形与原文不同)
    std::size_t canonical_bytes = 0;          // 第二遍扫了多少字节
};

// 一整套规则 + 建好的表。只读,换表时整体替换。
// 白名单:某个路径下,某些规则即使命中也不拦。
//
// 为什么需要:规则是"字符串命中即拦",而正常业务里确实会出现这些字。
// 比如一个技术博客站,文章内容里写 "select * from user" 是正常的,
// 但会被 SQL 规则拦掉 —— 站长会觉得"上了个 WAF,我自己啥都发不出去"。
//
// 为什么按 (路径, 规则) 而不是按"内容特征"放行:
//   按内容放行等于给攻击者一个可以伪造的通行证 —— 只要在自己的攻击
//   载荷里加上那个特征字符串,就绕过了。按路径放行则是运维显式声明的
//   信任边界,攻击者伪造不了。
//
// 代价必须说清楚:某个路径一旦排除了某条规则,那条路径上就真的不再
// 用这条规则拦人了。所以这份文件必须小、必须有人审。
struct AllowEntry {
    std::string              path_prefix;   // 只对以此开头的路径生效
    std::vector<std::string> rule_ids;      // 要排除的规则 ID
    bool                     all = false;   // true = 该路径下所有规则都放行
};

class Engine {
public:
    Engine() = default;

    // 从文件载入并建表。失败返回 false 并给出原因。
    // 支持的行格式:每行 "特征文本 <TAB> 规则ID <TAB> 类别 <TAB> 级别"
    // 以 # 开头的行是注释;空行跳过。
    bool load_from_file(const std::string& path, const EngineConfig& cfg, std::string& err);

    // 直接从内存里的规则集建表(测试用)
    bool build_from_rules(std::vector<Rule> rules, const EngineConfig& cfg, std::string& err);

    // 载入白名单(独立文件,缺失时视为空名单)
    bool load_allowlist(const std::string& path, std::string& err);

    // 载入处置策略(独立文件,缺失时视为"全部 BLOCK")。
    //
    // 格式:
    //   default BLOCK|ALERT        全库默认动作
    //   SQL-003 ALERT              按规则 ID 覆盖
    // 以 # 开头的行是注释。未知规则 ID 只会打日志,不影响启动 ——
    // 规则删了但策略里还留着,不该让服务起不来。
    bool load_policy(const std::string& path, std::string& err);

    // 这条规则的处置动作(按下标)
    [[nodiscard]] RuleAction rule_action(std::int32_t idx) const;

    // 被降级成 ALERT 的规则条数(启动日志和 /health 里能看到)
    [[nodiscard]] std::size_t alert_rule_count() const;

    // 这个路径下,这条规则是否被放行
    [[nodiscard]] bool is_allowlisted(std::string_view path,
                                      const std::string& rule_id) const;

    [[nodiscard]] std::size_t allowlist_size() const;

    // 匹配一段文本。返回命中的规则下标。
    //
    // 两遍取并集(项目 A):
    //   第 1 遍:原样文本(只小写),行为和加归一化层之前**完全一致**;
    //   第 2 遍:canonicalize() 还原编码/剥离注释/压缩空白后再匹配一次。
    // 关闭 engine.extra_normalization 就只剩第 1 遍,用于消融实验。
    [[nodiscard]] MatchResult search(std::string_view text) const;

    [[nodiscard]] std::size_t rule_count() const;
    [[nodiscard]] std::size_t node_count() const;
    [[nodiscard]] std::size_t memory_bytes() const;
    [[nodiscard]] const Rule& rule(std::int32_t idx) const;

    // 热加载:重新读文件,成功则换表。返回是否真的换了。
    bool reload_if_changed(const std::string& path, const EngineConfig& cfg,
                           std::size_t& new_rule_count);

    [[nodiscard]] std::uint64_t generation() const { return generation_.load(); }

private:
    struct Snapshot {
        AhoCorasick ac;
        std::vector<Rule> rules;
        std::vector<RuleAction> actions;   // 与 rules 一一对应的处置动作
        std::size_t max_hits = 512;
        std::vector<AllowEntry> allowlist;
        bool             extra_normalization = true;   // 是否跑第 2 遍
        NormalizeOptions nopt;
    };

    // 对一段文本跑一遍自动机,把结果并进 hits(两遍共用同一份上限与去重口径)
    void scan_into(std::string_view text, const Snapshot& snap,
                   std::vector<std::int32_t>& hits, std::size_t& max_len,
                   std::size_t& bytes, bool& truncated) const;

    [[nodiscard]] std::shared_ptr<const Snapshot> current() const {
        return std::atomic_load_explicit(&snapshot_, std::memory_order_acquire);
    }

    std::shared_ptr<const Snapshot> snapshot_;
    std::atomic<std::uint64_t> generation_{0};
    std::string loaded_path_;
    long long loaded_mtime_ = 0;   // 文件修改时间,用来判断要不要重载
    std::vector<AllowEntry> allowlist_;   // 白名单单独存,重建表时带上
    std::string allowlist_path_;
    long long allowlist_mtime_ = 0;

    // 处置策略:规则 ID -> 动作。建表时展开成 Snapshot::actions,
    // 这样匹配热路径上不用再查哈希表。
    std::unordered_map<std::string, RuleAction> policy_;
    RuleAction  default_action_ = RuleAction::kBlock;
    std::string policy_path_;
    long long   policy_mtime_ = -1;
};

}  // namespace secguard
