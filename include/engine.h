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
#include <vector>

#include "aho_corasick.h"
#include "util/config.h"

namespace secguard {

// 一条特征
struct Rule {
    std::string  text;          // 特征串
    std::string  id;            // 规则 ID,落 audit_log.rule_hit
    std::string  category;      // SQL_INJECTION / XSS / CMD_INJECTION / PATH_TRAVERSAL
    std::string  severity;      // LOW / MEDIUM / HIGH / CRITICAL
};

// 一次匹配的结果
struct MatchResult {
    std::vector<std::int32_t> rule_indices;   // 命中的规则下标(去重、有序)
    std::size_t max_matched_len = 0;          // 最长命中长度,落 audit_log.matched_len
    std::size_t scanned_bytes = 0;
    bool truncated = false;                   // 命中数超上限被截断(第 25 讲)
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

    // 这个路径下,这条规则是否被放行
    [[nodiscard]] bool is_allowlisted(std::string_view path,
                                      const std::string& rule_id) const;

    [[nodiscard]] std::size_t allowlist_size() const;

    // 匹配一段文本。返回命中的规则下标。
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
        std::size_t max_hits = 512;
        std::vector<AllowEntry> allowlist;
    };

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
};

}  // namespace secguard
