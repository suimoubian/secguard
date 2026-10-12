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
class Engine {
public:
    Engine() = default;

    // 从文件载入并建表。失败返回 false 并给出原因。
    // 支持的行格式:每行 "特征文本" 或 "特征文本 | 规则ID | 类别 | 级别"
    // 以 # 开头的行是注释;空行跳过。
    bool load_from_file(const std::string& path, const EngineConfig& cfg, std::string& err);

    // 直接从内存里的规则集建表(测试用)
    bool build_from_rules(std::vector<Rule> rules, const EngineConfig& cfg, std::string& err);

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
    };

    [[nodiscard]] std::shared_ptr<const Snapshot> current() const {
        return std::atomic_load_explicit(&snapshot_, std::memory_order_acquire);
    }

    std::shared_ptr<const Snapshot> snapshot_;
    std::atomic<std::uint64_t> generation_{0};
    std::string loaded_path_;
    long long loaded_mtime_ = 0;   // 文件修改时间,用来判断要不要重载
};

}  // namespace secguard
