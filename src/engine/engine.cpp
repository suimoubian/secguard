#include "engine.h"

#include <sys/stat.h>

#include <algorithm>
#include <fstream>
#include <sstream>

#include "util/log.h"

namespace secguard {
namespace {

constexpr const char* kTag = "[引擎] ";

// 按规则文本归一化:统一转小写(可按规则配置,这里先统一开)
// 归一化只做一次,放在进引擎之前(第 16 讲)
std::string normalize(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (c >= 'A' && c <= 'Z') out.push_back(static_cast<char>(c - 'A' + 'a'));
        else out.push_back(static_cast<char>(c));
    }
    return out;
}

// 去掉行首尾空白
std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// 按 TAB 切分。用 TAB 而不是竖线:特征文本里本身会出现 | ` $ 这些字符,
// 竖线做分隔符会产生歧义(踩过这个坑)。
std::vector<std::string> split_fields(const std::string& s) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == '\t') {
            out.push_back(trim(s.substr(start, i - start)));
            start = i + 1;
        }
    }
    return out;
}

long long file_mtime(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return -1;
    return static_cast<long long>(st.st_mtime);
}

}  // namespace

bool Engine::build_from_rules(std::vector<Rule> rules, const EngineConfig& cfg,
                              std::string& err) {
    auto snap = std::make_shared<Snapshot>();
    snap->max_hits = cfg.max_hits;
    snap->rules = std::move(rules);

    // 建表前预估节点数,预留避免扩容搬迁(第 22 讲)
    std::size_t total_len = 0;
    for (const auto& r : snap->rules) total_len += r.text.size();
    snap->ac.reserve(total_len + 16);
    snap->ac.set_max_pattern_len(cfg.max_pattern_len);

    // 内存预算检查:每节点一块 256 项转移表(第 26 讲)
    constexpr std::size_t kBytesPerNode = sizeof(AhoCorasick::Node);
    const std::size_t estimated = (total_len + 8) * kBytesPerNode;
    constexpr std::size_t kBudget = 256ull * 1024 * 1024;   // 256MB 上限
    if (estimated > kBudget) {
        std::ostringstream oss;
        oss << "特征库过大:预估需要 " << (estimated / 1024 / 1024)
            << " MB,超过上限 " << (kBudget / 1024 / 1024) << " MB";
        err = oss.str();
        return false;
    }

    for (const auto& r : snap->rules) {
        const std::string norm = normalize(r.text);
        const auto id = snap->ac.insert(norm);
        if (id < 0) {
            LOG_WARN(kTag, "跳过一条无效特征(空或超长):", r.id);
        }
    }
    snap->ac.build();

    std::ostringstream info;
    info << "建表完成:规则 " << snap->rules.size()
         << " 条,节点 " << snap->ac.node_count()
         << " 个,占用约 " << (snap->ac.memory_bytes() / 1024) << " KB";
    LOG_INFO(kTag, info.str());

    // 换成只读视图再发布:shared_ptr<Snapshot> -> shared_ptr<const Snapshot>
    // 一次性替换指针,正在跑的匹配继续用旧表,新来的用新表(第 14 讲)
    std::shared_ptr<const Snapshot> frozen = std::move(snap);
    std::atomic_store_explicit(&snapshot_, std::move(frozen), std::memory_order_release);
    generation_.fetch_add(1);
    return true;
}

bool Engine::load_from_file(const std::string& path, const EngineConfig& cfg,
                            std::string& err) {
    std::ifstream in(path);
    if (!in) {
        err = "打不开特征库文件: " + path;
        return false;
    }

    std::vector<Rule> rules;
    std::string line;
    int lineno = 0;
    int skipped = 0;
    while (std::getline(in, line)) {
        ++lineno;
        const std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;

        const auto parts = split_fields(t);
        if (parts.empty() || parts[0].empty()) { ++skipped; continue; }

        Rule r;
        r.text = parts[0];
        if (parts.size() >= 2 && !parts[1].empty()) r.id = parts[1];
        else r.id = "R" + std::to_string(lineno);
        r.category = (parts.size() >= 3 && !parts[2].empty()) ? parts[2] : "UNKNOWN";
        r.severity = (parts.size() >= 4 && !parts[3].empty()) ? parts[3] : "MEDIUM";
        rules.push_back(std::move(r));
    }

    if (rules.empty()) {
        err = "特征库为空(或格式不对): " + path;
        return false;
    }
    if (skipped > 0) LOG_WARN(kTag, "特征库有 ", skipped, " 行格式不对,已跳过");

    if (!build_from_rules(std::move(rules), cfg, err)) return false;

    loaded_path_ = path;
    loaded_mtime_ = file_mtime(path);
    LOG_INFO(kTag, "载入特征库 ", path, "(mtime=", loaded_mtime_, ")");
    return true;
}

MatchResult Engine::search(std::string_view text) const {
    MatchResult out;
    const auto snap = current();
    if (!snap) return out;

    // 归一化:只做一次(第 16 讲)
    const std::string normalized = normalize(text);
    out.scanned_bytes = normalized.size();

    std::vector<std::int32_t> hits;
    hits.reserve(16);
    std::size_t max_len = 0;

    snap->ac.search(normalized, [&](const Hit& h) {
        if (hits.size() >= snap->max_hits) { out.truncated = true; return; }
        hits.push_back(h.pattern_id);
        const std::size_t len = snap->rules[static_cast<std::size_t>(h.pattern_id)].text.size();
        if (len > max_len) max_len = len;
    });

    // 去重 + 排序:同一个规则在文本里命中多次只报一次(第 15 讲)
    std::sort(hits.begin(), hits.end());
    hits.erase(std::unique(hits.begin(), hits.end()), hits.end());

    out.rule_indices = std::move(hits);
    out.max_matched_len = max_len;
    return out;
}

std::size_t Engine::rule_count() const {
    const auto snap = current();
    return snap ? snap->rules.size() : 0;
}

std::size_t Engine::node_count() const {
    const auto snap = current();
    return snap ? snap->ac.node_count() : 0;
}

std::size_t Engine::memory_bytes() const {
    const auto snap = current();
    return snap ? snap->ac.memory_bytes() : 0;
}

const Rule& Engine::rule(std::int32_t idx) const {
    static const Rule kEmpty{};
    const auto snap = current();
    if (!snap || idx < 0 || static_cast<std::size_t>(idx) >= snap->rules.size()) {
        return kEmpty;
    }
    return snap->rules[static_cast<std::size_t>(idx)];
}

bool Engine::reload_if_changed(const std::string& path, const EngineConfig& cfg,
                               std::size_t& new_rule_count) {
    const long long mtime = file_mtime(path);
    if (mtime < 0) return false;
    if (path == loaded_path_ && mtime == loaded_mtime_) return false;   // 没变,不动

    LOG_INFO(kTag, "检测到特征库变化,开始热加载:", path);
    std::string err;
    if (!load_from_file(path, cfg, err)) {
        LOG_ERROR(kTag, "热加载失败,继续用旧表:", err);
        return false;   // 加载失败就保留旧表,不能把服务搞哑
    }
    new_rule_count = rule_count();
    return true;
}

}  // namespace secguard
