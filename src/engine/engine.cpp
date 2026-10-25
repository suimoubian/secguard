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
    snap->extra_normalization = cfg.extra_normalization;
    snap->nopt = NormalizeOptions{};
    snap->nopt.max_decode_rounds = cfg.normalize_decode_rounds;
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

    // 白名单跟着一起发:换表时名单也一起换,不会出现"新规则配旧名单"
    snap->allowlist = allowlist_;

    std::ostringstream info;
    info << "建表完成:规则 " << snap->rules.size()
         << " 条,节点 " << snap->ac.node_count()
         << " 个,白名单 " << snap->allowlist.size()
         << " 条,归一化 " << (snap->extra_normalization
                               ? ("开(最多解 " + std::to_string(snap->nopt.max_decode_rounds) + " 层)")
                               : std::string("关"))
         << ",占用约 " << (snap->ac.memory_bytes() / 1024) << " KB";
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

    // 白名单独立文件。缺失不算错误 —— 大多数部署不需要它。
    std::string aerr;
    if (!load_allowlist(cfg.allowlist_file, aerr)) {
        LOG_WARN(kTag, "白名单未载入: ", aerr);
    }
    return true;
}

// ---------------------------------------------------------------------------
// 白名单
//
// 格式(每行一个,字段用 TAB 分隔):
//   路径前缀 <TAB> 规则ID[,规则ID...]
//   路径前缀 <TAB> *            <- 该路径下全部放行
//
// 例:
//   /api/posts	SQL-003,SQL-004      # 发帖允许出现 select/insert 这类词
//   /docs	*                        # 文档站整体不检测
// ---------------------------------------------------------------------------
bool Engine::load_allowlist(const std::string& path, std::string& err) {
    std::ifstream in(path);
    if (!in) {
        err = "打不开白名单文件(可忽略): " + path;
        allowlist_.clear();          // 没有文件就当空名单
        return false;
    }

    std::vector<AllowEntry> list;
    std::string line;
    int lineno = 0;
    int bad = 0;
    while (std::getline(in, line)) {
        ++lineno;
        const std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;

        const auto parts = split_fields(t);
        if (parts.size() < 2 || parts[0].empty()) { ++bad; continue; }

        AllowEntry e;
        e.path_prefix = parts[0];
        if (parts[1] == "*") {
            e.all = true;
        } else {
            std::string cur;
            for (char c : parts[1]) {
                if (c == ',') { if (!cur.empty()) e.rule_ids.push_back(cur); cur.clear(); }
                else if (c != ' ' && c != '\t') cur.push_back(c);
            }
            if (!cur.empty()) e.rule_ids.push_back(cur);
        }
        list.push_back(std::move(e));
    }

    if (bad > 0) LOG_WARN(kTag, "白名单有 ", bad, " 行格式不对,已跳过");

    allowlist_ = std::move(list);
    allowlist_path_ = path;
    allowlist_mtime_ = file_mtime(path);

    if (!allowlist_.empty()) {
        LOG_INFO(kTag, "载入白名单 ", allowlist_path_, ": ", allowlist_.size(), " 条");
        for (const auto& e : allowlist_) {
            LOG_INFO(kTag, "  放行 ", e.path_prefix, " -> ",
                     e.all ? std::string("全部规则") : std::string("部分规则"));
        }
    }
    return true;
}

bool Engine::is_allowlisted(std::string_view path, const std::string& rule_id) const {
    const auto snap = current();
    if (!snap || snap->allowlist.empty()) return false;

    for (const auto& e : snap->allowlist) {
        // 前缀匹配。注意这是运维声明的信任边界,不是内容匹配 ——
        // 攻击者没法通过构造载荷来触发它。
        if (path.size() < e.path_prefix.size()) continue;
        if (path.compare(0, e.path_prefix.size(), e.path_prefix) != 0) continue;
        if (e.all) return true;
        for (const auto& id : e.rule_ids) {
            if (id == rule_id) return true;
        }
    }
    return false;
}

std::size_t Engine::allowlist_size() const {
    const auto snap = current();
    return snap ? snap->allowlist.size() : 0;
}

void Engine::scan_into(std::string_view text, const Snapshot& snap,
                       std::vector<std::int32_t>& hits, std::size_t& max_len,
                       std::size_t& bytes, bool& truncated) const {
    bytes += text.size();
    snap.ac.search(text, [&](const Hit& h) {
        if (hits.size() >= snap.max_hits) { truncated = true; return; }
        hits.push_back(h.pattern_id);
        const std::size_t len =
            snap.rules[static_cast<std::size_t>(h.pattern_id)].text.size();
        if (len > max_len) max_len = len;
    });
}

MatchResult Engine::search(std::string_view text) const {
    MatchResult out;
    const auto snap = current();
    if (!snap) return out;

    std::vector<std::int32_t> hits;
    hits.reserve(16);
    std::size_t max_len = 0;

    // 第 1 遍:原始文本。行为和加归一化层之前完全一致(只多了一个小写化),
    // 所以这一遍是零回归的保证 —— 已有 228 条规则能命中的,现在照样命中。
    const std::string normalized = normalize(text);
    std::size_t bytes = 0;
    scan_into(normalized, *snap, hits, max_len, bytes, out.truncated);
    out.scanned_bytes = bytes;

    // 第 2 遍:规范形。把 %20 / /**/ / &#x6a; / \x3c 这些"同一个东西的不同写法"
    // 收敛回原文,再匹配一次。
    //
    // 进这一遍之前先做一次带早退的标记扫描:文本里连一个变形标记都没有,
    // 就不必建规范形字符串、也不必再扫一遍自动机。正常请求走的就是这条路。
    if (snap->extra_normalization && may_obfuscate(text)) {
        const std::string canonical = canonicalize(text, snap->nopt);
        if (canonical != normalized) {
            out.canonical_pass = true;
            std::size_t cbytes = 0;
            scan_into(canonical, *snap, hits, max_len, cbytes, out.truncated);
            out.canonical_bytes = cbytes;
            out.scanned_bytes += cbytes;
        }
    }

    // 去重 + 排序:同一个规则在多处命中只报一次(第 15 讲)
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
    const long long pm = file_mtime(path);
    if (pm < 0) return false;

    const bool pattern_changed = (path != loaded_path_ || pm != loaded_mtime_);

    // 白名单也要看。只盯特征库文件的 mtime 是不够的 ——
    // 改白名单时特征库没动,热加载会认为"没变化"从而什么都不做,
    // 运维改了名单却看不到效果(这个坑实测踩到了)。
    const long long am = file_mtime(cfg.allowlist_file);
    const bool allow_changed = (am >= 0 &&
        (cfg.allowlist_file != allowlist_path_ || am != allowlist_mtime_));

    if (!pattern_changed && !allow_changed) return false;

    std::string err;

    if (pattern_changed) {
        LOG_INFO(kTag, "检测到特征库变化,开始热加载:", path);
        if (!load_from_file(path, cfg, err)) {
            LOG_ERROR(kTag, "热加载失败,继续用旧表:", err);
            return false;   // 加载失败就保留旧表,不能把服务搞哑
        }
        new_rule_count = rule_count();
        return true;
    }

    // 只改了白名单:不必重建自动机,把当前规则集和新名单一起发布即可。
    LOG_INFO(kTag, "检测到白名单变化,重新载入:", cfg.allowlist_file);
    std::string aerr;
    if (!load_allowlist(cfg.allowlist_file, aerr)) {
        LOG_ERROR(kTag, "白名单载入失败,继续用旧名单:", aerr);
        return false;
    }
    const auto snap = current();
    if (!snap) return false;
    std::vector<Rule> rules_copy = snap->rules;   // 拷贝一份(要按值传)
    if (!build_from_rules(std::move(rules_copy), cfg, err)) {
        LOG_ERROR(kTag, "白名单热加载后重建失败:", err);
        return false;
    }
    new_rule_count = rule_count();
    return true;
}

}  // namespace secguard
