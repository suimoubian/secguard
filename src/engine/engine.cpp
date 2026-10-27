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
//
// 返回的是**未修剪**的原始字段。为什么要保留原始值:
// 规则文件里写过 `select `(带尾空格,本意是"select 后面跟空格"),加载时
// 一律 trim 就变成了裸词匹配 —— 文件写的和实际跑的完全不是一回事,而且
// 没有任何提示。15 条规则这样沉在库里,直到评测把误报拉出来才被发现。
// 现在把原始值和修剪后的值都留着,由调用方决定是警告还是拒绝。
struct RawFields {
    std::vector<std::string> raw;      // 未修剪
    std::vector<std::string> trimmed;  // 修剪后(实际入库的值)
    bool text_had_space = false;       // 第一个字段修剪前后不一样
};

RawFields split_fields(const std::string& s) {
    RawFields out;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == '\t') {
            const std::string raw = s.substr(start, i - start);
            out.raw.push_back(raw);
            out.trimmed.push_back(trim(raw));
            start = i + 1;
        }
    }
    if (!out.raw.empty() && out.raw.front() != out.trimmed.front()) {
        out.text_had_space = true;
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

    // 处置动作在建表时展开成数组:匹配热路径上只做一次下标访问,
    // 不必每条命中都去查哈希表。策略改动会触发重建表,所以不会过期。
    snap->actions.assign(snap->rules.size(), default_action_);
    std::size_t alert_cnt = 0;
    for (std::size_t i = 0; i < snap->rules.size(); ++i) {
        const auto it = policy_.find(snap->rules[i].id);
        if (it != policy_.end()) snap->actions[i] = it->second;
        if (snap->actions[i] == RuleAction::kAlert) ++alert_cnt;
    }

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
         << " 条,处置 BLOCK " << (snap->rules.size() - alert_cnt) << " / ALERT " << alert_cnt
         << ",归一化 " << (snap->extra_normalization
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
    int space_trimmed = 0;      // 特征文本首尾带空白、被 trim 掉的条数
    int commented_rules = 0;    // 形如 "#  规则ID  类别 ..." 的行:八成是想写规则却写成了注释
    std::string trim_examples;
    std::string commented_examples;

    while (std::getline(in, line)) {
        ++lineno;
        std::string t = trim(line);
        if (t.empty()) continue;

        // 以 # 开头 = 注释。但有一种历史坑必须拦住:
        // 规则文件里的 `#\tSQL-033\tSQL_INJECTION\tMEDIUM` 看起来是规则,
        // 实际被当成注释整行丢弃 —— 这条规则从来没生效过,而且没有任何提示。
        // 判据:去掉 # 之后还带 TAB 分隔的字段,就当成"疑似被注释掉的规则"报警。
        if (t[0] == '#') {
            const std::string tail = trim(t.substr(1));
            if (tail.find('\t') != std::string::npos) {
                ++commented_rules;
                if (commented_examples.size() < 160) {
                    commented_examples += (commented_examples.empty() ? "" : "; ");
                    commented_examples += tail;
                }
            }
            continue;
        }

        // 转义:行首 `\#` 表示特征文本本身以 # 开头(否则永远没法表达)
        if (t.size() >= 2 && t[0] == '\\' && t[1] == '#') {
            t = t.substr(1);
        }

        const auto parts = split_fields(t);
        if (parts.trimmed.empty() || parts.trimmed[0].empty()) { ++skipped; continue; }

        if (parts.text_had_space) {
            ++space_trimmed;
            if (trim_examples.size() < 160) {
                trim_examples += (trim_examples.empty() ? "" : "; ");
                trim_examples += parts.trimmed[0];
            }
        }

        Rule r;
        r.text = parts.trimmed[0];
        if (parts.trimmed.size() >= 2 && !parts.trimmed[1].empty()) r.id = parts.trimmed[1];
        else r.id = "R" + std::to_string(lineno);
        r.category = (parts.trimmed.size() >= 3 && !parts.trimmed[2].empty())
                   ? parts.trimmed[2] : "UNKNOWN";
        r.severity = (parts.trimmed.size() >= 4 && !parts.trimmed[3].empty())
                   ? parts.trimmed[3] : "MEDIUM";
        rules.push_back(std::move(r));
    }

    if (rules.empty()) {
        err = "特征库为空(或格式不对): " + path;
        return false;
    }
    if (skipped > 0) LOG_WARN(kTag, "特征库有 ", skipped, " 行格式不对,已跳过");

    // 这两类问题以前是"静默生效"的:文件写的和跑的完全不是一回事,
    // 只能等评测把误报拉出来才发现。现在改成载入时就喊出来。
    if (space_trimmed > 0) {
        LOG_WARN(kTag, "有 ", space_trimmed, " 条特征的首尾空白被 trim 掉了"
                 "(文件里的 `select ` 实际是 `select`),例如: ", trim_examples,
                 "。如果本意是词边界,请改用归一化 + 策略,别靠空格表达");
    }
    if (commented_rules > 0) {
        LOG_WARN(kTag, "有 ", commented_rules, " 行以 # 开头但带 TAB 分隔,像是被注释掉的规则,"
                 "已按注释跳过: ", commented_examples);
    }

    // 策略要在建表之前载入:建表时会把动作展开成与规则一一对应的数组。
    // 载入失败不算错误 —— 缺失等于"全部 BLOCK",行为退回加策略层之前。
    {
        std::string perr;
        if (!load_policy(cfg.policy_file, perr)) LOG_WARN(kTag, "策略未载入: ", perr);
    }

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

        const auto parts = split_fields(t).trimmed;
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

// ---------------------------------------------------------------------------
// 处置策略:规则 ID -> BLOCK / ALERT
//
// 格式(每行两个字段,空格或 TAB 都行):
//   default BLOCK        # 全库默认动作(不写也是 BLOCK,即 fail-closed)
//   SQL-003 ALERT        # 按规则 ID 覆盖
//
// 为什么单独一个文件而不是写进规则行:
//   规则库是"检测能力",策略是"运维决定"。混在一起,想调一次阈值就得碰
//   检测库,手一滑就改坏了特征。分开之后,同一套规则可以在不同环境配不同
//   策略(演示环境全拦、生产环境只报警),而且策略改动可以单独热加载。
//
// 文件缺失时按"全部 BLOCK"处理 —— 也就是行为退回加策略层之前,
// 这是一个安全的默认值:配置丢了只会更严,不会更松。
// ---------------------------------------------------------------------------
bool Engine::load_policy(const std::string& path, std::string& err) {
    std::ifstream in(path);
    if (!in) {
        policy_.clear();
        default_action_ = RuleAction::kBlock;
        policy_path_ = path;
        policy_mtime_ = -1;
        err = "打不开策略文件(可忽略,按全部 BLOCK 处理): " + path;
        return false;
    }

    std::unordered_map<std::string, RuleAction> table;
    RuleAction def = RuleAction::kBlock;
    std::string line;
    int lineno = 0;
    int bad = 0;
    while (std::getline(in, line)) {
        ++lineno;
        const std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;

        std::istringstream iss(t);
        std::string key, act_str, extra;
        iss >> key >> act_str;
        if (key.empty() || act_str.empty() || (iss >> extra)) { ++bad; continue; }

        const std::string act = normalize(act_str);
        RuleAction a;
        if (act == "block")      a = RuleAction::kBlock;
        else if (act == "alert") a = RuleAction::kAlert;
        else { ++bad; continue; }

        if (normalize(key) == "default") def = a;
        else table[key] = a;      // 规则 ID 保持原样(大小写敏感)
    }

    if (bad > 0) LOG_WARN(kTag, "策略文件有 ", bad, " 行格式不对,已跳过");

    policy_ = std::move(table);
    default_action_ = def;
    policy_path_ = path;
    policy_mtime_ = file_mtime(path);

    std::size_t alerts = 0;
    for (const auto& kv : policy_) {
        if (kv.second == RuleAction::kAlert) ++alerts;
    }
    LOG_INFO(kTag, "载入处置策略 ", path, ": 覆盖 ", policy_.size(),
             " 条(其中 ALERT ", alerts, " 条),默认 ",
             def == RuleAction::kBlock ? "BLOCK" : "ALERT");
    return true;
}

RuleAction Engine::rule_action(std::int32_t idx) const {
    const auto snap = current();
    // 越界/无表时返回 BLOCK:失败方向必须更严,不能更松
    if (!snap || idx < 0 || static_cast<std::size_t>(idx) >= snap->actions.size()) {
        return RuleAction::kBlock;
    }
    return snap->actions[static_cast<std::size_t>(idx)];
}

std::size_t Engine::alert_rule_count() const {
    const auto snap = current();
    if (!snap) return 0;
    std::size_t n = 0;
    for (const auto a : snap->actions) {
        if (a == RuleAction::kAlert) ++n;
    }
    return n;
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

    // 策略文件也要看。理由和白名单一样:只盯特征库的 mtime,
    // 运维改了策略却看不到效果。
    const long long pm2 = file_mtime(cfg.policy_file);
    const bool policy_changed = (pm2 >= 0 &&
        (cfg.policy_file != policy_path_ || pm2 != policy_mtime_));

    if (!pattern_changed && !allow_changed && !policy_changed) return false;

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

    // 只改了策略:动作存在 Snapshot 里,所以必须重建一次表才能生效。
    // 自动机本身不用重建,但为了"换表"语义统一(旧表由最后一个引用者释放),
    // 这里走同一个 build_from_rules,代价是重建一棵 234 条规则的树,几十毫秒。
    if (policy_changed) {
        LOG_INFO(kTag, "检测到策略变化,重新载入:", cfg.policy_file);
        std::string perr;
        if (!load_policy(cfg.policy_file, perr)) {
            LOG_ERROR(kTag, "策略载入失败,继续用旧策略:", perr);
            return false;
        }
        const auto snap = current();
        if (!snap) return false;
        std::vector<Rule> rules_copy = snap->rules;
        if (!build_from_rules(std::move(rules_copy), cfg, err)) {
            LOG_ERROR(kTag, "策略热加载后重建失败:", err);
            return false;
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
