// waf_eval —— WAF 检出能力评测器(项目 A)
//
// ---------------------------------------------------------------------------
// 它解决什么问题
// ---------------------------------------------------------------------------
// "我的 WAF 能拦住 SQL 注入" 这句话没法验证,也没法比较。
// 能验证的说法是:
//
//   在 N 个标注样本上,引擎检出 X%;把攻击写法做 k 种变形之后,
//   检出掉到 Y%;加上归一化层之后回到 Z%;代价是误报 +a 个百分点、
//   每条请求多花 b 微秒。
//
// 这个程序就是产出上面那串数字的仪器。它做的事很窄:
//   1. 读规则文件,建两个引擎(一个关归一化 = 基线,一个开 = 加固)
//   2. 读标注语料,按 surface 还原成 build_scan_text 的形状
//   3. 两个引擎各跑一遍,逐条记录命中/未命中
//   4. 按"基线样本 / 变形样本 / 正常样本"三组算指标,输出 Markdown
//
// ---------------------------------------------------------------------------
// 语料格式(TSV,6 列,TAB 分隔)
// ---------------------------------------------------------------------------
//   id            样本唯一 ID
//   category      SQL_INJECTION / XSS / CMD_INJECTION / PATH_TRAVERSAL / BENIGN
//   technique     这条样本用的手法(编码、注释、分隔符、等价函数...)
//   surface       query / body / path / ua  —— 载荷出现在请求的哪个位置
//   payload       载荷原文(不要含 TAB;要测 TAB 请用 %09)
//   base          变形样本指向它来源的基线样本 ID;基线样本留空
//
// 为什么要有 base:"这个规则被绕过了" 单独看没有意义 —— 一条本来就不检的
// payload 谈不上"被绕过"。所以每条变形样本都必须能追溯到一条**基线命中**的
// 样本,漏报率才有分母。这是这套评测方法论的关键约束。
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#include "engine.h"
#include "util/config.h"

namespace fs = std::filesystem;
using namespace secguard;

namespace {

struct Sample {
    std::string id;
    std::string category;
    std::string technique;
    std::string surface;
    std::string payload;
    std::string base;

    [[nodiscard]] bool benign() const { return category == "BENIGN"; }
};

struct Verdict {
    bool        hit = false;
    std::string first_rule;   // 命中的第一条规则 ID(报告里用来归因)
};

struct Count {
    int total = 0;
    int hit = 0;
    [[nodiscard]] double rate() const {
        return total > 0 ? static_cast<double>(hit) / static_cast<double>(total) : 0.0;
    }
};

const char* kTag = "[评测] ";

// ---------------------------------------------------------------------------
// 语料加载
// ---------------------------------------------------------------------------
std::vector<std::string> split_tsv(const std::string& line) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= line.size(); ++i) {
        if (i == line.size() || line[i] == '\t') {
            out.push_back(line.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}

std::string trim_cr(std::string s) {
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) s.pop_back();
    return s;
}

bool load_corpus(const std::string& dir, std::vector<Sample>& out, std::string& err) {
    if (!fs::exists(dir)) { err = "语料目录不存在: " + dir; return false; }

    std::vector<fs::path> files;
    for (const auto& e : fs::directory_iterator(dir)) {
        if (!e.is_regular_file()) continue;
        if (e.path().extension() != ".tsv") continue;
        files.push_back(e.path());
    }
    if (files.empty()) { err = "语料目录里没有 .tsv: " + dir; return false; }
    std::sort(files.begin(), files.end());

    std::set<std::string> seen_ids;
    int lineno = 0;
    for (const auto& f : files) {
        std::ifstream in(f);
        if (!in) { err = "打不开语料: " + f.string(); return false; }
        std::string line;
        while (std::getline(in, line)) {
            ++lineno;
            line = trim_cr(line);
            if (line.empty()) continue;
            if (line.rfind("//", 0) == 0) continue;      // 注释
            const auto f6 = split_tsv(line);
            if (f6.size() != 6) {
                std::ostringstream oss;
                oss << f.string() << ":" << lineno << " 列数应为 6,实际 " << f6.size();
                err = oss.str();
                return false;
            }
            Sample s;
            s.id = f6[0];
            s.category = f6[1];
            s.technique = f6[2];
            s.surface = f6[3];
            s.payload = f6[4];
            s.base = f6[5];
            if (s.base == "-") s.base.clear();   // "-" = 基线样本,没有来源
            if (s.id.empty()) { err = f.string() + ":" + std::to_string(lineno) + " 缺 id"; return false; }
            if (!seen_ids.insert(s.id).second) {
                err = "样本 ID 重复: " + s.id;
                return false;
            }
            out.push_back(std::move(s));
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// 把载荷还原成 build_scan_text 的输出形状
//
// 这里必须和 app_context.cpp 的 build_scan_text 保持一致 —— 评测的必须是
// 真实检测链路看到的那段文本,否则量到的就是另一个系统的能力。
// (格式:每段 "标签:内容\n",段与段之间靠换行隔开)
// ---------------------------------------------------------------------------
std::string wrap_payload(const Sample& s) {
    static const std::string kFakePath = "/api/posts";
    std::string out;
    auto seg = [&out](const char* label, const std::string& v) {
        if (v.empty()) return;
        out += label;
        out += v;
        out.push_back('\n');
    };

    if (s.surface == "path") {
        seg("PATH:", s.payload);
    } else {
        seg("PATH:", kFakePath);
        if (s.surface == "query")      seg("QUERY:", s.payload);
        else if (s.surface == "body")  seg("BODY:", s.payload);
        else if (s.surface == "ua")    seg("UA:", s.payload);
    }
    return out;
}

// ---------------------------------------------------------------------------
// 跑一遍
// ---------------------------------------------------------------------------
struct RunResult {
    std::vector<Verdict> verdicts;
    double us_per_sample = 0.0;
    int    canonical_pass_count = 0;
};

RunResult run_engine(Engine& engine, const std::vector<Sample>& samples, int perf_repeat) {
    RunResult r;
    r.verdicts.resize(samples.size());

    // 预热(把自动机表和分支预测都跑热)
    for (const auto& s : samples) {
        const std::string text = wrap_payload(s);
        (void)engine.search(text);
    }

    const int repeat = perf_repeat > 0 ? perf_repeat : 1;
    const auto t0 = std::chrono::steady_clock::now();
    for (int rep = 0; rep < repeat; ++rep) {
        for (std::size_t i = 0; i < samples.size(); ++i) {
            const std::string text = wrap_payload(samples[i]);
            const MatchResult mr = engine.search(text);
            if (rep == 0) {
                r.verdicts[i].hit = !mr.rule_indices.empty();
                if (!mr.rule_indices.empty()) {
                    r.verdicts[i].first_rule =
                        engine.rule(mr.rule_indices.front()).id;
                }
                if (mr.canonical_pass) ++r.canonical_pass_count;
            }
        }
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double total_us =
        std::chrono::duration<double, std::micro>(t1 - t0).count();
    r.us_per_sample = total_us / (static_cast<double>(repeat) *
                                  static_cast<double>(samples.size()));
    return r;
}

std::string pct(double v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1f%%", v * 100.0);
    return buf;
}

std::string pct_delta(double after, double before) {
    const double d = (after - before) * 100.0;
    char buf[48];
    std::snprintf(buf, sizeof(buf), "%+.1f pp", d);
    return buf;
}

struct Group {
    Count all;
    Count hit_baseline;     // 基线样本里被检出的
    Count variant_meaningful;  // 变形样本里"基线命中"的(有效分母)
    Count variant_hit;      // 其中加固后仍检出
};

}  // namespace

int main(int argc, char** argv) {
    std::string rules_path = "rules/attack_patterns.txt";
    std::string corpus_dir = "tools/waf_eval/corpus";
    std::string out_md;
    std::string out_miss;
    int perf_repeat = 20;
    bool dump_rules = false;
    double max_miss = -1.0;   // <0 = 不设门禁
    double max_fp = -1.0;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "%s 缺少参数\n", name);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--rules")       rules_path = next("--rules");
        else if (a == "--corpus") corpus_dir = next("--corpus");
        else if (a == "--out")    out_md = next("--out");
        else if (a == "--miss")   out_miss = next("--miss");
        else if (a == "--repeat") perf_repeat = std::stoi(next("--repeat"));
        else if (a == "--dump-rules") dump_rules = true;
        else if (a == "--max-miss") max_miss = std::stod(next("--max-miss"));
        else if (a == "--max-fp")   max_fp = std::stod(next("--max-fp"));
        else {
            std::fprintf(stderr,
                "用法: %s [--rules 规则文件] [--corpus 语料目录] [--out 报告.md]\n"
                "        [--miss 漏报清单.md] [--repeat N] [--dump-rules]\n", argv[0]);
            return 2;
        }
    }

    // 把"引擎实际用的"规则打出来。注意不是直接 cat 规则文件 ——
    // 加载时会按 TAB 切分并 trim 每个字段,所以文件里写成 `select `(带尾空格)
    // 的规则,进引擎后是 `select`,语义完全不同。这个模式就是为了看见这件事。
    if (dump_rules) {
        EngineConfig rc;
        rc.pattern_file = rules_path;
        rc.allowlist_file = "";
        Engine e;
        std::string e2;
        if (!e.load_from_file(rules_path, rc, e2)) {
            std::fprintf(stderr, "%s规则载入失败: %s\n", kTag, e2.c_str());
            return 1;
        }
        for (std::size_t i = 0; i < e.rule_count(); ++i) {
            const Rule& r = e.rule(static_cast<std::int32_t>(i));
            std::printf("%s\t%s\t%s\t%s\n", r.id.c_str(), r.text.c_str(),
                        r.category.c_str(), r.severity.c_str());
        }
        return 0;
    }

    std::vector<Sample> samples;
    std::string err;
    if (!load_corpus(corpus_dir, samples, err)) {
        std::fprintf(stderr, "%s加载语料失败: %s\n", kTag, err.c_str());
        return 1;
    }

    EngineConfig cfg;
    cfg.pattern_file = rules_path;
    cfg.allowlist_file = "";        // 评测口径:不应用任何白名单
    cfg.max_text_bytes = 256 * 1024;
    cfg.max_hits = 512;
    cfg.max_pattern_len = 4096;
    cfg.normalize_decode_rounds = 3;

    Engine base_engine;
    cfg.extra_normalization = false;
    if (!base_engine.load_from_file(rules_path, cfg, err)) {
        std::fprintf(stderr, "%s规则载入失败: %s\n", kTag, err.c_str());
        return 1;
    }

    Engine hard_engine;
    cfg.extra_normalization = true;
    if (!hard_engine.load_from_file(rules_path, cfg, err)) {
        std::fprintf(stderr, "%s规则载入失败(加固引擎): %s\n", kTag, err.c_str());
        return 1;
    }

    std::printf("语料 %zu 条,规则 %zu 条\n", samples.size(), base_engine.rule_count());

    const RunResult base_run = run_engine(base_engine, samples, perf_repeat);
    const RunResult hard_run = run_engine(hard_engine, samples, perf_repeat);

    // --- 基准样本(无 base)与变形样本分开统计 ---
    // 变形样本的有效分母 = 它的 base 在当前引擎下被检出。
    std::map<std::string, std::size_t> by_id;
    for (std::size_t i = 0; i < samples.size(); ++i) by_id[samples[i].id] = i;

    auto compute = [&](const RunResult& run) {
        std::map<std::string, Group> by_cat;    // 按类别
        std::map<std::string, Group> by_tech;   // 按手法(只看变形)
        Count base_set, benign_set, variant_all;
        int variant_meaningful = 0, variant_missed = 0;

        for (std::size_t i = 0; i < samples.size(); ++i) {
            const Sample& s = samples[i];
            const bool hit = run.verdicts[i].hit;

            if (s.benign()) { benign_set.total++; if (hit) benign_set.hit++; continue; }

            if (s.base.empty()) {
                base_set.total++;
                if (hit) base_set.hit++;
                by_cat[s.category].all.total++;
                if (hit) by_cat[s.category].all.hit++;
                by_cat[s.category].hit_baseline.total++;
                if (hit) by_cat[s.category].hit_baseline.hit++;
            } else {
                variant_all.total++;
                by_tech[s.technique].all.total++;
                by_cat[s.category].all.total++;
                if (hit) { by_cat[s.category].all.hit++; by_tech[s.technique].all.hit++; }

                const auto it = by_id.find(s.base);
                bool base_hit = false;
                if (it != by_id.end()) base_hit = run.verdicts[it->second].hit;
                if (base_hit) {
                    ++variant_meaningful;
                    by_tech[s.technique].variant_meaningful.total++;
                    by_cat[s.category].variant_meaningful.total++;
                    if (hit) {
                        by_tech[s.technique].variant_meaningful.hit++;
                        by_cat[s.category].variant_meaningful.hit++;
                    } else {
                        ++variant_missed;
                    }
                }
            }
        }
        return std::make_tuple(base_set, benign_set, variant_all,
                               variant_meaningful, variant_missed, by_cat, by_tech);
    };

    const auto [base_base, base_benign, base_var_all, base_var_meaningful,
                base_var_missed, base_by_cat, base_by_tech] = compute(base_run);
    const auto [hard_base, hard_benign, hard_var_all, hard_var_meaningful,
                hard_var_missed, hard_by_cat, hard_by_tech] = compute(hard_run);
    (void)base_var_all; (void)hard_var_all;

    // --- 汇总到 stdout(报告细节写进 markdown) ---
    std::printf("基线样本 %d 条:基线检出 %s,加固检出 %s\n",
                base_base.total, pct(base_base.rate()).c_str(), pct(hard_base.rate()).c_str());
    std::printf("变形样本有效 %d 条:基线漏报 %d 条(%s),加固漏报 %d 条(%s)\n",
                base_var_meaningful, base_var_missed,
                pct(base_var_meaningful ? double(base_var_missed) / base_var_meaningful : 0).c_str(),
                hard_var_missed,
                pct(hard_var_meaningful ? double(hard_var_missed) / hard_var_meaningful : 0).c_str());
    std::printf("正常样本 %d 条:基线误报 %d(%s),加固误报 %d(%s)\n",
                base_benign.total, base_benign.hit, pct(base_benign.rate()).c_str(),
                hard_benign.hit, pct(hard_benign.rate()).c_str());
    std::printf("每样本耗时:基线 %.1f us,加固 %.1f us\n",
                base_run.us_per_sample, hard_run.us_per_sample);

    // --- 漏报清单(规则作者迭代用) ---
    if (!out_miss.empty()) {
        std::ofstream f(out_miss);
        if (!f) { std::fprintf(stderr, "写不了 %s\n", out_miss.c_str()); return 1; }
        auto dump_misses = [&](const RunResult& run, const char* title) {
            int n = 0;
            f << "\n## " << title << "\n\n";
            f << "| 样本 | 类别 | 手法 | 位置 | 载荷 | 来源基线 |\n|---|---|---|---|---|---|\n";
            for (std::size_t i = 0; i < samples.size(); ++i) {
                const Sample& s = samples[i];
                if (s.benign() || s.base.empty()) continue;
                if (run.verdicts[i].hit) continue;
                const auto it = by_id.find(s.base);
                if (it == by_id.end() || !base_run.verdicts[it->second].hit) continue;
                std::string p = s.payload;
                for (char& c : p) if (c == '|') c = '\\';
                f << "| `" << s.id << "` | " << s.category << " | " << s.technique
                  << " | " << s.surface << " | `" << p << "` | `" << s.base << "` |\n";
                ++n;
            }
            return n;
        };
        f << "# 变形样本漏报清单\n";
        const int n_base = dump_misses(base_run, "一、基线(只做字面匹配)下的漏报");
        const int n_hard = dump_misses(hard_run, "二、加固(加归一化层)后仍漏报");
        f.close();
        std::printf("漏报清单:基线 %d 条,加固 %d 条 -> %s\n", n_base, n_hard, out_miss.c_str());
    }

    // --- Markdown 报告 ---
    if (!out_md.empty()) {
        std::ofstream f(out_md);
        if (!f) { std::fprintf(stderr, "写不了 %s\n", out_md.c_str()); return 1; }
        f << "# WAF 绕过评测报告\n\n";
        f << "> 由 `tools/waf_eval` 生成。语料 " << samples.size()
          << " 条,规则 " << base_engine.rule_count() << " 条。\n";
        f << "> 基线 = 只做字面匹配(加归一化层之前的行为);"
             " 加固 = 字面 + 归一化双遍。\n\n";

        f << "## 一、总览\n\n";
        f << "| 指标 | 基线 | 加固 | 变化 |\n|---|---|---|---|\n";
        f << "| 基线样本检出率(" << base_base.total << " 条) | "
          << pct(base_base.rate()) << " | " << pct(hard_base.rate()) << " | "
          << pct_delta(hard_base.rate(), base_base.rate()) << " |\n";
        const double bm = base_var_meaningful ? double(base_var_missed) / base_var_meaningful : 0.0;
        const double hm = hard_var_meaningful ? double(hard_var_missed) / hard_var_meaningful : 0.0;
        f << "| 变形样本漏报率(" << base_var_meaningful << " 条) | "
          << pct(bm) << " | " << pct(hm) << " | " << pct_delta(hm, bm) << " |\n";
        f << "| 正常样本误报率(" << base_benign.total << " 条) | "
          << pct(base_benign.rate()) << " | " << pct(hard_benign.rate()) << " | "
          << pct_delta(hard_benign.rate(), base_benign.rate()) << " |\n";
        f << "| 每样本耗时 | " << base_run.us_per_sample << " us | "
          << hard_run.us_per_sample << " us | "
          << pct_delta(hard_run.us_per_sample, base_run.us_per_sample) << " |\n";
        f << "\n有效变形样本指的是「它的来源基线样本确实被检出」的那些——";
        f << "只有这种样本被漏掉,才叫绕过。\n";

        // 按类别
        f << "\n## 二、按攻击类别\n\n";
        f << "| 类别 | 基线样本 | 基线检出 | 有效变形 | 基线漏报 | 加固漏报 |\n";
        f << "|---|---|---|---|---|---|\n";
        for (const auto& [cat, g] : base_by_cat) {
            const auto hit2 = hard_by_cat.find(cat);
            const int hard_miss = hit2 == hard_by_cat.end()
                ? 0 : hit2->second.variant_meaningful.total - hit2->second.variant_meaningful.hit;
            const int base_miss = g.variant_meaningful.total - g.variant_meaningful.hit;
            f << "| " << cat << " | " << g.hit_baseline.total
              << " | " << g.hit_baseline.hit
              << " | " << g.variant_meaningful.total
              << " | " << base_miss
              << " | " << hard_miss << " |\n";
        }

        // 按手法
        f << "\n## 三、按绕过手法\n\n";
        f << "| 手法 | 有效变形 | 基线漏报 | 加固漏报 |\n|---|---|---|---|\n";
        std::vector<std::pair<std::string, Group>> techs(base_by_tech.begin(), base_by_tech.end());
        std::sort(techs.begin(), techs.end(), [](const auto& a, const auto& b) {
            const int ma = a.second.variant_meaningful.total - a.second.variant_meaningful.hit;
            const int mb = b.second.variant_meaningful.total - b.second.variant_meaningful.hit;
            return ma > mb;
        });
        for (const auto& [tech, g] : techs) {
            const auto hit2 = hard_by_tech.find(tech);
            const int hard_miss = hit2 == hard_by_tech.end()
                ? 0 : hit2->second.variant_meaningful.total - hit2->second.variant_meaningful.hit;
            const int base_miss = g.variant_meaningful.total - g.variant_meaningful.hit;
            f << "| " << tech << " | " << g.variant_meaningful.total
              << " | " << base_miss << " | " << hard_miss << " |\n";
        }

        // 误报变化
        f << "\n## 四、误报变化\n\n";
        if (hard_benign.hit <= base_benign.hit) {
            f << "加固后误报没有增加(" << base_benign.hit << " -> "
              << hard_benign.hit << ")。\n";
        } else {
            f << "加固后新增误报 " << (hard_benign.hit - base_benign.hit) << " 条:\n\n";
            for (std::size_t i = 0; i < samples.size(); ++i) {
                if (!samples[i].benign()) continue;
                if (base_run.verdicts[i].hit || !hard_run.verdicts[i].hit) continue;
                f << "- `" << samples[i].id << "` [" << samples[i].technique << "] "
                  << "`" << samples[i].payload << "` -> 命中 "
                  << hard_run.verdicts[i].first_rule << "\n";
            }
        }

        // 误报明细:哪条规则在正常流量上开火 —— 这是"规则分级"的依据
        f << "\n### 误报明细(加固模式下正常样本被判黑的每一条)\n\n";
        f << "| 样本 | 手法 | 载荷 | 命中规则 |\n|---|---|---|---|\n";
        std::map<std::string, int> rule_fp_count;
        for (std::size_t i = 0; i < samples.size(); ++i) {
            if (!samples[i].benign() || !hard_run.verdicts[i].hit) continue;
            std::string p = samples[i].payload;
            for (char& c : p) if (c == '|') c = '\\';
            if (p.size() > 60) p = p.substr(0, 57) + "...";
            f << "| `" << samples[i].id << "` | " << samples[i].technique
              << " | `" << p << "` | " << hard_run.verdicts[i].first_rule << " |\n";
            rule_fp_count[hard_run.verdicts[i].first_rule]++;
        }
        if (!rule_fp_count.empty()) {
            f << "\n按规则汇总:";
            for (const auto& [rid, cnt] : rule_fp_count) {
                f << " `" << rid << "`×" << cnt;
            }
            f << "\n";
        }

        f << "\n## 五、性能\n\n";
        f << "| 场景 | 每条耗时 | 相对基线 |\n|---|---|---|\n";
        f << "| 基线 | " << base_run.us_per_sample << " us | 1.00x |\n";
        f << "| 加固 | " << hard_run.us_per_sample << " us | "
          << (base_run.us_per_sample > 0
                  ? std::to_string(hard_run.us_per_sample / base_run.us_per_sample).substr(0, 4)
                  : std::string("n/a")) << "x |\n";
        f << "\n加固模式下有 " << hard_run.canonical_pass_count << " / " << samples.size()
          << " 条样本真的走了第二遍(规范形与原文不同);"
             "其余样本只有一遍的开销。\n";
        f.close();
        std::printf("报告 -> %s\n", out_md.c_str());
    }

    // --- 门禁:指标越界就返回非 0,让 CI 卡住"补一个漏报带出三个误报"的改动 ---
    int rc = 0;
    const double miss_rate = hard_var_meaningful > 0
        ? static_cast<double>(hard_var_missed) / hard_var_meaningful : 0.0;
    const double fp_rate = hard_benign.total > 0
        ? static_cast<double>(hard_benign.hit) / hard_benign.total : 0.0;
    if (max_miss >= 0 && miss_rate > max_miss) {
        std::fprintf(stderr, "门禁失败:变形漏报率 %s 超过上限 %s\n",
                     pct(miss_rate).c_str(), pct(max_miss).c_str());
        rc = 1;
    }
    if (max_fp >= 0 && fp_rate > max_fp) {
        std::fprintf(stderr, "门禁失败:正常样本误报率 %s 超过上限 %s\n",
                     pct(fp_rate).c_str(), pct(max_fp).c_str());
        rc = 1;
    }
    return rc;
}
