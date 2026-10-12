// 暴力对拍测试(第 64 则 / 寓言集第 64 讲)
//
// 方法:同一份输入分别喂给 AC 自动机和朴素逐串匹配,断言两边结果集合完全一致。
// 关键技巧:把字符集缩到 abc 三个字母 —— 这样随机数据里模式串高度重叠,
// fail 指针与 output 合并的逻辑才会被真正触发。字符集大的话,随机串几乎不重叠,
// 跑一万次也测不出问题。
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

#include "aho_corasick.h"

using secguard::AhoCorasick;
using secguard::Hit;

// ---------------------------------------------------------------------------
// 朴素实现:每个模式串单独在文本里找一遍。逻辑极简,可信度高,用作基准。
// ---------------------------------------------------------------------------
static std::vector<Hit> naive_search(const std::string& text,
                                     const std::vector<std::string>& patterns) {
    std::vector<Hit> hits;
    for (std::size_t id = 0; id < patterns.size(); ++id) {
        const std::string& p = patterns[id];
        if (p.empty()) continue;
        std::size_t pos = text.find(p);
        while (pos != std::string::npos) {
            hits.push_back(Hit{static_cast<std::int32_t>(id),
                               pos + p.size() - 1});
            pos = text.find(p, pos + 1);
        }
    }
    std::sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) {
        return a.pattern_id != b.pattern_id ? a.pattern_id < b.pattern_id
                                            : a.end_pos < b.end_pos;
    });
    return hits;
}

static std::vector<Hit> ac_search(AhoCorasick& ac, const std::string& text) {
    auto hits = ac.search_all(text);
    std::sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) {
        return a.pattern_id != b.pattern_id ? a.pattern_id < b.pattern_id
                                            : a.end_pos < b.end_pos;
    });
    return hits;
}

static bool same(const std::vector<Hit>& a, const std::vector<Hit>& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i].pattern_id != b[i].pattern_id || a[i].end_pos != b[i].end_pos) {
            return false;
        }
    }
    return true;
}

static void dump(const char* tag, const std::string& text,
                 const std::vector<std::string>& pats,
                 const std::vector<Hit>& hits) {
    std::printf("  %s: text=%s patterns=[", tag, text.c_str());
    for (std::size_t i = 0; i < pats.size(); ++i) {
        std::printf("%s%s", i ? "," : "", pats[i].c_str());
    }
    std::printf("] hits=[");
    for (std::size_t i = 0; i < hits.size(); ++i) {
        std::printf("%s(%d,%zu)", i ? "," : "", hits[i].pattern_id,
                    hits[i].end_pos);
    }
    std::printf("]\n");
}

static int g_fail = 0;

// 一次对拍:构建 -> 两边比对
static void check(const std::string& text, const std::vector<std::string>& pats,
                  bool verbose_on_fail = true) {
    AhoCorasick ac;
    for (const auto& p : pats) ac.insert(p);
    ac.build();

    const auto got = ac_search(ac, text);
    const auto want = naive_search(text, pats);

    if (!same(got, want)) {
        ++g_fail;
        std::printf("[FAIL] 对拍不一致\n");
        if (verbose_on_fail) {
            dump("AC  ", text, pats, got);
            dump("朴素", text, pats, want);
        }
    }
}

// ---------------------------------------------------------------------------
// 必测特例(寓言集第 13 则的三个边界 + 第 4 则的后缀用例)
// ---------------------------------------------------------------------------
static void test_known_cases() {
    std::printf("== 必测特例 ==\n");

    // 1. 经典后缀用例:he 是 she 的后缀(第 4 则,输出链合并的分水岭)
    check("ushers", {"he", "she", "hers"});
    std::printf("  he/she/hers 后缀用例 ......... %s\n", g_fail ? "有失败" : "通过");
    const int before = g_fail;
    {
        AhoCorasick ac;
        ac.insert("he");
        const auto she = ac.insert("she");
        ac.insert("hers");
        ac.build();
        const auto hits = ac.search_all("ushers");
        // 期望:she@3、he@3(被 output 合并带出来)、hers@5
        int n_she = 0, n_he = 0, n_hers = 0;
        for (const auto& h : hits) {
            if (h.pattern_id == she) ++n_she;
            else if (ac.pattern(h.pattern_id) == "he") ++n_he;
            else if (ac.pattern(h.pattern_id) == "hers") ++n_hers;
        }
        const bool ok = (n_she == 1 && n_he == 1 && n_hers == 1);
        std::printf("  ushers 命中 she/he/hers 各 1 次 %s\n", ok ? "通过" : "失败");
        if (!ok) {
            ++g_fail;
            std::printf("    实际: she=%d he=%d hers=%d\n", n_she, n_he, n_hers);
        }
    }
    (void)before;

    // 2. 公共前缀
    check("union uni unite union", {"union", "uni", "unite"});
    std::printf("  公共前缀 union/uni/unite ... %s\n", g_fail ? "有失败" : "通过");

    // 3. 高字节:验证 unsigned char(第 7 则)
    {
        std::string text = "\xE4\xB8\xAD\xE6\x96\x87";   // "中文" 的 UTF-8
        std::vector<std::string> pats = {"\xE4\xB8\xAD", "\xB8\xAD\xE6"};
        check(text, pats);
        std::printf("  高字节文本(UTF-8) ......... %s\n", g_fail ? "有失败" : "通过");
    }

    // 4. 空文本 / 空模式
    {
        AhoCorasick ac;
        const auto r1 = ac.insert("");            // 空模式应被拒
        const auto id = ac.insert("abc");
        ac.build();
        const auto hits = ac.search_all("");      // 空文本应零命中
        const bool ok = (r1 == -1 && id == 0 && hits.empty());
        std::printf("  空模式被拒 + 空文本零命中 ... %s\n", ok ? "通过" : "失败");
        if (!ok) ++g_fail;
    }

    // 5. 重复插入同一模式:应复用编号
    {
        AhoCorasick ac;
        const auto a = ac.insert("dup");
        const auto b = ac.insert("dup");
        ac.build();
        const auto hits = ac.search_all("dupdup");
        const bool ok = (a == b && ac.pattern_count() == 1 && hits.size() == 2);
        std::printf("  重复插入同一模式 ............ %s\n", ok ? "通过" : "失败");
        if (!ok) ++g_fail;
    }

    // 6. 超长模式被拒
    {
        AhoCorasick ac;
        ac.set_max_pattern_len(16);
        const auto r = ac.insert(std::string(64, 'x'));
        const bool ok = (r == -1);
        std::printf("  超长模式被拒 ................ %s\n", ok ? "通过" : "失败");
        if (!ok) ++g_fail;
    }

    // 7. 完全匹配失败(验证不越界)
    check("zzzzzzzz", {"abc", "def"});
    std::printf("  完全不匹配不越界 ............ %s\n", g_fail ? "有失败" : "通过");

    // 8. 模式是另一个模式的后缀链 a/ba/cba
    check("cba", {"a", "ba", "cba"});
    std::printf("  后缀链 a/ba/cba ............. %s\n", g_fail ? "有失败" : "通过");
}

// 生成一组**互不重复**的模式。
// 为什么要去重:引擎按设计把重复插入的同一模式归成一个编号(第 12 则),
// 而朴素实现是按"每个模式串扫一遍"统计的。若喂进重复的模式,
// 两边对"重复"的定义不同,比较就失去意义了 —— 那测的是测试自己,不是引擎。
template <class Rng, class Dist>
static std::vector<std::string> unique_patterns(
    Rng& rng, Dist& ch,
    std::uniform_int_distribution<int>& len_pat,
    std::uniform_int_distribution<int>& n_pat) {
    std::vector<std::string> pats;
    std::string seen;
    const int want = n_pat(rng);
    int guard = 0;
    while (static_cast<int>(pats.size()) < want && guard++ < 200) {
        std::string p;
        const int L = len_pat(rng);
        for (int j = 0; j < L; ++j) p.push_back(static_cast<char>('a' + ch(rng)));
        const std::string key = "|" + p + "|";
        if (seen.find(key) != std::string::npos) continue;
        seen += key;
        pats.push_back(std::move(p));
    }
    return pats;
}

// ---------------------------------------------------------------------------
// 随机对拍:一万次。字符集缩到 abc,制造高重叠(第 64 则的关键技巧)
// ---------------------------------------------------------------------------
static void test_random(int trials) {
    std::printf("\n== 随机对拍 %d 次(字符集 abc) ==\n", trials);

    std::mt19937 rng(20261012);
    std::uniform_int_distribution<int> len_pat(1, 8);
    std::uniform_int_distribution<int> len_txt(20, 200);
    std::uniform_int_distribution<int> n_pat(1, 12);
    std::uniform_int_distribution<int> ch(0, 2);

    int inconsistent = 0;
    for (int t = 0; t < trials; ++t) {
        const auto pats = unique_patterns(rng, ch, len_pat, n_pat);
        std::string text;
        const int LT = len_txt(rng);
        for (int j = 0; j < LT; ++j) text.push_back(static_cast<char>('a' + ch(rng)));

        const int before = g_fail;
        check(text, pats, false);
        if (g_fail != before) {
            if (++inconsistent <= 3) {
                std::printf("[FAIL] 第 %d 次对拍不一致\n", t);
                AhoCorasick ac;
                for (const auto& p : pats) ac.insert(p);
                ac.build();
                dump("AC  ", text, pats, ac_search(ac, text));
                dump("朴素", text, pats, naive_search(text, pats));
            }
        }
    }
    std::printf("  进行 %d 次,不一致 %d 次 -> %s\n", trials, inconsistent,
                inconsistent == 0 ? "通过" : "失败");
    // 再跑一轮:字符集缩到 ab(重叠更极端)
    std::printf("\n== 随机对拍 %d 次(字符集 ab,更极端)==\n", trials / 2);
    std::uniform_int_distribution<int> ch2(0, 1);
    int inc2 = 0;
    for (int t = 0; t < trials / 2; ++t) {
        const auto pats = unique_patterns(rng, ch2, len_pat, n_pat);
        std::string text;
        const int LT = len_txt(rng);
        for (int j = 0; j < LT; ++j) text.push_back(static_cast<char>('a' + ch2(rng)));
        const int before = g_fail;
        check(text, pats, false);
        if (g_fail != before) ++inc2;
    }
    std::printf("  进行 %d 次,不一致 %d 次 -> %s\n", trials / 2, inc2,
                inc2 == 0 ? "通过" : "失败");
}

int main(int argc, char** argv) {
    const int trials = (argc > 1) ? std::atoi(argv[1]) : 10000;

    std::printf("SecGuard AC 自动机 对拍测试\n");
    std::printf("============================\n\n");

    test_known_cases();
    test_random(trials);

    std::printf("\n============================\n");
    if (g_fail == 0) {
        std::printf("全部通过\n");
        return 0;
    }
    std::printf("失败 %d 处\n", g_fail);
    return 1;
}
