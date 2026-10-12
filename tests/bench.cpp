// 性能对比基准(第 66 则 / 寓言集第 8、24、25 讲)
//
// 产出简历上那行"吞吐提升 __ 倍"。
// 按指南要求测三组特征数(200 / 500 / 1000),展示:
//   AC 自动机耗时几乎不随特征数增长,朴素版线性增长。
// 这个对比比单个倍数有说服力得多 —— 它证明了 O(n+m) 与 O(n x k) 的差异。
//
// 注意:必须用 Release(-O2)构建。Debug/sanitizer 版本会慢好几倍,数据失真。
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

#include "aho_corasick.h"

using secguard::AhoCorasick;
using Clock = std::chrono::steady_clock;

// ---------------------------------------------------------------------------
// 朴素多模式匹配:每个模式串单独扫一遍文本
// ---------------------------------------------------------------------------
static std::size_t naive_count(const std::string& text,
                               const std::vector<std::string>& patterns) {
    std::size_t n = 0;
    for (const auto& p : patterns) {
        if (p.empty()) continue;
        std::size_t pos = text.find(p);
        while (pos != std::string::npos) {
            ++n;
            pos = text.find(p, pos + 1);
        }
    }
    return n;
}

// ---------------------------------------------------------------------------
// 造特征库:模拟真实攻击特征(可见 ASCII,长短混合)
// ---------------------------------------------------------------------------
static std::vector<std::string> make_patterns(std::size_t count, std::uint32_t seed) {
    static const char* kAtoms[] = {
        "union", "select", "insert", "update", "delete", "drop", "where",
        "script", "onerror", "onload", "javascript", "alert", "img", "svg",
        "../", "..%2f", "%2e%2e", "/etc/passwd", "cmd", "exec", "system",
        "cat%20", "wget", "curl", "bash", "-c", "&&", "%0a", "sleep(",
        "benchmark(", "information_schema", "load_file", "outfile", "' or '",
        "1=1", "--", "/*", "*/", "0x", "char(", "concat(",
    };
    std::mt19937 rng(seed);
    std::uniform_int_distribution<int> atom(0, static_cast<int>(sizeof(kAtoms) / sizeof(kAtoms[0])) - 1);
    std::uniform_int_distribution<int> parts(1, 3);

    std::vector<std::string> out;
    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        std::string p;
        const int n = parts(rng);
        for (int k = 0; k < n; ++k) {
            if (k) p.push_back(' ');
            p += kAtoms[atom(rng)];
        }
        p += std::to_string(i);          // 让每条特征唯一
        out.push_back(std::move(p));
    }
    return out;
}

// 造一段"像 HTTP 请求"的文本:大部分干净,夹带少量攻击串
static std::string make_text(std::size_t len, std::uint32_t seed) {
    static const char* kWords[] = {
        "user", "login", "id", "page", "search", "index", "post", "comment",
        "token", "value", "name", "file", "path", "data", "item", "list",
    };
    std::mt19937 rng(seed);
    std::uniform_int_distribution<int> w(0, static_cast<int>(sizeof(kWords) / sizeof(kWords[0])) - 1);

    std::string t;
    t.reserve(len + 16);
    while (t.size() < len) {
        t += kWords[w(rng)];
        t.push_back('=');
        t += std::to_string(rng() % 100000);
        t.push_back('&');
    }
    // 夹带两处攻击串,保证确实有命中
    t.insert(t.size() / 3, "union select");
    t.insert(t.size() / 2, "' or '1=1'--");
    return t;
}

struct Result {
    std::size_t patterns;
    std::size_t nodes;
    double ac_us;        // 单次匹配平均微秒
    double naive_us;
    double speedup;
    std::size_t hits;
};

// 把结果喂给一个外部可见的累加器,防止编译器把整个循环优化掉。
// (用 volatile 局部变量是没用的 —— 优化器照样能删掉整段计算。)
static std::size_t g_sink = 0;

static Result bench(std::size_t n_patterns, const std::string& text, int iters) {
    auto patterns = make_patterns(n_patterns, 42 + static_cast<std::uint32_t>(n_patterns));

    AhoCorasick ac;
    ac.reserve(patterns.size() * 16 + 16);
    for (const auto& p : patterns) ac.insert(p);
    ac.build();

    std::size_t hits = 0;
    std::size_t naive_hits = 0;

    // 预热(让 cache 热起来,避免冷启动污染结果)
    for (int i = 0; i < 3; ++i) {
        ac.search(text, [&hits](const secguard::Hit&) { ++hits; });
        naive_hits += naive_count(text, patterns);
    }

    // --- AC ---
    hits = 0;
    const auto t1 = Clock::now();
    for (int i = 0; i < iters; ++i) {
        ac.search(text, [&hits](const secguard::Hit&) { ++hits; });
    }
    const auto t2 = Clock::now();

    // --- 朴素 ---
    naive_hits = 0;
    const auto t3 = Clock::now();
    for (int i = 0; i < iters; ++i) {
        naive_hits += naive_count(text, patterns);
    }
    const auto t4 = Clock::now();

    g_sink += hits + naive_hits;   // 结果必须被外部用到,否则整段会被优化掉

    const double ac_total = std::chrono::duration<double, std::micro>(t2 - t1).count();
    const double nv_total = std::chrono::duration<double, std::micro>(t4 - t3).count();

    Result r{};
    r.patterns = n_patterns;
    r.nodes = ac.node_count();
    r.ac_us = ac_total / iters;
    r.naive_us = nv_total / iters;
    r.speedup = (r.ac_us > 0) ? r.naive_us / r.ac_us : 0.0;
    r.hits = hits / static_cast<std::size_t>(iters);
    return r;
}
int main(int argc, char** argv) {
    const int iters = (argc > 1) ? std::atoi(argv[1]) : 2000;
    const std::size_t text_len = (argc > 2) ? static_cast<std::size_t>(std::atoi(argv[2])) : 2048;

    const std::string text = make_text(text_len, 7);

    std::printf("SecGuard 性能基准:AC 自动机 vs 朴素逐串匹配\n");
    std::printf("============================================================\n");
    std::printf("文本长度 %zu 字节,每档迭代 %d 次,取平均\n\n", text.size(), iters);

    std::printf("%8s %10s %14s %14s %10s %10s\n",
                "特征数", "节点数", "AC(微秒)", "朴素(微秒)", "加速比", "每次命中");
    std::printf("--------------------------------------------------------------------------\n");

    std::vector<Result> rs;
    for (const std::size_t n : {200u, 500u, 1000u}) {
        const Result r = bench(n, text, iters);
        rs.push_back(r);
        std::printf("%8zu %10zu %14.2f %14.2f %9.1fx %10.1f\n",
                    r.patterns, r.nodes, r.ac_us, r.naive_us, r.speedup,
                    static_cast<double>(r.hits));
    }
    std::printf("--------------------------------------------------------------------------\n");

    if (!rs.empty()) {
        std::printf("\n吞吐(QPS,按单次匹配耗时折算,仅匹配部分):\n");
        for (const auto& r : rs) {
            std::printf("  特征 %4zu 条:AC %8.0f 次/秒   朴素 %8.0f 次/秒\n",
                        r.patterns, 1e6 / r.ac_us, 1e6 / r.naive_us);
        }
        const double ac_growth = rs.back().ac_us / rs.front().ac_us;
        const double nv_growth = rs.back().naive_us / rs.front().naive_us;
        std::printf("\n特征数 200 -> 1000(5 倍):\n");
        std::printf("  AC 自动机耗时变化:%.2fx\n", ac_growth);
        std::printf("  朴素匹配耗时变化:%.2fx\n", nv_growth);
        std::printf("\n结论:朴素版随特征数近似线性增长,AC 版几乎不变。\n");
        std::printf("      这印证了 O(n x k) 与 O(n + m) 的差异 —— 特征库越大,优势越明显。\n");
    }
    return 0;
}
