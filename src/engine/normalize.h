// 归一化层:把同一个攻击的无数种"写法"收敛成同一个规范形(项目 A)
//
// ---------------------------------------------------------------------------
// 为什么需要这一层
// ---------------------------------------------------------------------------
// 引擎原本只做一次小写化,然后拿原样的 QUERY / BODY 去匹配(见
// app_context.cpp 的 build_scan_text:注释里明写"原样,不解码")。
//
// 这等于假设"攻击者会把 payload 老老实实写成明文"。而现实中任何 HTTP
// 客户端都会对 URL 编码 —— 只要把空格写成 %20:
//
//     ?id=1 union select 1      -> 命中 SQL-001(union select)
//     ?id=1%20union%20select%201 -> 一条规则都不命中
//
// 后者不是"高级绕过手法",而是浏览器和 curl --data-urlencode 的默认行为。
// 也就是说原有的 228 条规则里有相当一部分,在真实编码流量面前是失效的。
//
// ---------------------------------------------------------------------------
// 两层检测:原始遍 + 归一化遍,取并集
// ---------------------------------------------------------------------------
//   第 1 遍(原始):对原样文本(仅小写)匹配。
//                  保留所有"字面特征"的检出能力,包括那些故意写成编码形的
//                  规则(如 `%3cscript`、`\x3cscript`)。这一遍**完全不动**,
//                  所以对已有行为是零回归。
//   第 2 遍(归一):对 canonicalize() 之后的规范形匹配。
//                  编码还原、注释剥离、空白压缩、转义还原、转小写之后,
//                  同一类攻击会收敛到同一个字符串,规则只需要写"语义形状"。
//
// 两遍取并集,所以只可能多检出,不可能少检出。这一点是硬要求:
// 安全组件的任何"升级"都不应该降低已有检出率,否则升级本身就是事故。
//
// ---------------------------------------------------------------------------
// 为什么归一化是"还原"而不是"猜"
// ---------------------------------------------------------------------------
// 这一层只做**有明确定义**的变换(percent-decoding、HTML 实体、JS 转义、
// SQL 注释语法、空白折叠),每一条都能在对应的解析器规范里找到依据。
// 不做模糊匹配、不做语义推断 —— 那种东西没法解释,误报也没法归因。
#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>

namespace secguard {

// 归一化策略。全部可逐项关闭,用于消融实验:关掉某一项之后重跑语料,
// 就能量化"这一项到底贡献了多少检出率"(见 tools/waf_eval)。
struct NormalizeOptions {
    bool percent_decode   = true;   // %XX 反复解码(应对单层/双层/三层编码)
    bool decode_plus      = true;   // '+' -> 空格(application/x-www-form-urlencoded)
    bool entity_decode    = true;   // &#x6a; / &#106; / &lt;(HTML 实体)
    bool escape_decode    = true;   // \x3c / \u003c / \/(JS / JSON 转义)
    bool strip_comments   = true;   // /**/ -- #(SQL 注释语法)
    bool drop_nul         = true;   // 去掉 \0(很多解析器在 \0 处截断)
    bool collapse_space   = true;   // 连续空白压成一个空格
    bool lowercase        = true;   // ASCII 转小写
    int  max_decode_rounds = 3;     // 最多解几层编码,防止构造性膨胀
};

namespace detail {

[[nodiscard]] inline int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// 把一个 Unicode 码点写成 UTF-8。规则库是 ASCII,这里保留完整实现是为了
// 不丢信息(比如 &#x4e2d; 这种,归一化后不该变成问号)。
inline void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0x10FFFF) {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

// %XX 解一层。返回值表示"这一层有没有解出东西"。
inline bool percent_decode_once(std::string_view in, std::string& out, bool plus_as_space) {
    out.clear();
    out.reserve(in.size());
    bool changed = false;
    for (std::size_t i = 0; i < in.size(); ++i) {
        const char c = in[i];
        if (c == '%' && i + 2 < in.size()) {
            const int hi = hex_val(in[i + 1]);
            const int lo = hex_val(in[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>(hi * 16 + lo));
                i += 2;
                changed = true;
                continue;
            }
        }
        if (plus_as_space && c == '+') {
            out.push_back(' ');
            changed = true;
            continue;
        }
        out.push_back(c);
    }
    return changed;
}

// HTML 实体:&#x6a; &#106; &lt; &nbsp; ...
inline bool decode_entities(std::string_view in, std::string& out) {
    static constexpr struct { const char* name; char ch; } kNamed[] = {
        {"lt", '<'},     {"gt", '>'},     {"amp", '&'},    {"quot", '"'},
        {"apos", '\''},  {"nbsp", ' '},   {"tab", '\t'},   {"newline", '\n'},
        {"sol", '/'},    {"bsol", '\\'},  {"lpar", '('},   {"rpar", ')'},
        {"colon", ':'},  {"semi", ';'},   {"equals", '='}, {"plus", '+'},
        {"comma", ','},  {"period", '.'}, {"num", '#'},    {"percnt", '%'},
        {"ast", '*'},    {"quest", '?'},  {"commat", '@'}, {"lsqb", '['},
        {"rsqb", ']'},   {"lcub", '{'},   {"rcub", '}'},   {"grave", '`'},
        {"dollar", '$'}, {"excl", '!'},   {"verbar", '|'}, {"lowbar", '_'},
    };

    out.clear();
    out.reserve(in.size());
    bool changed = false;
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '&' || i + 2 >= in.size()) {
            out.push_back(in[i]);
            continue;
        }
        // 形如 &#x6a; / &#106;
        if (in[i + 1] == '#') {
            std::size_t j = i + 2;
            std::uint32_t cp = 0;
            bool hex = false;
            if (j < in.size() && (in[j] == 'x' || in[j] == 'X')) { hex = true; ++j; }
            const std::size_t start = j;
            while (j < in.size()) {
                const int v = hex ? hex_val(in[j]) : (in[j] >= '0' && in[j] <= '9' ? in[j] - '0' : -1);
                if (v < 0) break;
                if (cp > 0x10FFFF) break;                 // 防止溢出
                cp = cp * (hex ? 16u : 10u) + static_cast<std::uint32_t>(v);
                ++j;
            }
            if (j > start && j < in.size() && in[j] == ';' && cp <= 0x10FFFF) {
                append_utf8(out, cp);
                i = j;
                changed = true;
                continue;
            }
            out.push_back(in[i]);
            continue;
        }
        // 形如 &lt;
        bool matched = false;
        for (const auto& e : kNamed) {
            const std::size_t n = std::char_traits<char>::length(e.name);
            if (i + 1 + n >= in.size()) continue;
            if (in.compare(i + 1, n, e.name) != 0) continue;
            if (in[i + 1 + n] != ';') continue;
            out.push_back(e.ch);
            i += 1 + n;              // for 循环还会 +1,所以这里只加到分号前
            changed = true;
            matched = true;
            break;
        }
        if (!matched) out.push_back(in[i]);
    }
    return changed;
}

// JS / JSON 转义:x 形式、u 形式、u{...} 形式,以及斜杠和反斜杠的转义
inline bool decode_escapes(std::string_view in, std::string& out) {
    out.clear();
    out.reserve(in.size());
    bool changed = false;
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '\\' || i + 1 >= in.size()) {
            out.push_back(in[i]);
            continue;
        }
        const char n = in[i + 1];
        if (n == 'x' && i + 3 < in.size()) {
            const int hi = hex_val(in[i + 2]);
            const int lo = hex_val(in[i + 3]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>(hi * 16 + lo));
                i += 3;
                changed = true;
                continue;
            }
        }
        if (n == 'u') {
            // \u{1F600}
            if (i + 2 < in.size() && in[i + 2] == '{') {
                std::size_t j = i + 3;
                std::uint32_t cp = 0;
                const std::size_t start = j;
                while (j < in.size()) {
                    const int v = hex_val(in[j]);
                    if (v < 0) break;
                    if (cp > 0x10FFFF) break;
                    cp = cp * 16u + static_cast<std::uint32_t>(v);
                    ++j;
                }
                if (j > start && j < in.size() && in[j] == '}' && cp <= 0x10FFFF) {
                    append_utf8(out, cp);
                    i = j;
                    changed = true;
                    continue;
                }
            }
            // \u003c
            if (i + 5 < in.size()) {
                std::uint32_t cp = 0;
                bool ok = true;
                for (int k = 0; k < 4; ++k) {
                    const int v = hex_val(in[i + 2 + k]);
                    if (v < 0) { ok = false; break; }
                    cp = cp * 16u + static_cast<std::uint32_t>(v);
                }
                if (ok) {
                    append_utf8(out, cp);
                    i += 5;
                    changed = true;
                    continue;
                }
            }
        }
        if (n == '/' || n == '\\') { out.push_back(n); i += 1; changed = true; continue; }
        out.push_back(in[i]);
    }
    return changed;
}

// SQL 块注释。
//   /* ... */      块注释,在 SQL 里等价于一个空白 —— `union/**/select` 就是
//                  `union select`。这是最经典的"绕关键词匹配"手法,必须还原。
//   /*!50000 x */  版本注释,MySQL 会**执行**里面的 x,所以保留 x、丢掉外壳。
//
// 为什么**不剥** `--` 和 `#` 行注释:
//   规则库里有 `order by 1--`、`or true--`、`'--` 这些"连注释一起写进特征"
//   的规则。如果归一化把 `--` 到行尾整段删掉,这些规则在规范形里就永远
//   不可能命中 —— 归一化层反而把本该检出的东西藏起来了。
//   实测踩到:编码空格的 `order by 1--` 在加固后**仍然漏报**,原因就在这。
//   教训:归一化只能做"把变形还原成原形"的操作,不能做"删除信息"的操作。
inline bool strip_block_comments(std::string_view in, std::string& out) {
    out.clear();
    out.reserve(in.size());
    bool changed = false;
    for (std::size_t i = 0; i < in.size();) {
        if (in[i] == '/' && i + 1 < in.size() && in[i + 1] == '*') {
            std::size_t j = i + 2;
            // 版本注释 /*!50000 ... */
            if (j < in.size() && in[j] == '!') {
                ++j;
                while (j < in.size() && in[j] >= '0' && in[j] <= '9') ++j;
                const std::size_t body = j;
                const std::size_t close = in.find("*/", body);
                if (close != std::string_view::npos) {
                    out.append(in.substr(body, close - body));
                    out.push_back(' ');
                    i = close + 2;
                    changed = true;
                    continue;
                }
            }
            const std::size_t close = in.find("*/", j);
            if (close != std::string_view::npos) {
                out.push_back(' ');
                i = close + 2;
                changed = true;
                continue;
            }
            // 没闭合:剩下的都当注释吃掉
            out.push_back(' ');
            changed = true;
            break;
        }
        out.push_back(in[i]);
        ++i;
    }
    return changed;
}

inline void collapse_ws(std::string& s) {
    std::string out;
    out.reserve(s.size());
    bool pending_space = false;
    for (char c : s) {
        const bool ws = (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
                         c == '\f' || c == '\v');
        if (ws) { pending_space = !out.empty(); continue; }
        if (pending_space) { out.push_back(' '); pending_space = false; }
        out.push_back(c);
    }
    s.swap(out);
}

inline void ascii_lower(std::string& s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
}

inline void drop_nuls(std::string& s) {
    if (s.find('\0') == std::string::npos) return;
    s.erase(std::remove(s.begin(), s.end(), '\0'), s.end());
}

}  // namespace detail

// 快速预判:这段文本里有没有"可能改变匹配结果"的变形标记。
//
// 为什么需要:canonicalize() 会重建一个字符串,这个开销对每条请求都要付。
// 而绝大多数正常请求(纯静态路径、普通 JSON 表单)里一个变形标记都没有,
// 本来就不需要第二遍。用一次带早退的字节扫描把这类请求挡掉,能把
// 归一化层的平均开销压到接近 0。
//
// 标记集合的取舍:
//   %        百分号编码
//   +        form-urlencoded 里的空格(只在启用了 decode_plus 时算)
//   \        反斜杠转义
//   \t \r    可被当作分隔符的控制字符(单独空格不算,空格太常见)
//   "  "     连续两个空格(`;  whoami` 这种,折叠后变成 `; whoami`)
//   &        实体/命名引用的起点(要求后面跟 `#` 或 `名字;`)
//   /*       SQL 块注释
// 注意不能把 `&` 一律当标记 —— 查询串里到处是 `&`,那样等于没有快路。
[[nodiscard]] inline bool may_obfuscate(std::string_view s) {
    const std::size_t n = s.size();
    for (std::size_t i = 0; i < n; ++i) {
        const char c = s[i];
        switch (c) {
            case '%': case '+': case '\\': case '\t': case '\r': case '\f': case '\v':
                return true;
            case ' ': {
                // 连续空白会改变分词(`;  whoami` 折叠成 `; whoami`)
                std::size_t j = i;
                while (j < n && s[j] == ' ') ++j;
                if (j - i >= 2) return true;
                i = j - 1;
                break;
            }
            case '/':
                if (i + 1 < n && s[i + 1] == '*') return true;
                break;
            case '&': {
                // &#x3c; / &#60; / &lt;
                if (i + 1 < n && s[i + 1] == '#') return true;
                std::size_t j = i + 1;
                while (j < n && j < i + 10 &&
                       ((s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z'))) {
                    ++j;
                }
                if (j > i + 1 && j < n && s[j] == ';') return true;
                break;
            }
            default:
                break;
        }
    }
    return false;
}

// 把原始待检文本变成规范形。
//
// 顺序是有讲究的,不能随便换:
//   1. percent-decode  先还原最外层传输编码,否则后面的实体/注释规则
//                      会看到一堆 %XX 而不是它们认识的字符
//   2. escape-decode   \x3c \u003c(JSON / JS 里常见)
//   3. entity-decode   &#x6a;(HTML 属性里常见)
//   4. NUL 清理        很多解析器在 \0 处截断,`..%00/` 对它们等于 `../`
//   5. block-comment   `/**/` 等价于空白,`/*!50000x*/` 里保留 x
//   6. whitespace      压成一个空格 —— 这一步同时把 \t \n \r %09 这些
//                      "分隔符变形"全部收敛掉
//   7. lowercase       规则库是小写的
[[nodiscard]] inline std::string canonicalize(std::string_view raw, const NormalizeOptions& opt) {
    std::string cur(raw);
    std::string tmp;

    if (opt.percent_decode) {
        for (int round = 0; round < opt.max_decode_rounds; ++round) {
            // 只有真的解出了东西才继续下一轮(双层 %252e -> %2e -> .)
            if (!detail::percent_decode_once(cur, tmp, opt.decode_plus)) break;
            cur.swap(tmp);
        }
    } else if (opt.decode_plus) {
        // 只把 '+' 当空格,不解 %XX。
        // (这里原来误用了 percent_decode_once,导致关掉 percent_decode 之后
        //  仍在解百分号编码 —— 消融实验会因此得到"这一项没用"的错误结论)
        std::string plus_only;
        plus_only.reserve(cur.size());
        for (char c : cur) plus_only.push_back(c == '+' ? ' ' : c);
        cur.swap(plus_only);
    }

    if (opt.escape_decode) {
        if (detail::decode_escapes(cur, tmp)) cur.swap(tmp);
    }
    if (opt.entity_decode) {
        if (detail::decode_entities(cur, tmp)) cur.swap(tmp);
    }
    if (opt.drop_nul) detail::drop_nuls(cur);
    if (opt.strip_comments) {
        if (detail::strip_block_comments(cur, tmp)) cur.swap(tmp);
    }
    if (opt.collapse_space) detail::collapse_ws(cur);
    if (opt.lowercase) detail::ascii_lower(cur);
    return cur;
}

}  // namespace secguard
