// SecGuard - AC 自动机多模式匹配引擎
// ---------------------------------------------------------------------------
// 对应知识点(见 对话产出/寓言集 第 1~17 则):
//   1  Trie 与公共前缀共享            10 节点结构(走/退/结尾/是谁的结尾)
//   2  失败指针 = 最长真后缀           11 匹配结果怎么返回(流式回调)
//   3  BFS 建 fail 的顺序必要性        12 重复模式(编号唯一,来源保留)
//   4  output 合并,防后缀漏报          13 空/超长/空文本三个边界
//   5  补全缺失转移,消除 while 追 fail 16 大小写与编码归一化
//   6  array<int,256> 转移表           17 引擎输入(由上层翻译 HTTP)
//   7  unsigned char 符号坑
//   8  O(n+m) vs O(n x k)
//   9  root 自环(不补就崩)
// ---------------------------------------------------------------------------
//
// 两个阶段的语义分得很清楚,这是不出错的关键:
//   构建期(insert):  next[c] == -1 表示"这条边还不存在"
//   构建后(build) :  next[c] >=  0 恒成立,缺失转移被补成"fail 链上的去处"
// 所以 insert 必须在 build 之前全部做完;build 之后 next 里不会再有 -1。
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <queue>
#include <string>
#include <string_view>
#include <vector>

namespace secguard {

// 一次命中的记录。只带"哪个模式"和"结束在哪个位置"两样东西 ——
// 去重、排序、截断是调用方的语义,引擎不替业务做决定(第 11、15 则)。
struct Hit {
    std::int32_t pattern_id;   // 模式编号(唯一:同一模式重复插入也只占一个编号)
    std::size_t  end_pos;      // 该模式最后一个字符在文本中的下标
};

class AhoCorasick {
public:
    static constexpr int kAlphabet = 256;   // 按字节处理,覆盖二进制与 URL 编码

    // 一个状态要存哪几样东西(第 10 则)
    struct Node {
        std::array<std::int32_t, kAlphabet> next;  // 往哪走(-1 = 还没这条边)
        std::int32_t fail = 0;                     // 接不上退到哪
        std::vector<std::int32_t> output;          // 到这儿结束的是哪几个模式

        Node() { next.fill(-1); }
    };

    AhoCorasick() { nodes_.emplace_back(); }       // 0 号 = root
    AhoCorasick(const AhoCorasick&) = delete;
    AhoCorasick& operator=(const AhoCorasick&) = delete;

    // ---- 构建期 ----

    // 插入一个模式,返回编号。重复插入返回同一编号(第 12 则)。
    // 空模式、超长模式拒收,返回 -1(第 13 则)。
    std::int32_t insert(std::string_view pattern) {
        if (pattern.empty()) return -1;
        if (pattern.size() > max_pattern_len_) return -1;

        std::int32_t cur = 0;
        for (unsigned char c : pattern) {          // 第 7 则:必须 unsigned
            // 注意:这里必须先取值、再决定是否 emplace_back、最后才写回。
            // 若写成 `std::int32_t& edge = nodes_[cur].next[c];` 再 emplace_back,
            // 引用会在 vector 扩容时失效 —— 那是个很难查的段错误。
            std::int32_t edge = nodes_[cur].next[c];
            if (edge == -1) {
                edge = static_cast<std::int32_t>(nodes_.size());
                nodes_.emplace_back();
                nodes_[cur].next[c] = edge;   // 扩容之后重新按下标访问,安全
            }
            cur = edge;
        }

        // 同一个模式重复插入 -> 复用编号,不重复报(第 12 则)
        for (const std::int32_t id : nodes_[cur].output) {
            if (patterns_[id] == pattern) return id;
        }

        const auto id = static_cast<std::int32_t>(patterns_.size());
        patterns_.emplace_back(pattern);
        total_len_ += pattern.size();
        nodes_[cur].output.push_back(id);
        return id;
    }

    // BFS 建 fail + 合并 output + 补全缺失转移。
    // 必须在所有 insert 之后调用一次(第 5 则)。
    void build() {
        std::queue<std::int32_t> q;                 // 队列,不是栈(第 3 则)

        // 第一层:root 的直接子节点,fail 指向 root;root 的缺失补成自环(第 9 则)
        for (int c = 0; c < kAlphabet; ++c) {
            const std::int32_t child = nodes_[0].next[c];
            if (child != -1) {
                nodes_[child].fail = 0;
                q.push(child);
            } else {
                nodes_[0].next[c] = 0;              // 缺失 -> 回自己(自环)
            }
        }

        while (!q.empty()) {
            const std::int32_t cur = q.front();
            q.pop();

            for (int c = 0; c < kAlphabet; ++c) {
                const std::int32_t child = nodes_[cur].next[c];
                if (child != -1) {
                    // fail(子) = next[fail(父)][c]。BFS 保证父的 fail 已算好(第 3 则)
                    nodes_[child].fail = nodes_[nodes_[cur].fail].next[c];

                    // 合并 output:把 fail 节点的输出继承过来(第 4 则)。
                    // BFS 保证 fail 节点的 output 已完整,继承一次就够,不必递归。
                    const auto& inherit = nodes_[nodes_[child].fail].output;
                    if (!inherit.empty()) {
                        auto& dst = nodes_[child].output;
                        dst.insert(dst.end(), inherit.begin(), inherit.end());
                    }
                    q.push(child);
                } else {
                    // 缺失转移直接指向"fail 节点的同字符转移",匹配时无需 while(第 5 则)
                    nodes_[cur].next[c] = nodes_[nodes_[cur].fail].next[c];
                }
            }
        }
        built_ = true;
    }

    // ---- 匹配期 ----

    // 流式返回:每命中一次回调一次,内存恒定(第 11、25 则)。
    // 模板化以省掉 std::function 的间接调用。
    template <class Fn>
    void search(std::string_view text, Fn&& on_hit) const {
        if (!built_ || patterns_.empty()) return;    // 空表 / 空文本:什么都不报(第 13 则)
        std::int32_t cur = 0;
        for (std::size_t i = 0; i < text.size(); ++i) {
            const auto c = static_cast<unsigned char>(text[i]);
            cur = nodes_[cur].next[c];               // 一次索引到位,无 while、无回退
            if (!nodes_[cur].output.empty()) {
                for (const std::int32_t id : nodes_[cur].output) {
                    on_hit(Hit{id, i});
                }
            }
        }
    }

    // 收集版:方便小规模使用。命中很多时请用流式接口(第 25 则)。
    [[nodiscard]] std::vector<Hit> search_all(std::string_view text) const {
        std::vector<Hit> hits;
        search(text, [&hits](const Hit& h) { hits.push_back(h); });
        return hits;
    }

    // ---- 查询 ----

    [[nodiscard]] std::size_t node_count() const noexcept { return nodes_.size(); }
    [[nodiscard]] std::size_t pattern_count() const noexcept { return patterns_.size(); }
    [[nodiscard]] std::size_t pattern_total_len() const noexcept { return total_len_; }
    [[nodiscard]] const std::string& pattern(std::int32_t id) const { return patterns_[id]; }
    [[nodiscard]] bool built() const noexcept { return built_; }

    // 内存占用:每节点一块 256 项转移表(第 26 则的内存预算)
    [[nodiscard]] std::size_t memory_bytes() const noexcept {
        std::size_t n = nodes_.size() * sizeof(Node);
        for (const auto& nd : nodes_) n += nd.output.capacity() * sizeof(std::int32_t);
        for (const auto& p : patterns_) n += p.capacity();
        return n;
    }

    void reserve(std::size_t node_hint) { nodes_.reserve(node_hint); }
    void set_max_pattern_len(std::size_t n) noexcept { max_pattern_len_ = n; }

private:
    std::vector<Node> nodes_;
    std::vector<std::string> patterns_;
    std::size_t total_len_ = 0;
    std::size_t max_pattern_len_ = 4096;   // 超长模式拒收(第 13 则)
    bool built_ = false;
};

}  // namespace secguard
