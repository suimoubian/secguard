// UTF-8 安全的字符串截断
//
// 为什么需要:大量代码习惯写 `s.substr(0, N)` 来限长。对 ASCII 没问题,
// 但对中文就是错的 —— 一个汉字占 3 个字节,按字节切正好切在字符中间,
// 留下一个孤立的引导字节(0xE0~0xEF),整个字符串就成了非法 UTF-8。
//
// 实测踩过:聚合告警时 `reasoning.substr(0, 200) + "…"` 把某个汉字的
// 3 个字节切成 1 个,MySQL 直接报
//   code=1366 Incorrect string value: '\xE9\xE2\x80\xA6' for column 'reasoning'
// 告警写不进库,而日志里只有一句"写聚合告警失败",查了很久。
//
// 用法:把 `s.substr(0, N)` 换成 `utf8::truncate(s, N)` 即可,
// 语义一致(最多 N 字节),但保证不会切断字符。
#pragma once

#include <string>
#include <string_view>

namespace secguard::utf8 {

// 返回最多 max_bytes 字节的前缀,且保证不切断 UTF-8 字符。
// 若 max_bytes 落在字符中间,会回退到该字符的起始位置
// (所以结果可能比 max_bytes 短 1~3 字节,这是正确行为)。
[[nodiscard]] inline std::string truncate(std::string_view s, std::size_t max_bytes) {
    if (s.size() <= max_bytes) return std::string(s);

    std::size_t n = max_bytes;
    // UTF-8 续字节的形态是 10xxxxxx(0x80~0xBF)。
    // 往前退,直到落在一个字符的首字节上(或退到 0)。
    while (n > 0) {
        const auto c = static_cast<unsigned char>(s[n]);
        if ((c & 0xC0) != 0x80) break;   // 不是续字节 -> n 就是字符边界
        --n;
    }
    return std::string(s.substr(0, n));
}

// 截断并追加省略号(同样保证不切断字符)。
[[nodiscard]] inline std::string truncate_with_ellipsis(std::string_view s,
                                                        std::size_t max_bytes,
                                                        std::string_view ellipsis = "…") {
    if (s.size() <= max_bytes) return std::string(s);
    return truncate(s, max_bytes) + std::string(ellipsis);
}

}  // namespace secguard::utf8
