// 最小验证:base64url 编解码 + PBKDF2 往返
#include <cstdio>
#include <string>

#include "crypto/auth_crypto.h"

using namespace secguard;

int main() {
    int fail = 0;
    auto check = [&](bool ok, const char* what) {
        std::printf("  %-46s %s\n", what, ok ? "通过" : "失败");
        if (!ok) ++fail;
    };

    std::printf("=== base64url 往返 ===\n");
    const char* samples[] = {
        "",
        "a",
        "ab",
        "abc",
        "abcd",
        "hello",
        "hello world",
        "{\"sub\":42,\"name\":\"alice\"}",
        "\x00\x01\x02\xff\xfe",                  // 含不可打印字节
    };
    for (const char* s : samples) {
        const std::string raw(s, std::char_traits<char>::length(s));
        // 含 \x00 的样本用 strlen 截断了,这里只测能测的
        const std::string enc = crypto::b64url_encode(raw);
        std::string dec;
        const bool ok = crypto::b64url_decode(enc, dec);
        const bool same = (dec == raw);
        std::printf("  %-24s enc=%-30s dec_ok=%d same=%d\n",
                    raw.empty() ? "(空)" : raw.c_str(), enc.c_str(),
                    static_cast<int>(ok), static_cast<int>(same));
        if (!same) ++fail;
    }

    std::printf("\n=== 二进制往返(含 0x00 与高位字节)===\n");
    {
        std::string raw;
        for (int i = 0; i < 256; ++i) raw.push_back(static_cast<char>(i));
        const std::string enc = crypto::b64url_encode(raw);
        std::string dec;
        const bool ok = crypto::b64url_decode(enc, dec);
        std::printf("  256 字节:enc 长度=%zu dec 长度=%zu ok=%d 一致=%d\n",
                    enc.size(), dec.size(), static_cast<int>(ok),
                    static_cast<int>(dec == raw));
        check(ok && dec == raw, "256 字节全值往返一致");
    }

    std::printf("\n=== PBKDF2 往返 ===\n");
    {
        const std::string pw = "correct-horse-battery";
        const std::string h = crypto::hash_password(pw, 100000);
        std::printf("  哈希: %s\n", h.c_str());

        // 手工把哈希拆开,一步步查
        const auto p1 = h.find('$');
        const auto p2 = h.find('$', p1 + 1);
        const auto p3 = h.find('$', p2 + 1);
        const auto p4 = h.find('$', p3 + 1);
        std::printf("  分段: alg=%s  hash=%s  iter=%s  salt_len=%zu  hash_len=%zu\n",
                    h.substr(0, p1).c_str(),
                    h.substr(p1 + 1, p2 - p1 - 1).c_str(),
                    h.substr(p2 + 1, p3 - p2 - 1).c_str(),
                    p4 - p3 - 1,
                    h.size() - p4 - 1);

        std::string salt, want;
        const bool salt_ok = crypto::b64url_decode(h.substr(p3 + 1, p4 - p3 - 1), salt);
        const bool hash_ok = crypto::b64url_decode(h.substr(p4 + 1), want);
        std::printf("  salt 解码=%d 长度=%zu;hash 解码=%d 长度=%zu(应为 32)\n",
                    static_cast<int>(salt_ok), salt.size(),
                    static_cast<int>(hash_ok), want.size());
        check(salt_ok && salt.size() == 16, "盐解码为 16 字节");
        check(hash_ok && want.size() == 32, "哈希解码为 32 字节");

        check(crypto::verify_password(pw, h), "正确口令验证通过");
        check(!crypto::verify_password(pw + "x", h), "多一个字符被拒");
    }

    std::printf("\n失败 %d 处\n", fail);
    return fail == 0 ? 0 : 1;
}
