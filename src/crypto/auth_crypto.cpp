#include "crypto/auth_crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstring>
#include <vector>

#include "util/log.h"

namespace secguard::crypto {
namespace {

constexpr const char* kTag = "[加密] ";
constexpr int kSaltBytes = 16;
constexpr int kHashBytes = 32;

std::string to_hex(const unsigned char* data, std::size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

// 从 base64url 字符串拆出各段
std::vector<std::string> split(std::string_view s, char sep) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == sep) {
            parts.emplace_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return parts;
}

}  // namespace

std::string random_bytes(std::size_t n) {
    std::string out(n, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(out.data()),
                   static_cast<int>(n)) != 1) {
        LOG_ERROR(kTag, "RAND_bytes 失败");
        return {};
    }
    return out;
}

std::string b64url_encode(std::string_view raw) {
    if (raw.empty()) return {};
    std::string out;
    out.resize(4 * ((raw.size() + 2) / 3));
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                  reinterpret_cast<const unsigned char*>(raw.data()),
                                  static_cast<int>(raw.size()));
    out.resize(static_cast<std::size_t>(n));
    // 换成 URL 安全字符并去掉填充
    for (char& c : out) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    while (!out.empty() && out.back() == '=') out.pop_back();
    return out;
}

bool b64url_decode(std::string_view text, std::string& out) {
    if (text.empty()) { out.clear(); return true; }

    // 记下原始长度,用来算真实字节数。
    // 坑:base64url 常常不带 '=' 填充,所以不能靠数 '=' 来定长度 ——
    // 那样算出来的长度会比真实值多(踩过这个坑:256 字节解出 258 字节)。
    const std::size_t original_len = text.size();

    std::string s(text);
    for (char& c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (s.size() % 4 != 0) s.push_back('=');

    out.resize(3 * (s.size() / 4));
    const int n = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                  reinterpret_cast<const unsigned char*>(s.data()),
                                  static_cast<int>(s.size()));
    if (n < 0) return false;

    // 真实字节数由原始字符数决定:每 4 个字符还原 3 字节,
    // 余 2 个字符还原 1 字节,余 3 个字符还原 2 字节。
    const std::size_t real = (original_len / 4) * 3
                           + (original_len % 4 == 2 ? 1
                              : original_len % 4 == 3 ? 2 : 0);
    out.resize(real);
    return true;
}

bool constant_time_equal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string sha256_hex(std::string_view data) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), md);
    return to_hex(md, sizeof(md));
}

std::string hmac_sha256(std::string_view key, std::string_view data) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(),
              key.data(), static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char*>(data.data()), data.size(),
              out, &len)) {
        LOG_ERROR(kTag, "HMAC 失败");
        return {};
    }
    return std::string(reinterpret_cast<char*>(out), len);
}

// ---------------------------------------------------------------------------
// 密码
// ---------------------------------------------------------------------------
std::string hash_password(const std::string& password, int iterations) {
    if (iterations < 10000) iterations = 10000;

    const std::string salt = random_bytes(kSaltBytes);
    if (salt.empty()) return {};

    std::array<unsigned char, kHashBytes> hash{};
    // PBKDF2-HMAC-SHA256:内部反复迭代,把"快哈希"变成"慢哈希"
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                          reinterpret_cast<const unsigned char*>(salt.data()),
                          static_cast<int>(salt.size()),
                          iterations, EVP_sha256(),
                          static_cast<int>(hash.size()), hash.data()) != 1) {
        LOG_ERROR(kTag, "PBKDF2 失败");
        return {};
    }

    return "pbkdf2$sha256$" + std::to_string(iterations) + "$"
         + b64url_encode(salt) + "$"
         + b64url_encode(std::string(reinterpret_cast<char*>(hash.data()), hash.size()));
}

bool verify_password(const std::string& password, const std::string& stored) {
    const auto parts = split(stored, '$');
    if (parts.size() != 5 || parts[0] != "pbkdf2" || parts[1] != "sha256") {
        LOG_ERROR(kTag, "密码哈希格式不认识");
        return false;
    }
    int iterations = 0;
    {
        const auto& s = parts[2];
        auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), iterations);
        if (ec != std::errc() || p != s.data() + s.size() || iterations < 10000) {
            LOG_ERROR(kTag, "密码哈希里的迭代数不合法");
            return false;
        }
    }
    std::string salt, want;
    if (!b64url_decode(parts[3], salt) || !b64url_decode(parts[4], want)) {
        LOG_ERROR(kTag, "密码哈希里的 base64 解不开");
        return false;
    }

    std::array<unsigned char, kHashBytes> got{};
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                          reinterpret_cast<const unsigned char*>(salt.data()),
                          static_cast<int>(salt.size()),
                          iterations, EVP_sha256(),
                          static_cast<int>(got.size()), got.data()) != 1) {
        return false;
    }
    const std::string got_str(reinterpret_cast<char*>(got.data()), got.size());
    // 定长比较:别用 == ,那会泄露"前几个字节对不对"
    return constant_time_equal(got_str, want);
}

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------
std::int64_t now_unix() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

namespace {
std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    // 控制字符一律丢掉,别让它破坏 JSON
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}
}  // namespace

std::string jwt_sign(const JwtClaims& claims, const std::string& secret) {
    const std::string header = R"({"alg":"HS256","typ":"JWT"})";

    std::string payload = "{";
    payload += "\"sub\":" + std::to_string(claims.user_id);
    payload += ",\"name\":\"" + json_escape(claims.username) + "\"";
    payload += ",\"iat\":" + std::to_string(claims.issued_at);
    payload += ",\"exp\":" + std::to_string(claims.expires_at);
    payload += "}";

    const std::string signing_input =
        b64url_encode(header) + "." + b64url_encode(payload);
    const std::string sig = hmac_sha256(secret, signing_input);
    if (sig.empty()) return {};
    return signing_input + "." + b64url_encode(sig);
}

JwtStatus jwt_verify(std::string_view token, const std::string& secret,
                     JwtClaims& out) {
    const auto parts = split(token, '.');
    if (parts.size() != 3) return JwtStatus::kMalformed;

    // 第一步:验签名 —— 改了内容签名就对不上,攻击者没有密钥(第 44 讲)
    const std::string signing_input = parts[0] + "." + parts[1];
    const std::string expect = hmac_sha256(secret, signing_input);
    std::string got;
    if (!b64url_decode(parts[2], got)) return JwtStatus::kMalformed;
    if (!constant_time_equal(expect, got)) return JwtStatus::kBadSignature;

    // 第二步:取内容
    std::string payload;
    if (!b64url_decode(parts[1], payload)) return JwtStatus::kMalformed;

    auto pick_int = [&payload](const std::string& key, std::int64_t& v) -> bool {
        const std::string needle = "\"" + key + "\":";
        const auto pos = payload.find(needle);
        if (pos == std::string::npos) return false;
        const char* begin = payload.data() + pos + needle.size();
        const char* end = payload.data() + payload.size();
        auto [p, ec] = std::from_chars(begin, end, v);
        return ec == std::errc();
    };
    auto pick_str = [&payload](const std::string& key, std::string& v) -> bool {
        const std::string needle = "\"" + key + "\":\"";
        const auto pos = payload.find(needle);
        if (pos == std::string::npos) return false;
        const std::size_t b = pos + needle.size();
        std::string acc;
        for (std::size_t i = b; i < payload.size(); ++i) {
            if (payload[i] == '\\' && i + 1 < payload.size()) { acc.push_back(payload[++i]); continue; }
            if (payload[i] == '"') { v = acc; return true; }
            acc.push_back(payload[i]);
        }
        return false;
    };

    if (!pick_int("sub", out.user_id)) return JwtStatus::kMalformed;
    if (!pick_int("exp", out.expires_at)) return JwtStatus::kMalformed;
    pick_int("iat", out.issued_at);
    pick_str("name", out.username);

    // 第三步:看过期
    if (out.expires_at <= now_unix()) return JwtStatus::kExpired;
    return JwtStatus::kOk;
}

}  // namespace secguard::crypto
