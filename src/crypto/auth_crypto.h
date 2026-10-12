// 密码哈希与 JWT(寓言集第 43~45 讲)
//
// 设计要点:
//   密码 —— PBKDF2-HMAC-SHA256 + 每用户随机盐 + 可调迭代轮数
//           "故意算得慢":你一辈子算一次,攻击者要算几十亿次(第 43 讲)
//   令牌 —— HMAC-SHA256 签名的 JWT
//           签名只保证"没被改",不保证"看不见" -> 内容里不放敏感信息(第 44 讲)
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace secguard::crypto {

// 密码学安全随机字节
[[nodiscard]] std::string random_bytes(std::size_t n);
// URL 安全的 base64(无填充)
[[nodiscard]] std::string b64url_encode(std::string_view raw);
[[nodiscard]] bool b64url_decode(std::string_view text, std::string& out);

// 密码哈希,输出格式:pbkdf2$sha256$<iter>$<salt_b64>$<hash_b64>
// 把算法与参数一起存进去,将来换算法能平滑迁移(第 43 讲)
[[nodiscard]] std::string hash_password(const std::string& password, int iterations);
[[nodiscard]] bool verify_password(const std::string& password,
                                   const std::string& stored);

[[nodiscard]] std::string hmac_sha256(std::string_view key, std::string_view data);
[[nodiscard]] std::string sha256_hex(std::string_view data);

// 定长比较,防时序侧信道
[[nodiscard]] bool constant_time_equal(std::string_view a, std::string_view b);

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------
struct JwtClaims {
    std::int64_t user_id = 0;
    std::string  username;
    std::int64_t issued_at = 0;    // unix 秒
    std::int64_t expires_at = 0;   // unix 秒
};

// 签发。返回 "" 表示失败。
[[nodiscard]] std::string jwt_sign(const JwtClaims& claims, const std::string& secret);

enum class JwtStatus { kOk, kMalformed, kBadSignature, kExpired };

// 校验:验签名 -> 看过期 -> 取内容(第 44 讲的三步)
JwtStatus jwt_verify(std::string_view token, const std::string& secret,
                     JwtClaims& out);

[[nodiscard]] std::int64_t now_unix();

}  // namespace secguard::crypto
