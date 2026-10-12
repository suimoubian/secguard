// 单元自检:密码哈希、JWT、引擎匹配、HTTP->文本翻译
// 用来把"端到端失败"定位到具体模块
#include <cstdio>
#include <string>

#include "crypto/auth_crypto.h"
#include "engine.h"
#include "net/app_context.h"

using namespace secguard;

static int g_fail = 0;
static void check(bool ok, const char* what) {
    std::printf("  %-52s %s\n", what, ok ? "通过" : "失败");
    if (!ok) ++g_fail;
}

int main() {
    std::printf("=== 1. 密码哈希 ===\n");
    {
        const std::string pw = "correct-horse-battery";
        const std::string h = crypto::hash_password(pw, 100000);
        std::printf("  哈希串: %s\n", h.c_str());
        check(!h.empty(), "哈希非空");
        check(h.rfind("pbkdf2$sha256$100000$", 0) == 0, "前缀与迭代数正确");
        check(crypto::verify_password(pw, h), "正确口令验证通过");
        check(!crypto::verify_password("wrong", h), "错误口令被拒");
        // 同一个口令两次哈希应该不同(盐不同)
        const std::string h2 = crypto::hash_password(pw, 100000);
        check(h != h2, "两次哈希不同(盐随机)");
    }

    std::printf("\n=== 2. JWT ===\n");
    {
        const std::string secret = "test-secret-1234567890";
        crypto::JwtClaims c;
        c.user_id = 42;
        c.username = "alice";
        c.issued_at = crypto::now_unix();
        c.expires_at = c.issued_at + 3600;
        const std::string tok = crypto::jwt_sign(c, secret);
        std::printf("  令牌: %s\n", tok.c_str());
        check(!tok.empty(), "签发成功");

        crypto::JwtClaims out;
        check(crypto::jwt_verify(tok, secret, out) == crypto::JwtStatus::kOk, "校验通过");
        check(out.user_id == 42, "user_id 正确");
        check(out.username == "alice", "username 正确");
        check(crypto::jwt_verify(tok, "wrong-secret", out) == crypto::JwtStatus::kBadSignature,
              "换密钥 -> 签名错");
        check(crypto::jwt_verify(tok + "x", secret, out) == crypto::JwtStatus::kBadSignature,
              "改动令牌 -> 签名错");

        // 过期
        crypto::JwtClaims e = c;
        e.expires_at = crypto::now_unix() - 10;
        const std::string expired = crypto::jwt_sign(e, secret);
        check(crypto::jwt_verify(expired, secret, out) == crypto::JwtStatus::kExpired,
              "过期令牌被拒");
    }

    std::printf("\n=== 3. 引擎匹配(直接喂文本)===\n");
    {
        Config cfg;
        cfg.engine.pattern_file = "rules/attack_patterns.txt";
        Engine eng;
        std::string err;
        const bool loaded = eng.load_from_file(cfg.engine.pattern_file, cfg.engine, err);
        check(loaded, "特征库载入");
        if (!loaded) { std::printf("  错误: %s\n", err.c_str()); return 1; }
        std::printf("  规则 %zu 条,节点 %zu 个\n", eng.rule_count(), eng.node_count());

        struct Case { const char* text; bool should_hit; const char* note; };
        const Case cases[] = {
            {"union select 1,2,3",           true,  "SQL 注入"},
            {"1' or '1'='1",                 true,  "布尔盲注"},
            {"<script>alert(1)</script>",    true,  "XSS"},
            {"../../../../etc/passwd",       true,  "路径穿越"},
            {"; cat /etc/passwd",            true,  "命令注入"},
            {"hello world normal text",      false, "正常文本"},
            {"this is a shopping list",      false, "正常英文"},
        };
        for (const auto& c : cases) {
            const auto mr = eng.search(c.text);
            const bool hit = !mr.rule_indices.empty();
            char buf[256];
            std::snprintf(buf, sizeof(buf), "%s -> %s (%s)", c.text,
                          hit ? "命中" : "未命中", c.note);
            check(hit == c.should_hit, buf);
            if (hit) {
                std::printf("        规则: ");
                for (std::size_t i = 0; i < mr.rule_indices.size() && i < 4; ++i) {
                    std::printf("%s ", eng.rule(mr.rule_indices[i]).id.c_str());
                }
                std::printf("\n");
            }
        }
    }

    std::printf("\n=== 4. HTTP -> 待检文本 的翻译 ===\n");
    {
        bool truncated = false;
        const std::string t = build_scan_text("/api/posts", "id=1' or '1'='1",
                                              "{\"title\":\"<script>\"}",
                                              "Mozilla/5.0", 64 * 1024, truncated);
        std::printf("  翻译结果:\n%s\n", t.c_str());
        check(t.find("id=1' or '1'='1") != std::string::npos, "查询串进了待检文本");
        check(t.find("<script>") != std::string::npos, "请求体进了待检文本");
        check(!truncated, "未截断");
    }

    std::printf("\n=== 5. Guard 封禁逻辑 ===\n");
    {
        Guard g;
        bool banned = false;
        for (int i = 0; i < 5; ++i) {
            banned = g.record_hit("1.2.3.4", 100.0 + i * 0.1, 60, 5, 10);
        }
        check(banned, "窗口内命中 5 次触发封禁");
        check(g.is_banned("1.2.3.4", 105.0), "封禁期内判定为封禁");
        check(!g.is_banned("1.2.3.4", 200.0), "封禁期过后自动解除");
        check(!g.is_banned("9.9.9.9", 105.0), "别的 IP 不受影响");
    }

    std::printf("\n=== 6. params_digest 脱敏 ===\n");
    {
        const std::string d1 = build_params_digest("a=1", "b=2");
        const std::string d2 = build_params_digest("a=1", "b=2");
        const std::string d3 = build_params_digest("a=1", "b=3");
        std::printf("  digest: %s\n", d1.c_str());
        check(d1 == d2, "同样输入摘要相同");
        check(d1 != d3, "不同输入摘要不同");
        check(d1.find("b=2") == std::string::npos, "原文不出现在摘要里");
    }

    std::printf("\n============================\n");
    if (g_fail == 0) { std::printf("全部通过\n"); return 0; }
    std::printf("失败 %d 处\n", g_fail);
    return 1;
}
