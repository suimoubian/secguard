// 单元自检:密码 / JWT / 引擎 / 翻译 / 防护 / 无锁队列
// 用来把"端到端失败"定位到具体模块

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include "cache/distributed_guard.h"
#include "cache/redis_client.h"
#include "crypto/auth_crypto.h"
#include "engine.h"
#include "net/app_context.h"
#include "util/mpsc_queue.h"

using namespace secguard;

static int g_fail = 0;
static void check(bool ok, const char* what) {
    std::printf("  %-52s %s\n", what, ok ? "通过" : "失败");
    if (!ok) ++g_fail;
}

// ---------------------------------------------------------------------------
int main() {
    std::printf("=== 1. 密码哈希 ===\n");
    {
        const std::string pw = "correct-horse-battery";
        const std::string h = crypto::hash_password(pw, 100000);
        check(!h.empty(), "哈希非空");
        check(h.rfind("pbkdf2$sha256$100000$", 0) == 0, "前缀与迭代数正确");
        check(crypto::verify_password(pw, h), "正确口令验证通过");
        check(!crypto::verify_password("wrong", h), "错误口令被拒");
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
        check(!tok.empty(), "签发成功");

        crypto::JwtClaims out;
        check(crypto::jwt_verify(tok, secret, out) == crypto::JwtStatus::kOk, "校验通过");
        check(out.user_id == 42, "user_id 正确");
        check(out.username == "alice", "username 正确");
        check(crypto::jwt_verify(tok, "wrong-secret", out) == crypto::JwtStatus::kBadSignature,
              "换密钥 -> 签名错");
        check(crypto::jwt_verify(tok + "x", secret, out) == crypto::JwtStatus::kBadSignature,
              "改动令牌 -> 签名错");

        crypto::JwtClaims e = c;
        e.expires_at = crypto::now_unix() - 10;
        const std::string expired = crypto::jwt_sign(e, secret);
        check(crypto::jwt_verify(expired, secret, out) == crypto::JwtStatus::kExpired,
              "过期令牌被拒");
    }

    std::printf("\n=== 3. 引擎匹配 ===\n");
    {
        Config cfg;
        cfg.engine.pattern_file = "rules/attack_patterns.txt";
        Engine eng;
        std::string err;
        if (!eng.load_from_file(cfg.engine.pattern_file, cfg.engine, err)) {
            std::printf("  特征库载入失败: %s\n", err.c_str());
            ++g_fail;
        } else {
            check(true, "特征库载入");
            std::printf("  规则 %zu 条,节点 %zu 个\n", eng.rule_count(), eng.node_count());

            struct Case { const char* text; bool should_hit; };
            const Case cases[] = {
                {"union select 1,2,3",        true},
                {"1' or '1'='1",              true},
                {"<script>alert(1)</script>", true},
                {"../../../../etc/passwd",    true},
                {"; cat /etc/passwd",         true},
                {"hello world normal text",   false},
                {"this is a shopping list",   false},
            };
            for (const auto& c : cases) {
                const auto mr = eng.search(c.text);
                const bool hit = !mr.rule_indices.empty();
                char buf[256];
                std::snprintf(buf, sizeof(buf), "%s -> %s", c.text, hit ? "命中" : "未命中");
                check(hit == c.should_hit, buf);
            }
        }
    }

    std::printf("\n=== 4. HTTP -> 待检文本 ===\n");
    {
        bool truncated = false;
        const std::string t = build_scan_text("/api/posts", "id=1' or '1'='1",
                                              "{\"title\":\"<script>\"}",
                                              "Mozilla/5.0", 64 * 1024, truncated);
        check(t.find("id=1' or '1'='1") != std::string::npos, "查询串进了待检文本");
        check(t.find("<script>") != std::string::npos, "请求体进了待检文本");
        check(!truncated, "未截断");
    }

    std::printf("\n=== 5. 登录爆破防护 ===\n");
    {
        LoginThrottle lt;
        bool locked = false;
        for (int i = 0; i < 5; ++i) {
            locked = lt.record_fail("1.2.3.4:alice", 300, 5);
        }
        check(locked, "连续失败 5 次触发锁定");
        check(lt.is_locked("1.2.3.4:alice", 300, 5), "锁定状态可查");
        lt.clear("1.2.3.4:alice");
        check(!lt.is_locked("1.2.3.4:alice", 300, 5), "清除后解锁");
        check(!lt.is_locked("9.9.9.9:bob", 300, 5), "别的 key 不受影响");
    }

    std::printf("\n=== 6. params_digest 脱敏 ===\n");
    {
        const std::string d1 = build_params_digest("a=1", "b=2");
        const std::string d2 = build_params_digest("a=1", "b=2");
        const std::string d3 = build_params_digest("a=1", "b=3");
        check(d1 == d2, "同样输入摘要相同");
        check(d1 != d3, "不同输入摘要不同");
        check(d1.find("b=2") == std::string::npos, "原文不出现在摘要里");
    }

    std::printf("\n=== 7. 无锁 MPSC 队列 ===\n");
    {
        MpscQueue<int, 1024> q;

        check(q.push(1) && q.push(2) && q.push(3), "入队三条");
        int v = 0;
        check(q.pop(v) && v == 1, "出队顺序 1");
        check(q.pop(v) && v == 2, "出队顺序 2");
        check(q.pop(v) && v == 3, "出队顺序 3");
        check(!q.pop(v), "空了返回 false");

        // 容量边界:容量 8 的队列塞 20 条,只应接受 8 条
        MpscQueue<int, 8> small;
        int accepted = 0;
        for (int i = 0; i < 20; ++i) {
            if (small.push(i)) ++accepted;
        }
        check(accepted == 8, "容量 8 的队列只收 8 条,其余返回 false");

        // 多生产者 + 单消费者:8 个线程各推 10000 条,校验和必须一条不差
        MpscQueue<std::uint64_t, 1 << 16> big;
        constexpr int kThreads = 8;
        constexpr int kPerThread = 10000;
        std::atomic<std::uint64_t> consumed_sum{0};

        std::thread consumer([&] {
            std::uint64_t sum = 0;
            std::size_t count = 0;
            const std::size_t want = static_cast<std::size_t>(kThreads) * kPerThread;
            while (count < want) {
                std::uint64_t x = 0;
                if (big.pop(x)) { sum += x; ++count; }
            }
            consumed_sum.store(sum);
        });

        std::vector<std::thread> producers;
        for (int t = 0; t < kThreads; ++t) {
            producers.emplace_back([&big, t] {
                for (int i = 0; i < kPerThread; ++i) {
                    std::uint64_t val = static_cast<std::uint64_t>(t) * kPerThread + i + 1;
                    while (!big.push(val)) std::this_thread::yield();   // 满了重试
                }
            });
        }
        for (auto& p : producers) p.join();
        consumer.join();

        std::uint64_t expect = 0;
        for (int t = 0; t < kThreads; ++t) {
            for (int i = 0; i < kPerThread; ++i) {
                expect += static_cast<std::uint64_t>(t) * kPerThread + i + 1;
            }
        }
        check(consumed_sum.load() == expect,
              "8x1万条:校验和一致(无丢失、无重复)");
        std::printf("        收到总和=%llu 期望=%llu\n",
                    static_cast<unsigned long long>(consumed_sum.load()),
                    static_cast<unsigned long long>(expect));
    }

    std::printf("\n=== 8. 重放防护 ===\n");
    {
        const auto now = static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        check(DistributedGuard::timestamp_fresh(now, 300), "当前时间戳新鲜");
        check(DistributedGuard::timestamp_fresh(now - 100, 300), "100 秒前仍新鲜");
        check(!DistributedGuard::timestamp_fresh(now - 1000, 300), "1000 秒前已过期");
        check(!DistributedGuard::timestamp_fresh(now + 600, 300), "超前太多被拒");

        // nonce 只能用一次(无 Redis 时走本地降级,语义一致)
        Config cfg;
        cfg.redis.enabled = false;
        RedisClient no_redis(cfg.redis);
        DistributedGuard guard(&no_redis, cfg.guard);

        check(guard.consume_nonce("nonce-abc-123", 60), "首次使用 nonce 放行");
        check(!guard.consume_nonce("nonce-abc-123", 60), "同一 nonce 第二次被拒(重放)");
        check(guard.consume_nonce("nonce-def-456", 60), "换一个 nonce 放行");
        check(!guard.consume_nonce(std::string(), 60), "空 nonce 被拒");
    }

    std::printf("\n=== 9. 分布式防护(有 Redis 走共享,无则降级)===\n");
    {
        Config cfg;
        cfg.redis.host = "127.0.0.1";
        cfg.redis.port = 6379;
        cfg.redis.timeout_ms = 300;
        RedisClient redis(cfg.redis);
        if (redis.available()) {
            std::printf("  Redis 可用,使用共享状态\n");
            check(redis.ping(), "Redis PING 通");
        } else {
            std::printf("  Redis 不可用,本次走降级路径\n");
        }

        GuardConfig gc;
        gc.rate_per_sec = 10.0;
        gc.burst = 5.0;
        gc.hit_threshold = 3;
        gc.window_seconds = 60;
        gc.ban_seconds = 2;

        DistributedGuard guard(&redis, gc);

        // 用独特 key,避免与其他测试/上次残留互相干扰
        const std::string key = "unittest-" + std::to_string(::getpid());
        const std::vector<std::string> cleanup = {
            "DEL", "sg:rl:" + key, "sg:hit:" + key, "sg:ban:" + key};
        if (redis.available()) redis.exec(cleanup);

        int allowed = 0;
        for (int i = 0; i < 8; ++i) {
            if (guard.allow(key)) ++allowed;
        }
        check(allowed == 5, "突发容量 5:连续 8 次只放行 5 次");
        std::printf("        放行 %d / 8\n", allowed);

        bool banned = false;
        for (int i = 0; i < 3; ++i) {
            banned = guard.record_hit(key, 3, 60, 2);
        }
        check(banned, "命中 3 次触发封禁");
        check(guard.is_banned(key), "封禁状态可查");

        if (redis.available()) redis.exec(cleanup);
    }

    std::printf("\n============================\n");
    if (g_fail == 0) { std::printf("全部通过\n"); return 0; }
    std::printf("失败 %d 处\n", g_fail);
    return 1;
}
