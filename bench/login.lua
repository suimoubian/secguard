-- 登录压测脚本
--
-- 为什么登录要单独压:口令哈希是**故意算得慢**的(PBKDF2 12 万轮),
-- 它必然成为最慢的接口。这个数字不是缺陷,而是设计意图 ——
-- 慢是为了让爆破不划算。压测是为了知道"慢到什么程度",
-- 从而决定登录接口要不要单独限流。
--
-- wrk -t2 -c8 -d10s --latency -s bench/login.lua http://127.0.0.1:8099

wrk.method = "POST"
wrk.path   = "/api/login"
wrk.headers["Content-Type"] = "application/json"
wrk.body   = '{"username":"benchuser","password":"bench-password-2026"}'
