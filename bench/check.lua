-- 检测接口压测脚本
--
-- /api/check 只做特征检测、不落业务数据,是"纯检测链路"的代表。
-- 把它和 /?q=... 对比,可以分离出"业务逻辑"与"审计落库"的成本。
--
-- wrk -t4 -c64 -d10s --latency -s bench/check.lua http://127.0.0.1:8099

wrk.method = "POST"
wrk.path   = "/api/check"
wrk.headers["Content-Type"] = "application/json"
wrk.body   = '{"payload":"GET /index.html HTTP/1.1 Host: example.com User-Agent: Mozilla/5.0"}'
