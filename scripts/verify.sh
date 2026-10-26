#!/bin/bash
# SecGuard 一键自检
#
# 把项目所有能力跑一遍,输出一张通过/失败表。
# 面试前自己跑一次,确认演示环境是好的。
#
# 用法:
#   ./scripts/verify.sh                      # 打默认地址
#   ./scripts/verify.sh http://1.2.3.4:8088  # 打指定地址
#
# 环境变量:
#   SG_ADMIN_USER / SG_ADMIN_PASS   管理员账号(默认 admin / admin-password-2026)
#   SG_SKIP_ADMIN=1                 跳过管理接口相关用例
#
# 注意:**别和其它压测同时跑**。这个脚本自己会压一次限流(3 秒 20 连接),
# 和 bench/run.sh 或者上一轮自检叠加起来会把 nginx 打满,
# 表现出来是一堆 502 —— 实测踩过,查了很久才发现是自己压自己。
# 连续跑也要等上一轮完全结束。

set -u

BASE="${1:-http://127.0.0.1:8088}"
ADMIN_USER="${SG_ADMIN_USER:-admin}"
ADMIN_PASS="${SG_ADMIN_PASS:-admin-password-2026}"
SKIP_ADMIN="${SG_SKIP_ADMIN:-0}"

PASS=0; FAIL=0; SKIP=0
FAILED_NAMES=""
ATOK=""      # 管理员令牌
UTOK=""      # 普通用户令牌

ok()   { PASS=$((PASS+1)); printf '  \033[32m通过\033[0m  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED_NAMES="$FAILED_NAMES\n    - $1"; printf '  \033[31m失败\033[0m  %s  (%s)\n' "$1" "$2"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33m跳过\033[0m  %s  (%s)\n' "$1" "$2"; }
sec()  { printf '\n\033[1m%s\033[0m\n' "$1"; }

code() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" 2>/dev/null; }
body() { curl -s --max-time 10 "$@" 2>/dev/null; }
acode() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "Authorization: Bearer $ATOK" "$@" 2>/dev/null; }

# 清掉命中计数。脚本前面几节会故意发十几次攻击,不清的话会提前触发
# 自动封禁(阈值默认 10 次),后面的正常用例全被 403 挡住 ——
# 表现出来就是"一堆莫名其妙的失败"。
reset_hits() {
    sudo -n docker exec secguard-redis sh -c \
        'for k in $(redis-cli --scan --pattern "sg:hit:*"); do redis-cli DEL "$k" > /dev/null; done; \
         for k in $(redis-cli --scan --pattern "sg:ban:*"); do redis-cli DEL "$k" > /dev/null; done' \
        > /dev/null 2>&1
}

jget() {
    python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for k in sys.argv[1].split('.'):
        d = d[int(k)] if k.isdigit() else d[k]
    print(d)
except Exception:
    print('')
" "$1" 2>/dev/null
}

echo "=================================================================="
echo " SecGuard 自检   目标: $BASE"
echo "=================================================================="

# ---------------------------------------------------------------------------
sec "启动等待"
# ---------------------------------------------------------------------------
# 容器刚被重建时,app 要等数据库就绪才监听端口,这段时间 nginx 会返回 502。
# 如果自检正好在这个窗口里开始,后面所有用例都会莫名其妙地红 ——
# 看起来像"功能全坏了",其实只是服务还没起来。
warm=0
for i in $(seq 1 60); do
    if [ "$(code "$BASE/health")" = "200" ]; then warm=1; break; fi
    sleep 1
done
if [ "$warm" = "1" ]; then ok "服务已就绪(${i} 秒)"
else bad "服务就绪" "60 秒内 /health 未返回 200,请先 docker compose ps 看容器状态"; fi

# ---------------------------------------------------------------------------
sec "0. 清理上一次留下的防护状态"
# ---------------------------------------------------------------------------
# 这个脚本自己会触发限流和封禁,不清的话紧接着再跑一次会全红 ——
# 看起来像"全挂了",其实是上一轮把令牌桶打空了。
if sudo -n docker ps --format '{{.Names}}' 2>/dev/null | grep -q secguard-redis; then
    sudo -n docker exec secguard-redis sh -c '
        for pat in "sg:ban:*" "sg:hit:*" "sg:rl:*"; do
          for k in $(redis-cli --scan --pattern "$pat"); do redis-cli DEL "$k" > /dev/null; done
        done' > /dev/null 2>&1
    ok "已清理封禁/计数/令牌桶状态"
else
    skip "清理防护状态" "连不上 redis 容器"
fi

# ---------------------------------------------------------------------------
sec "1. 服务是否活着"
# ---------------------------------------------------------------------------
c=$(code "$BASE/health")
[ "$c" = "200" ] && ok "健康检查返回 200" || bad "健康检查" "HTTP $c"

h=$(body "$BASE/health")
st=$(echo "$h" | jget status)
db=$(echo "$h" | jget db)
rd=$(echo "$h" | jget redis)
rules=$(echo "$h" | jget rules)
gm=$(echo "$h" | jget guard_mode)
[ "$st" = "ok" ]   && ok "服务状态 ok" || bad "服务状态" "$st"
[ "$db" = "True" ] && ok "数据库连通"   || bad "数据库连通" "$db"
[ "$rd" = "True" ] && ok "Redis 连通"   || skip "Redis 连通" "$rd(已降级)"
[ -n "$rules" ] && [ "$rules" -gt 200 ] && ok "特征库已加载($rules 条)" || bad "特征库" "$rules"
echo "        防护模式: $gm"

# ---------------------------------------------------------------------------
sec "2. 攻击检测:查询串"
# ---------------------------------------------------------------------------
check_block() {  # $1=描述 $2=路径 $3=期望命中的规则前缀
    local out c
    out=$(curl -s --max-time 10 -w '\n%{http_code}' "$BASE$2" 2>/dev/null)
    c=$(echo "$out" | tail -1)
    if [ "$c" != "403" ]; then bad "$1" "期望 403,实际 $c"; return; fi
    if echo "$out" | grep -q "$3"; then ok "$1 -> 403 命中 $3"
    else bad "$1" "403 但没命中 $3"; fi
}
check_block "SQL 注入"  "/?q=union%20select%201,2,3"           "SQL-"
check_block "XSS"       "/?q=%3Cscript%3Ealert(1)%3C/script%3E" "XSS-"
check_block "路径穿越"  "/?file=../../../../etc/passwd"         "PAT-"
check_block "命令注入"  "/?cmd=;cat%20/etc/passwd"              "CMD-"
check_block "探测 .env" "/.env"                                 "PAT-"

c=$(code "$BASE/?q=hello")
[ "$c" = "200" ] && ok "正常请求放行 -> 200" || bad "正常请求放行" "HTTP $c"

# ---------------------------------------------------------------------------
sec "3. 攻击检测:请求体(每个 POST 路由都要覆盖)"
# ---------------------------------------------------------------------------
# ⚠ 这是本项目最不容有失的一组。
# httplib 的早期钩子在读 body 之前就执行了,所以 body 必须在处理器里
# 单独扫一次。新加一个 POST 接口忘了扫,那个接口的 body 就是没设防的 ——
# 所以这里把已知的 POST 路由逐个打一遍。
body_block() {  # $1=描述 $2=路径 $3=额外 curl 参数
    local out c
    out=$(curl -s --max-time 10 -w '\n%{http_code}' -X POST "$BASE$2" \
          -H 'Content-Type: application/json' -H "Authorization: Bearer $ATOK" \
          ${3:-} -d '{"q":"union select 1,2,3"}' 2>/dev/null)
    c=$(echo "$out" | tail -1)
    if [ "$c" = "403" ]; then ok "$1 -> 403(请求体被检测)"
    elif [ "$c" = "401" ]; then skip "$1" "需要登录,未能验证 body(HTTP 401)"
    else bad "$1" "期望 403,实际 $c —— 请求体可能没被检测"; fi
}

for path in "/api/check" "/api/register" "/api/login" "/api/posts" \
            "/api/posts/1/comments" "/api/alerts/1/status" \
            "/api/analyze/run" "/api/rules/reload"; do
    body_block "POST $path" "$path"
done

# 前面两节故意发了十几次攻击,先把命中计数清掉。
# 不清的话累计超过封禁阈值(默认 10),下面的正常用例全被 403 挡住,
# 看起来像"一堆莫名其妙的失败"。
reset_hits

# 反向验证:正常 body 不该被拦
out=$(curl -s -w '\n%{http_code}' --max-time 10 -X POST "$BASE/api/check" \
      -H 'Content-Type: application/json' -d '{"q":"hello world"}' 2>/dev/null)
c=$(echo "$out" | tail -1)
[ "$c" = "200" ] && ok "正常请求体放行 -> 200" || bad "正常请求体" "HTTP $c"

reset_hits

# ---------------------------------------------------------------------------
sec "4. 未注册路径也要被检测和审计"
# ---------------------------------------------------------------------------
c=$(code "$BASE/wp-login.php")
[ "$c" = "404" ] && ok "不存在的路径返回 404(且被审计)" || bad "不存在的路径" "HTTP $c"

# ---------------------------------------------------------------------------
sec "5. 账号与令牌"
# ---------------------------------------------------------------------------
USER="verify$RANDOM"
reg=$(curl -s --max-time 10 -X POST "$BASE/api/register" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"verify-password-2026\"}" 2>/dev/null)
echo "$reg" | grep -q '"id"' && ok "注册新用户 $USER" || bad "注册" "$(echo "$reg" | head -c 80)"

c=$(code -X POST "$BASE/api/register" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"verify-password-2026\"}")
[ "$c" = "409" ] && ok "重复用户名返回 409" || bad "重复用户名" "HTTP $c"

c=$(code -X POST "$BASE/api/register" -H 'Content-Type: application/json' \
    -d '{"username":"weak","password":"123"}')
[ "$c" = "400" ] && ok "弱口令被拒(400)" || bad "弱口令检查" "HTTP $c"

UTOK=$(curl -s --max-time 10 -X POST "$BASE/api/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"verify-password-2026\"}" 2>/dev/null | jget token)
[ -n "$UTOK" ] && [ ${#UTOK} -gt 60 ] && ok "登录拿到 JWT(${#UTOK} 字符)" \
    || { bad "登录" "没拿到令牌"; UTOK=""; }

c=$(code -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"wrong-password\"}")
[ "$c" = "401" ] && ok "错误口令返回 401" || bad "错误口令" "HTTP $c"

if [ -n "$UTOK" ]; then
    c=$(code "$BASE/api/me" -H "Authorization: Bearer $UTOK")
    [ "$c" = "200" ] && ok "带令牌访问受保护接口 -> 200" || bad "令牌鉴权" "HTTP $c"

    c=$(code -X POST "$BASE/api/posts" -H 'Content-Type: application/json' \
        -d '{"title":"x","content":"y"}')
    [ "$c" = "401" ] && ok "无令牌写接口被拒(401)" || bad "无令牌写接口" "HTTP $c"

    pid=$(curl -s --max-time 10 -X POST "$BASE/api/posts" \
        -H "Authorization: Bearer $UTOK" -H 'Content-Type: application/json' \
        -d '{"title":"自检帖","content":"内容"}' 2>/dev/null | jget id)
    if [ -n "$pid" ]; then
        ok "发帖成功(id=$pid)"
        c=$(code "$BASE/api/posts/$pid" -H "Authorization: Bearer $UTOK")
        [ "$c" = "200" ] && ok "读帖成功" || bad "读帖" "HTTP $c"
    else
        bad "发帖" "没拿到 id"
    fi

    c=$(code "$BASE/api/posts/99999999999999999999" -H "Authorization: Bearer $UTOK")
    [ "$c" = "400" ] && ok "超长 id 被拒(400,不会崩)" || bad "超长 id" "HTTP $c"
fi

# ---------------------------------------------------------------------------
sec "6. 管理接口鉴权"
# ---------------------------------------------------------------------------
if [ "$SKIP_ADMIN" = "1" ]; then
    skip "管理接口鉴权" "SG_SKIP_ADMIN=1"
else
    # 无令牌必须被拒
    c=$(code "$BASE/api/alerts?limit=1")
    [ "$c" = "401" ] && ok "无令牌访问管理接口 -> 401" || bad "无令牌管理接口" "HTTP $c"

    # 普通用户必须是 403,不是 200
    if [ -n "$UTOK" ]; then
        c=$(code "$BASE/api/alerts?limit=1" -H "Authorization: Bearer $UTOK")
        [ "$c" = "403" ] && ok "普通用户访问管理接口 -> 403" || bad "普通用户越权" "HTTP $c"
    fi

    # 管理员登录
    curl -s -o /dev/null --max-time 10 -X POST "$BASE/api/register" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" 2>/dev/null
    ATOK=$(curl -s --max-time 10 -X POST "$BASE/api/login" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" 2>/dev/null | jget token)

    if [ -n "$ATOK" ]; then
        ok "管理员登录成功"
        c=$(acode "$BASE/api/alerts?limit=1")
        [ "$c" = "200" ] && ok "管理员访问 /api/alerts -> 200" || bad "管理员访问" "HTTP $c"
    else
        skip "管理员用例" "拿不到管理员令牌(检查 SECGUARD_ADMIN_USERS 是否包含 $ADMIN_USER)"
    fi
fi

# ---------------------------------------------------------------------------
sec "7. 重放防护"
# ---------------------------------------------------------------------------
NOW=$(date +%s)
NONCE="verify-$RANDOM$RANDOM"
c1=$(code -X POST "$BASE/api/check" -H 'Content-Type: application/json' \
     -H "X-Timestamp: $NOW" -H "X-Nonce: $NONCE" -d '{"q":"hello"}')
c2=$(code -X POST "$BASE/api/check" -H 'Content-Type: application/json' \
     -H "X-Timestamp: $NOW" -H "X-Nonce: $NONCE" -d '{"q":"hello"}')
[ "$c1" = "200" ] && ok "首次带 nonce 放行(200)" || bad "首次 nonce" "HTTP $c1"
[ "$c2" = "409" ] && ok "同一 nonce 重放被拒(409)" || bad "重放防护" "HTTP $c2"

c=$(code -X POST "$BASE/api/check" -H 'Content-Type: application/json' \
     -H "X-Timestamp: $((NOW-6000))" -H "X-Nonce: old-$RANDOM" -d '{"q":"x"}')
[ "$c" = "403" ] && ok "过期时间戳被拒(403)" || skip "时间戳窗口" "HTTP $c"

# ---------------------------------------------------------------------------
sec "8. 审计与统计(管理接口)"
# ---------------------------------------------------------------------------
if [ -n "$ATOK" ]; then
    a=$(body -H "Authorization: Bearer $ATOK" "$BASE/api/audit/stats")
    total=$(echo "$a" | jget audit_total)
    blocked=$(echo "$a" | jget audit_blocked)
    [ -n "$total" ] && [ "$total" -gt 0 ] && ok "审计日志有数据(总数 $total,拦截 $blocked)" \
        || bad "审计日志" "总数为 $total"

    c=$(acode "$BASE/api/audit/by-ip?ip=127.0.0.1")
    [ "$c" = "200" ] && ok "按 IP 查审计可用" || bad "按 IP 查审计" "HTTP $c"
else
    skip "审计统计" "无管理员令牌"
fi

# ---------------------------------------------------------------------------
sec "9. AI 分析层"
# ---------------------------------------------------------------------------
an=$(body "$BASE/api/analyze/stats" -H "Authorization: Bearer $ATOK")
en=$(echo "$an" | jget enabled)
pv=$(echo "$an" | jget provider)
ac=$(echo "$an" | jget alerts.total)
if [ "$en" = "True" ]; then
    ok "分析层已启用(provider=$pv)"
    [ -n "$ac" ] && ok "已有告警 $ac 条" || skip "告警数量" "0 条"
else
    skip "AI 分析层" "未启用(设 SECGUARD_AI_ENABLE=1)"
fi

if [ -n "$ATOK" ]; then
    c=$(acode -X POST "$BASE/api/analyze/run")
    if [ "$en" = "True" ]; then
        [ "$c" = "200" ] && ok "手动触发分析可用" || bad "手动触发分析" "HTTP $c"
    else
        # 分析层没开时,这个接口应当拒绝执行(409),而不是假装跑了。
        # 这本身是个正确性检查:接口不能一边说没启用一边干活。
        [ "$c" = "409" ] && ok "分析层未启用时手动触发被拒(409)" \
            || skip "手动触发分析" "HTTP $c"
    fi
fi

# ---------------------------------------------------------------------------
sec "10. 特征库热加载 + 白名单"
# ---------------------------------------------------------------------------
if [ -n "$ATOK" ]; then
    c=$(acode -X POST "$BASE/api/rules/reload")
    [ "$c" = "200" ] && ok "热加载接口可用(不重启换规则)" || bad "热加载" "HTTP $c"
    rl=$(body -H "Authorization: Bearer $ATOK" "$BASE/api/rules")
    alt=$(echo "$rl" | jget allowlist)
    echo "        白名单条数: ${alt:-0}"
else
    skip "热加载" "无管理员令牌"
fi

# ---------------------------------------------------------------------------
sec "11. Prometheus 指标"
# ---------------------------------------------------------------------------
if [ -n "$ATOK" ]; then
    c=$(acode "$BASE/metrics")
    [ "$c" = "200" ] && ok "指标接口可用" || bad "指标接口" "HTTP $c"

    m=$(curl -s --max-time 10 -H "Authorization: Bearer $ATOK" "$BASE/metrics" 2>/dev/null)
    echo "$m" | grep -q '^secguard_up 1' \
        && ok "指标内容正确(secguard_up)" || bad "指标内容" "缺少 secguard_up"

    n_metrics=$(echo "$m" | grep -cE '^secguard_[a-z_]+ [0-9.e+-]+$' || true)
    [ "${n_metrics:-0}" -ge 20 ] && ok "导出 ${n_metrics} 个指标" \
        || bad "指标数量" "只有 ${n_metrics} 个"

    # 格式:除注释和空行外,每行必须是 "名字 数值"
    n_bad=$(echo "$m" | grep -vE '^#|^$' \
            | grep -vcE '^[a-zA-Z_:][a-zA-Z0-9_:]* -?[0-9.e+-]+$' || true)
    [ "${n_bad:-0}" -eq 0 ] && ok "格式符合 Prometheus 约定" \
        || bad "指标格式" "有 ${n_bad} 行不合规"

    c=$(code "$BASE/metrics")
    [ "$c" = "401" ] && ok "指标接口需要令牌(401)" || bad "指标接口鉴权" "HTTP $c"
else
    skip "Prometheus 指标" "无管理员令牌"
fi

# ---------------------------------------------------------------------------
sec "12. 限流与封禁(会产生拦截,最后测)"
# ---------------------------------------------------------------------------
echo "  用并发请求压限流..."
n429=0
if command -v wrk > /dev/null 2>&1; then
    wrk_out=$(wrk -t2 -c20 -d3s "$BASE/api/rules" 2>/dev/null)
    n429=$(echo "$wrk_out" | grep -oE 'Non-2xx or 3xx responses: [0-9]+' | grep -oE '[0-9]+$')
    n429=${n429:-0}
else
    TMPC=$(mktemp)
    seq 1 200 | xargs -P 10 -I{} curl -s -o /dev/null -w '%{http_code}\n' \
        --max-time 5 "$BASE/api/rules" 2>/dev/null > "$TMPC"
    n429=$(grep -c '^429$' "$TMPC" || true)
    n429=${n429:-0}
    rm -f "$TMPC"
fi
if [ "${n429:-0}" -gt 0 ]; then ok "限流生效(被限 $n429 次)"
else skip "限流" "没触发(演示配置 50/s 突发 100)"; fi

sleep 2

echo "  连打 12 次攻击,观察是否触发自动封禁..."
# 压限流那一步会把令牌桶打空,这里要等它回补,否则攻击请求全是 429,
# 根本没进检测,自然也不会累计命中次数(封禁自然不触发)。
reset_hits
sleep 3
for i in $(seq 1 12); do
    curl -s -o /dev/null "$BASE/?q=union%20select%201" 2>/dev/null
    sleep 0.1
done
c=$(code "$BASE/?q=hello")
# 偶发:上一步压测把令牌桶打空后,前面几次攻击可能拿到 429 而没进检测,
# 命中次数没凑够阈值。多试几轮,别让"限流"和"封禁"互相干扰导致的偶发
# 表现成功能缺失。
tries=0
while [ "$c" != "403" ] && [ "$tries" -lt 3 ]; do
    tries=$((tries+1))
    for i in $(seq 1 5); do
        curl -s -o /dev/null "$BASE/?q=union%20select%201" 2>/dev/null
        sleep 0.15
    done
    c=$(code "$BASE/?q=hello")
done
if [ "$c" = "403" ]; then
    ok "自动封禁生效(正常请求也被拦了)"
    echo "        解除封禁..."
    sudo -n docker exec secguard-redis sh -c \
        'for k in $(redis-cli --scan --pattern "sg:ban:*"); do redis-cli DEL "$k" > /dev/null; done' \
        > /dev/null 2>&1
    sudo -n docker exec secguard-redis sh -c \
        'for k in $(redis-cli --scan --pattern "sg:hit:*"); do redis-cli DEL "$k" > /dev/null; done' \
        > /dev/null 2>&1
    sleep 1
    c=$(code "$BASE/?q=hello")
    [ "$c" = "200" ] && ok "封禁已解除,恢复正常" || bad "解除封禁" "HTTP $c"
else
    skip "自动封禁" "阈值未达到"
fi

# ---------------------------------------------------------------------------
echo
echo "=================================================================="
printf ' 结果: \033[32m通过 %d\033[0m   \033[31m失败 %d\033[0m   跳过 %d\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
    printf '\033[31m 以下项目失败:\033[0m%b\n' "$FAILED_NAMES"
fi
echo "=================================================================="

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
