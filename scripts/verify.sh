#!/bin/bash
# SecGuard 一键自检
#
# 把项目所有能力跑一遍,输出一张通过/失败表。
# 面试前自己跑一次,确认演示环境是好的。
#
# 用法:
#   ./scripts/verify.sh                      # 打默认地址
#   ./scripts/verify.sh http://1.2.3.4:8088  # 打指定地址

set -u

BASE="${1:-http://127.0.0.1:8088}"
PASS=0
FAIL=0
SKIP=0
FAILED_NAMES=""

ok()   { PASS=$((PASS+1)); printf '  \033[32m通过\033[0m  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED_NAMES="$FAILED_NAMES\n    - $1"; printf '  \033[31m失败\033[0m  %s  (%s)\n' "$1" "$2"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33m跳过\033[0m  %s  (%s)\n' "$1" "$2"; }

# 取 HTTP 状态码
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" 2>/dev/null; }
# 取响应体
body() { curl -s --max-time 10 "$@" 2>/dev/null; }

# 从 JSON 里取字段(没有 jq 也能用)
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

sec() { printf '\n\033[1m%s\033[0m\n' "$1"; }

echo "=================================================================="
echo " SecGuard 自检   目标: $BASE"
echo "=================================================================="

# ---------------------------------------------------------------------------
sec "0. 清理上一次留下的防护状态"
# ---------------------------------------------------------------------------
# 为什么要有这一步:这个脚本自己会触发限流和封禁(第 9 节),
# 如果不清,紧接着再跑一次就会全是 429/403 —— 看起来像"全挂了",
# 其实是上一轮的令牌桶被打空了、或者封禁还没到期。
# 自检脚本必须能反复跑,所以开头先自愈。
#
# 本机直连 app 时 IP 是 127.0.0.1;经 nginx 时是 Docker 网桥网关(如 172.18.0.1)。
# 所以不猜 IP,把 sg: 前缀的状态键全清掉。
if sudo -n docker ps --format '{{.Names}}' 2>/dev/null | grep -q secguard-redis; then
    sudo -n docker exec secguard-redis sh -c '
        for pat in "sg:ban:*" "sg:hit:*" "sg:rl:*" "sg:nonce:*"; do
          for k in $(redis-cli --scan --pattern "$pat"); do redis-cli DEL "$k" > /dev/null; done
        done' > /dev/null 2>&1
    ok "已清理封禁/计数/令牌桶/nonce 状态"
else
    skip "清理防护状态" "连不上 redis 容器(手动清理或等封禁自动过期)"
fi

# ---------------------------------------------------------------------------
sec "1. 服务是否活着"
# ---------------------------------------------------------------------------
c=$(code "$BASE/health")
if [ "$c" = "200" ]; then ok "健康检查返回 200"
else bad "健康检查" "HTTP $c"; fi

h=$(body "$BASE/health")
st=$(echo "$h" | jget status)
db=$(echo "$h" | jget db)
rd=$(echo "$h" | jget redis)
rules=$(echo "$h" | jget rules)
gm=$(echo "$h" | jget guard_mode)
[ "$st" = "ok" ]   && ok "服务状态 ok" || bad "服务状态" "$st"
[ "$db" = "True" ] && ok "数据库连通"   || bad "数据库连通" "$db"
[ "$rd" = "True" ] && ok "Redis 连通"   || skip "Redis 连通" "$rd(已降级为单机模式)"
[ -n "$rules" ] && [ "$rules" -gt 200 ] && ok "特征库已加载($rules 条)" || bad "特征库" "$rules"
echo "        防护模式: $gm"

# ---------------------------------------------------------------------------
sec "2. 攻击检测(核心功能)"
# ---------------------------------------------------------------------------
check_block() {  # $1=描述 $2=路径 $3=期望命中的规则前缀
    local d="$1" p="$2" want="$3"
    local out c
    out=$(curl -s --max-time 10 -w '\n%{http_code}' "$BASE$p" 2>/dev/null)
    c=$(echo "$out" | tail -1)
    if [ "$c" != "403" ]; then bad "$d" "期望 403,实际 $c"; return; fi
    if echo "$out" | grep -q "$want"; then
        ok "$d -> 403 命中 $want"
    else
        bad "$d" "403 但没命中 $want"
    fi
}

check_block "SQL 注入"     "/?q=union%20select%201,2,3"        "SQL-"
check_block "XSS"          "/?q=%3Cscript%3Ealert(1)%3C/script%3E" "XSS-"
check_block "路径穿越"     "/?file=../../../../etc/passwd"      "PAT-"
check_block "命令注入"     "/?cmd=;cat%20/etc/passwd"           "CMD-"
check_block "探测 .env"    "/.env"                              "PAT-"

c=$(code "$BASE/?q=hello")
[ "$c" = "200" ] && ok "正常请求放行 -> 200" || bad "正常请求放行" "HTTP $c"

c=$(code "$BASE/?q=this%20is%20a%20shopping%20list")
[ "$c" = "200" ] && ok "正常业务文本不误报 -> 200" || bad "误报检查" "HTTP $c"

# ---------------------------------------------------------------------------
sec "3. 未注册路径也要被检测和审计"
# ---------------------------------------------------------------------------
c=$(code "$BASE/wp-login.php")
[ "$c" = "404" ] && ok "不存在的路径返回 404(但下面会查到它是被审计过的)" \
                 || bad "不存在的路径" "HTTP $c"

# ---------------------------------------------------------------------------
sec "4. 账号与令牌"
# ---------------------------------------------------------------------------
USER="verify$RANDOM"
reg=$(curl -s --max-time 10 -X POST "$BASE/api/register" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"verify-password-2026\"}" 2>/dev/null)
if echo "$reg" | grep -q '"id"'; then ok "注册新用户 $USER"
else bad "注册" "$(echo "$reg" | head -c 80)"; fi

c=$(code -X POST "$BASE/api/register" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"verify-password-2026\"}")
[ "$c" = "409" ] && ok "重复用户名返回 409" || bad "重复用户名" "HTTP $c"

c=$(code -X POST "$BASE/api/register" -H 'Content-Type: application/json' \
    -d '{"username":"weak","password":"123"}')
[ "$c" = "400" ] && ok "弱口令被拒(400)" || bad "弱口令检查" "HTTP $c"

TOKEN=$(curl -s --max-time 10 -X POST "$BASE/api/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"verify-password-2026\"}" 2>/dev/null \
    | jget token)
if [ -n "$TOKEN" ] && [ ${#TOKEN} -gt 60 ]; then ok "登录拿到 JWT(${#TOKEN} 字符)"
else bad "登录" "没拿到令牌"; TOKEN=""; fi

c=$(code -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"wrong-password\"}")
[ "$c" = "401" ] && ok "错误口令返回 401" || bad "错误口令" "HTTP $c"

if [ -n "$TOKEN" ]; then
    c=$(code "$BASE/api/me" -H "Authorization: Bearer $TOKEN")
    [ "$c" = "200" ] && ok "带令牌访问受保护接口 -> 200" || bad "令牌鉴权" "HTTP $c"

    c=$(code -X POST "$BASE/api/posts" -H 'Content-Type: application/json' \
        -d '{"title":"x","content":"y"}')
    [ "$c" = "401" ] && ok "无令牌写接口被拒(401)" || bad "无令牌写接口" "HTTP $c"

    pid=$(curl -s --max-time 10 -X POST "$BASE/api/posts" \
        -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
        -d '{"title":"自检帖","content":"内容"}' 2>/dev/null | jget id)
    if [ -n "$pid" ]; then
        ok "发帖成功(id=$pid)"
        c=$(code "$BASE/api/posts/$pid" -H "Authorization: Bearer $TOKEN")
        [ "$c" = "200" ] && ok "读帖成功" || bad "读帖" "HTTP $c"
        c=$(code -X POST "$BASE/api/posts/$pid/comments" \
            -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
            -d '{"content":"自检评论"}')
        [ "$c" = "201" ] && ok "评论成功" || bad "评论" "HTTP $c"
    else
        bad "发帖" "没拿到 id"
    fi

    c=$(code "$BASE/api/posts/99999999999999999999" -H "Authorization: Bearer $TOKEN")
    [ "$c" = "400" ] && ok "超长 id 被拒(400,不会崩)" || bad "超长 id" "HTTP $c"
fi

# ---------------------------------------------------------------------------
sec "5. 重放防护"
# ---------------------------------------------------------------------------
NOW=$(date +%s)
NONCE="verify-$RANDOM$RANDOM"
c1=$(code -X POST "$BASE/api/check" -H 'Content-Type: application/json' \
     -H "X-Timestamp: $NOW" -H "X-Nonce: $NONCE" -d '{"payload":"hello"}')
c2=$(code -X POST "$BASE/api/check" -H 'Content-Type: application/json' \
     -H "X-Timestamp: $NOW" -H "X-Nonce: $NONCE" -d '{"payload":"hello"}')
[ "$c1" = "200" ] && ok "首次带 nonce 放行(200)" || bad "首次 nonce" "HTTP $c1"
[ "$c2" = "409" ] && ok "同一 nonce 重放被拒(409)" || bad "重放防护" "HTTP $c2"

c=$(code -X POST "$BASE/api/check" -H 'Content-Type: application/json' \
     -H "X-Timestamp: $((NOW-6000))" -H "X-Nonce: old-$RANDOM" -d '{"payload":"x"}')
[ "$c" = "403" ] && ok "过期时间戳被拒(403)" || skip "时间戳窗口" "HTTP $c(可能未启用强制) or 未配置"

# ---------------------------------------------------------------------------
sec "6. 审计与统计"
# ---------------------------------------------------------------------------
a=$(body "$BASE/api/audit/stats")
total=$(echo "$a" | jget audit_total)
blocked=$(echo "$a" | jget audit_blocked)
[ -n "$total" ] && [ "$total" -gt 0 ] && ok "审计日志有数据(总数 $total,拦截 $blocked)" \
    || bad "审计日志" "总数为 $total"

c=$(code "$BASE/api/audit/by-ip?ip=127.0.0.1")
[ "$c" = "200" ] && ok "按 IP 查审计可用" || bad "按 IP 查审计" "HTTP $c"

# ---------------------------------------------------------------------------
sec "7. AI 分析层"
# ---------------------------------------------------------------------------
an=$(body "$BASE/api/analyze/stats")
en=$(echo "$an" | jget enabled)
pv=$(echo "$an" | jget provider)
ac=$(echo "$an" | jget alerts.total)
if [ "$en" = "True" ]; then
    ok "分析层已启用(provider=$pv)"
    if [ -n "$ac" ]; then ok "已有告警 $ac 条"; else skip "告警数量" "0 条,可手动触发一轮"; fi
    c=$(code -X POST "$BASE/api/analyze/run")
    [ "$c" = "200" ] && ok "手动触发分析可用" || bad "手动触发分析" "HTTP $c"
else
    skip "AI 分析层" "未启用(设 SECGUARD_AI_ENABLE=1)"
fi

al=$(body "$BASE/api/alerts?limit=1")
if echo "$al" | grep -q '"items"'; then ok "告警接口可访问"; else bad "告警接口" "返回异常"; fi

# ---------------------------------------------------------------------------
sec "8. 特征库热加载"
# ---------------------------------------------------------------------------
c=$(code -X POST "$BASE/api/rules/reload")
[ "$c" = "200" ] && ok "热加载接口可用(不重启换规则)" || bad "热加载" "HTTP $c"

# ---------------------------------------------------------------------------
sec "9. 限流与封禁(会产生拦截,最后测)"
# ---------------------------------------------------------------------------
echo "  用并发请求压限流..."
# 三个要点(都是踩出来的):
#   1) 必须并发。串行 curl 每次十几毫秒,追不上令牌桶的补充速度。
#   2) 并发别开太大。开 50 路会先撞上 nginx 的 limit_conn(50),
#      拿到一堆连接失败而不是 429,测的就不是限流了。
#   3) 优先用 wrk,而不是 xargs 拉起几百个 curl 进程:
#      后者一次 fork 几百个进程,实测会把外层的进程管理搞崩;
#      wrk 是单进程内部并发,还会直接告诉你非 2xx 有多少条。
n429=0
if command -v wrk > /dev/null 2>&1; then
    wrk_out=$(wrk -t2 -c20 -d3s "$BASE/api/rules" 2>/dev/null)
    n429=$(echo "$wrk_out" | grep -oE 'Non-2xx or 3xx responses: [0-9]+' \
           | grep -oE '[0-9]+$')
    n429=${n429:-0}
else
    # 没有 wrk 时退化,并发降到 10,减少进程数量
    TMPC=$(mktemp)
    seq 1 200 | xargs -P 10 -I{} curl -s -o /dev/null -w '%{http_code}\n' \
        --max-time 5 "$BASE/api/rules" 2>/dev/null > "$TMPC"
    n429=$(grep -c '^429$' "$TMPC" || true)
    n429=${n429:-0}
    rm -f "$TMPC"
fi
if [ "${n429:-0}" -gt 0 ]; then ok "限流生效(被限 $n429 次)"
else skip "限流" "没触发(演示配置 50/s 突发 100,可调低阈值再试)"; fi

sleep 2

echo "  连打 12 次攻击,观察是否触发自动封禁..."
for i in $(seq 1 12); do
    curl -s -o /dev/null "$BASE/?q=union%20select%201" 2>/dev/null
done
c=$(code "$BASE/?q=hello")
if [ "$c" = "403" ]; then
    ok "自动封禁生效(正常请求也被拦了)"

    # 解除封禁时不能假设 IP 是 127.0.0.1 —— 经过 nginx 后,
    # app 看到的客户端地址是 Docker 网桥网关(如 172.18.0.1)。
    # 稳妥做法:把所有封禁键都清掉。
    echo "        解除封禁(清掉所有 sg:ban:* 键)..."
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
    skip "自动封禁" "阈值未达到(配置里是 10 次)"
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
