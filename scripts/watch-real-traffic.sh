#!/bin/bash
# 看有没有真实攻击打进来
#
# 用法(在服务器上跑):
#   ./scripts/watch-real-traffic.sh          # 看一次汇总
#   ./scripts/watch-real-traffic.sh --loop   # 每 30 秒刷新一次
#
# 判断依据:审计表里"非自己产生"的 IP 记录。
# 自己产生的流量有两个固定来源:
#   172.18.0.1       docker 网桥(服务器本机经 nginx 转发的请求:自检、演示脚本、curl)
#   <你的公网IP>      从你电脑打过去的验证请求
# 其它 IP 都算陌生来源。

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

LOOP=0
[ "${1:-}" = "--loop" ] && LOOP=1

# ---------------------------------------------------------------------------
# "自己人"名单
#
# 为什么要文件而不是写死:家庭宽带的公网 IP 是会变的(重启光猫就换),
# 硬编码在脚本里,过几天就全变成"陌生来源"了。
#
# 第一行默认是 docker 网桥 —— 凡是经 nginx 进来的请求都是它,
# 包括自检脚本、演示脚本、服务器上的 curl。它不是真实攻击。
# 后面每行加一个自己的公网 IP(用 curl ip.sb 查)。
# ---------------------------------------------------------------------------
SELF_FILE="${SELF_IP_FILE:-$HOME/.secguard_self_ips}"
if [ ! -f "$SELF_FILE" ]; then
    printf '172.18.0.1\n' > "$SELF_FILE"
fi
# 环境变量 SELF_IP 仍然优先(临时用)
if [ -n "${SELF_IP:-}" ] && ! grep -qxF "$SELF_IP" "$SELF_FILE" 2>/dev/null; then
    echo "$SELF_IP" >> "$SELF_FILE"
fi

# 拼成 SQL 的 NOT IN 列表
SELF_LIST=$(awk 'NF && $1 !~ /^#/ {printf "%s'\''%s'\''", (n++ ? "," : ""), $1}' "$SELF_FILE")
[ -n "$SELF_LIST" ] || SELF_LIST="'172.18.0.1'"

DBPASS=$(grep '^SECGUARD_DB_PASS=' .env 2>/dev/null | cut -d= -f2-)
[ -n "$DBPASS" ] || { echo "读不到 .env 里的 SECGUARD_DB_PASS"; exit 1; }

q() { sudo docker exec secguard-mysql mysql -usecguard -p"$DBPASS" -N -B -e "$1" 2>/dev/null; }

render() {
    clear 2>/dev/null || true
    echo "SecGuard 真实流量观察  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "服务运行: $(curl -s --max-time 5 http://127.0.0.1:8088/health 2>/dev/null \
        | python3 -c 'import sys,json;u=json.load(sys.stdin)["uptime_sec"];print(f"{u//3600} 小时 {(u%3600)//60} 分")' 2>/dev/null || echo '读不到')"
    echo "================================================================"

    echo
    echo "【按 IP 汇总】"
    q "SELECT ip, COUNT(*) n, SUM(action='BLOCK') blk, SUM(action='ALERT') alt,
              MIN(created_at), MAX(created_at)
       FROM secguard.audit_log GROUP BY ip ORDER BY n DESC" \
    | awk -F'\t' '{printf "  %-18s %6s 条   拦截 %-4s 告警级 %-4s  %s ~ %s\n", $1,$2,$3,$4,$5,$6}'

    echo
    echo "【陌生来源的请求(排除自己人: docker 网桥 + 你的公网 IP)】"
    local where="ip NOT IN ($SELF_LIST)"
    local rows
    rows=$(q "SELECT COUNT(*) FROM secguard.audit_log WHERE $where")
    if [ "${rows:-0}" = "0" ]; then
        echo "  暂无陌生来源。"
        echo
        echo "  说明:服务在 8088 和 80 上都开着。80 端口更容易被通用扫描器扫到,"
        echo "       但要等 —— 上线几小时内没动静是正常的。"
    else
        echo "  共 $rows 条:"
        q "SELECT id, ip, method, LEFT(uri,42), action, status_code,
                  IFNULL(LEFT(rule_hit,30),'-'), created_at
           FROM secguard.audit_log WHERE $where ORDER BY id DESC LIMIT 15" \
        | awk -F'\t' '{printf "  #%-5s %-16s %-5s %-42s %-6s %s  %-30s %s\n", $1,$2,$3,$4,$5,$6,$7,$8}'

        echo
        echo "  【其中被判为攻击的(有命中规则)】"
        q "SELECT id, ip, LEFT(uri,40), action, LEFT(rule_hit,40), created_at
           FROM secguard.audit_log WHERE $where AND rule_hit IS NOT NULL
           ORDER BY id DESC LIMIT 10" \
        | awk -F'\t' 'NF>0 {printf "  #%-5s %-16s %-40s %-6s %-40s %s\n", $1,$2,$3,$4,$5,$6}'
        local hit
        hit=$(q "SELECT COUNT(*) FROM secguard.audit_log WHERE $where AND rule_hit IS NOT NULL")
        if [ "${hit:-0}" = "0" ]; then
            echo "    (没有 —— 陌生访问都是正常请求)"
        fi
    fi

    echo
    echo "【AI 告警按来源】"
    q "SELECT ip, COUNT(*), MAX(created_at) FROM secguard.alert GROUP BY ip" \
    | awk -F'\t' '{printf "  %-18s %s 条   最近 %s\n", $1,$2,$3}'

    echo
    echo "【注意】172.18.0.1 是 docker 网桥:凡是经 nginx 进来的请求都是这个地址,"
    echo "       包括自检脚本、演示脚本、服务器上的 curl。它不代表真实攻击。"
    echo "       真实外部请求会显示为具体公网 IP。"
}

if [ "$LOOP" = "1" ]; then
    while true; do
        render
        sleep 30
    done
else
    render
fi
