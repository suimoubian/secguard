#!/bin/bash
# 演示:制造一批可识别的攻击流量,让 AI 分析层产出告警
#
# 用途:演示时不用临场敲 curl,一条命令就有"攻击 -> 拦截 -> 审计 -> AI 判定"的完整链路。
#
# 用法:
#   ./scripts/demo-attack.sh                      # 打本机 8088
#   ./scripts/demo-attack.sh http://1.2.3.4:8088  # 打指定地址
#   ./scripts/demo-attack.sh --reset              # 只清空命中计数(被演示累了时用)
#
# ⚠ 注意:每发一次攻击都会累计命中次数,达到 SECGUARD_HIT_THRESHOLD(默认 20)
#   就会把来源 IP 封禁 SECGUARD_BAN_SECONDS 秒。本脚本一共发 8 次,所以连跑
#   两轮(16 次)还安全,第三轮可能会被封。被封了就等一会儿,或者用 --reset。
#   注意 --reset 只能在本机执行(要访问 docker)。

set -uo pipefail

BASE="http://127.0.0.1:8088"
RESET_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --reset) RESET_ONLY=1 ;;
        http*)   BASE="$arg" ;;
        *)       echo "未知参数: $arg"; exit 1 ;;
    esac
done

GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; NC=$'\033[0m'

reset_hits() {
    if command -v docker > /dev/null 2>&1; then
        docker exec secguard-redis sh -c '
            for pat in "sg:hit:*" "sg:ban:*"; do
              for k in $(redis-cli --scan --pattern "$pat"); do redis-cli DEL "$k" > /dev/null; done
            done' > /dev/null 2>&1 \
            && echo "  已清空命中计数与封禁" \
            || echo "  清理失败(可能需要 sudo docker)"
    else
        echo "  本机没有 docker,无法清理"
    fi
}

if [ "$RESET_ONLY" = "1" ]; then
    reset_hits
    exit 0
fi

echo "目标: $BASE"
echo

# ---------------------------------------------------------------------------
# 八个请求,分四类。分类是为了让 AI 有"多类型交叉命中"可看 ——
# 单一类型重复打,它只会说"高频重复",加上不同类型才像扫描器。
# ---------------------------------------------------------------------------
send() {  # $1=说明  $2=路径
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$BASE$2" 2>/dev/null)
    if [ "$code" = "403" ]; then
        printf '  %s拦截%s  HTTP %s  %-44s %s\n' "$GREEN" "$NC" "$code" "$2" "$DIM$1$NC"
    elif [ "$code" = "429" ]; then
        printf '  %s限流%s  HTTP %s  %-44s %s\n' "$YELLOW" "$NC" "$code" "$2" "$DIM$1$NC"
    else
        printf '  %s放行%s  HTTP %s  %-44s %s\n' "$RED" "$NC" "$code" "$2" "$DIM$1$NC"
    fi
    sleep 0.2
}

echo "=== 发送演示攻击(共 8 次)==="
send "SQL 注入:union select"        "/?q=union%20select%201,2,3"
send "SQL 注入:or 1=1"              "/?q=1%27%20or%201=1--"
send "子查询(命中 SQL-003,该规则是 ALERT 级 -> 预期 200)" \
                                    "/?q=1%20and%20(select%20count(*)%20from%20user)"
send "XSS:script 标签"              "/?q=%3Cscript%3Ealert(1)%3C/script%3E"
send "XSS:onerror 事件"             "/?q=%3Cimg%20src=x%20onerror=alert(1)%3E"
send "路径穿越:/etc/passwd"         "/?file=../../../../etc/passwd"
send "命令注入:cat"                 "/?cmd=;cat%20/etc/passwd"
send "敏感文件探测:.env"            "/.env"

echo
echo "=== 再补一条请求体攻击(POST body 里的注入)==="
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -X POST "$BASE/api/check" \
        -H 'Content-Type: application/json' \
        -d '{"payload":"admin'"'"' union select password from user--"}' 2>/dev/null)
printf '  HTTP %s  POST /api/check (body 里带注入)\n' "$code"

echo
echo "${DIM}等 2 秒让审计队列落库(批量 500 条 / 每 1 秒)...${NC}"
sleep 2

echo
echo "=== 结果 ==="
echo "  8 个请求被拦(403)。第 3 个返回 200 是**正常的**,不是漏洞:"
echo "  它命中 SQL-003,而这条规则在 rules/policy.conf 里被降级成 ALERT ——"
echo "  仍然记录、仍然进 AI 分析,只是不返回 403。原因见 docs/演示素材.md。"
echo
echo "  1) 看审计流水(管理接口,需要管理员令牌):"
echo "       TOKEN=\$(curl -s -X POST $BASE/api/login \\"
echo "         -H 'Content-Type: application/json' \\"
echo "         -d '{\"username\":\"admin\",\"password\":\"<管理员密码>\"}' | jq -r .token)"
echo "       curl -s -H \"Authorization: Bearer \$TOKEN\" $BASE/api/audit/stats | jq"
echo
echo "  2) 触发一轮 AI 分析(约 2 秒):"
echo "       curl -s -X POST -H \"Authorization: Bearer \$TOKEN\" $BASE/api/analyze/run | jq"
echo
echo "  3) 看 AI 生成的告警:"
echo "       curl -s -H \"Authorization: Bearer \$TOKEN\" \"$BASE/api/alerts?limit=3\" | jq"
echo
echo "  4) 或者直接打开首页,点那四个演示链接:"
echo "       http://<服务器IP>:8088"
echo
echo "  ${YELLOW}提示${NC}:连跑多轮会累计命中次数,达到阈值(默认 20)会被封禁。"
echo "        想重来:本机执行 ./scripts/demo-attack.sh --reset"
